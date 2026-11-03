//go:build linux

package collector

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// ringReader reads the event rings of every CPU as one stream, it takes the
// next record from the next ring that holds one, so a busy ring cannot starve
// the others, and sleeps on one epoll set over all rings when they are empty
type ringReader struct {
	rings []*ringbuf.Reader
	drops *ebpf.Map
	epfd  int
	// next is the ring the next read looks at first
	next     int
	deadline time.Time
	events   []unix.EpollEvent
	// rec is reused by every read, ReadRawEvent hands out its sample
	rec ringbuf.Record
}

// NewReader wraps the event rings of every CPU and a per-CPU drop counter map
func NewReader(rings []*ebpf.Map, drops *ebpf.Map) (Reader, error) {
	if len(rings) == 0 {
		return nil, errors.New("no event rings")
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create epoll: %w", err)
	}
	r := &ringReader{drops: drops, epfd: epfd, events: make([]unix.EpollEvent, len(rings))}
	for i, ring := range rings {
		rd, err := ringbuf.NewReader(ring)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("open ring buffer of cpu %d: %w", i, err)
		}
		// reads only go to a ring that holds data, a deadline in the past
		// keeps them from blocking
		rd.SetDeadline(time.Unix(1, 0))
		r.rings = append(r.rings, rd)
		ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(i)}
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, ring.FD(), &ev); err != nil {
			r.Close()
			return nil, fmt.Errorf("watch ring buffer of cpu %d: %w", i, err)
		}
	}
	return r, nil
}

func (r *ringReader) ReadRawEvent() ([]byte, error) {
	for {
		for range r.rings {
			rd := r.rings[r.next]
			r.next = (r.next + 1) % len(r.rings)
			if rd.AvailableBytes() == 0 {
				continue
			}
			err := rd.ReadInto(&r.rec)
			if err == nil {
				return r.rec.RawSample, nil
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, err
			}
		}
		if err := r.wait(); err != nil {
			return nil, err
		}
	}
}

// wait sleeps until a ring holds data or the deadline passes, a ring polls
// readable while it holds data, so a record written without a wakeup is
// found by the next wait
func (r *ringReader) wait() error {
	timeout := -1
	if !r.deadline.IsZero() {
		d := time.Until(r.deadline)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		timeout = int((d + time.Millisecond - 1) / time.Millisecond)
	}
	for {
		n, err := unix.EpollWait(r.epfd, r.events, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for ring buffers: %w", err)
		}
		if n == 0 {
			return os.ErrDeadlineExceeded
		}
		return nil
	}
}

func (r *ringReader) SetDeadline(t time.Time) {
	r.deadline = t
}

func (r *ringReader) DroppedEvents() (uint64, error) {
	var key uint32
	var vals []uint64
	if err := r.drops.Lookup(key, &vals); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	return total, nil
}

func (r *ringReader) Close() error {
	var errs []error
	for _, rd := range r.rings {
		errs = append(errs, rd.Close())
	}
	errs = append(errs, unix.Close(r.epfd))
	return errors.Join(errs...)
}
