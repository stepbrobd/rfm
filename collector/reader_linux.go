//go:build linux

package collector

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// ringReader reads every CPU's ring as one stream, up to readBatch records per ring in turn
type ringReader struct {
	rings []*eventRing
	drops *ebpf.Map
	epfd  int
	// live lists the rings the last scan found records in, in turn order
	live []int
	// next indexes the live ring the next read takes from
	next int
	// burst counts the records that ring gave in a row
	burst int
	// since counts the records read since the last scan
	since int
	// held is the ring whose burst ended on the sample last handed out, committed at the next read
	held     *eventRing
	deadline time.Time
	events   []unix.EpollEvent

	// added holds the rings AddRing mapped since the last scan, which takes
	// them into rings, guarded by mu, pending tells a scan there are some
	mu      sync.Mutex
	added   []*eventRing
	pending atomic.Bool
}

// rescanEvery bounds how many records the live rings give before a ring that turned busy joins them
const rescanEvery = 256

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
		rd, err := newEventRing(ring)
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("map ring buffer %d: %w", i, err)
		}
		r.rings = append(r.rings, rd)
		ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(i)}
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, ring.FD(), &ev); err != nil {
			r.Close()
			return nil, fmt.Errorf("watch ring buffer %d: %w", i, err)
		}
	}
	return r, nil
}

func (r *ringReader) ReadRawEvent() ([]byte, error) {
	if r.held != nil {
		r.held.commit()
		r.held = nil
	}
	if r.since >= rescanEvery {
		r.scan()
	}
	for {
		for len(r.live) > 0 {
			ring := r.rings[r.live[r.next]]
			if raw := ring.next(); raw != nil {
				r.since++
				if r.burst++; r.burst == readBatch {
					r.held = ring
					r.turn()
				}
				return raw, nil
			}
			ring.commit()
			r.drop()
		}
		if r.scan() {
			continue
		}
		if err := r.wait(); err != nil {
			return nil, err
		}
		r.scan()
	}
}

// AddRing reads ring too from the next scan on, the ring of a CPU that came
// online after the reader opened, it is safe beside a read in progress
func (r *ringReader) AddRing(ring *ebpf.Map) error {
	rd, err := newEventRing(ring)
	if err != nil {
		return fmt.Errorf("map ring buffer: %w", err)
	}
	// the ring is watched before a scan can take it, a wait it ends finds it at the scan after
	ev := unix.EpollEvent{Events: unix.EPOLLIN}
	if err := unix.EpollCtl(r.epfd, unix.EPOLL_CTL_ADD, ring.FD(), &ev); err != nil {
		rd.Close()
		return fmt.Errorf("watch ring buffer: %w", err)
	}
	r.mu.Lock()
	r.added = append(r.added, rd)
	r.pending.Store(true)
	r.mu.Unlock()
	return nil
}

// scan commits every ring and lists the ones that hold records, the others cost no read until the next scan
func (r *ringReader) scan() bool {
	if r.pending.Load() {
		r.mu.Lock()
		r.rings = append(r.rings, r.added...)
		r.added = nil
		r.pending.Store(false)
		r.mu.Unlock()
	}
	r.live = r.live[:0]
	for i, ring := range r.rings {
		ring.commit()
		if ring.ready() {
			r.live = append(r.live, i)
		}
	}
	r.next, r.burst, r.since = 0, 0, 0
	return len(r.live) > 0
}

// turn hands the next read to the next live ring
func (r *ringReader) turn() {
	r.next = (r.next + 1) % len(r.live)
	r.burst = 0
}

// drop takes the ring the last read emptied out of the turn
func (r *ringReader) drop() {
	r.live = slices.Delete(r.live, r.next, r.next+1)
	if r.next == len(r.live) {
		r.next = 0
	}
	r.burst = 0
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
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rd := range slices.Concat(r.rings, r.added) {
		errs = append(errs, rd.Close())
	}
	errs = append(errs, unix.Close(r.epfd))
	return errors.Join(errs...)
}
