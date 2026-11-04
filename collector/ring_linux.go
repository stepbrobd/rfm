//go:build linux

package collector

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// the record header of a BPF ring buffer, from include/uapi/linux/bpf.h
const (
	ringBusyBit    = 1 << 31
	ringDiscardBit = 1 << 30
	ringHdrSize    = 8
)

// eventRing reads one BPF ring buffer in place, it loads the producer position once per batch and stores the consumer position on commit
type eventRing struct {
	consPage, rest   []byte
	consPos, prodPos *uintptr
	// data maps the ring twice in a row, so a record that wraps reads whole
	data []byte
	mask uintptr
	// head is past the last record handed out, tail the producer position last loaded, committed the consumer position last stored
	head, tail, committed uintptr
}

func newEventRing(m *ebpf.Map) (*eventRing, error) {
	page := os.Getpagesize()
	size := int(m.MaxEntries())
	cons, err := unix.Mmap(m.FD(), 0, page, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap consumer page: %w", err)
	}
	rest, err := unix.Mmap(m.FD(), int64(page), page+2*size, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(cons)
		return nil, fmt.Errorf("mmap producer and data pages: %w", err)
	}
	r := &eventRing{
		consPage: cons,
		rest:     rest,
		consPos:  (*uintptr)(unsafe.Pointer(&cons[0])),
		prodPos:  (*uintptr)(unsafe.Pointer(&rest[0])),
		data:     rest[page:],
		mask:     uintptr(size - 1),
	}
	r.head = atomic.LoadUintptr(r.consPos)
	r.tail, r.committed = r.head, r.head
	return r, nil
}

// ready loads the producer position and reports whether it is past the records handed out
func (r *eventRing) ready() bool {
	r.tail = atomic.LoadUintptr(r.prodPos)
	return r.tail != r.head
}

// next returns the sample of the next committed record or nil, the sample stays valid until commit
func (r *eventRing) next() []byte {
	for {
		if r.head == r.tail && !r.ready() {
			return nil
		}
		off := r.head & r.mask
		// the atomic load orders the header after the kernel's commit of the record
		hdr := atomic.LoadUint32((*uint32)(unsafe.Pointer(&r.data[off])))
		if hdr&ringBusyBit != 0 {
			return nil
		}
		n := uintptr(hdr &^ (ringBusyBit | ringDiscardBit))
		size := (ringHdrSize + n + 7) &^ 7
		if size > r.tail-r.head {
			return nil
		}
		r.head += size
		if hdr&ringDiscardBit != 0 {
			continue
		}
		start := off + ringHdrSize
		return r.data[start : start+n : start+n]
	}
}

// commit gives the space of every record handed out back to the producers
func (r *eventRing) commit() {
	if r.committed != r.head {
		atomic.StoreUintptr(r.consPos, r.head)
		r.committed = r.head
	}
}

func (r *eventRing) Close() error {
	cons, rest := r.consPage, r.rest
	r.consPage, r.rest, r.data = nil, nil, nil
	return errors.Join(unix.Munmap(cons), unix.Munmap(rest))
}
