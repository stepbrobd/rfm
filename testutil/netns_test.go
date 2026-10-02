//go:build linux

package testutil

import (
	"bytes"
	"testing"
	"unsafe"
)

func TestVirtioNetHdrHostOrder(t *testing.T) {
	hdr := virtioNetHdr{
		Flags:      virtioNetHdrNeedsCsum,
		GSOType:    virtioNetHdrGSOTCPv6,
		HdrLen:     0x0102,
		GSOSize:    0x0304,
		CsumStart:  0x0506,
		CsumOffset: 0x0708,
	}

	got := hdr.marshal()
	if len(got) != virtioNetHdrLen {
		t.Fatalf("header is %d bytes, want %d", len(got), virtioNetHdrLen)
	}

	// AF_PACKET reads the fields of struct virtio_net_hdr in host byte
	// order, as they lie in memory
	want := unsafe.Slice((*byte)(unsafe.Pointer(&hdr)), unsafe.Sizeof(hdr))
	if !bytes.Equal(got, want) {
		t.Fatalf("header = % x, want the host order layout % x", got, want)
	}
}
