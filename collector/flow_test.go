package collector

import (
	"math/rand/v2"
	"net/netip"
	"reflect"
	"testing"
	"unsafe"
)

// hasPointers reports whether a value of typ holds a pointer the garbage
// collector has to follow
func hasPointers(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Pointer, reflect.UnsafePointer, reflect.Slice, reflect.Map, reflect.Chan,
		reflect.Func, reflect.Interface, reflect.String:
		return true
	case reflect.Array:
		return typ.Len() > 0 && hasPointers(typ.Elem())
	case reflect.Struct:
		for field := range typ.Fields() {
			if hasPointers(field.Type) {
				return true
			}
		}
	}
	return false
}

func TestExportedFlowIsCompactAndPointerFree(t *testing.T) {
	// the ipfix queue holds as many records as the flow table holds flows,
	// a record with pointers would have every collection scan the queue
	typ := reflect.TypeFor[ExportedFlow]()
	if hasPointers(typ) {
		t.Fatal("ExportedFlow holds pointers")
	}
	if size := typ.Size(); size > 96 {
		t.Fatalf("ExportedFlow is %d bytes, want at most 96", size)
	}

	// a flow keeps the counters its records already carried, not a copy of
	// its whole entry
	sent, _ := reflect.TypeFor[flowState]().FieldByName("sent")
	if size := sent.Type.Size(); size > 32 {
		t.Fatalf("flowState.sent is %d bytes, want the counters a record carries", size)
	}
}

func TestFlowEventKey(t *testing.T) {
	ev := FlowEvent{
		Ifindex: 1,
		Dir:     0,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
		Segs:    1,
		Len:     100,
	}

	k1 := ev.Key()
	k2 := ev.Key()
	if k1 != k2 {
		t.Fatalf("same event produced different keys: %v != %v", k1, k2)
	}

	// different port = different key
	ev.SrcPort = 9999
	k3 := ev.Key()
	if k1 == k3 {
		t.Fatal("different events produced same key")
	}
}

func TestFlowEventIPBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   FlowEvent
		want uint64
	}{
		{"one packet", FlowEvent{Segs: 1, Len: 1514, L2Len: 14}, 1500},
		{"vlan tagged", FlowEvent{Segs: 1, Len: 104, L2Len: 18}, 86},
		{"gro skb", FlowEvent{Segs: 3, Len: 3 * 1514, L2Len: 14}, 4500},
		{"no l2 header", FlowEvent{Segs: 1, Len: 60}, 60},
	} {
		if got := tc.ev.IPBytes(); got != tc.want {
			t.Errorf("%s: ip bytes = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestFlowIDRoundTrips(t *testing.T) {
	for _, k := range []FlowKey{
		{Ifindex: 2, Dir: 1, Proto: 6, SrcAddr: netip.MustParseAddr("::ffff:192.0.2.1"), DstAddr: netip.MustParseAddr("::ffff:198.51.100.7"), SrcPort: 1, DstPort: 2},
		{Ifindex: 1<<31 - 1, Proto: 58, SrcAddr: netip.MustParseAddr("fe80::1"), DstAddr: netip.MustParseAddr("ff02::1")},
	} {
		id := k.id()
		if got := id.key(); got != k {
			t.Fatalf("key %+v came back %+v", k, got)
		}
	}

	// keys that differ in one field have different ids
	base := FlowKey{Ifindex: 2, Proto: 6, SrcAddr: netip.MustParseAddr("::ffff:192.0.2.1"), DstAddr: netip.MustParseAddr("::ffff:192.0.2.2"), SrcPort: 1, DstPort: 2}
	for _, other := range []FlowKey{
		{Ifindex: 3, Proto: 6, SrcAddr: base.SrcAddr, DstAddr: base.DstAddr, SrcPort: 1, DstPort: 2},
		{Ifindex: 2, Dir: 1, Proto: 6, SrcAddr: base.SrcAddr, DstAddr: base.DstAddr, SrcPort: 1, DstPort: 2},
		{Ifindex: 2, Proto: 17, SrcAddr: base.SrcAddr, DstAddr: base.DstAddr, SrcPort: 1, DstPort: 2},
		{Ifindex: 2, Proto: 6, SrcAddr: base.DstAddr, DstAddr: base.SrcAddr, SrcPort: 1, DstPort: 2},
		{Ifindex: 2, Proto: 6, SrcAddr: base.SrcAddr, DstAddr: base.DstAddr, SrcPort: 2, DstPort: 1},
	} {
		if other.id() == base.id() {
			t.Fatalf("%+v and %+v share an id", other, base)
		}
	}
}

func TestFlowIDEqualComparesEveryByte(t *testing.T) {
	// an id without padding has every byte in some field
	if size := unsafe.Sizeof(flowID{}); size != 42 {
		t.Fatalf("flowID is %d bytes, want 42", size)
	}
	base := FlowKey{
		Ifindex: 0x01020304, Dir: 1, Proto: 6,
		SrcAddr: netip.MustParseAddr("2001:db8::1"), DstAddr: netip.MustParseAddr("2001:db8::2"),
		SrcPort: 0x0506, DstPort: 0x0708,
	}.id()
	same := base
	if !base.equal(&same) {
		t.Fatal("an id differs from its copy")
	}
	for i := range unsafe.Sizeof(base) {
		other := base
		(*[unsafe.Sizeof(flowID{})]byte)(unsafe.Pointer(&other))[i] ^= 0x80
		if base.equal(&other) || other.equal(&base) {
			t.Fatalf("ids that differ in byte %d compare equal", i)
		}
	}
}

func TestFlowHashKeepsStructuredIDsApart(t *testing.T) {
	// the ids traffic has, sources of one network on few ports, both
	// directions of each, where symmetric ports make a flow and its reverse
	// differ only by swapped addresses, and ipv6 sources
	dst := netip.MustParseAddr("::ffff:198.51.100.7")
	var ids []flowID
	for i := range 1 << 14 {
		src := netip.AddrFrom16(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).As16())
		for _, port := range []uint16{53, 443, uint16(1024 + i)} {
			k := FlowKey{Ifindex: 2, Proto: 17, SrcAddr: src, DstAddr: dst, SrcPort: port, DstPort: 53}
			ids = append(ids, k.id())
			k.SrcAddr, k.DstAddr, k.SrcPort, k.DstPort = k.DstAddr, k.SrcAddr, k.DstPort, k.SrcPort
			ids = append(ids, k.id())
		}
		v6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)})
		ids = append(ids, FlowKey{Ifindex: 3, Dir: 1, Proto: 6, SrcAddr: v6, DstAddr: dst, SrcPort: 443, DstPort: 443}.id())
	}
	// fixed keys keep the test the same on every run
	for seed := range uint64(3) {
		rng := rand.New(rand.NewPCG(seed, 1))
		var k flowHash
		for i := range k {
			k[i] = rng.Uint64()
		}
		seen := make(map[uint64]int, len(ids))
		for i := range ids {
			h := k.sum(&ids[i])
			if j, ok := seen[h]; ok {
				t.Fatalf("keys %d: %+v and %+v share hash %#x", seed, ids[j].key(), ids[i].key(), h)
			}
			seen[h] = i
		}
	}
}
