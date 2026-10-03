package collector

import (
	"net/netip"
	"reflect"
	"testing"
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

func TestLabelsZeroValue(t *testing.T) {
	var l Labels
	if l.ASN != 0 {
		t.Errorf("ASN=%d want 0", l.ASN)
	}
	if l.City != "" {
		t.Errorf("City=%q want empty", l.City)
	}
}
