package collector

import (
	"net/netip"
	"testing"
)

func TestFlowEventKey(t *testing.T) {
	ev := FlowEvent{
		Ifindex: 1,
		Dir:     0,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("::ffff:10.0.0.1"),
		DstAddr: netip.MustParseAddr("::ffff:10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
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
		{"one packet", FlowEvent{Len: 1514, L2Len: 14}, 1500},
		{"vlan tagged", FlowEvent{Len: 104, L2Len: 18}, 86},
		{"gro skb", FlowEvent{Segs: 3, Len: 3 * 1514, L2Len: 14}, 4500},
		{"no l2 header", FlowEvent{Len: 60}, 60},
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
