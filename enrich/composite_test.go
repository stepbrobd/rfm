package enrich

import (
	"net/netip"
	"testing"

	"ysun.co/rfm/collector"
)

type fakeEnricher struct {
	src collector.Labels
	dst collector.Labels
}

func (f fakeEnricher) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return f.src, f.dst
}

func TestCompositeFirstNonZeroWins(t *testing.T) {
	c := composite{
		enrichers: []collector.Enricher{
			fakeEnricher{
				src: collector.Labels{ASN: 64512},
			},
			fakeEnricher{
				src: collector.Labels{ASN: 64513, City: "Paris"},
				dst: collector.Labels{City: "London"},
			},
		},
	}

	src, dst := c.Enrich(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
	)

	if src.ASN != 64512 {
		t.Fatalf("src ASN = %d, want 64512", src.ASN)
	}
	if src.City != "Paris" {
		t.Fatalf("src city = %q, want Paris", src.City)
	}
	if dst.City != "London" {
		t.Fatalf("dst city = %q, want London", dst.City)
	}
}
