package enrich

import (
	"net/netip"
	"testing"

	"ysun.co/rfm/collector"
	"ysun.co/rfm/enrich/rib"
)

type fakeEnricher struct {
	src collector.Labels
	dst collector.Labels
}

func (f fakeEnricher) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return f.src, f.dst
}

func TestCompositeDefaultRouteFallsBackToMMDB(t *testing.T) {
	tab := rib.NewTable()
	tab.Apply(rib.Update{Reach: []rib.Route{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), OriginASN: 64500, ASPath: []uint32{64500}},
	}})
	c := composite{
		enrichers: []collector.Enricher{
			tab,
			fakeEnricher{
				src: collector.Labels{ASN: 15169, City: "Mountain View"},
				dst: collector.Labels{ASN: 13335},
			},
		},
	}

	src, dst := c.Enrich(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"))
	if src != (collector.Labels{ASN: 15169, City: "Mountain View"}) || dst != (collector.Labels{ASN: 13335}) {
		t.Fatalf("labels = %+v and %+v, want the MMDB labels behind a default route", src, dst)
	}
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
