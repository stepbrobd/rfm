package enrich

import (
	"net/netip"

	"ysun.co/rfm/collector"
)

type composite struct {
	enrichers []collector.Enricher
}

func (c composite) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	var srcOut collector.Labels
	var dstOut collector.Labels

	for _, enricher := range c.enrichers {
		srcLabels, dstLabels := enricher.Enrich(src, dst)
		srcOut = mergeLabels(srcOut, srcLabels)
		dstOut = mergeLabels(dstOut, dstLabels)
	}

	return srcOut, dstOut
}

func mergeLabels(base, next collector.Labels) collector.Labels {
	if base.ASN == 0 {
		base.ASN = next.ASN
	}
	if base.City == "" {
		base.City = next.City
	}
	return base
}
