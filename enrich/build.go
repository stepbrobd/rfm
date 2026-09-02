package enrich

import (
	"io"

	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/enrich/mmdb"
	"ysun.co/rfm/enrich/rib"
)

// Backends holds the configured enrichment backends
// Enricher is what the collector uses, RIB and MMDB stay reachable for the
// control plane, either may be nil
type Backends struct {
	Enricher collector.Enricher
	RIB      *rib.Server
	MMDB     *mmdb.Enricher
	closers  []io.Closer
}

// Build constructs the configured enrichment backends
// when no backend is configured, it returns nil, nil
func Build(cfg config.EnrichConfig) (*Backends, error) {
	b := &Backends{}
	var enrichers []collector.Enricher

	r, rCloser, err := rib.Listen(cfg.RIB)
	if err != nil {
		return nil, err
	}
	if r != nil {
		b.RIB = r.(*rib.Server)
		enrichers = append(enrichers, r)
		b.closers = append(b.closers, rCloser)
	}

	mm, mmCloser, err := mmdb.Open(cfg.MMDB)
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	if mm != nil {
		b.MMDB = mm.(*mmdb.Enricher)
		enrichers = append(enrichers, mm)
		b.closers = append(b.closers, mmCloser)
	}

	switch len(enrichers) {
	case 0:
		return nil, nil
	case 1:
		b.Enricher = enrichers[0]
	default:
		b.Enricher = composite{enrichers: enrichers}
	}
	return b, nil
}

// Close closes every backend and returns the first error
func (b *Backends) Close() error {
	var first error
	for _, closer := range b.closers {
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
