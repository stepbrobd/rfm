package enrich

import (
	"errors"
	"net/netip"

	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/enrich/mmdb"
	"ysun.co/rfm/enrich/rib"
)

// Backends holds the configured enrichment backends, either may be nil
type Backends struct {
	RIB  *rib.Server
	MMDB *mmdb.Enricher
}

// Build starts the configured backends, it returns nil, nil when none is
func Build(cfg config.EnrichConfig) (*Backends, error) {
	r, err := rib.Listen(cfg.RIB)
	if err != nil {
		return nil, err
	}
	m, err := mmdb.Open(cfg.MMDB)
	if err != nil {
		if r != nil {
			_ = r.Close()
		}
		return nil, err
	}
	if r == nil && m == nil {
		return nil, nil
	}
	return &Backends{RIB: r, MMDB: m}, nil
}

// Enrich labels from the RIB first and from MMDB what the RIB left out
func (b *Backends) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	var s, d collector.Labels
	if b.RIB != nil {
		s, d = b.RIB.Enrich(src, dst)
	}
	if b.MMDB != nil {
		s, d = b.MMDB.Fill(src, s), b.MMDB.Fill(dst, d)
	}
	return s, d
}

// Close closes every backend
func (b *Backends) Close() error {
	var err error
	if b.RIB != nil {
		err = b.RIB.Close()
	}
	if b.MMDB != nil {
		err = errors.Join(err, b.MMDB.Close())
	}
	return err
}
