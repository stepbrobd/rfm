package enrich

import (
	"io"

	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/enrich/mmdb"
	"ysun.co/rfm/enrich/rib"
)

// Build constructs the configured enrichment backends.
// When no backend is configured, it returns nil, nil, nil.
func Build(cfg config.EnrichConfig) (collector.Enricher, io.Closer, error) {
	var enrichers []collector.Enricher
	var closers []io.Closer

	add := func(enricher collector.Enricher, closer io.Closer) {
		if enricher != nil {
			enrichers = append(enrichers, enricher)
		}
		if closer != nil {
			closers = append(closers, closer)
		}
	}

	r, rCloser, err := rib.Listen(cfg.RIB)
	if err != nil {
		return nil, nil, err
	}
	add(r, rCloser)

	mm, mmCloser, err := mmdb.Open(cfg.MMDB)
	if err != nil {
		closeAll(closers)
		return nil, nil, err
	}
	add(mm, mmCloser)

	if len(enrichers) == 0 {
		return nil, nil, nil
	}

	var closer io.Closer
	switch len(closers) {
	case 0:
	case 1:
		closer = closers[0]
	default:
		closer = multiCloser(closers)
	}

	if len(enrichers) == 1 {
		return enrichers[0], closer, nil
	}

	return composite{enrichers: enrichers}, closer, nil
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var first error
	for _, closer := range m {
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func closeAll(closers []io.Closer) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}
