package mmdb

import (
	"fmt"
	"io"
	"net/netip"
	"os"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

// Open opens the configured MMDB databases
// when no MMDB database is configured, it returns nil, nil, nil
func Open(cfg config.MMDBConfig) (collector.Enricher, io.Closer, error) {
	if cfg.ASNDB == "" && cfg.CityDB == "" {
		return nil, nil, nil
	}

	m := &Enricher{}

	if cfg.ASNDB != "" {
		if err := checkPath(cfg.ASNDB); err != nil {
			return nil, nil, err
		}
		db, err := maxminddb.Open(cfg.ASNDB)
		if err != nil {
			return nil, nil, fmt.Errorf("open ASN MMDB %q: %w", cfg.ASNDB, err)
		}
		m.asn = db
	}

	if cfg.CityDB != "" {
		if err := checkPath(cfg.CityDB); err != nil {
			_ = m.Close()
			return nil, nil, err
		}
		db, err := maxminddb.Open(cfg.CityDB)
		if err != nil {
			_ = m.Close()
			return nil, nil, fmt.Errorf("open city MMDB %q: %w", cfg.CityDB, err)
		}
		m.city = db
	}

	return m, m, nil
}

// Enricher reads optional ASN and city data from MMDB files
type Enricher struct {
	asn  *maxminddb.Reader
	city *maxminddb.Reader
}

func (m *Enricher) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return m.lookup(src), m.lookup(dst)
}

func (m *Enricher) lookup(addr netip.Addr) collector.Labels {
	addr = addr.Unmap()

	var labels collector.Labels

	if m.asn != nil {
		asn, err := lookupASN(m.asn, addr)
		if err == nil {
			labels.ASN = asn
		}
	}

	if m.city != nil {
		city, err := lookupCity(m.city, addr)
		if err == nil {
			labels.City = city
		}
	}

	return labels
}

func (m *Enricher) Close() error {
	var first error
	if m.asn != nil {
		if err := m.asn.Close(); err != nil {
			first = err
		}
	}
	if m.city != nil {
		if err := m.city.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func lookupASN(db *maxminddb.Reader, addr netip.Addr) (uint32, error) {
	res := db.Lookup(addr)
	if err := res.Err(); err != nil {
		return 0, err
	}

	paths := [][]any{
		{"autonomous_system_number"},
		{"asn"},
	}
	for _, path := range paths {
		var asn *uint32
		if err := res.DecodePath(&asn, path...); err != nil {
			return 0, err
		}
		if asn != nil {
			return *asn, nil
		}
	}

	return 0, nil
}

func lookupCity(db *maxminddb.Reader, addr netip.Addr) (string, error) {
	res := db.Lookup(addr)
	if err := res.Err(); err != nil {
		return "", err
	}

	paths := [][]any{
		{"city", "names", "en"},
		{"city", "name"},
	}
	for _, path := range paths {
		var city *string
		if err := res.DecodePath(&city, path...); err != nil {
			return "", err
		}
		if city != nil {
			return *city, nil
		}
	}

	return "", nil
}

func checkPath(path string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	return nil
}
