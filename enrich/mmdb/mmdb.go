package mmdb

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/log"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

// reloadInterval is how often the database files are checked for a
// replacement on disk, the tests shorten it
var reloadInterval = time.Minute

// Open opens the configured databases and reopens a file an updater renamed over the old one, nil when none is configured
func Open(cfg config.MMDBConfig) (*Enricher, error) {
	if cfg.ASNDB == "" && cfg.CityDB == "" {
		return nil, nil
	}

	m := &Enricher{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	if cfg.ASNDB != "" {
		if err := m.asn.load(cfg.ASNDB, "ASN"); err != nil {
			return nil, err
		}
	}

	if cfg.CityDB != "" {
		if err := m.city.load(cfg.CityDB, "city"); err != nil {
			_ = m.asn.close()
			return nil, err
		}
	}

	go m.watch(reloadInterval)
	return m, nil
}

// Enricher reads optional ASN and city data from MMDB files
type Enricher struct {
	mu   sync.RWMutex
	asn  database
	city database

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// database is one MMDB file together with the stat it was opened from
// an empty path means the database is not configured, reported is set once
// a lookup in the open file failed and logged it
type database struct {
	path     string
	kind     string
	reader   *maxminddb.Reader
	stamp    stamp
	reported atomic.Bool
}

// stamp identifies the on-disk version of a database file
// size and mtime change on every replacement done by an updater
type stamp struct {
	size  int64
	mtime time.Time
}

func statStamp(path string) (stamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}, fmt.Errorf("stat %q: %w", path, err)
	}
	return stamp{size: fi.Size(), mtime: fi.ModTime()}, nil
}

func (d *database) load(path, kind string) error {
	st, err := statStamp(path)
	if err != nil {
		return err
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("open %s MMDB %q: %w", kind, path, err)
	}
	d.path = path
	d.kind = kind
	d.reader = reader
	d.stamp = st
	return nil
}

func (d *database) close() error {
	if d.reader == nil {
		return nil
	}
	err := d.reader.Close()
	d.reader = nil
	return err
}

// changed reports whether the file on disk differs from the one opened
func (d *database) changed() (stamp, bool, error) {
	if d.path == "" {
		return stamp{}, false, nil
	}
	st, err := statStamp(d.path)
	if err != nil {
		return stamp{}, false, err
	}
	return st, st != d.stamp, nil
}

// Fill sets the city of addr in labels, and its ASN when labels has none
func (m *Enricher) Fill(addr netip.Addr, labels collector.Labels) collector.Labels {
	addr = addr.Unmap()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if labels.ASN == 0 && m.asn.reader != nil {
		asn, err := lookupASN(m.asn.reader, addr)
		m.asn.report(err)
		labels.ASN = asn
	}

	if m.city.reader != nil {
		city, err := lookupCity(m.city.reader, addr)
		m.city.report(err)
		labels.City = city
	}

	return labels
}

// report logs the first error of a lookup in the open file, a file in a
// layout rfm does not read fails every lookup alike
func (d *database) report(err error) {
	if err != nil && !d.reported.Swap(true) {
		log.Error("mmdb lookup", "kind", d.kind, "path", d.path, "err", err)
	}
}

// Versions returns the build epoch of the open ASN and city databases
// a database that is not configured reports 0
func (m *Enricher) Versions() (asn, city uint) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.asn.reader != nil {
		asn = m.asn.reader.Metadata.BuildEpoch
	}
	if m.city.reader != nil {
		city = m.city.reader.Metadata.BuildEpoch
	}
	return asn, city
}

// Reload reopens every configured database whose file changed on disk
// a database that fails to open keeps serving from the previous reader
func (m *Enricher) Reload() error {
	var first error
	for _, d := range []*database{&m.asn, &m.city} {
		if err := m.reload(d); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (m *Enricher) reload(d *database) error {
	m.mu.RLock()
	st, changed, err := d.changed()
	path, kind := d.path, d.kind
	m.mu.RUnlock()
	if err != nil || !changed {
		return err
	}

	// open outside the lock, lookups keep running on the old reader
	reader, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("reopen %s MMDB %q: %w", kind, path, err)
	}

	m.mu.Lock()
	old := d.reader
	d.reader = reader
	d.stamp = st
	d.reported.Store(false)
	m.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	log.Info("mmdb reloaded", "kind", kind, "path", path, "build_epoch", reader.Metadata.BuildEpoch)
	return nil
}

func (m *Enricher) watch(interval time.Duration) {
	defer close(m.done)

	tick := time.NewTicker(interval)
	defer tick.Stop()

	var failed bool
	for {
		select {
		case <-m.stop:
			return
		case <-tick.C:
			err := m.Reload()
			if err != nil && !failed {
				log.Error("mmdb reload", "err", err)
			}
			failed = err != nil
		}
	}
}

func (m *Enricher) Close() error {
	m.closeOnce.Do(func() {
		close(m.stop)
	})
	<-m.done

	m.mu.Lock()
	defer m.mu.Unlock()

	var first error
	for _, d := range []*database{&m.asn, &m.city} {
		if err := d.close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// errASNLayout fails the lookup of a record without the ASN, every record of
// a GeoLite2-ASN database has one
var errASNLayout = errors.New("record without autonomous_system_number, asn_db takes the GeoLite2-ASN layout MaxMind and DB-IP use")

// lookupASN reads the ASN of addr from a database in the GeoLite2-ASN layout
func lookupASN(db *maxminddb.Reader, addr netip.Addr) (uint32, error) {
	res := db.Lookup(addr)
	if !res.Found() {
		return 0, res.Err()
	}
	var asn *uint32
	if err := res.DecodePath(&asn, "autonomous_system_number"); err != nil {
		return 0, fmt.Errorf("read autonomous_system_number: %w", err)
	}
	if asn == nil {
		return 0, errASNLayout
	}
	return *asn, nil
}

// lookupCity reads the English city name of addr from a database in the
// GeoLite2-City layout, a record of a country without a city has none
func lookupCity(db *maxminddb.Reader, addr netip.Addr) (string, error) {
	res := db.Lookup(addr)
	if !res.Found() {
		return "", res.Err()
	}
	var city *string
	if err := res.DecodePath(&city, "city", "names", "en"); err != nil {
		return "", fmt.Errorf("read city.names.en, city_db takes the GeoLite2-City layout MaxMind and DB-IP use: %w", err)
	}
	if city == nil {
		return "", nil
	}
	return *city, nil
}
