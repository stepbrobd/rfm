package mmdb

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

// DefaultReloadInterval is how often the database files are checked for a
// replacement on disk
const DefaultReloadInterval = time.Minute

// Open opens the configured MMDB databases and keeps them current
// updaters such as geoipupdate rename a new file over the old one, and a
// reader that keeps the old mapping open serves stale data until restart, so
// the enricher polls the paths and swaps in a fresh reader when a file changed
// the reader maps the file shared, so a rename is the only safe way to
// replace it, a writer that truncates and rewrites the file in place shows
// lookups a half written database and kills the agent with SIGBUS when a
// lookup reads past the new end of the file
// when no MMDB database is configured, it returns nil, nil, nil
func Open(cfg config.MMDBConfig) (collector.Enricher, io.Closer, error) {
	return OpenWithInterval(cfg, DefaultReloadInterval)
}

// OpenWithInterval is Open with an explicit reload poll interval
// an interval of zero or less disables reloading
func OpenWithInterval(cfg config.MMDBConfig, interval time.Duration) (collector.Enricher, io.Closer, error) {
	if cfg.ASNDB == "" && cfg.CityDB == "" {
		return nil, nil, nil
	}

	m := &Enricher{
		open: func(path string) (*maxminddb.Reader, error) { return maxminddb.Open(path) },
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	if cfg.ASNDB != "" {
		if err := m.asn.load(cfg.ASNDB, "ASN", m.open); err != nil {
			return nil, nil, err
		}
	}

	if cfg.CityDB != "" {
		if err := m.city.load(cfg.CityDB, "city", m.open); err != nil {
			_ = m.asn.close()
			return nil, nil, err
		}
	}

	if interval > 0 {
		go m.watch(interval)
	} else {
		close(m.done)
	}

	return m, m, nil
}

// Enricher reads optional ASN and city data from MMDB files
type Enricher struct {
	mu   sync.RWMutex
	asn  database
	city database

	open      func(string) (*maxminddb.Reader, error)
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// database is one MMDB file together with the stat it was opened from
// an empty path means the database is not configured
type database struct {
	path   string
	kind   string
	reader *maxminddb.Reader
	stamp  stamp
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

func (d *database) load(path, kind string, open func(string) (*maxminddb.Reader, error)) error {
	st, err := statStamp(path)
	if err != nil {
		return err
	}
	reader, err := open(path)
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

func (m *Enricher) Enrich(src, dst netip.Addr) (collector.Labels, collector.Labels) {
	return m.lookup(src), m.lookup(dst)
}

func (m *Enricher) lookup(addr netip.Addr) collector.Labels {
	addr = addr.Unmap()

	var labels collector.Labels

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.asn.reader != nil {
		asn, err := lookupASN(m.asn.reader, addr)
		if err == nil {
			labels.ASN = asn
		}
	}

	if m.city.reader != nil {
		city, err := lookupCity(m.city.reader, addr)
		if err == nil {
			labels.City = city
		}
	}

	return labels
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
	reader, err := m.open(path)
	if err != nil {
		return fmt.Errorf("reopen %s MMDB %q: %w", kind, path, err)
	}

	m.mu.Lock()
	old := d.reader
	d.reader = reader
	d.stamp = st
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
