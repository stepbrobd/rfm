package mmdb

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/log"
	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

// mmdbBytes builds the smallest valid MaxMind DB file
// the search tree has one node whose records both point at node_count, so
// every lookup ends without data, and the metadata carries buildEpoch so a
// test can tell two files apart
func mmdbBytes(buildEpoch uint64) []byte {
	// search tree, one node with two 24 bit records equal to node_count
	return mmdbFile(buildEpoch, 1, []byte{0, 0, 1, 0, 0, 1}, nil)
}

// mmdbRecord builds a MaxMind DB file in which the ipv4 prefix maps to
// record and every other address to no data
// the ipv6 tree reaches ipv4 addresses through 96 zero bits, a node per bit
// leads on to the next and its other record ends the lookup without data,
// the last one points at the record, the first value of the data section
func mmdbRecord(prefix netip.Prefix, record any) []byte {
	bits := make([]byte, 96, 96+prefix.Bits())
	addr := prefix.Addr().As4()
	for i := range prefix.Bits() {
		bits = append(bits, addr[i/8]>>(7-i%8)&1)
	}
	nodes := len(bits)
	var tree []byte
	for i, bit := range bits {
		next := i + 1
		if next == nodes {
			next = nodes + 16
		}
		records := [2]int{nodes, nodes}
		records[bit] = next
		for _, r := range records {
			tree = append(tree, byte(r>>16), byte(r>>8), byte(r))
		}
	}
	return mmdbFile(1, nodes, tree, mmdbValue(record))
}

// mmdbValue encodes strings, uint32 values and maps of them for the data
// section, each shorter than 29 bytes or entries
func mmdbValue(v any) []byte {
	switch v := v.(type) {
	case string:
		return append([]byte{0x40 | byte(len(v))}, v...)
	case uint32:
		var n []byte
		for ; v > 0; v >>= 8 {
			n = append([]byte{byte(v)}, n...)
		}
		return append([]byte{0xC0 | byte(len(n))}, n...)
	case map[string]any:
		b := []byte{0xE0 | byte(len(v))}
		for _, key := range slices.Sorted(maps.Keys(v)) {
			b = append(b, mmdbValue(key)...)
			b = append(b, mmdbValue(v[key])...)
		}
		return b
	}
	panic(fmt.Sprintf("no mmdb encoding for %T", v))
}

// mmdbFile assembles a MaxMind DB file from a search tree of nodes nodes
// with 24 bit records and its data section
func mmdbFile(buildEpoch uint64, nodes int, tree, data []byte) []byte {
	b := slices.Concat(tree, make([]byte, 16), data)
	// metadata marker
	b = append(b, "\xAB\xCD\xEFMaxMind.com"...)

	key := func(s string) {
		b = append(b, 0x40|byte(len(s)))
		b = append(b, s...)
	}

	var epoch []byte
	for v := buildEpoch; v > 0; v >>= 8 {
		epoch = append([]byte{byte(v)}, epoch...)
	}

	// map with 9 entries
	b = append(b, 0xE0|9)
	key("binary_format_major_version")
	b = append(b, 0xA1, 2)
	key("binary_format_minor_version")
	b = append(b, 0xA0)
	key("build_epoch")
	b = append(b, byte(len(epoch)), 0x02)
	b = append(b, epoch...)
	key("database_type")
	b = append(b, 0x40|8)
	b = append(b, "rfm-test"...)
	key("description")
	b = append(b, 0xE0)
	key("ip_version")
	b = append(b, 0xA1, 6)
	key("languages")
	b = append(b, 0x00, 0x04)
	key("node_count")
	b = append(b, mmdbValue(uint32(nodes))...)
	key("record_size")
	b = append(b, 0xA1, 24)

	return b
}

// writeMMDB writes a test database with buildEpoch to path through a
// rename, the way geoipupdate replaces a database, with an mtime that moves
// forward by one hour per epoch so a replacement within the same second is
// still visible to the stat based change check
func writeMMDB(t *testing.T, path string, buildEpoch uint64) {
	t.Helper()

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, mmdbBytes(buildEpoch), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Unix(int64(buildEpoch)*3600, 0)
	if err := os.Chtimes(tmp, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestMinimalDatabaseOpens(t *testing.T) {
	reader, err := maxminddb.OpenBytes(mmdbBytes(7))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if reader.Metadata.BuildEpoch != 7 {
		t.Fatalf("build epoch = %d, want 7", reader.Metadata.BuildEpoch)
	}
	res := reader.Lookup(netip.MustParseAddr("192.0.2.1"))
	if err := res.Err(); err != nil {
		t.Fatal(err)
	}
	if res.Found() {
		t.Fatal("empty database reported a record")
	}
}

func TestOpenAndLookup(t *testing.T) {
	dir := t.TempDir()
	asn := filepath.Join(dir, "asn.mmdb")
	city := filepath.Join(dir, "city.mmdb")
	writeMMDB(t, asn, 1)
	writeMMDB(t, city, 2)

	enricher, closer, err := OpenWithInterval(config.MMDBConfig{ASNDB: asn, CityDB: city}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()

	src, dst := enricher.Enrich(netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("2001:db8::1"))
	if src.ASN != 0 || src.City != "" || dst.ASN != 0 || dst.City != "" {
		t.Fatalf("empty databases produced labels: src=%+v dst=%+v", src, dst)
	}

	m := enricher.(*Enricher)
	if a, c := m.Versions(); a != 1 || c != 2 {
		t.Fatalf("versions = (%d, %d), want (1, 2)", a, c)
	}
}

func TestLookupReadsTheGeoLite2Layout(t *testing.T) {
	var out bytes.Buffer
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)

	addr := netip.MustParseAddr("192.0.2.1")
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	for _, tc := range []struct {
		name      string
		asn, city map[string]any
		want      collector.Labels
		// failed holds the field each logged lookup error names
		failed []string
	}{
		{
			name: "geolite2",
			asn:  map[string]any{"autonomous_system_number": uint32(64500)},
			city: map[string]any{"city": map[string]any{"names": map[string]any{"en": "Paris"}}},
			want: collector.Labels{ASN: 64500, City: "Paris"},
		},
		{
			// MaxMind and DB-IP both use the geolite2 layout, a file in
			// another one fails its first lookup with a log line
			name:   "other layouts",
			asn:    map[string]any{"asn": uint32(64500)},
			city:   map[string]any{"city": "Paris"},
			failed: []string{"autonomous_system_number", "city.names.en"},
		},
		{
			// a country without a city has no city record
			name: "no city",
			asn:  map[string]any{"autonomous_system_number": uint32(64500)},
			city: map[string]any{"country": map[string]any{"iso_code": "FR"}},
			want: collector.Labels{ASN: 64500},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			dir := t.TempDir()
			cfg := config.MMDBConfig{ASNDB: filepath.Join(dir, "asn.mmdb"), CityDB: filepath.Join(dir, "city.mmdb")}
			if err := os.WriteFile(cfg.ASNDB, mmdbRecord(prefix, tc.asn), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.CityDB, mmdbRecord(prefix, tc.city), 0o644); err != nil {
				t.Fatal(err)
			}
			enricher, closer, err := OpenWithInterval(cfg, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer closer.Close()

			for range 2 {
				if src, _ := enricher.Enrich(addr, netip.MustParseAddr("198.51.100.1")); src != tc.want {
					t.Fatalf("labels = %+v, want %+v", src, tc.want)
				}
			}
			if got := strings.Count(out.String(), "mmdb lookup"); got != len(tc.failed) {
				t.Fatalf("logged %d lookup errors, want %d:\n%s", got, len(tc.failed), out.String())
			}
			for _, field := range tc.failed {
				if !strings.Contains(out.String(), field) {
					t.Fatalf("log does not name %s:\n%s", field, out.String())
				}
			}
		})
	}
}

func TestOpenMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, _, err := OpenWithInterval(config.MMDBConfig{ASNDB: filepath.Join(dir, "missing.mmdb")}, 0)
	if err == nil {
		t.Fatal("expected error for missing database")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want wrapped ErrNotExist", err)
	}
}

func TestReloadPicksUpReplacedFile(t *testing.T) {
	dir := t.TempDir()
	asn := filepath.Join(dir, "asn.mmdb")
	writeMMDB(t, asn, 1)

	enricher, closer, err := OpenWithInterval(config.MMDBConfig{ASNDB: asn}, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	m := enricher.(*Enricher)

	writeMMDB(t, asn, 2)

	deadline := time.Now().Add(2 * time.Second)
	for {
		if a, _ := m.Versions(); a == 2 {
			break
		}
		if time.Now().After(deadline) {
			a, _ := m.Versions()
			t.Fatalf("asn build epoch = %d after replacement, want 2", a)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// lookups keep working on the new reader
	src, _ := m.Enrich(netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.2"))
	if src.ASN != 0 {
		t.Fatalf("unexpected asn %d from empty database", src.ASN)
	}
}

func TestReloadKeepsOldReaderOnBadFile(t *testing.T) {
	dir := t.TempDir()
	asn := filepath.Join(dir, "asn.mmdb")
	writeMMDB(t, asn, 1)

	enricher, closer, err := OpenWithInterval(config.MMDBConfig{ASNDB: asn}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	m := enricher.(*Enricher)

	if err := os.WriteFile(asn, []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(asn, future, future); err != nil {
		t.Fatal(err)
	}

	if err := m.Reload(); err == nil {
		t.Fatal("expected reload error for a corrupt database")
	}
	if a, _ := m.Versions(); a != 1 {
		t.Fatalf("asn build epoch = %d after failed reload, want 1", a)
	}

	// the stamp was not advanced, so a later good file is still picked up
	writeMMDB(t, asn, 3)
	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if a, _ := m.Versions(); a != 3 {
		t.Fatalf("asn build epoch = %d after recovery, want 3", a)
	}
}

func TestReloadUnchangedFileIsNoop(t *testing.T) {
	dir := t.TempDir()
	asn := filepath.Join(dir, "asn.mmdb")
	writeMMDB(t, asn, 1)

	opens := 0
	m := &Enricher{
		open: func(path string) (*maxminddb.Reader, error) {
			opens++
			return maxminddb.Open(path)
		},
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	close(m.done)
	if err := m.asn.load(asn, "ASN", m.open); err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if opens != 1 {
		t.Fatalf("opens = %d, want 1 (unchanged file must not be reopened)", opens)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	asn := filepath.Join(dir, "asn.mmdb")
	writeMMDB(t, asn, 1)

	_, closer, err := OpenWithInterval(config.MMDBConfig{ASNDB: asn}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
}
