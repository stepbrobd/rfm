package mmdb

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
	"ysun.co/rfm/config"
)

// mmdbBytes builds the smallest valid MaxMind DB file
// the search tree has one node whose records both point at node_count, so
// every lookup ends without data, and the metadata carries buildEpoch so a
// test can tell two files apart
func mmdbBytes(buildEpoch uint64) []byte {
	var b []byte

	// search tree, one node with two 24 bit records equal to node_count
	b = append(b, 0, 0, 1, 0, 0, 1)
	// data section separator
	b = append(b, make([]byte, 16)...)
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
	b = append(b, 0xC1, 1)
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
