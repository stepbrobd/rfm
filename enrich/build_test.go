package enrich

import (
	"testing"

	"ysun.co/rfm/config"
)

func TestBuildNilWhenUnset(t *testing.T) {
	enricher, closer, err := Build(config.EnrichConfig{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if enricher != nil {
		t.Fatal("expected nil enricher")
	}
	if closer != nil {
		t.Fatal("expected nil closer")
	}
}

func TestBuildNilWhenMMDBEmpty(t *testing.T) {
	enricher, closer, err := Build(config.EnrichConfig{
		MMDB: config.MMDBConfig{},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if enricher != nil {
		t.Fatal("expected nil enricher")
	}
	if closer != nil {
		t.Fatal("expected nil closer")
	}
}

func TestBuildMMDBBadPath(t *testing.T) {
	_, _, err := Build(config.EnrichConfig{
		MMDB: config.MMDBConfig{
			ASNDB: "/does/not/exist.mmdb",
		},
	})
	if err == nil {
		t.Fatal("expected error for missing MMDB file")
	}
}

func TestBuildRIBBadListen(t *testing.T) {
	_, _, err := Build(config.EnrichConfig{
		RIB: config.RIBConfig{
			BMPListen: "bad",
		},
	})
	if err == nil {
		t.Fatal("expected error for bad BMP listen address")
	}
}
