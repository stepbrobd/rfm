package enrich

import (
	"testing"

	"ysun.co/rfm/config"
)

func TestBuildNilWhenUnset(t *testing.T) {
	backends, err := Build(config.EnrichConfig{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if backends != nil {
		t.Fatal("expected nil backends")
	}
}

func TestBuildNilWhenMMDBEmpty(t *testing.T) {
	backends, err := Build(config.EnrichConfig{
		MMDB: config.MMDBConfig{},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if backends != nil {
		t.Fatal("expected nil backends")
	}
}

func TestBuildRIBExposesServer(t *testing.T) {
	backends, err := Build(config.EnrichConfig{
		RIB: config.RIBConfig{
			BMP: config.BMPConfig{Host: "127.0.0.1", Port: 0},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	defer backends.Close()
	if backends.RIB == nil || backends.Enricher == nil || backends.MMDB != nil {
		t.Fatalf("backends = %+v, want a rib server and enricher only", backends)
	}
}

func TestBuildMMDBBadPath(t *testing.T) {
	_, err := Build(config.EnrichConfig{
		MMDB: config.MMDBConfig{
			ASNDB: "/does/not/exist.mmdb",
		},
	})
	if err == nil {
		t.Fatal("expected error for missing MMDB file")
	}
}

func TestBuildRIBBadListen(t *testing.T) {
	_, err := Build(config.EnrichConfig{
		RIB: config.RIBConfig{
			BMP: config.BMPConfig{
				Host: "bad",
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for bad BMP listen address")
	}
}
