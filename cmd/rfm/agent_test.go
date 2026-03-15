package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rfm.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunAgentWithConfig(t *testing.T) {
	cfgFile = writeTestConfig(t, `
[agent]
interfaces = ["lo"]
`)
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("runAgent returned nil, want error")
	}
}

func TestRunAgentBadInterface(t *testing.T) {
	cfgFile = writeTestConfig(t, `
[agent]
interfaces = ["doesnotexist999"]
`)
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("should fail on bad interface")
	}
	if !strings.Contains(err.Error(), "doesnotexist999") {
		t.Errorf("error should mention interface name, got: %v", err)
	}
}

func TestRunAgentBadMMDBPath(t *testing.T) {
	cfgFile = writeTestConfig(t, `
[agent]
interfaces = ["lo"]

[agent.enrich.mmdb]
asn_db = "/does/not/exist.mmdb"
`)
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("should fail on bad MMDB path")
	}
	if !strings.Contains(err.Error(), "/does/not/exist.mmdb") {
		t.Errorf("error should mention MMDB path, got: %v", err)
	}
}

func TestRunAgentBadConfig(t *testing.T) {
	cfgFile = writeTestConfig(t, `
[agent]
interfaces = []
`)
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("should fail on empty interfaces")
	}
}
