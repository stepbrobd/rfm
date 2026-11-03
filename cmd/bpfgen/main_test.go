package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ysun.co/rfm/testutil"
)

func TestPkgconfig(t *testing.T) {
	testutil.RequireCommand(t, "pkg-config")

	got, err := pkgconfig([]string{"libbpf"})
	if err != nil {
		t.Skipf("libbpf pkg-config metadata not available: %v", err)
	}
	if len(got) == 0 {
		t.Error("pkgconfig([libbpf]) returned empty")
	}
}

func TestWriteCompDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compile_commands.json")

	if err := writeCompDB(path, "testdata/without.bpf.c", []string{"-O2", "-Ifoo"}); err != nil {
		t.Fatal(err)
	}

	db := readCompDB(t, path)
	if len(db) != 1 {
		t.Fatalf("got %d entries, want 1", len(db))
	}
	if !strings.HasSuffix(db[0].File, "testdata/without.bpf.c") {
		t.Errorf("file = %q", db[0].File)
	}

	if err := writeCompDB(path, "testdata/with.bpf.c", []string{"-O2", "-Ibar"}); err != nil {
		t.Fatal(err)
	}

	db = readCompDB(t, path)
	if len(db) != 2 {
		t.Fatalf("got %d entries, want 2", len(db))
	}

	// an entry of the same file is replaced
	if err := writeCompDB(path, "testdata/without.bpf.c", []string{"-O2", "-Inew"}); err != nil {
		t.Fatal(err)
	}

	db = readCompDB(t, path)
	if len(db) != 2 {
		t.Fatalf("got %d entries after update, want 2", len(db))
	}

	// -I paths are absolute
	for _, e := range db {
		if strings.HasSuffix(e.File, "without.bpf.c") {
			hasNew := slices.ContainsFunc(e.Args, func(s string) bool {
				return strings.HasPrefix(s, "-I") && strings.HasSuffix(s, "/new")
			})
			if !hasNew {
				t.Errorf("updated entry missing -I.../new: %v", e.Args)
			}
			hasFoo := slices.ContainsFunc(e.Args, func(s string) bool {
				return strings.HasPrefix(s, "-I") && strings.HasSuffix(s, "/foo")
			})
			if hasFoo {
				t.Error("updated entry still has old -I.../foo")
			}
		}
	}

	// a file that does not parse stays as it is
	bad := filepath.Join(t.TempDir(), "compile_commands.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeCompDB(bad, "testdata/without.bpf.c", nil); err == nil {
		t.Fatal("writeCompDB over a file that does not parse succeeded")
	}
	if data, err := os.ReadFile(bad); err != nil || string(data) != "not json" {
		t.Fatalf("file after the refused write = %q, %v, want it unchanged", data, err)
	}
}

func readCompDB(t *testing.T, path string) []compentry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var db []compentry
	if err := json.Unmarshal(data, &db); err != nil {
		t.Fatal(err)
	}
	return db
}

func requirePkgConfigLib(t *testing.T, lib string) {
	t.Helper()
	testutil.RequireCommand(t, "pkg-config")
	if err := exec.Command("pkg-config", "--exists", lib).Run(); err != nil {
		t.Skipf("%s not available via pkg-config", lib)
	}
}

func TestBuild(t *testing.T) {
	testutil.RequireLinux(t)
	testutil.RequireCommand(t, "clang")

	tests := []struct {
		name   string
		source string
		flags  []string
	}{
		{"without_libbpf", "testdata/without.bpf.c", nil},
		{"with_libbpf", "testdata/with.bpf.c", []string{"--pkg-config", "libbpf"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, f := range tt.flags {
				if f == "--pkg-config" && i+1 < len(tt.flags) {
					requirePkgConfigLib(t, tt.flags[i+1])
				}
			}

			outdir := t.TempDir()
			args := []string{
				"tool", "bpfgen",
				"--ident", "test",
				"--output-dir", outdir,
				"--package", "testpkg",
			}
			args = append(args, tt.flags...)
			args = append(args, tt.source)

			out, err := exec.Command("go", args...).CombinedOutput()
			if err != nil {
				t.Fatalf("bpfgen failed: %v\n%s", err, out)
			}

			for _, suffix := range []string{"bpfel.o", "bpfeb.o", "bpfel.go", "bpfeb.go"} {
				path := filepath.Join(outdir, "test_"+suffix)
				data, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("missing %s", suffix)
					continue
				}
				if len(data) == 0 {
					t.Errorf("%s is empty", suffix)
					continue
				}

				// .o files should be valid ELF
				if strings.HasSuffix(suffix, ".o") {
					if len(data) < 4 || string(data[:4]) != "\x7fELF" {
						t.Errorf("%s is not valid ELF", suffix)
					}
				}

				// .go files should have correct package
				if strings.HasSuffix(suffix, ".go") {
					if !strings.Contains(string(data), "package testpkg") {
						t.Errorf("%s missing 'package testpkg'", suffix)
					}
				}
			}
		})
	}
}

func TestBuildCompDB(t *testing.T) {
	testutil.RequireLinux(t)
	testutil.RequireCommand(t, "clang")

	outdir := t.TempDir()
	dbpath := filepath.Join(outdir, "compile_commands.json")

	out, err := exec.Command("go",
		"tool", "bpfgen",
		"--ident", "test",
		"--output-dir", outdir,
		"--package", "testpkg",
		"--compdb", dbpath,
		"testdata/without.bpf.c",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("bpfgen failed: %v\n%s", err, out)
	}

	// verify compile_commands.json was created
	db := readCompDB(t, dbpath)
	if len(db) != 1 {
		t.Fatalf("got %d entries, want 1", len(db))
	}

	// verify entry has clang target and source
	e := db[0]
	if !slices.Contains(e.Args, "--target=bpf") {
		t.Error("missing --target=bpf")
	}
	if !strings.HasSuffix(e.File, "without.bpf.c") {
		t.Errorf("file = %q", e.File)
	}

	// verify build output also exists
	if _, err := os.Stat(filepath.Join(outdir, "test_bpfel.o")); err != nil {
		t.Error("build output missing alongside compdb generation")
	}
}
