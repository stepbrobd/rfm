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

func TestDetect(t *testing.T) {
	tests := []struct {
		arch    string
		want    config
		wantErr bool
	}{
		{"amd64", config{"x86", "x86"}, false},
		{"x86_64", config{"x86", "x86"}, false},
		{"386", config{"x86", "x86"}, false},
		{"arm", config{"arm", "arm"}, false},
		{"arm64", config{"arm64", "aarch64"}, false},
		{"aarch64", config{"arm64", "aarch64"}, false},
		{"loong64", config{"loongarch", "loongarch64"}, false},
		{"riscv64", config{"riscv", "riscv64"}, false},
		{"ppc64le", config{"powerpc", "powerpc"}, false},
		{"s390x", config{"s390", "s390x"}, false},
		{"mips", config{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			got, err := detect(tt.arch)
			if (err != nil) != tt.wantErr {
				t.Fatalf("detect(%q) error = %v, wantErr %v", tt.arch, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("detect(%q) = %v, want %v", tt.arch, got, tt.want)
			}
		})
	}
}

func TestCFlags(t *testing.T) {
	tests := []struct {
		name   string
		source string
		cfg    config
		extra  []string
		want   []string
	}{
		{
			name:   "basic",
			source: "testdata/without.bpf.c",
			cfg:    config{"x86", "x86"},
			want: []string{
				"-O2", "-g", "-Wall", "-Wno-missing-declarations",
				"-Itestdata/include",
				"-Itestdata/include/vmlinux/x86",
				"-D__TARGET_ARCH_x86",
			},
		},
		{
			name:   "with_extra",
			source: "testdata/with.bpf.c",
			cfg:    config{"arm64", "aarch64"},
			extra:  []string{"-I/usr/include/bpf"},
			want: []string{
				"-O2", "-g", "-Wall", "-Wno-missing-declarations",
				"-Itestdata/include",
				"-Itestdata/include/vmlinux/aarch64",
				"-D__TARGET_ARCH_arm64",
				"-I/usr/include/bpf",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cflags(tt.source, tt.cfg, tt.extra)
			if !slices.Equal(got, tt.want) {
				t.Errorf("cflags:\ngot:  %v\nwant: %v", got, tt.want)
			}
		})
	}
}

func TestBpf2go(t *testing.T) {
	flags := []string{"-O2", "-g", "-Wall", "-Wno-missing-declarations", "-Itestdata/include", "-D__TARGET_ARCH_x86"}
	got := bpf2go("testdata/without.bpf.c", "test", "testdata", "mypkg", flags)
	want := []string{
		"tool", "bpf2go",
		"-tags", "linux",
		"-go-package", "mypkg",
		"-output-dir", "testdata",
		"test",
		"testdata/without.bpf.c",
		"--",
		"-O2", "-g", "-Wall", "-Wno-missing-declarations", "-Itestdata/include", "-D__TARGET_ARCH_x86",
	}
	if !slices.Equal(got, want) {
		t.Errorf("bpf2go:\ngot:  %v\nwant: %v", got, want)
	}
}

func TestPkgconfig(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		got, err := pkgconfig(nil)
		if err != nil {
			t.Fatalf("pkgconfig(nil) error = %v", err)
		}
		if got != nil {
			t.Errorf("pkgconfig(nil) = %v, want nil", got)
		}
	})

	t.Run("libbpf", func(t *testing.T) {
		testutil.RequireCommand(t, "pkg-config")

		got, err := pkgconfig([]string{"libbpf"})
		if err != nil {
			t.Skipf("libbpf pkg-config metadata not available: %v", err)
		}
		if len(got) == 0 {
			t.Error("pkgconfig([libbpf]) returned empty")
		}
	})
}

func TestWriteCompDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compile_commands.json")

	// create new
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

	// add second entry
	if err := writeCompDB(path, "testdata/with.bpf.c", []string{"-O2", "-Ibar"}); err != nil {
		t.Fatal(err)
	}

	db = readCompDB(t, path)
	if len(db) != 2 {
		t.Fatalf("got %d entries, want 2", len(db))
	}

	// update existing entry (should replace, not append)
	if err := writeCompDB(path, "testdata/without.bpf.c", []string{"-O2", "-Inew"}); err != nil {
		t.Fatal(err)
	}

	db = readCompDB(t, path)
	if len(db) != 2 {
		t.Fatalf("got %d entries after update, want 2", len(db))
	}

	// verify updated flags
	// -I paths are absolutized so check suffix
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
