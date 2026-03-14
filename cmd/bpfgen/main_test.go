package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
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

func TestBpf2go(t *testing.T) {
	tests := []struct {
		name   string
		source string
		ident  string
		outdir string
		pkg    string
		cfg    config
		cflags []string
		want   []string
	}{
		{
			name:   "basic",
			source: "testdata/without.bpf.c",
			ident:  "test",
			outdir: "testdata",
			pkg:    "mypkg",
			cfg:    config{"x86", "x86"},
			want: []string{
				"tool", "bpf2go",
				"-tags", "linux",
				"-go-package", "mypkg",
				"-output-dir", "testdata",
				"test",
				"testdata/without.bpf.c",
				"--",
				"-O2", "-g", "-Wall",
				"-Itestdata/include",
				"-Itestdata/include/vmlinux/x86",
				"-D__TARGET_ARCH_x86",
			},
		},
		{
			name:   "with_cflags",
			source: "testdata/with.bpf.c",
			ident:  "test",
			outdir: "testdata",
			pkg:    "mypkg",
			cfg:    config{"arm64", "aarch64"},
			cflags: []string{"-I/usr/include/bpf"},
			want: []string{
				"tool", "bpf2go",
				"-tags", "linux",
				"-go-package", "mypkg",
				"-output-dir", "testdata",
				"test",
				"testdata/with.bpf.c",
				"--",
				"-O2", "-g", "-Wall",
				"-Itestdata/include",
				"-Itestdata/include/vmlinux/aarch64",
				"-D__TARGET_ARCH_arm64",
				"-I/usr/include/bpf",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bpf2go(tt.source, tt.ident, tt.outdir, tt.pkg, tt.cfg, tt.cflags)
			if !slices.Equal(got, tt.want) {
				t.Errorf("bpf2go:\ngot:  %v\nwant: %v", got, tt.want)
			}
		})
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
		if _, err := exec.LookPath("pkg-config"); err != nil {
			t.Skip("pkg-config not available")
		}

		got, err := pkgconfig([]string{"libbpf"})
		if err != nil {
			t.Fatalf("pkgconfig([libbpf]) error = %v", err)
		}
		if len(got) == 0 {
			t.Error("pkgconfig([libbpf]) returned empty")
		}
	})
}

func TestBuild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires linux")
	}

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
