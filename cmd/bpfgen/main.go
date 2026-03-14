// bpfgen is a thin wrapper around cilium/ebpf bpf2go
// to resolve target arch, set up vmlinux include paths for
// multi arch build then forwards everything to bpf2go
// e.g.
// //go:generate go tool bpfgen --ident foo --output-dir testdata --pkg-config libbpf source.bpf.c

package main

import (
	"cmp"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

type config struct {
	arch    string
	vmlinux string
}

var (
	ident  string
	outdir string
	pkg    string
	libs   []string
)

var cmd = &cobra.Command{
	Use:           "bpfgen [flags] <source>",
	Short:         "Generate Go bindings from BPF C source",
	Args:          cobra.ExactArgs(1),
	RunE:          run,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	cmd.Flags().StringVar(&ident, "ident", "", "stem for generated Go types and files")
	cmd.Flags().StringVarP(&outdir, "output-dir", "o", ".", "directory for generated files")
	cmd.Flags().StringVar(&pkg, "package", os.Getenv("GOPACKAGE"), "Go package for generated files")
	cmd.Flags().StringSliceVar(&libs, "pkg-config", nil, "pkg-config libraries for include flags")
	cmd.MarkFlagRequired("ident")
}

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "bpfgen: %v\n", err)
		os.Exit(1)
	}
}

func run(_ *cobra.Command, args []string) error {
	if runtime.GOOS != "linux" && os.Getenv("BPFGEN_FORCE") != "1" {
		fmt.Fprintf(os.Stderr, "bpfgen: skipping on GOOS=%s\n", runtime.GOOS)
		return nil
	}

	if pkg == "" {
		return fmt.Errorf("--package is required or GOPACKAGE must be set")
	}

	arch := cmp.Or(os.Getenv("BPF_TARGET_ARCH"), os.Getenv("GOARCH"), runtime.GOARCH)
	cfg, err := detect(arch)
	if err != nil {
		return err
	}

	cflags, err := pkgconfig(libs)
	if err != nil {
		return err
	}
	cflags = append(cflags, strings.Fields(os.Getenv("BPFGEN_EXTRA_CFLAGS"))...)

	proc := exec.Command("go", bpf2go(args[0], ident, outdir, pkg, cfg, cflags)...)
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr

	if err := proc.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}

	return nil
}

func detect(arch string) (config, error) {
	switch arch {
	case "386", "i386", "x86", "x86_64", "amd64":
		return config{"x86", "x86"}, nil
	case "arm":
		return config{"arm", "arm"}, nil
	case "arm64", "aarch64":
		return config{"arm64", "aarch64"}, nil
	case "loong64", "loongarch64", "loongarch":
		return config{"loongarch", "loongarch64"}, nil
	case "ppc64", "ppc64le", "powerpc":
		return config{"powerpc", "powerpc"}, nil
	case "riscv64", "riscv":
		return config{"riscv", "riscv64"}, nil
	case "s390", "s390x":
		return config{"s390", "s390x"}, nil
	default:
		return config{}, fmt.Errorf("unsupported arch %q", arch)
	}
}

func bpf2go(source, ident, outdir, pkg string, cfg config, cflags []string) []string {
	incdir := filepath.Join(filepath.Dir(source), "include")
	flags := []string{
		"-O2",
		"-g",
		"-Wall",
		"-I" + incdir,
		"-I" + filepath.Join(incdir, "vmlinux", cfg.vmlinux),
		"-D__TARGET_ARCH_" + cfg.arch,
	}
	flags = append(flags, cflags...)

	args := []string{
		"tool", "bpf2go",
		"-tags", "linux",
		"-go-package", pkg,
		"-output-dir", outdir,
		ident,
		source,
		"--",
	}

	return append(args, flags...)
}

func pkgconfig(libs []string) ([]string, error) {
	if len(libs) == 0 {
		return nil, nil
	}

	args := append([]string{"--cflags-only-I"}, libs...)
	out, err := exec.Command("pkg-config", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("pkg-config %q: %s", strings.Join(libs, " "), msg)
	}

	return strings.Fields(strings.TrimSpace(string(out))), nil
}
