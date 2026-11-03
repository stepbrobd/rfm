package probe

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"ysun.co/rfm/testutil"
)

// tcPrograms compiles the BPF source for target against the vmlinux.h of
// arch and returns the instructions of every tc program in the object
func tcPrograms(t *testing.T, clang string, cflags []string, target, arch string) map[string]asm.Instructions {
	t.Helper()

	obj := filepath.Join(t.TempDir(), target+"-"+arch+".o")
	args := []string{"-O2", "-mcpu=v1", "-g", "-target", target,
		"-I../bpf/include", "-I../bpf/include/vmlinux/" + arch}
	args = append(args, cflags...)
	args = append(args, "-c", "../bpf/rfm_tc.c", "-o", obj)
	if out, err := exec.Command(clang, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile for %s against %s: %v\n%s", target, arch, err, out)
	}

	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	progs := make(map[string]asm.Instructions)
	for name, p := range spec.Programs {
		if strings.HasPrefix(p.SectionName, "tc/") {
			progs[name] = p.Instructions
		}
	}
	if len(progs) == 0 {
		t.Fatalf("no tc programs in the %s object", target)
	}
	return progs
}

// sameUpToCORE compares two programs except the immediates the loader relocates against the kernel's BTF
func sameUpToCORE(a, b asm.Instructions) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.OpCode != y.OpCode || x.Dst != y.Dst || x.Src != y.Src {
			return false
		}
		if btf.CORERelocationMetadata(&x) == nil && (x.Offset != y.Offset || x.Constant != y.Constant) {
			return false
		}
	}
	return true
}

// bpfgen compiles the bpfel and the bpfeb object against the vmlinux.h of
// the host, so on x86_64 the big endian object sees little endian bitfields
// the programs must therefore not read a header bitfield such as iphdr.ihl,
// which compiles to the other nibble of the byte under the other byte order
// the x86_64 and the s390x headers lay their bitfields out in opposite
// orders, so both must give the same instructions for either target
func TestProgramsIgnoreHeaderBitfieldLayout(t *testing.T) {
	clang := testutil.RequireCommand(t, "clang")
	pkgConfig := testutil.RequireCommand(t, "pkg-config")
	out, err := exec.Command(pkgConfig, "--cflags-only-I", "libbpf").Output()
	if err != nil {
		t.Skipf("libbpf headers not available: %v", err)
	}
	cflags := strings.Fields(string(out))

	for _, target := range []string{"bpfel", "bpfeb"} {
		little := tcPrograms(t, clang, cflags, target, "x86_64")
		big := tcPrograms(t, clang, cflags, target, "s390x")
		for name, insns := range little {
			if !sameUpToCORE(insns, big[name]) {
				t.Errorf("%s %s depends on the bitfield layout of vmlinux.h", target, name)
			}
		}
	}
}
