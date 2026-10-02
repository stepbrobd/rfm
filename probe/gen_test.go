package probe

import (
	"bytes"
	"debug/elf"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ysun.co/rfm/testutil"
)

// tcSections compiles the BPF source for target against the vmlinux.h of
// arch and returns the instructions of every tc program in the object
func tcSections(t *testing.T, clang string, cflags []string, target, arch string) map[string][]byte {
	t.Helper()

	obj := filepath.Join(t.TempDir(), target+"-"+arch+".o")
	args := []string{"-O2", "-mcpu=v1", "-g", "-target", target,
		"-I../bpf/include", "-I../bpf/include/vmlinux/" + arch}
	args = append(args, cflags...)
	args = append(args, "-c", "../bpf/rfm_tc.c", "-o", obj)
	if out, err := exec.Command(clang, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile for %s against %s: %v\n%s", target, arch, err, out)
	}

	f, err := elf.Open(obj)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	progs := make(map[string][]byte)
	for _, s := range f.Sections {
		if !strings.HasPrefix(s.Name, "tc/") {
			continue
		}
		data, err := s.Data()
		if err != nil {
			t.Fatal(err)
		}
		progs[s.Name] = data
	}
	if len(progs) == 0 {
		t.Fatalf("no tc programs in the %s object", target)
	}
	return progs
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
		little := tcSections(t, clang, cflags, target, "x86_64")
		big := tcSections(t, clang, cflags, target, "s390x")
		for name, insns := range little {
			if !bytes.Equal(insns, big[name]) {
				t.Errorf("%s %s depends on the bitfield layout of vmlinux.h", target, name)
			}
		}
	}
}
