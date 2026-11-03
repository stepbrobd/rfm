//go:build linux

package collector

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestBootEpochIsTheKernelBootTime(t *testing.T) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// btime is the wall time of boot in whole seconds
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		v, ok := strings.CutPrefix(sc.Text(), "btime ")
		if !ok {
			continue
		}
		btime, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := BootEpoch().Unix(); got < btime-1 || got > btime+1 {
			t.Fatalf("boot epoch = %d, want the kernel's btime %d", got, btime)
		}
		return
	}
	t.Fatalf("no btime in /proc/stat: %v", sc.Err())
}
