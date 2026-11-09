package probe

import (
	"fmt"
	"strconv"
	"strings"
)

// parseCPUList parses a kernel CPU list such as "0-3,8,10-11" into its CPUs
// in ascending order
func parseCPUList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var cpus []int
	for part := range strings.SplitSeq(s, ",") {
		lo, hi, ranged := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil || first < 0 {
			return nil, fmt.Errorf("cpu list %q: bad cpu %q", s, lo)
		}
		last := first
		if ranged {
			last, err = strconv.Atoi(hi)
			if err != nil || last < first {
				return nil, fmt.Errorf("cpu list %q: bad range %q", s, part)
			}
		}
		if len(cpus) > 0 && first <= cpus[len(cpus)-1] {
			return nil, fmt.Errorf("cpu list %q: not ascending at %q", s, part)
		}
		for c := first; c <= last; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus, nil
}
