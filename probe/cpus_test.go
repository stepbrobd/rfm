package probe

import (
	"slices"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []int
	}{
		{"0\n", []int{0}},
		{"0-3\n", []int{0, 1, 2, 3}},
		{"0-1,4,6-7", []int{0, 1, 4, 6, 7}},
		{"", nil},
		{"\n", nil},
	} {
		got, err := parseCPUList(tc.in)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("parseCPUList(%q) = %v, %v, want %v", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{"a", "1-", "-1", "3-1", "0,,1", "2,1", "0-2,1"} {
		if got, err := parseCPUList(in); err == nil {
			t.Errorf("parseCPUList(%q) = %v, want an error", in, got)
		}
	}
}
