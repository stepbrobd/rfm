//go:build ebpf_test

package probe

import "testing"

func TestLoad(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
}
