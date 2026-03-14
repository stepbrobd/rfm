//go:build ebpf_test

package probe

import (
	"testing"

	"ysun.co/rfm/testutil"
)

func TestLoad(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
}

func TestAttach(t *testing.T) {
	ns := testutil.NewNS(t)

	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if err := p.Attach(ns.Ifindex()); err != nil {
		t.Fatal(err)
	}
}
