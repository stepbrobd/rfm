package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestRunAgent(t *testing.T) {
	// runAgent requires BPF privileges; without them it should fail gracefully
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("runAgent returned nil, want error")
	}
}
