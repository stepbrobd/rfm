package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunAgent(t *testing.T) {
	// runAgent requires BPF privileges; without them it should fail gracefully
	agentIface = "lo"
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("runAgent returned nil, want error")
	}
}

func TestRunAgentBadInterface(t *testing.T) {
	agentIface = "doesnotexist999"
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("runAgent with bad interface should return error")
	}
	if !strings.Contains(err.Error(), "doesnotexist999") {
		t.Errorf("error should mention interface name, got: %v", err)
	}
}
