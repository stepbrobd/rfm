package main

import "testing"

func TestRunAgent(t *testing.T) {
	// runAgent requires BPF privileges; without them it should fail gracefully
	err := runAgent(nil, nil)
	if err == nil {
		t.Fatal("runAgent returned nil, want error")
	}
}
