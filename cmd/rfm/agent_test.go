package main

import "testing"

func TestRunAgent(t *testing.T) {
	err := runAgent(nil, nil)
	if err == nil {
		t.Fatal("runAgent returned nil, want error")
	}
	if got := err.Error(); got != "agent mode is not implemented yet" {
		t.Fatalf("runAgent error = %q, want %q", got, "agent mode is not implemented yet")
	}
}
