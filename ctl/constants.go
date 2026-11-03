package ctl

import "time"

// DefaultSocket is where the NixOS module puts the control socket
const DefaultSocket = "/run/rfm/rfm.sock"

const (
	// requestTimeout bounds one connection so a stuck client cannot pin a
	// server goroutine
	requestTimeout = 5 * time.Second
	// maxRequestSize bounds one request, real ones are a few hundred bytes
	maxRequestSize = 64 << 10
	// maxConns bounds the connections served at once, further clients wait in
	// the listen backlog
	maxConns = 16
	// acceptBackoffMin and acceptBackoffMax bound the wait between accepts that fail for want of file descriptors, as net/http does
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
	// defaultTopFlows is how many flows flows top lists when the request names no count
	defaultTopFlows = 20
)
