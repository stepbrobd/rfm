package rib

import (
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

const (
	// bmpScannerMaxBuf bounds a message, a route monitoring message holds one BGP message of up to 65535 bytes (RFC 8654), a peer up two OPENs
	bmpScannerMaxBuf = bmp.BMP_HEADER_SIZE + bmp.BMP_PEER_HEADER_SIZE + 2*65535
	// removeChunk is how many routes removePeer withdraws per hold of mu, the
	// collector's read loop waits for labels meanwhile
	removeChunk = 1024
	// maxSessions bounds the BMP sessions open at once, a router runs one
	// or a few and every session holds a goroutine and its read buffer
	maxSessions = 16
	// maxPathLen and maxCommunities are the attribute values a route keeps, the origin is kept apart
	maxPathLen     = 32
	maxCommunities = 32
	// staleSweep is how often the server looks for views past staleGrace
	staleSweep = time.Minute
	// acceptBackoffMin and acceptBackoffMax bound the wait between accepts that fail for want of file descriptors, as net/http does
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
	// limitLogInterval keeps the warning about a full table or session limit to one a minute
	limitLogInterval = time.Minute
)

// the tests lower these, so they are variables
var (
	// maxRoutes bounds the routes the RIB keeps, six views of a full table
	// of about 1.25M prefixes fit, and maxViews bounds the views
	maxRoutes = 1 << 23
	maxViews  = 1024
	// staleGrace is how long a view of an ended session waits to be announced again, over twice the 120 s ConnectRetryTime of RFC 4271
	staleGrace = 5 * time.Minute
)
