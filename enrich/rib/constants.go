package rib

import "time"

const (
	// bmpScannerMaxBuf caps BMP message size, very big and prob not necessary (just in case)
	bmpScannerMaxBuf = 1 << 20
	// removeChunk is how many routes removePeer withdraws per hold of mu, the
	// collector's read loop waits for labels meanwhile
	removeChunk = 1024
	// maxSessions bounds the BMP sessions open at once, a router runs one
	// or a few and every session holds a goroutine and its read buffer
	maxSessions = 16
	// maxPathLen and maxCommunities bound what a route keeps of its
	// attributes, labels need only the origin, which the route keeps apart,
	// and a lookup shows the leading part of a longer list on a route
	// marked truncated, a route whose attributes no other route shares then
	// holds under 2 KiB of heap however long they are
	maxPathLen     = 32
	maxCommunities = 32
	// maxRoutes bounds the routes the RIB keeps, six views of a full table
	// of about 1.25M prefixes fit, and maxViews bounds the views
	maxRoutes = 1 << 23
	maxViews  = 1024
	// staleGrace is how long an open session of the same speaker, a later
	// one or one already open, has to announce a view again before the
	// routes an ended session left in it go, counted from when the view went
	// stale or the session opened, whichever is later, over twice the 120 s
	// ConnectRetryTime RFC 4271 suggests, so a peer that the restarted
	// speaker connects to again is back in time, and staleSweep is how often
	// the server looks
	staleGrace = 5 * time.Minute
	staleSweep = time.Minute
	// acceptBackoffMin and acceptBackoffMax bound the wait between accepts that fail for want of file descriptors, as net/http does
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
	// limitLogInterval keeps the warning about a full table or session limit to one a minute
	limitLogInterval = time.Minute
)
