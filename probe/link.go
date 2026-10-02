package probe

import "errors"

// ErrUnsupportedLink marks a link whose frames do not start with an ethernet
// header at the tc hooks, such as tun, wireguard or xfrm devices, the
// programs would read their IP header as ethernet
var ErrUnsupportedLink = errors.New("link frames carry no ethernet header")

// LinkEvent is one attach or detach done by Watch
type LinkEvent struct {
	Name     string
	Ifindex  int
	Attached bool
}

// WatchState is what the interface watcher reports about itself
type WatchState struct {
	// Running is true while a link subscription is open
	Running bool
	// Synced is true once the link dump of the open subscription is
	// reconciled with the attached interfaces
	Synced bool
	// Resubscribes counts the subscriptions that failed and were opened
	// again, an overflowed socket (ENOBUFS) among them
	Resubscribes uint64
	// PruneErrors counts the prune passes that failed to delete the counters
	// a pinned map holds for interfaces this run neither attaches nor
	// retries, a pass stops at its first failed delete and the dump of every
	// later subscription tries again until one succeeds
	PruneErrors uint64
	// Errors counts the link messages the watcher dropped, a dropped
	// message ends no subscription
	Errors uint64
	// AttachErrors counts the failed attaches of matching links, every try
	// of a link that stays pending counts again, an attach that finds the
	// link gone does not count
	AttachErrors uint64
	// LastError describes the latest failed subscription or dropped message
	LastError string
}
