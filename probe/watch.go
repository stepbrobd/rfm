//go:build linux

package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// a failed subscription is opened again after watchRetryMin, doubled up to
// watchRetryMax while the next ones fail before their dump is through
const (
	watchRetryMin = 100 * time.Millisecond
	watchRetryMax = 30 * time.Second
)

// Watch attaches the interfaces whose name match accepts and follows link
// changes until ctx is done
// every subscription dumps the links on its own socket, so no change between
// the dump and the next message is lost, and once the dump is through every
// attached interface that is gone is detached, which catches up with links
// that came or went before Watch ran or while a subscription was down
// after the first dump the counters of every interface that is not attached
// are deleted, a pinned map from an earlier run may hold them, and a link
// that goes loses its counters whether this run attached it or not
// a subscription that fails, on ENOBUFS after a burst of link messages for
// one, is opened again after a pause, a message the watcher cannot use is
// logged and counted and ends nothing, WatchState reports both
// a link without an ethernet header is skipped with a warning
// Watch returns the error of the first subscription when that one cannot be
// opened, and ctx.Err() once ctx is done
// netlink and tcx address interfaces in the calling thread's network
// namespace, so Watch must run on a thread that lives in the namespace of
// the interfaces it manages
// notify, when set, is called after every attach and detach
func (p *Probe) Watch(ctx context.Context, match func(name string) bool, notify func(LinkEvent)) error {
	if notify == nil {
		notify = func(LinkEvent) {}
	}
	defer p.updateWatch(func(st *WatchState) { st.Running, st.Synced = false, false })

	// once the first dump is reconciled every interface of this run is
	// attached, counters a pinned map kept for any other one are stale
	pruned := false
	onSync := func() {
		if pruned {
			return
		}
		if err := p.pruneIfaceStats(); err != nil {
			log.Error("prune interface counters", "err", err)
			p.updateWatch(func(st *WatchState) { st.PruneErrors++ })
			return
		}
		pruned = true
	}

	opened := false
	retry := watchRetryMin
	for {
		synced, err := p.watch(ctx, match, notify, onSync, &opened)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !opened {
			return err
		}
		if synced {
			retry = watchRetryMin
		}

		log.Warn("interface watch restarting", "err", err, "in", retry)
		p.updateWatch(func(st *WatchState) {
			st.Running, st.Synced = false, false
			st.Resubscribes++
			st.LastError = err.Error()
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retry):
		}
		retry = min(2*retry, watchRetryMax)
	}
}

// watch runs one link subscription until it fails or ctx is done, onSync
// runs after its dump is reconciled, opened is set once the socket is open
// and synced reports whether the dump went through
func (p *Probe) watch(ctx context.Context, match func(string) bool, notify func(LinkEvent), onSync func(), opened *bool) (synced bool, err error) {
	s, err := nl.Subscribe(unix.NETLINK_ROUTE, unix.RTNLGRP_LINK)
	if err != nil {
		return false, fmt.Errorf("subscribe to link updates: %w", err)
	}
	// ctx closes the socket to end a Receive blocked on it, never during a
	// call on its raw descriptor, which a close could hand to another file
	stop := func() bool { return true }
	defer func() {
		if stop() {
			s.Close()
		}
	}()
	if p.rcvbuf > 0 {
		if err := s.SetReceiveBufferSize(p.rcvbuf, false); err != nil {
			return false, fmt.Errorf("size link subscription: %w", err)
		}
	}
	// a notification can carry the sequence number of the request that
	// caused it, only the dump replies carry the port of this socket too
	port, err := s.GetPid()
	if err != nil {
		return false, fmt.Errorf("link subscription port: %w", err)
	}
	*opened = true
	p.updateWatch(func(st *WatchState) { st.Running = true })

	dump, err := dumpLinks(s)
	if err != nil {
		return false, err
	}
	stop = context.AfterFunc(ctx, s.Close)

	// seen collects the links the dump and the messages next to it showed,
	// it is nil once the dump is through
	seen := make(map[int]bool)
	intr := false
	for {
		msgs, from, err := s.Receive()
		if err != nil {
			return synced, fmt.Errorf("receive link updates: %w", err)
		}
		if from.Pid != nl.PidKernel {
			p.watchError(fmt.Errorf("link message from port %d instead of the kernel", from.Pid))
			continue
		}

		for _, m := range msgs {
			if p.mangle != nil {
				p.mangle(m.Header.Type, m.Data)
			}
			dumped := seen != nil && m.Header.Seq == dump.Seq && m.Header.Pid == port
			if dumped && m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				intr = true
			}

			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if !dumped {
					continue
				}
				if intr {
					// links came or went while the kernel walked them, a
					// fresh dump has a consistent view
					if !stop() {
						return synced, ctx.Err()
					}
					dump, err = dumpLinks(s)
					stop = context.AfterFunc(ctx, s.Close)
					if err != nil {
						return synced, err
					}
					seen, intr = make(map[int]bool), false
					continue
				}
				p.reconcile(seen, notify)
				onSync()
				seen, synced = nil, true
				p.updateWatch(func(st *WatchState) { st.Synced = true })
			case unix.NLMSG_ERROR:
				errno, err := nlmsgErrno(m.Data)
				if err == nil && errno == 0 {
					continue
				}
				if err == nil {
					err = errno
				}
				if dumped {
					return synced, fmt.Errorf("dump links: %w", err)
				}
				p.watchError(fmt.Errorf("link message error: %w", err))
			case unix.RTM_NEWLINK, unix.RTM_DELLINK:
				hdr := unix.NlMsghdr(m.Header)
				l, err := netlink.LinkDeserialize(&hdr, m.Data)
				if err != nil {
					// a link that cannot be read may need an attach or a
					// detach, and a dump would take it for gone, the dump
					// of a fresh subscription catches up
					return synced, fmt.Errorf("decode link message: %w", err)
				}
				attrs := l.Attrs()
				// a message next to the dump is at least as recent as it
				if seen != nil {
					seen[attrs.Index] = m.Header.Type == unix.RTM_NEWLINK
				}
				p.handleLink(m.Header.Type, attrs, match, notify)
			}
		}
	}
}

// dumpLinks asks for every link on the subscribed socket s
// the request goes to the kernel alone, Send would address the link group
// of s as well, which hands the request to every other link subscriber and
// takes CAP_NET_ADMIN
func dumpLinks(s *nl.NetlinkSocket) (*nl.NetlinkRequest, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETLINK, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfInfomsg(unix.AF_UNSPEC))
	if err := unix.Sendto(s.GetFd(), req.Serialize(), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("dump links: %w", err)
	}
	return req, nil
}

// nlmsgErrno reads the negated errno of an NLMSG_ERROR payload
func nlmsgErrno(data []byte) (syscall.Errno, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("short error message of %d bytes", len(data))
	}
	return syscall.Errno(-int32(binary.NativeEndian.Uint32(data[:4]))), nil
}

func (p *Probe) handleLink(typ uint16, attrs *netlink.LinkAttrs, match func(string) bool, notify func(LinkEvent)) {
	switch typ {
	case unix.RTM_NEWLINK:
		// every state change of a link arrives as a new link message, an
		// interface that is already attached stays as it is
		if !match(attrs.Name) {
			return
		}
		if err := checkLinkType(attrs); err != nil {
			p.skip(attrs.Name, attrs.Index, err)
			return
		}
		attached, err := p.attach(attrs.Index, attrs.Name)
		if errors.Is(err, unix.ENODEV) {
			// the link went away before the attach, its delete message
			// follows
			log.Warn("attach interface", "interface", attrs.Name, "err", err)
			return
		}
		if err != nil {
			log.Error("attach interface", "interface", attrs.Name, "err", err)
			return
		}
		if attached {
			notify(LinkEvent{Name: attrs.Name, Ifindex: attrs.Index, Attached: true})
		}
	case unix.RTM_DELLINK:
		p.unskip(attrs.Index)
		p.forget(attrs.Index, notify)
	}
}

// reconcile detaches every attached interface the dump did not show, and
// forgets the skipped links that are gone
func (p *Probe) reconcile(seen map[int]bool, notify func(LinkEvent)) {
	p.mu.Lock()
	var gone []int
	for ifindex := range p.links {
		if !seen[ifindex] {
			gone = append(gone, ifindex)
		}
	}
	for ifindex := range p.skipped {
		if !seen[ifindex] {
			delete(p.skipped, ifindex)
		}
	}
	p.mu.Unlock()

	for _, ifindex := range gone {
		p.forget(ifindex, notify)
	}
}

// forget detaches an interface that is gone and drops its counters, which a
// pinned map from an earlier run can hold even when this run never attached
// the interface
func (p *Probe) forget(ifindex int, notify func(LinkEvent)) {
	name, detached, err := p.detach(ifindex)
	if !detached {
		err = p.clearIfaceStats(ifindex)
	}
	if err != nil {
		log.Error("detach interface", "interface", name, "ifindex", ifindex, "err", err)
	}
	if detached {
		notify(LinkEvent{Name: name, Ifindex: ifindex, Attached: false})
	}
}

// skip logs once that a matching link is left alone
func (p *Probe) skip(name string, ifindex int, reason error) {
	p.mu.Lock()
	seen := p.skipped[ifindex]
	p.skipped[ifindex] = true
	p.mu.Unlock()
	if !seen {
		log.Warn("interface skipped", "interface", name, "err", reason)
	}
}

// unskip forgets a skipped link once it is gone, its index may come back
func (p *Probe) unskip(ifindex int) {
	p.mu.Lock()
	delete(p.skipped, ifindex)
	p.mu.Unlock()
}

// watchError counts and logs a link message the watcher dropped
func (p *Probe) watchError(err error) {
	log.Warn("link message dropped", "err", err)
	p.updateWatch(func(st *WatchState) {
		st.Errors++
		st.LastError = err.Error()
	})
}

// WatchState returns what the interface watcher reports about itself
func (p *Probe) WatchState() WatchState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.watchState
}

func (p *Probe) updateWatch(fn func(*WatchState)) {
	p.mu.Lock()
	fn(&p.watchState)
	p.mu.Unlock()
}
