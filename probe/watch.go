//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// LinkEvent is one attach or detach done by Watch
type LinkEvent struct {
	Name     string
	Ifindex  int
	Attached bool
}

// Watch follows link changes until ctx is done
// an interface whose name match accepts is attached when it appears and
// every attached interface is detached when it goes, so a tunnel that comes
// up after the agent or an interface recreated under a new index is
// monitored without a restart, interfaces present when Watch starts are the
// caller's job
// netlink and tcx address interfaces in the calling thread's network
// namespace, so Watch must run on a thread that lives in the namespace of
// the interfaces it manages
// notify, when set, is called after every change
func (p *Probe) Watch(ctx context.Context, match func(name string) bool, notify func(LinkEvent)) error {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	defer close(done)

	errs := make(chan error, 1)
	err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			select {
			case errs <- err:
			default:
			}
		},
	})
	if err != nil {
		return fmt.Errorf("subscribe to link updates: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errs:
			return fmt.Errorf("link updates: %w", err)
		case update, ok := <-updates:
			if !ok {
				return errors.New("link updates closed")
			}
			p.handleLink(update, match, notify)
		}
	}
}

func (p *Probe) handleLink(update netlink.LinkUpdate, match func(string) bool, notify func(LinkEvent)) {
	attrs := update.Link.Attrs()
	if attrs == nil {
		return
	}

	switch update.Header.Type {
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
		attached, err := p.attach(attrs.Index)
		if err != nil {
			log.Error("attach interface", "interface", attrs.Name, "err", err)
			return
		}
		if attached && notify != nil {
			notify(LinkEvent{Name: attrs.Name, Ifindex: attrs.Index, Attached: true})
		}
	case unix.RTM_DELLINK:
		p.unskip(attrs.Index)
		detached, err := p.detach(attrs.Index)
		if err != nil {
			log.Error("detach interface", "interface", attrs.Name, "err", err)
		}
		if detached && notify != nil {
			notify(LinkEvent{Name: attrs.Name, Ifindex: attrs.Index, Attached: false})
		}
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
