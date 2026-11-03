package ctl

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
)

// Server answers requests on a unix socket
type Server struct {
	handler  Handler
	listener net.Listener
	path     string
	// created is the socket file Listen made, close unlinks the path only
	// while it still names this file
	created   os.FileInfo
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// Listen creates the socket at path, replacing a stale one left by an
// earlier run, and refuses a path that is not a socket or that another
// process still listens on, the socket is only reachable by the owner
func Listen(path string, handler Handler) (*Server, error) {
	if err := removeStale(path); err != nil {
		return nil, err
	}
	// bind gives the socket 0777 less the umask, it is 0600 before a client
	// can connect
	umask := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(umask)
	if err != nil {
		return nil, fmt.Errorf("listen control socket %q: %w", path, err)
	}
	ln.SetUnlinkOnClose(false)
	created, err := os.Lstat(path)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("stat control socket %q: %w", path, err)
	}
	return &Server{handler: handler, listener: ln, path: path, created: created}, nil
}

// removeStale unlinks a socket no process listens on, it checks the file type before dialing, a regular file also gives ECONNREFUSED
func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat control socket %q: %w", path, err)
	}
	if fi.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("control socket path %q exists and is not a socket", path)
	}
	conn, err := net.Dial("unix", path)
	switch {
	case err == nil:
		conn.Close()
		return fmt.Errorf("control socket %q is in use by another process", path)
	case errors.Is(err, os.ErrNotExist):
		return nil
	case !errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("probe control socket %q: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale control socket %q: %w", path, err)
	}
	return nil
}

// close unlinks before closing, Serve then sees the listener closed with the file gone
func (s *Server) close() {
	s.closeOnce.Do(func() {
		if fi, err := os.Lstat(s.path); err == nil && os.SameFile(fi, s.created) {
			_ = os.Remove(s.path)
		}
		s.listener.Close()
	})
}

// Close closes the socket of a server that is not serving, Serve closes it
// itself when it returns, closing twice is harmless
func (s *Server) Close() error {
	s.close()
	return nil
}

// Serve answers connections until ctx is done or accept fails with an error
// that is not temporary, and closes the socket when it returns
func (s *Server) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, s.close)
	defer stop()
	defer s.wg.Wait()
	defer s.close()

	slots := make(chan struct{}, maxConns)
	var delay time.Duration
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		conn, err := s.listener.Accept()
		if err != nil {
			<-slots
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// accept still marks fd exhaustion with the deprecated
			// Temporary, which net/http retries on as well
			var te interface{ Temporary() bool }
			if !errors.As(err, &te) || !te.Temporary() {
				return fmt.Errorf("accept control connection: %w", err)
			}
			delay = min(max(2*delay, acceptBackoffMin), acceptBackoffMax)
			log.Error("accept control connection", "err", err, "retry_in", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		delay = 0
		s.wg.Go(func() {
			defer func() { <-slots }()
			defer conn.Close()
			s.serveConn(conn)
		})
	}
}

func (s *Server) serveConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	var req Request
	body := &io.LimitedReader{R: conn, N: maxRequestSize}
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		msg := "decode request: " + err.Error()
		if body.N == 0 {
			msg = fmt.Sprintf("request exceeds %d bytes", maxRequestSize)
		}
		writeResponse(conn, Response{Error: msg})
		return
	}
	writeResponse(conn, s.dispatch(req))
}

func writeResponse(conn net.Conn, resp Response) {
	enc := json.NewEncoder(conn)
	_ = enc.Encode(resp)
}

func (s *Server) dispatch(req Request) Response {
	data, err := s.handle(req)
	if err != nil {
		return Response{Error: err.Error()}
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return Response{Error: "encode response: " + err.Error()}
	}
	return Response{Data: raw}
}

func (s *Server) handle(req Request) (any, error) {
	switch req.Command {
	case CmdStatus:
		return s.handler.Status()
	case CmdFlowsTop:
		n := defaultTopFlows
		if v := req.Args["n"]; v != "" {
			parsed, err := strconv.Atoi(v)
			if err != nil || parsed < 1 {
				return nil, fmt.Errorf("n must be a positive integer, got %q", v)
			}
			n = parsed
		}
		by := req.Args["by"]
		if by == "" {
			by = "bytes"
		}
		if by != "bytes" && by != "packets" {
			return nil, fmt.Errorf("by must be bytes or packets, got %q", by)
		}
		rows, err := s.handler.FlowsTop(n, by)
		if err != nil {
			return nil, err
		}
		if rows == nil {
			rows = []FlowRow{}
		}
		return rows, nil
	case CmdFlowsCount:
		return s.handler.FlowsCount(), nil
	case CmdRIBLookup:
		addr, err := netip.ParseAddr(req.Args["addr"])
		if err != nil {
			return nil, fmt.Errorf("addr: %w", err)
		}
		route, ok, err := s.handler.RIBLookup(addr)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("no route for %s", addr)
		}
		return route, nil
	case CmdRIBSummary:
		return s.handler.RIBSummary()
	case CmdSetRate:
		rate, err := strconv.ParseUint(req.Args["rate"], 10, 32)
		if err != nil || rate == 0 {
			return nil, fmt.Errorf("rate must be a positive integer, got %q", req.Args["rate"])
		}
		if err := s.handler.SetSampleRate(uint32(rate)); err != nil {
			return nil, err
		}
		return Sampling{Rate: uint32(rate)}, nil
	case CmdConfigShow:
		return s.handler.ConfigShow(), nil
	case CmdReloadMMDB:
		return nil, s.handler.ReloadMMDB()
	default:
		return nil, fmt.Errorf("unknown command %q", req.Command)
	}
}
