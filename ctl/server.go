package ctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"
)

// requestTimeout bounds one connection so a stuck client cannot pin a
// server goroutine
const requestTimeout = 5 * time.Second

// Server answers requests on a unix socket
type Server struct {
	handler  Handler
	listener net.Listener
	wg       sync.WaitGroup
}

// Listen creates the socket at path, replacing a stale one left by an
// earlier run, the socket is only reachable by the owner
func Listen(path string, handler Handler) (*Server, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale control socket %q: %w", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen control socket %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod control socket %q: %w", path, err)
	}
	return &Server{handler: handler, listener: ln}, nil
}

// Addr returns the socket path
func (s *Server) Addr() string {
	return s.listener.Addr().String()
}

// Serve answers connections until ctx is done
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			s.wg.Wait()
			return fmt.Errorf("accept control connection: %w", err)
		}
		s.wg.Go(func() {
			defer conn.Close()
			s.serveConn(conn)
		})
	}
}

func (s *Server) serveConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	var req Request
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
		writeResponse(conn, Response{Error: "decode request: " + err.Error()})
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
		return s.handler.Status(), nil
	case CmdFlowsTop:
		n := 20
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
		rows := s.handler.FlowsTop(n, by)
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
		if err := s.handler.ReloadMMDB(); err != nil {
			return nil, err
		}
		return "reloaded", nil
	default:
		return nil, fmt.Errorf("unknown command %q", req.Command)
	}
}
