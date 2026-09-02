package ctl

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// DefaultSocket is where the NixOS module puts the control socket
const DefaultSocket = "/run/rfm/rfm.sock"

// Client talks to one agent over its control socket
type Client struct {
	Socket  string
	Timeout time.Duration
}

// Do sends one request and decodes the data part of the response
func (c *Client) Do(command string, args map[string]string, out any) error {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = requestTimeout
	}
	conn, err := net.DialTimeout("unix", c.Socket, timeout)
	if err != nil {
		return fmt.Errorf("connect to %s: %w (is the agent running with agent.control.socket set?)", c.Socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := json.NewEncoder(conn).Encode(Request{Command: command, Args: args}); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(resp.Data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// Raw sends one request and returns the response data as sent
func (c *Client) Raw(command string, args map[string]string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.Do(command, args, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *Client) Status() (Status, error) {
	var s Status
	err := c.Do(CmdStatus, nil, &s)
	return s, err
}

func (c *Client) FlowsTop(n int, by string) ([]FlowRow, error) {
	var rows []FlowRow
	err := c.Do(CmdFlowsTop, map[string]string{"n": strconv.Itoa(n), "by": by}, &rows)
	return rows, err
}

func (c *Client) FlowsCount() (uint64, error) {
	var n uint64
	err := c.Do(CmdFlowsCount, nil, &n)
	return n, err
}

func (c *Client) RIBLookup(addr netip.Addr) (Route, error) {
	var r Route
	err := c.Do(CmdRIBLookup, map[string]string{"addr": addr.String()}, &r)
	return r, err
}

func (c *Client) RIBSummary() (RIB, error) {
	var r RIB
	err := c.Do(CmdRIBSummary, nil, &r)
	return r, err
}

func (c *Client) SetSampleRate(rate uint32) error {
	return c.Do(CmdSetRate, map[string]string{"rate": strconv.FormatUint(uint64(rate), 10)}, nil)
}

func (c *Client) ConfigShow() (string, error) {
	var s string
	err := c.Do(CmdConfigShow, nil, &s)
	return s, err
}

func (c *Client) ReloadMMDB() error {
	return c.Do(CmdReloadMMDB, nil, nil)
}
