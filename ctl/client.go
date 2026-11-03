package ctl

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// DefaultSocket is where the NixOS module puts the control socket
const DefaultSocket = "/run/rfm/rfm.sock"

// Client talks to one agent over its control socket
type Client struct {
	Socket string
}

// Do sends one request and decodes the data part of the response
func (c *Client) Do(command string, args map[string]string, out any) error {
	conn, err := net.DialTimeout("unix", c.Socket, requestTimeout)
	if err != nil {
		return fmt.Errorf("connect to %s: %w (is the agent running with agent.control.socket set?)", c.Socket, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

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

func (c *Client) Status() (Status, error) {
	var s Status
	err := c.Do(CmdStatus, nil, &s)
	return s, err
}

// FlowsTop asks for the n busiest flows by bytes or packets, the agent
// checks both and defaults an empty one
func (c *Client) FlowsTop(n, by string) ([]FlowRow, error) {
	var rows []FlowRow
	err := c.Do(CmdFlowsTop, map[string]string{"n": n, "by": by}, &rows)
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

// SetSampleRate asks the agent to sample 1 in rate skbs and returns the rate
// it applied
func (c *Client) SetSampleRate(rate string) (Sampling, error) {
	var s Sampling
	err := c.Do(CmdSetRate, map[string]string{"rate": rate}, &s)
	return s, err
}

func (c *Client) ConfigShow() (string, error) {
	var s string
	err := c.Do(CmdConfigShow, nil, &s)
	return s, err
}

func (c *Client) ReloadMMDB() error {
	return c.Do(CmdReloadMMDB, nil, nil)
}
