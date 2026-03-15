package main

import (
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/probe"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "start the rfm agent daemon",
	RunE:  runAgent,
}

func init() {
	root.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	p, err := probe.Load(probe.Config{SampleRate: 100})
	if err != nil {
		return fmt.Errorf("load probe: %w", err)
	}
	defer p.Close()

	// TODO: accept ifindex from flag or config
	ifindex := 1
	if err := p.Attach(ifindex); err != nil {
		return fmt.Errorf("attach: %w", err)
	}

	rd, err := collector.NewReader(p.FlowEvents(), p.FlowDrops())
	if err != nil {
		return fmt.Errorf("open reader: %w", err)
	}
	defer rd.Close()

	c := collector.New(30 * time.Second)

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return c.Run(ctx, rd)
}
