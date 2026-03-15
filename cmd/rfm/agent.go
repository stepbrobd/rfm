package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/export"
	"ysun.co/rfm/probe"
)

var agentIface string

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "start the rfm agent daemon",
	RunE:  runAgent,
}

func init() {
	agentCmd.Flags().StringVarP(&agentIface, "interface", "i", "", "network interface to attach to (required)")
	agentCmd.MarkFlagRequired("interface")
	root.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	iface, err := net.InterfaceByName(agentIface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", agentIface, err)
	}

	p, err := probe.Load(probe.Config{SampleRate: 100})
	if err != nil {
		return fmt.Errorf("load probe: %w", err)
	}
	defer p.Close()

	if err := p.Attach(iface.Index); err != nil {
		return fmt.Errorf("attach %s: %w", agentIface, err)
	}

	rd, err := collector.NewReader(p.FlowEvents(), p.FlowDrops())
	if err != nil {
		return fmt.Errorf("open reader: %w", err)
	}
	defer rd.Close()

	c := collector.New(30*time.Second, nil, 65536)

	mc := export.New(&export.ProbeSource{Probe: p}, c)
	prometheus.MustRegister(mc)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: ":9669", Handler: mux}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "http: %v\n", err)
		}
	}()

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	runErr := c.Run(ctx, rd)
	srv.Shutdown(context.Background())
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}
