package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/enrich"
	"ysun.co/rfm/export"
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
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}

	indices, err := config.ResolveInterfaces(cfg.Agent.Interfaces)
	if err != nil {
		return err
	}

	enricher, enrichCloser, err := enrich.Build(cfg.Agent.Enrich)
	if err != nil {
		return err
	}
	if enrichCloser != nil {
		defer enrichCloser.Close()
	}

	// 2 directions × 3 protos (ipv4, ipv6, other) per interface, rounded up
	ifaceStatsSize := len(indices) * 8
	if ifaceStatsSize < 64 {
		ifaceStatsSize = 64
	}

	p, err := probe.Load(probe.Config{
		SampleRate:     cfg.Agent.BPF.SampleRate,
		RingBufSize:    cfg.Agent.BPF.RingBufSize,
		IfaceStatsSize: ifaceStatsSize,
	})
	if err != nil {
		return fmt.Errorf("load probe: %w", err)
	}
	defer p.Close()

	for _, idx := range indices {
		iface, _ := net.InterfaceByIndex(idx)
		name := strconv.Itoa(idx)
		if iface != nil {
			name = iface.Name
		}
		if err := p.Attach(idx); err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		log.Info("attached", "interface", name)
	}

	rd, err := collector.NewReader(p.FlowEvents(), p.FlowDrops())
	if err != nil {
		return fmt.Errorf("open reader: %w", err)
	}
	defer rd.Close()

	c := collector.New(
		cfg.Agent.Collector.EvictionTimeout,
		enricher,
		cfg.Agent.Collector.MaxFlows,
	)

	var ipfixExp *export.IPFIXExporter
	if cfg.Agent.IPFIX.Enabled() {
		ipfixExp, err = export.NewIPFIX(cfg.Agent.IPFIX, cfg.Agent.BPF.SampleRate)
		if err != nil {
			return fmt.Errorf("init ipfix exporter: %w", err)
		}
		c.SetFlowExporter(ipfixExp)
		if cfg.Agent.IPFIX.Bind.Enabled() {
			log.Info("ipfix exporter", "addr", cfg.Agent.IPFIX.Addr(), "bind", cfg.Agent.IPFIX.Bind.Addr())
		} else {
			log.Info("ipfix exporter", "addr", cfg.Agent.IPFIX.Addr())
		}
	}

	mc := export.New(&export.ProbeSource{Probe: p}, c)

	reg := prometheus.NewRegistry()
	reg.MustRegister(mc)

	addr := net.JoinHostPort(cfg.Agent.Prometheus.Host,
		strconv.Itoa(cfg.Agent.Prometheus.Port))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	srv := &http.Server{Addr: addr, Handler: mux}

	// start listener and fail immediately if bind fails
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Info("metrics server", "addr", addr)

	ctx, cancel := signal.NotifyContext(cmd.Context(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server died, shutting down", "err", err)
			cancel()
		}
	}()

	runErr := c.Run(ctx, rd)
	if ipfixExp != nil {
		c.Flush(collector.FlowEndReasonEndOfFlow)
		if err := ipfixExp.Close(); err != nil {
			log.Error("close ipfix exporter", "err", err)
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}
