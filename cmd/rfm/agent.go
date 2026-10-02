package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
	"ysun.co/rfm/ctl"
	"ysun.co/rfm/enrich"
	"ysun.co/rfm/export"
	"ysun.co/rfm/probe"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Start the RFM agent daemon",
	RunE:  runAgent,
}

func init() {
	root.AddCommand(agentCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	started := time.Now()
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return err
	}
	cfgText, err := os.ReadFile(cfgFile)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	ifaces, err := config.ResolveInterfaces(cfg.Agent.Interfaces)
	if err != nil {
		return err
	}
	names := make([]string, len(ifaces))
	for i, iface := range ifaces {
		names[i] = iface.Name
	}
	log.Info("interfaces matched", "count", len(ifaces), "names", names)

	backends, err := enrich.Build(cfg.Agent.Enrich)
	if err != nil {
		return err
	}
	var enricher collector.Enricher
	if backends != nil {
		defer backends.Close()
		enricher = backends.Enricher
	}

	ifaceStatsSize := cfg.Agent.BPF.IfaceStatsSize
	if ifaceStatsSize == 0 {
		// 2 directions and 3 protos (ipv4, ipv6, other) per interface, rounded up
		ifaceStatsSize = max(len(ifaces)*8, 64)
	}

	p, err := probe.Load(probe.Config{
		SampleRate:     cfg.Agent.BPF.SampleRate,
		RingBufSize:    cfg.Agent.BPF.RingBufSize,
		WakeupBatch:    cfg.Agent.BPF.WakeupBatch,
		IfaceStatsSize: ifaceStatsSize,
		PinPath:        cfg.Agent.BPF.PinPath,
	})
	if err != nil {
		return fmt.Errorf("load probe: %w", err)
	}
	defer p.Close()

	var failures []string
	for _, iface := range ifaces {
		if err := p.Attach(iface.Index); err != nil {
			log.Error("attach failed", "interface", iface.Name, "err", err)
			failures = append(failures, fmt.Sprintf("%s: %v", iface.Name, err))
			continue
		}
		log.Info("attached", "interface", iface.Name)
	}
	log.Info("attach summary", "successful", len(ifaces)-len(failures), "total", len(ifaces))
	if len(failures) > 0 {
		return fmt.Errorf("attach failed for %d/%d interfaces: %s", len(failures), len(ifaces), strings.Join(failures, "; "))
	}

	matcher, err := config.InterfaceMatcher(cfg.Agent.Interfaces)
	if err != nil {
		return err
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
	c.SetActiveTimeout(cfg.Agent.Collector.ActiveTimeout)
	c.SetSampleRate(cfg.Agent.BPF.SampleRate, 0)
	c.SetRateApplier(p.SetSampleRate)
	if cfg.Agent.BPF.AdaptiveSampling {
		c.SetRateController(cfg.Agent.BPF.SampleRate, cfg.Agent.BPF.MaxSampleRate, p.SetSampleRate)
	}

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
	if ipfixExp != nil {
		mc.SetIPFIX(ipfixExp.Stats)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(mc)
	// process and runtime metrics give operators the agent's own footprint
	// (rss, cpu, goroutines, gc) from the same scrape as the flow data
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector())

	addr := net.JoinHostPort(cfg.Agent.Prometheus.Host,
		strconv.Itoa(cfg.Agent.Prometheus.Port))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	// bound header reads so an idle client cannot hold a connection open
	// forever when the endpoint is exposed beyond loopback
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

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

	if cfg.Agent.Control.Socket != "" {
		handler := &controlHandler{
			started:  started,
			cfg:      cfg,
			cfgText:  string(cfgText),
			probe:    p,
			col:      c,
			ipfix:    ipfixExp,
			backends: backends,
		}
		ctlSrv, err := ctl.Listen(cfg.Agent.Control.Socket, handler)
		if err != nil {
			return err
		}
		log.Info("control socket", "path", cfg.Agent.Control.Socket)
		go func() {
			if err := ctlSrv.Serve(ctx); err != nil && ctx.Err() == nil {
				log.Error("control socket stopped", "err", err)
			}
		}()
	}

	// follow interfaces that appear or vanish while the agent runs
	go func() {
		err := p.Watch(ctx, matcher, func(ev probe.LinkEvent) {
			if ev.Attached {
				log.Info("attached", "interface", ev.Name)
			} else {
				log.Info("detached", "interface", ev.Name)
			}
		})
		if err != nil && ctx.Err() == nil {
			log.Error("interface watch stopped", "err", err)
		}
	}()

	runErr := c.Run(ctx, rd)
	if ipfixExp != nil {
		c.Flush(collector.FlowEndReasonForcedEnd)
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
