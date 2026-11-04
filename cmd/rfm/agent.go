package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
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

var cfgFile string

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Start the RFM agent daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		// SIGINT and SIGTERM stop the agent
		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return runAgent(ctx, cfgFile, kernelDeps)
	},
}

func init() {
	// the agent alone reads the file, the other commands reach it over
	// --socket
	agentCmd.Flags().StringVarP(&cfgFile, "config", "c",
		"/etc/rfm/rfm.toml", "RFM configuration file path")
	root.AddCommand(agentCmd)
}

// agentProbe is what the agent uses of the loaded BPF programs, tests run
// the agent on a fake that needs no privileges
type agentProbe interface {
	export.Probe
	Close() error
	Attached() []int
	// Pending lists the matching links whose attach failed, the watcher
	// tries them again
	Pending() []int
	SetSampleRate(n uint32) error
	Watch(ctx context.Context, match func(string) bool, notify func(probe.LinkEvent)) error
	WatchState() probe.WatchState
	Synced() <-chan struct{}
	// Events opens the reader of the sampled flow events
	Events() (collector.Reader, error)
}

// agentDeps is what the agent needs privileges or a fixed address for
type agentDeps struct {
	loadProbe func(probe.Config) (agentProbe, error)
	// listen opens the metrics listener
	listen func(network, addr string) (net.Listener, error)
}

// kernelDeps load the programs into the kernel and listen where the
// configuration says
var kernelDeps = agentDeps{loadProbe: loadProbe, listen: net.Listen}

// kernelProbe is the agentProbe of the programs in the kernel
type kernelProbe struct {
	*probe.Probe
}

func loadProbe(cfg probe.Config) (agentProbe, error) {
	p, err := probe.Load(cfg)
	if err != nil {
		return nil, err
	}
	return kernelProbe{p}, nil
}

func (p kernelProbe) Events() (collector.Reader, error) {
	return collector.NewReader(p.FlowRings(), p.FlowDrops())
}

// runAgent runs the agent the file at path configures until ctx is done
func runAgent(ctx context.Context, path string, deps agentDeps) error {
	started := time.Now()
	cfgText, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}
	cfg, err := config.Parse(cfgText)
	if err != nil {
		return err
	}

	// the watcher attaches the interfaces, those up now from its first link
	// dump and those that come later, so none has to match yet
	matcher, err := config.InterfaceMatcher(cfg.Agent.Interfaces)
	if err != nil {
		return err
	}
	for _, pattern := range config.GlobPatterns(cfg.Agent.Interfaces) {
		log.Warn("interface pattern reads like a shell glob, it is an anchored regular expression", "pattern", pattern)
	}

	// a second agent with the same pin or the same control socket stops
	// here, before it loads anything, the pin lock is released last, once
	// the probe is closed
	if pin := cfg.Agent.BPF.PinPath; pin != "" {
		release, err := lockPin(pin)
		if err != nil {
			return err
		}
		defer release()
	}
	// the control socket is taken now and served once the agent is set up,
	// a start that fails before removes it
	handler := &controlHandler{started: started, cfg: cfg, cfgText: string(cfgText)}
	var ctlSrv *ctl.Server
	if socket := cfg.Agent.Control.Socket; socket != "" {
		ctlSrv, err = ctl.Listen(socket, handler)
		if err != nil {
			return err
		}
		defer ctlSrv.Close()
		log.Info("control socket", "path", socket)
	}

	backends, err := enrich.Build(cfg.Agent.Enrich)
	if err != nil {
		return err
	}
	var enricher collector.Enricher
	if backends != nil {
		defer backends.Close()
		enricher = backends
	}

	p, err := deps.loadProbe(probeConfig(cfg))
	if err != nil {
		return fmt.Errorf("load probe: %w", err)
	}
	defer p.Close()

	rd, err := p.Events()
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
	c.SetRateApplier(cfg.Agent.BPF.SampleRate, p.SetSampleRate)
	if cfg.Agent.BPF.AdaptiveSampling {
		c.SetRateController(cfg.Agent.BPF.SampleRate, cfg.Agent.BPF.MaxSampleRate)
	}

	var ipfixExp *export.IPFIXExporter
	if cfg.Agent.IPFIX.Enabled() {
		ipfixExp, err = export.NewIPFIX(cfg.Agent.IPFIX)
		if err != nil {
			return fmt.Errorf("init ipfix exporter: %w", err)
		}
		defer ipfixExp.Close()
		c.SetFlowExporter(ipfixExp)
		if cfg.Agent.IPFIX.Bind.Enabled() {
			log.Info("ipfix exporter", "addr", cfg.Agent.IPFIX.Addr(), "bind", cfg.Agent.IPFIX.Bind.Addr())
		} else {
			log.Info("ipfix exporter", "addr", cfg.Agent.IPFIX.Addr())
		}
	}

	mc := export.New(p, c)
	if ipfixExp != nil {
		mc.SetIPFIX(ipfixExp.Stats)
	}
	mc.AddErrors("netlink", func() uint64 { st := p.WatchState(); return st.Errors + st.Resubscribes })
	mc.AddErrors("attach", func() uint64 { return p.WatchState().AttachErrors })
	mc.AddErrors("bpf_map", func() uint64 { return p.WatchState().PruneErrors })
	if backends != nil && backends.RIB != nil {
		bmp := backends.RIB
		mc.AddErrors("bmp", func() uint64 {
			s := bmp.Stats()
			return s.ParseErrors + s.SessionsRejected + s.RoutesRejected + s.Inconsistencies
		})
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(mc)
	// process and runtime metrics give operators the agent's own footprint
	// (rss, cpu, goroutines, gc) from the same scrape as the flow data
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector())

	addr := net.JoinHostPort(cfg.Agent.Prometheus.Host,
		strconv.Itoa(cfg.Agent.Prometheus.Port))

	srv := newMetricsServer(reg, metricsTimeout)

	handler.probe, handler.col, handler.backends = p, c, backends
	if ipfixExp != nil {
		handler.ipfix = ipfixExp.Stats
	}

	// a failed component cancels run with its error, ctx ending is a clean stop
	// the goroutines are done before the probe and the reader close
	run, fail := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer fail(nil)

	// the collector reads the rings before the watcher attaches a program, so no event waits in a ring nobody drains
	collected := make(chan struct{})
	wg.Go(func() {
		defer close(collected)
		if err := c.Run(run, rd); err != nil && run.Err() == nil {
			fail(fmt.Errorf("collector: %w", err))
		}
	})

	if ctlSrv != nil {
		wg.Go(func() {
			if err := ctlSrv.Serve(run); err != nil && run.Err() == nil {
				fail(fmt.Errorf("control socket: %w", err))
			}
		})
	}
	if backends != nil && backends.RIB != nil {
		bmp := backends.RIB
		wg.Go(func() {
			if err := bmp.Wait(run); err != nil && run.Err() == nil {
				fail(fmt.Errorf("bmp listener: %w", err))
			}
		})
	}

	wg.Go(func() {
		err := p.Watch(run, matcher, func(ev probe.LinkEvent) {
			if ev.Attached {
				log.Info("attached", "interface", ev.Name)
			} else {
				log.Info("detached", "interface", ev.Name)
			}
		})
		if err != nil && run.Err() == nil {
			fail(fmt.Errorf("interface watch: %w", err))
		}
	})
	wg.Go(func() { reportInterfaces(run, p, cfg.Agent.Interfaces) })

	// the metrics port opens after the first link dump
	if !waitSynced(run, p) {
		return stopped(ctx, run)
	}

	// fail immediately if bind fails
	ln, err := deps.listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Info("metrics server", "addr", ln.Addr().String())
	wg.Go(func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fail(fmt.Errorf("metrics server: %w", err))
		}
	})

	<-collected
	if ipfixExp != nil {
		c.Flush(collector.FlowEndReasonForcedEnd)
		if err := ipfixExp.Close(); err != nil {
			log.Error("close ipfix exporter", "err", err)
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
	return stopped(ctx, run)
}

// stopped is what the agent returns once run, derived from ctx, ended, nil
// when ctx ended it and the failure that ended it otherwise
func stopped(ctx, run context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	return context.Cause(run)
}

// waitSynced reports whether the watcher's first link dump went through
// before ctx was done
func waitSynced(ctx context.Context, p agentProbe) bool {
	select {
	case <-p.Synced():
		return true
	case <-ctx.Done():
		return false
	}
}

// reportInterfaces waits for the watcher's first link dump, then logs the
// interfaces it attached, those whose attach failed and every pattern that
// matches no link, once, the links of such a pattern are attached when they
// appear and the failed ones once a later try succeeds
func reportInterfaces(ctx context.Context, p agentProbe, patterns []string) {
	if !waitSynced(ctx, p) {
		return
	}

	links, err := net.Interfaces()
	if err != nil {
		log.Error("list interfaces", "err", err)
		return
	}
	names := make([]string, len(links))
	byIndex := make(ifnames, len(links))
	for i, l := range links {
		names[i] = l.Name
		byIndex[l.Index] = l.Name
	}
	var attached, pending []string
	for _, ifindex := range p.Attached() {
		attached = append(attached, byIndex.name(ifindex))
	}
	for _, ifindex := range p.Pending() {
		pending = append(pending, byIndex.name(ifindex))
	}
	slices.Sort(attached)
	slices.Sort(pending)
	switch {
	case len(attached) > 0:
		log.Info("interfaces attached", "count", len(attached), "names", attached)
	case len(pending) == 0:
		log.Warn("no interface attached yet, matching links are attached when they appear", "patterns", patterns)
	}
	if len(pending) > 0 {
		log.Warn("interface attach failed, retrying", "count", len(pending), "names", pending)
	}
	for _, pattern := range config.UnmatchedPatterns(patterns, names) {
		log.Warn("interface pattern matches no link yet", "pattern", pattern)
	}
}

// promhttp encodes into a buffer under a timeout, the write timeout ends a client that does not read
func newMetricsServer(reg prometheus.Gatherer, timeout time.Duration) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		MaxRequestsInFlight: metricsInFlight,
		Timeout:             timeout,
	}))
	// bound header reads, response writes and keep-alive idling so a client
	// cannot hold a connection open forever when the endpoint is exposed
	// beyond loopback
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: metricsReadHeaderTimeout,
		WriteTimeout:      timeout + metricsWriteSlack,
		IdleTimeout:       metricsIdleTimeout,
	}
}

func probeConfig(cfg *config.Config) probe.Config {
	return probe.Config{
		SampleRate:     cfg.Agent.BPF.SampleRate,
		RingBufSize:    cfg.Agent.BPF.RingBufSize,
		WakeupBatch:    cfg.Agent.BPF.WakeupBatch,
		IfaceStatsSize: cfg.Agent.BPF.IfaceStatsSize,
		PinPath:        cfg.Agent.BPF.PinPath,
		SampledOnly:    cfg.Agent.BPF.SampledOnly,
	}
}
