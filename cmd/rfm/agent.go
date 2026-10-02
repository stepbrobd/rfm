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
	root.AddCommand(agentCmd)
}

// agentProbe is what the agent uses of the loaded BPF programs, tests run
// the agent on a fake that needs no privileges
type agentProbe interface {
	Close() error
	Attach(ifindex int) error
	Attached() []int
	SetSampleRate(n uint32) error
	Watch(ctx context.Context, match func(string) bool, notify func(probe.LinkEvent)) error
	WatchState() probe.WatchState
	// Stats reads the interface counters and the sample rate for a scrape
	Stats() export.IfaceStatsSource
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

// Stats also reports the counter updates the interface stats map refused,
// as bpf_map errors
func (p kernelProbe) Stats() export.IfaceStatsSource {
	return &export.ProbeSource{Probe: p.Probe}
}

func (p kernelProbe) Events() (collector.Reader, error) {
	return collector.NewReader(p.FlowEvents(), p.FlowDrops())
}

// runAgent runs the agent the file at path configures until ctx is done
func runAgent(ctx context.Context, path string, deps agentDeps) error {
	started := time.Now()
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	cfgText, err := os.ReadFile(path)
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
		enricher = backends.Enricher
	}

	p, err := deps.loadProbe(probeConfig(cfg))
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

	mc := export.New(p.Stats(), c)
	if ipfixExp != nil {
		mc.SetIPFIX(ipfixExp.Stats)
	}
	mc.AddErrors("netlink", func() uint64 { return p.WatchState().Errors })
	if backends != nil && backends.RIB != nil {
		bmp := backends.RIB
		// a message that does not parse in full, a session or a route the
		// listener refuses past its bounds and the rib contradicting itself
		// are bmp errors
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

	// start listener and fail immediately if bind fails
	ln, err := deps.listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Info("metrics server", "addr", ln.Addr().String())

	handler.probe, handler.col, handler.ipfix, handler.backends = p, c, ipfixExp, backends

	// the goroutines are done before the probe and the reader close
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	wg.Go(func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server died, shutting down", "err", err)
			cancel()
		}
	})

	if ctlSrv != nil {
		wg.Go(func() {
			if err := ctlSrv.Serve(ctx); err != nil && ctx.Err() == nil {
				log.Error("control socket stopped", "err", err)
			}
		})
	}

	// follow interfaces that appear or vanish while the agent runs
	wg.Go(func() {
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
	})

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

// a scrape gathers and encodes every series, tens of MiB at the fleet's
// series count, which the endpoint must not let clients multiply
const (
	// metricsInFlight lets a scraper and an operator's curl gather at the
	// same time, further scrapes are refused with 503 until one is done
	metricsInFlight = 2
	// metricsTimeout bounds a gather, past it the scrape gets a 503
	metricsTimeout = 30 * time.Second
)

// newMetricsServer serves reg on /metrics, gathers that run longer than
// timeout are answered with 503
// with a timeout the handler encodes into a buffer and gives up its slot
// before the response goes out, so a client that does not read holds the
// encoded body and no gather, and the write timeout ends its connection
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
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      timeout + 30*time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// probeConfig is the probe setup cfg asks for
// iface_stats_size 0 keeps the size the object declares, 4096 counter keys,
// rather than one sized for the links up at start, which interfaces that
// come later would overflow, and which would change with the links up from
// one start to the next, while a pinned map of another size fails the start
func probeConfig(cfg *config.Config) probe.Config {
	return probe.Config{
		SampleRate:     cfg.Agent.BPF.SampleRate,
		RingBufSize:    cfg.Agent.BPF.RingBufSize,
		WakeupBatch:    cfg.Agent.BPF.WakeupBatch,
		IfaceStatsSize: cfg.Agent.BPF.IfaceStatsSize,
		PinPath:        cfg.Agent.BPF.PinPath,
	}
}
