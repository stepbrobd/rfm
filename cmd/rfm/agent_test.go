package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"ysun.co/rfm/testutil"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rfm.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunAgentWithConfig(t *testing.T) {
	lo := testutil.LoopbackName(t)
	cfgFile = writeTestConfig(t, fmt.Sprintf(`
[agent]
interfaces = [%q]
`, lo))
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("runAgent returned nil, want error")
	}
}

func TestRunAgentBadInterface(t *testing.T) {
	cfgFile = writeTestConfig(t, `
[agent]
interfaces = ["doesnotexist999"]
`)
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("should fail on bad interface")
	}
	if !strings.Contains(err.Error(), "doesnotexist999") {
		t.Errorf("error should mention interface name, got: %v", err)
	}
}

func TestRunAgentBadMMDBPath(t *testing.T) {
	lo := testutil.LoopbackName(t)
	cfgFile = writeTestConfig(t, fmt.Sprintf(`
[agent]
interfaces = [%q]

[agent.enrich.mmdb]
asn_db = "/does/not/exist.mmdb"
`, lo))
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("should fail on bad MMDB path")
	}
	if !strings.Contains(err.Error(), "/does/not/exist.mmdb") {
		t.Errorf("error should mention MMDB path, got: %v", err)
	}
}

// blockingCollector holds every gather in Collect until release is closed
type blockingCollector struct {
	entered chan struct{}
	release chan struct{}
}

var descBlocking = prometheus.NewDesc("rfm_test_blocking", "A series whose gather waits for the test.", nil, nil)

func newBlockingRegistry(t *testing.T) (*prometheus.Registry, *blockingCollector) {
	t.Helper()
	b := &blockingCollector{entered: make(chan struct{}, 16), release: make(chan struct{})}
	reg := prometheus.NewRegistry()
	reg.MustRegister(b)
	return reg, b
}

func (b *blockingCollector) Describe(ch chan<- *prometheus.Desc) { ch <- descBlocking }

func (b *blockingCollector) Collect(ch chan<- prometheus.Metric) {
	b.entered <- struct{}{}
	<-b.release
	ch <- prometheus.MustNewConstMetric(descBlocking, prometheus.GaugeValue, 1)
}

// scrape gets url and returns the status code
func scrape(client *http.Client, url string) (int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, err
}

func TestMetricsServerBoundsConcurrentGathers(t *testing.T) {
	reg, b := newBlockingRegistry(t)
	ts := httptest.NewServer(newMetricsServer(reg, time.Minute).Handler)
	defer ts.Close()
	released := false
	release := func() {
		if !released {
			close(b.release)
			released = true
		}
	}
	defer release()
	client := &http.Client{Timeout: 5 * time.Second}

	codes := make(chan int, metricsInFlight)
	for range metricsInFlight {
		go func() {
			code, err := scrape(client, ts.URL+"/metrics")
			if err != nil {
				t.Error(err)
			}
			codes <- code
		}()
	}
	for range metricsInFlight {
		select {
		case <-b.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("scrapes did not reach the gather")
		}
	}

	// every slot holds a gather, one more scrape is refused at once instead
	// of gathering and holding another copy of every series
	if code, err := scrape(&http.Client{Timeout: time.Second}, ts.URL+"/metrics"); err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("scrape beyond %d gathers = %d, %v, want 503", metricsInFlight, code, err)
	}
	release()
	for range metricsInFlight {
		if code := <-codes; code != http.StatusOK {
			t.Fatalf("held scrape = %d, want 200", code)
		}
	}
}

func TestMetricsServerTimesOutAGather(t *testing.T) {
	reg, b := newBlockingRegistry(t)
	ts := httptest.NewServer(newMetricsServer(reg, 50*time.Millisecond).Handler)
	defer ts.Close()
	defer close(b.release)

	code, err := scrape(&http.Client{Timeout: 5 * time.Second}, ts.URL+"/metrics")
	if err != nil || code != http.StatusServiceUnavailable {
		t.Fatalf("scrape of a gather past the timeout = %d, %v, want 503", code, err)
	}
}

func TestMetricsServerTimeouts(t *testing.T) {
	srv := newMetricsServer(prometheus.NewRegistry(), metricsTimeout)
	if srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatalf("read header timeout %v, idle timeout %v, want both set", srv.ReadHeaderTimeout, srv.IdleTimeout)
	}
	// a client that reads slowly is cut off, after a gather that took the
	// whole timeout still had time to be sent
	if srv.WriteTimeout <= metricsTimeout {
		t.Fatalf("write timeout %v, want it above the gather timeout %v", srv.WriteTimeout, metricsTimeout)
	}
}

func TestRunAgentBadConfig(t *testing.T) {
	cfgFile = writeTestConfig(t, `
[agent]
interfaces = []
`)
	err := runAgent(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("should fail on empty interfaces")
	}
}
