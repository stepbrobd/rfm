package export

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ysun.co/rfm/collector"
	"ysun.co/rfm/config"
)

func TestIPFIXExportsToGoFlow2(t *testing.T) {
	goflow2, err := exec.LookPath("goflow2")
	if err != nil {
		t.Skip("goflow2 not found")
	}

	port := reserveUDPPort(t)
	dir := t.TempDir()
	outPath := filepath.Join(dir, "goflow2.jsonl")
	logPath := filepath.Join(dir, "goflow2.log")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	defer logFile.Close()

	cmd := exec.CommandContext(
		ctx,
		goflow2,
		"-listen", fmt.Sprintf("netflow://127.0.0.1:%d", port),
		"-format", "json",
		"-transport", "file",
		"-transport.file", outPath,
		"-loglevel", "debug",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start goflow2: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	time.Sleep(300 * time.Millisecond)

	exp, err := NewIPFIX(config.IPFIXConfig{
		Host: "127.0.0.1",
		Port: port,
	}, 100)
	if err != nil {
		t.Fatalf("NewIPFIX: %v", err)
	}
	defer exp.Close()

	flow := collector.ExportedFlow{
		Key: collector.FlowKey{
			Ifindex: 7,
			Dir:     0,
			Proto:   17,
			SrcAddr: netip.MustParseAddr("10.0.0.1"),
			DstAddr: netip.MustParseAddr("10.0.0.2"),
			SrcPort: 12345,
			DstPort: 53,
		},
		Entry: collector.FlowEntry{
			FirstSeen: time.Unix(1_700_000_000, 0).UTC(),
			LastSeen:  time.Unix(1_700_000_000, 0).UTC(),
			Packets:   3,
			Bytes:     384,
		},
		EndReason: collector.FlowEndReasonIdleTimeout,
	}
	if err := exp.ExportFlow(flow); err != nil {
		t.Fatalf("ExportFlow: %v", err)
	}

	var records []map[string]any
	waitErr := waitForGoFlow2Output(outPath, 5*time.Second, &records)
	if waitErr != nil {
		logs, _ := os.ReadFile(logPath)
		t.Fatalf("wait for goflow2 output: %v\nlogs:\n%s", waitErr, logs)
	}

	if len(records) == 0 {
		t.Fatalf("goflow2 wrote no records")
	}

	found := false
	for _, record := range records {
		if record["dst_addr"] == "10.0.0.2" &&
			record["dst_port"] == float64(53) &&
			record["src_port"] == float64(12345) &&
			record["proto"] == "UDP" &&
			record["bytes"] == float64(384) &&
			record["packets"] == float64(3) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing exported record in %#v", records)
	}
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected udp addr type %T", conn.LocalAddr())
	}
	return addr.Port
}

func waitForGoFlow2Output(path string, timeout time.Duration, records *[]map[string]any) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			lines := splitNonEmptyLines(string(data))
			out := make([]map[string]any, 0, len(lines))
			for _, line := range lines {
				var record map[string]any
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					return fmt.Errorf("decode json line %q: %w", line, err)
				}
				out = append(out, record)
			}
			*records = out
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

func splitNonEmptyLines(s string) []string {
	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '\n' {
			continue
		}
		if i > start {
			lines = append(lines, s[start:i])
		}
		start = i + 1
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
