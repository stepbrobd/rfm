package collector

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/log"
)

// refusingExporter refuses every record, as a full queue does
type refusingExporter struct{ calls int }

var errRefused = errors.New("queue full")

func (r *refusingExporter) ExportFlow(ExportedFlow) error {
	r.calls++
	return errRefused
}

func TestExportRefusalsLogOnceAnInterval(t *testing.T) {
	var out bytes.Buffer
	log.SetOutput(&out)
	defer log.SetOutput(os.Stderr)
	lines := func() []string { return strings.Split(strings.TrimSpace(out.String()), "\n") }

	c := New(30*time.Second, nil, 1024)
	exp := &refusingExporter{}
	// the first refusal logs at once, the ones after it wait out the interval
	for range 100 {
		c.exportFlows(exp, make([]ExportedFlow, 10))
	}
	if exp.calls != 1000 {
		t.Fatalf("records offered = %d, want 1000", exp.calls)
	}
	if l := lines(); len(l) != 1 || !strings.Contains(l[0], "refused=10 ") {
		t.Fatalf("logs = %q, want one line with the 10 refusals of the first batch", l)
	}

	// past the interval the next refusal logs every one since the last log
	c.exportLogAt.Store(time.Now().Add(-time.Second).UnixNano())
	c.exportFlows(exp, make([]ExportedFlow, 1))
	if l := lines(); len(l) != 2 || !strings.Contains(l[1], "refused=991 ") {
		t.Fatalf("logs = %q, want a second line with the 991 refusals since the first", l)
	}
}
