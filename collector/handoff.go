package collector

import "time"

// a run loop that is busy for most of a window hands its batches to a
// recorder goroutine and only reads and decodes, and it records inline again
// once the two together use less than half a core, so a lightly loaded agent
// keeps one goroutine and pays no handoff
const (
	// handoffStages is the batches in flight between the reader and the recorder
	handoffStages = 4
	// handoffBatch is the records of a batch the loop hands off, more than it records inline since the handoff costs per batch
	handoffBatch = 1024
	// loadWindow is how long the run loop sums its busy time before it decides
	loadWindow = 100 * time.Millisecond
	// handoffLoad is the share of a window the loop recording inline must be busy for the recorder to start
	handoffLoad = 0.85
	// inlineLoad is the share of a window the reader and the recorder together must stay under to record inline again
	inlineLoad = 0.5
)

// stage is one batch on its way to the recorder and back
type stage struct {
	batch []sample
	// busy is the time the recorder spent on the batch
	busy time.Duration
}

// handoff is the recorder goroutine of a run loop, the loop owns one batch
// and the stages own the others, so no batch is written while it is recorded
type handoff struct {
	full, free chan *stage
	done       chan struct{}
	// busy sums the recorder's time on the stages that came back in the window
	busy time.Duration
}

// startHandoff starts a recorder goroutine that records the batches handed to it in order
func (c *Collector) startHandoff() *handoff {
	h := &handoff{
		full: make(chan *stage, handoffStages),
		free: make(chan *stage, handoffStages),
		done: make(chan struct{}),
	}
	for range handoffStages {
		h.free <- &stage{batch: make([]sample, 0, handoffBatch)}
	}
	go func() {
		defer close(h.done)
		// a table at its cap evicts a flow for each new one, one buffer holds the records and the labels of batch after batch
		var buf recordBuf
		for st := range h.full {
			t := time.Now()
			c.record(st.batch, nil, &buf)
			st.busy = time.Since(t)
			h.free <- st
		}
	}()
	return h
}

// hand queues batch for the recorder and returns the empty batch to fill
// next, it waits while every stage is out, which holds the loop to the
// recorder's pace
func (h *handoff) hand(batch []sample) []sample {
	st := <-h.free
	h.busy += st.busy
	next := st.batch[:0]
	st.batch, st.busy = batch, 0
	h.full <- st
	return next
}

// stop returns once the recorder has recorded every batch handed to it
func (h *handoff) stop() {
	close(h.full)
	<-h.done
}

// loadMeter sums the run loop's busy time, from a batch's first record to
// the next read, over a window
type loadMeter struct {
	start time.Time
	busy  time.Duration
}

// due reports whether the window that now ends has run its length, and the
// share of it the loop and the recorder were busy for
func (m *loadMeter) due(now time.Time, h *handoff) (bool, float64) {
	if m.start.IsZero() {
		m.start = now
		return false, 0
	}
	span := now.Sub(m.start)
	if span < loadWindow {
		return false, 0
	}
	busy := m.busy
	if h != nil {
		busy += h.busy
		h.busy = 0
	}
	m.start, m.busy = now, 0
	return true, float64(busy) / float64(span)
}
