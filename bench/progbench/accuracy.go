//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// srcPortOff is the offset of src_port in struct rfm_flow_event, the BPF
// side has already converted it to host order
const srcPortOff = 48

type accuracyResult struct {
	Label     string  `json:"label"`
	Prog      string  `json:"prog"`
	Order     string  `json:"order"`
	N         uint32  `json:"n"`
	Flows     int     `json:"flows"`
	M         int     `json:"m"`
	Events    int     `json:"events"`
	Drops     uint64  `json:"ring_drops"`
	Coverage  float64 `json:"coverage"`
	Bias      float64 `json:"bias"`
	MeanAbs   float64 `json:"mean_abs_rel_err"`
	StdRel    float64 `json:"std_rel_err"`
	P95Abs    float64 `json:"p95_abs_rel_err"`
	MaxAbs    float64 `json:"max_abs_rel_err"`
	Bernoulli float64 `json:"bernoulli_std"`
	Kernel    string  `json:"kernel"`
}

// accuracy feeds the ingress program prog K flows of exactly M packets each, one
// test run per packet, with the flows interleaved round robin as the
// sequential pktgen ports of accuracy.nu produce or each sent as one burst,
// then reads every event from the ring and scales each flow's samples by N
func accuracy(obj, label, prog, km string, n, ringOrder, stage uint32, kernel string) error {
	parts := strings.Split(km, ":")
	if len(parts) < 2 || len(parts) > 3 || (len(parts) == 3 && parts[2] != "burst") {
		return fmt.Errorf("-accuracy wants K:M or K:M:burst, got %q", km)
	}
	ks, ms := parts[0], parts[1]
	burst := len(parts) == 3
	k, err := strconv.Atoi(ks)
	if err != nil {
		return err
	}
	m, err := strconv.Atoi(ms)
	if err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return err
	}
	if _, ok := spec.Programs[prog]; !ok {
		return fmt.Errorf("no %s program", prog)
	}
	for name := range spec.Programs {
		if name != prog {
			delete(spec.Programs, name)
		}
	}
	sizeRings(spec, ringOrder)
	if err := setStage(spec, stage); err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer coll.Close()
	if err := writeConfig(spec, coll, n); err != nil {
		return err
	}
	rings, own, err := eventRings(spec, coll, pinnedRing(ringOrder))
	if err != nil {
		return err
	}
	if own {
		defer closeRings(rings)
	}
	if sm, ok := coll.Maps["rfm_iface_slot"]; ok {
		if err := sm.Put(uint32(1), uint32(1)); err != nil {
			return err
		}
	}
	p := coll.Programs[prog]

	const portBase = 10000
	frames := make([]frame, k)
	for i := range frames {
		d := pad(slices.Concat(eth(0x0800), ipv4(20), tcp()), 64)
		binary.BigEndian.PutUint16(d[14+20:], uint16(portBase+i))
		frames[i] = frame{data: d}
	}
	// round robin interleaves the flows, burst sends each flow's M packets
	// back to back, the case where a skip gap that is not memoryless could
	// differ from Bernoulli sampling
	if burst {
		for i := range frames {
			for range m {
				if _, _, err := testRun(p.FD(), frames[i], 1, true); err != nil {
					return err
				}
			}
		}
	} else {
		for range m {
			for i := range frames {
				if _, _, err := testRun(p.FD(), frames[i], 1, true); err != nil {
					return err
				}
			}
		}
	}

	// the last events of a stage program wait for the flush of their stage
	if err := waitStages(coll); err != nil {
		return err
	}
	counts := make([]int, k)
	events := 0
	for _, ring := range rings {
		rd, err := ringbuf.NewReader(ring)
		if err != nil {
			return err
		}
		rd.SetDeadline(time.Now())
		var rec ringbuf.Record
		for {
			if err := rd.ReadInto(&rec); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					break
				}
				rd.Close()
				return err
			}
			raw := rec.RawSample
			if len(raw) == 0 || len(raw)%eventSize != 0 {
				rd.Close()
				return fmt.Errorf("record of %d bytes, not a positive multiple of the %d of an event", len(raw), eventSize)
			}
			for off := 0; off < len(raw); off += eventSize {
				port := int(binary.NativeEndian.Uint16(raw[off+srcPortOff:])) - portBase
				if port < 0 || port >= k {
					rd.Close()
					return fmt.Errorf("event for unknown source port %d", port+portBase)
				}
				counts[port]++
				events++
			}
		}
		rd.Close()
	}

	order := "round_robin"
	if burst {
		order = "burst"
	}
	res := accuracyResult{Label: label, Prog: prog, Order: order, N: n, Flows: k, M: m, Events: events, Drops: drops(coll), Kernel: kernel}
	var covered int
	var sum, sumAbs float64
	rel := make([]float64, k)
	abs := make([]float64, k)
	for i, c := range counts {
		if c > 0 {
			covered++
		}
		rel[i] = (float64(c)*float64(n) - float64(m)) / float64(m)
		abs[i] = math.Abs(rel[i])
		sum += rel[i]
		sumAbs += abs[i]
	}
	mean := sum / float64(k)
	var ss float64
	for _, r := range rel {
		ss += (r - mean) * (r - mean)
	}
	slices.Sort(abs)
	res.Coverage = float64(covered) / float64(k)
	res.Bias = mean
	res.MeanAbs = sumAbs / float64(k)
	res.StdRel = math.Sqrt(ss / float64(k-1))
	res.P95Abs = abs[int(0.95*float64(k-1))]
	res.MaxAbs = abs[k-1]
	// relative standard deviation of a binomial count with p = 1/N scaled by N
	res.Bernoulli = math.Sqrt((float64(n) - 1) / float64(m))

	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
