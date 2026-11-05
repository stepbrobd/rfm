package collector

import "testing"

func TestRateControllerDoublesOnDropsAndRelaxes(t *testing.T) {
	r := newRateController(10, 80)

	steps := []struct {
		drops   uint64
		want    uint32
		changed bool
	}{
		{0, 10, false},
		{5, 20, true},
		{1, 40, true},
		{1, 80, true},
		{1, 80, false}, // capped
	}
	for i, s := range steps {
		got, changed := r.step(s.drops)
		if got != s.want || changed != s.changed {
			t.Fatalf("step %d: rate=%d changed=%v, want %d %v", i, got, changed, s.want, s.changed)
		}
	}

	// nine quiet ticks keep the rate, the tenth halves it
	for range quietTicks - 1 {
		if got, changed := r.step(0); got != 80 || changed {
			t.Fatalf("relaxed too early: rate=%d changed=%v", got, changed)
		}
	}
	if got, changed := r.step(0); got != 40 || !changed {
		t.Fatalf("rate after %d quiet ticks = %d changed=%v, want 40", quietTicks, got, changed)
	}

	// a drop resets the quiet streak
	for range quietTicks - 1 {
		r.step(0)
	}
	if got, _ := r.step(3); got != 80 {
		t.Fatalf("rate after drops = %d, want 80", got)
	}
	if got, changed := r.step(0); got != 80 || changed {
		t.Fatalf("quiet streak was not reset: rate=%d changed=%v", got, changed)
	}
}

func TestRateControllerNeverGoesBelowBase(t *testing.T) {
	// 150 doubles to 300, then two quiet streaks halve it to 150 and to the base 100, not to 75
	r := newRateController(100, 1000)
	r.reset(150)
	r.step(1)
	for range 2 * quietTicks {
		r.step(0)
	}
	if r.rate != 100 {
		t.Fatalf("rate after two quiet streaks = %d, want the base 100", r.rate)
	}
}

func TestRateControllerNeverLowersTheRateUnderDrops(t *testing.T) {
	// a rate past 2^31 doubled in 32 bits would wrap below itself, it must stop at the max instead
	r := newRateController(3000000000, 4294967295)
	prev := r.rate
	for i := range 4 {
		rate, _ := r.step(1)
		if rate < prev {
			t.Fatalf("step %d under drops lowered the rate from %d to %d", i, prev, rate)
		}
		prev = rate
	}
	if r.rate != 4294967295 {
		t.Fatalf("rate under drops = %d, want the max 4294967295", r.rate)
	}
}
