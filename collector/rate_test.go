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
	r := newRateController(10, 10)
	for range 3 * quietTicks {
		if got, changed := r.step(0); got != 10 || changed {
			t.Fatalf("rate=%d changed=%v, want 10 unchanged", got, changed)
		}
	}
	if got, changed := r.step(9); got != 10 || changed {
		t.Fatalf("rate with max == base = %d changed=%v, want 10 unchanged", got, changed)
	}
}
