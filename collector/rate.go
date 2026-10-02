package collector

// rateController adapts the sample rate to ring buffer pressure
// a tick with dropped events doubles the rate up to max, quietTicks ticks in
// a row without drops halve it back down to the configured base, so a node
// whose consumer cannot keep up degrades to coarser sampling instead of
// losing events, and returns to the configured rate once the burst is over
type rateController struct {
	base, max, rate uint32
	quiet           int
}

// quietTicks is how many drop free ticks relax the rate one step
const quietTicks = 10

func newRateController(base, max uint32) *rateController {
	if base == 0 {
		base = 1
	}
	if max < base {
		max = base
	}
	return &rateController{base: base, max: max, rate: base}
}

// reset makes rate the current rate, set elsewhere, and starts the quiet
// streak over, the next steps move from there
func (r *rateController) reset(rate uint32) {
	r.rate = rate
	r.quiet = 0
}

// step feeds the drops seen since the last tick and returns the rate to
// apply and whether it changed
func (r *rateController) step(drops uint64) (uint32, bool) {
	if drops > 0 {
		r.quiet = 0
		if r.rate >= r.max {
			return r.rate, false
		}
		r.rate = min(r.rate*2, r.max)
		return r.rate, true
	}

	r.quiet++
	if r.quiet < quietTicks || r.rate <= r.base {
		return r.rate, false
	}
	r.quiet = 0
	r.rate = max(r.rate/2, r.base)
	return r.rate, true
}
