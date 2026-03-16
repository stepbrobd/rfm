package collector

type flowState struct {
	key   FlowKey
	entry FlowEntry
	index int
}

type flowHeap []*flowState

func (h flowHeap) Len() int {
	return len(h)
}

func (h flowHeap) Less(i, j int) bool {
	return h[i].entry.LastSeen.Before(h[j].entry.LastSeen)
}

func (h flowHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *flowHeap) Push(x any) {
	state := x.(*flowState)
	state.index = len(*h)
	*h = append(*h, state)
}

func (h *flowHeap) Pop() any {
	old := *h
	n := len(old)
	state := old[n-1]
	state.index = -1
	*h = old[:n-1]
	return state
}

func (h flowHeap) peek() *flowState {
	if len(h) == 0 {
		return nil
	}
	return h[0]
}
