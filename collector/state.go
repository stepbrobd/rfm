package collector

import "container/list"

// flowState is one live flow with its position in the lru list
type flowState struct {
	key   FlowKey
	entry FlowEntry
	elem  *list.Element
}
