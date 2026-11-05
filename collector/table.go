package collector

import (
	"iter"
	"sync/atomic"
)

// flowRef names a slot of the flow table, 0 names none
type flowRef uint32

// flowLinks are the neighbors of a flow in one list of the table
type flowLinks struct {
	prev, next flowRef
}

// flowList is the oldest and the newest flow of one list of the table
type flowList struct {
	head, tail flowRef
}

// the lists of the flow table, a flow's links hold its place in each
const (
	// lruList orders the flows by their last event to within the lru slack, oldest first, it links the free slots too
	lruList = iota
	// activeList orders the flows by the start of their unexported interval, oldest first
	activeList
)

// tableChunkBits sets the slots of a chunk, 1024 slots of 256 bytes for flows and of 128 for tuples
const tableChunkBits = 10

const tableChunk = 1 << tableChunkBits

// flowTable holds the flows in chunks that never move and names each by its slot, so a flow costs no allocation once the table has grown and its index holds no pointers
type flowTable struct {
	// index finds a flow's slot from the table hash of its id
	index flowIndex
	// keys holds the key of a flow whose event named an address in a form its id does not keep, 4 byte, zoned or invalid, events from the rings never do
	keys   map[flowRef]FlowKey
	chunks []*[tableChunk]flowState
	lists  [2]flowList
	// free heads the slots of removed flows, linked through their lru links
	free flowRef
	// next is the first slot never handed out, slot 0 stays unused so that 0 names none
	next flowRef
}

// warmFrom is how many flows the table holds before a batch warms its lookups, the slots of a smaller table stay in the last level cache and a full default table of 65536 churns, where a warm pass finds nothing to warm
const warmFrom = 1 << 18

// warmed keeps the loads of warm from being optimized away, an atomic store keeps the tables of concurrent tests from racing on it
var warmed atomic.Uint32

// warmGroup is how many events one warm pass covers, few enough that the loads of a pass fit in the window the core runs ahead in
const warmGroup = 8

// warm loads the home cells of the hashes of batch, then the first line of the slot that each one's first cell of a matching tag names, so the lookups that follow wait on neither, the loads of a pass overlap where lookups one at a time wait on each in turn
func (t *flowTable) warm(batch []sample) {
	x := &t.index
	if x.n == 0 {
		return
	}
	var sink uint32
	// the cells first, without a branch on what they hold, so every load of the pass is out at once
	for i := range batch {
		sink += uint32(x.cells[x.home(indexTag(batch[i].hash))].ref)
	}
	mask := len(x.cells) - 1
	for i := range batch {
		tag := indexTag(batch[i].hash)
		for j, n := x.home(tag), 0; n < 4; j, n = (j+1)&mask, n+1 {
			c := x.cells[j]
			if c.ref == 0 {
				break
			}
			if c.tag == tag {
				sink += uint32(t.at(c.ref).id.proto)
				break
			}
		}
	}
	warmed.Store(sink)
}

func newFlowTable() flowTable {
	return flowTable{keys: make(map[flowRef]FlowKey), next: 1}
}

// at returns the flow in slot r
func (t *flowTable) at(r flowRef) *flowState {
	return &t.chunks[r>>tableChunkBits][r&(tableChunk-1)]
}

// len returns the number of flows
func (t *flowTable) len() int {
	return t.index.n
}

// get returns the slot of the flow under id, whose hash is h, the id it compares sits on the lines a hit goes on to update
func (t *flowTable) get(h uint64, id *flowID) (flowRef, bool) {
	x := &t.index
	if x.n == 0 {
		return 0, false
	}
	tag, mask := indexTag(h), len(x.cells)-1
	// a cell of another tag costs no read of its slot, flows whose hashes collide probe on by id
	for i := x.home(tag); ; i = (i + 1) & mask {
		c := x.cells[i]
		if c.ref == 0 {
			return 0, false
		}
		if c.tag == tag && t.at(c.ref).id.equal(id) {
			return c.ref, true
		}
	}
}

// add stores s, which carries its id and its hash, as the newest flow of both lists and returns its slot
func (t *flowTable) add(s *flowState) flowRef {
	r := t.free
	if r != 0 {
		t.free = t.at(r).links[lruList].next
	} else {
		if int(t.next>>tableChunkBits) == len(t.chunks) {
			t.chunks = append(t.chunks, new([tableChunk]flowState))
		}
		r = t.next
		t.next++
	}
	*t.at(r) = *s
	t.index.put(indexTag(s.hash), r)
	t.pushBack(lruList, r)
	t.pushBack(activeList, r)
	return r
}

// keepKey makes key the one a listing shows for the flow in slot r, it names the flow's id in a form the id does not keep
func (t *flowTable) keepKey(r flowRef, key FlowKey) {
	t.keys[r] = key
}

// key returns the key of the flow in slot r as its event named it
func (t *flowTable) key(r flowRef) FlowKey {
	if len(t.keys) != 0 {
		if k, ok := t.keys[r]; ok {
			return k
		}
	}
	return t.at(r).id.key()
}

// remove takes the flow in slot r out of the table and clears the slot, so it keeps nothing of the flow alive
func (t *flowTable) remove(r flowRef) {
	s := t.at(r)
	t.unlink(lruList, r)
	t.unlink(activeList, r)
	t.index.del(indexTag(s.hash), r)
	if len(t.keys) != 0 {
		delete(t.keys, r)
	}
	*s = flowState{}
	s.links[lruList].next = t.free
	t.free = r
}

// front returns the oldest flow of list l, 0 when the list is empty
func (t *flowTable) front(l int) flowRef {
	return t.lists[l].head
}

// moveToBack makes the flow in slot r the newest of list l
func (t *flowTable) moveToBack(l int, r flowRef) {
	if t.lists[l].tail == r {
		return
	}
	t.unlink(l, r)
	t.pushBack(l, r)
}

func (t *flowTable) pushBack(l int, r flowRef) {
	tail := t.lists[l].tail
	t.at(r).links[l] = flowLinks{prev: tail}
	if tail == 0 {
		t.lists[l].head = r
	} else {
		t.at(tail).links[l].next = r
	}
	t.lists[l].tail = r
}

func (t *flowTable) unlink(l int, r flowRef) {
	ln := t.at(r).links[l]
	if ln.prev == 0 {
		t.lists[l].head = ln.next
	} else {
		t.at(ln.prev).links[l].next = ln.next
	}
	if ln.next == 0 {
		t.lists[l].tail = ln.prev
	} else {
		t.at(ln.next).links[l].prev = ln.prev
	}
}

// all yields every flow with its slot, in no fixed order, a flow removed while it runs may move another past it
func (t *flowTable) all() iter.Seq2[flowRef, *flowState] {
	return func(yield func(flowRef, *flowState) bool) {
		for _, c := range t.index.cells {
			if c.ref != 0 && !yield(c.ref, t.at(c.ref)) {
				return
			}
		}
	}
}

// indexCell names the flow in slot ref under the tag of its table hash, ref 0 marks the cell empty
type indexCell struct {
	tag uint32
	ref flowRef
}

// flowIndex finds a flow's slot by linear probing from the cell the top bits of its tag name
type flowIndex struct {
	cells []indexCell
	// bits is the log2 of the cells
	bits uint8
	n    int
}

// minIndexBits sizes the index of a table that held no flow yet, 64 cells of 8 bytes
const minIndexBits = 6

// indexTag returns the tag of table hash h, the top half of a bijective mix of all its bits, since the table hash of sequential IPv4 sources can cluster in its own top bits and linear probing slows on clustered homes
func indexTag(h uint64) uint32 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return uint32(h >> 32)
}

// home returns the first cell a lookup of tag probes
func (x *flowIndex) home(tag uint32) int {
	return int(tag >> (32 - x.bits))
}

// put names slot r under tag, growing the cells to keep them at most three quarters full
func (x *flowIndex) put(tag uint32, r flowRef) {
	if (x.n+1)*4 > len(x.cells)*3 {
		x.grow()
	}
	mask := len(x.cells) - 1
	i := x.home(tag)
	for x.cells[i].ref != 0 {
		i = (i + 1) & mask
	}
	x.cells[i] = indexCell{tag: tag, ref: r}
	x.n++
}

// grow doubles the cells and names every slot again
func (x *flowIndex) grow() {
	old := x.cells
	x.bits = max(x.bits+1, minIndexBits)
	x.cells = make([]indexCell, 1<<x.bits)
	x.n = 0
	for _, c := range old {
		if c.ref != 0 {
			x.put(c.tag, c.ref)
		}
	}
}

// del takes slot r, named under tag, out of the index and moves back the cells after it that probed past its cell, so no lookup stops short of them
func (x *flowIndex) del(tag uint32, r flowRef) {
	if x.n == 0 || r == 0 {
		return
	}
	mask := len(x.cells) - 1
	i := x.home(tag)
	for x.cells[i].ref != r {
		// an empty cell ends the probe of a slot the index does not name
		if x.cells[i].ref == 0 {
			return
		}
		i = (i + 1) & mask
	}
	for j := (i + 1) & mask; x.cells[j].ref != 0; j = (j + 1) & mask {
		// the cell at j stays where it is when its home lies cyclically after i and up to j
		if k := x.home(x.cells[j].tag); (i < j && i < k && k <= j) || (i > j && (k <= j || i < k)) {
			continue
		}
		x.cells[i] = x.cells[j]
		i = j
	}
	x.cells[i] = indexCell{}
	x.n--
}

// rollupRef names a slot of the rollup table, 0 names none
type rollupRef uint32

// rollupLinks are the neighbors of a tuple in the idle list of the rollup table
type rollupLinks struct {
	prev, next rollupRef
}

// rollupTable holds the label tuples in chunks that never move and names each by its slot, so a new tuple costs no allocation once the table has grown and a tuple going idle costs none
type rollupTable struct {
	index map[RollupKey]rollupRef
	// recent holds the slots of recent tuples by a hash of their numbers, a hit skips the map's hash of the city strings
	recent [recentTuples]recentTuple
	chunks []*[tableChunk]rollupState
	// idle lists every tuple without live flows by when it lost its last one, oldest first, a new tuple waits there for its first flow
	idle struct{ head, tail rollupRef }
	// free heads the slots of dropped tuples, linked through their next links
	free rollupRef
	// next is the first slot never handed out, slot 0 stays unused so that 0 names none
	next rollupRef
	// ids counts the tuples ever made, the newest has the count as its id
	ids uint64
}

func newRollupTable() rollupTable {
	return rollupTable{index: make(map[RollupKey]rollupRef), next: 1}
}

// at returns the tuple in slot r
func (t *rollupTable) at(r rollupRef) *rollupState {
	return &t.chunks[r>>tableChunkBits][r&(tableChunk-1)]
}

// len returns the number of tuples
func (t *rollupTable) len() int {
	return len(t.index)
}

// recentBits sizes the cache of recent tuples, which holds recentTuples slots
const (
	recentBits   = 6
	recentTuples = 1 << recentBits
)

// recentTuple is one slot of the cache of recent tuples, the tag tells most other tuples apart before their slot is read
type recentTuple struct {
	tag uint32
	ref rollupRef
}

// recentSlot returns where the cache of recent tuples keeps k and the tag it keeps k under, tuples that differ only in their cities share both
func recentSlot(k *RollupKey) (uint, uint32) {
	x := uint64(k.Ifindex)<<16 | uint64(k.Dir)<<8 | uint64(k.Proto)
	x ^= (uint64(k.Src.ASN)<<32 | uint64(k.Dst.ASN)) * 0x9e3779b97f4a7c15
	x *= 0xff51afd7ed558ccd
	return uint(x >> (64 - recentBits)), uint32(x >> (32 - recentBits))
}

// get returns the slot of the tuple under k and writes the cache of recent tuples, its caller holds mu for writing
func (t *rollupTable) get(k RollupKey) (rollupRef, bool) {
	i, tag := recentSlot(&k)
	// a dropped slot reads id 0, and a slot taken again holds its new tuple's key
	if c := t.recent[i]; c.ref != 0 && c.tag == tag {
		if s := t.at(c.ref); s.id != 0 && s.key == k {
			return c.ref, true
		}
	}
	r, ok := t.index[k]
	if ok {
		t.recent[i] = recentTuple{tag, r}
	}
	return r, ok
}

// add stores a new tuple under k as the newest idle tuple and returns its slot
func (t *rollupTable) add(k RollupKey) rollupRef {
	r := t.free
	if r != 0 {
		t.free = t.at(r).links.next
	} else {
		if int(t.next>>tableChunkBits) == len(t.chunks) {
			t.chunks = append(t.chunks, new([tableChunk]rollupState))
		}
		r = t.next
		t.next++
	}
	t.ids++
	*t.at(r) = rollupState{key: k, id: t.ids}
	t.index[k] = r
	i, tag := recentSlot(&k)
	t.recent[i] = recentTuple{tag, r}
	t.pushBack(r)
	return r
}

// drop takes the idle tuple in slot r out of the table and clears the slot, so it keeps nothing of the tuple alive
func (t *rollupTable) drop(r rollupRef) {
	s := t.at(r)
	t.unlink(r)
	delete(t.index, s.key)
	*s = rollupState{}
	s.links.next = t.free
	t.free = r
}

// front returns the tuple idle the longest, 0 when none is idle
func (t *rollupTable) front() rollupRef {
	return t.idle.head
}

// pushBack makes the tuple in slot r the newest idle tuple
func (t *rollupTable) pushBack(r rollupRef) {
	tail := t.idle.tail
	t.at(r).links = rollupLinks{prev: tail}
	if tail == 0 {
		t.idle.head = r
	} else {
		t.at(tail).links.next = r
	}
	t.idle.tail = r
}

// unlink takes the tuple in slot r out of the idle list
func (t *rollupTable) unlink(r rollupRef) {
	ln := t.at(r).links
	if ln.prev == 0 {
		t.idle.head = ln.next
	} else {
		t.at(ln.prev).links.next = ln.next
	}
	if ln.next == 0 {
		t.idle.tail = ln.prev
	} else {
		t.at(ln.next).links.prev = ln.prev
	}
}

// all yields every tuple, in no fixed order
func (t *rollupTable) all() iter.Seq[*rollupState] {
	return func(yield func(*rollupState) bool) {
		for _, r := range t.index {
			if !yield(t.at(r)) {
				return
			}
		}
	}
}
