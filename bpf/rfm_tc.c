// SPDX-License-Identifier: GPL-2.0
#include "rfm_common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define NEXTHDR_HOP 0
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH 51
#define NEXTHDR_DEST 60

// rfc 8200 puts at most six extension headers before the upper layer header
#define RFM_IPV6_EXTHDRS 6

// smallest network and transport header of a segment, ipv4 and udp
#define RFM_SEG_HDR_MIN 28

// longest network header read directly, one bounded offset for the verifier
#define RFM_DIRECT_OFF_MAX 255

#define CLOCK_BOOTTIME 7

// the flush timer writes a stage at most this long after it was armed
#define RFM_STAGE_FLUSH_NS (10 * 1000 * 1000)

struct rfm_vlan_hdr {
	__u16 tci;
	__u16 encap_proto;
};

struct rfm_config rfm_cfg;

// counters of an interface without a slot, allocated on first use since most hosts have none
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct rfm_iface_key);
	__type(value, struct rfm_iface_value);
} rfm_iface_stats SEC(".maps");

// 1 + the counter slot of an ifindex, 0 for none
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RFM_SLOT_IFINDEX_MAX);
	__type(key, __u32);
	__type(value, __u32);
} rfm_iface_slot SEC(".maps");

// counters at slot * 2 * RFM_FAMILIES + dir * RFM_FAMILIES + family, the loader sizes it to the configured slots
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, RFM_SLOTS * 2 * RFM_FAMILIES);
	__type(key, __u32);
	__type(value, struct rfm_slot_value);
} rfm_iface_arr SEC(".maps");

// skip count per CPU of every draw without a slot, and the wakeup countdown of the CPU's ring for the programs without a stage, the stage programs keep theirs in rfm_cpu_stage
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rfm_slot_value);
} rfm_cpu_draw SEC(".maps");

// counter updates rfm_iface_stats refused
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_iface_errors SEC(".maps");

// gso skbs counted without the header size their counts needed
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_gso_hdr_errors SEC(".maps");

// a ring per possible CPU, indexed by CPU id, filled by Load
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, 1);
	__type(key, __u32);
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_RINGBUF);
			__uint(max_entries, 256 * 1024);
		});
} rfm_flow_rings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_flow_drops SEC(".maps");

// events per ring record of the stage programs, Load sets it from 2 to RFM_STAGE_MAX
volatile const __u32 rfm_stage_events = 16;

// the events each CPU holds for its next ring record
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rfm_stage);
} rfm_cpu_stage SEC(".maps");

// the flush timer of every possible CPU, indexed by CPU id, sized by Load
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rfm_stage_timer);
} rfm_stage_timers SEC(".maps");

// one vmlinux.h serves both byte orders, its bitfields fit only one
static __always_inline __u32 rfm_ipv4_hdr_len(struct iphdr *ip)
{
	return (__u32)(*(__u8 *)ip & 0x0f) << 2;
}

static __always_inline __u32 rfm_tcp_hdr_len(__u8 doff_byte)
{
	return (__u32)(doff_byte >> 4) << 2;
}

// rfm_l4 returns the upper layer offset from l3, 0 when the ip header is short
// a helper walk, variable packet offsets would multiply verifier states
static __always_inline __u32 rfm_l4(struct __sk_buff *skb, void *l3, void *end,
				    __u32 l3_off, __u16 eth_proto, __u8 *proto,
				    bool *later_frag)
{
	*later_frag = false;

	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return 0;
		__u32 len = rfm_ipv4_hdr_len(ip);
		if (len < sizeof(*ip))
			return 0;
		*proto = ip->protocol;
		*later_frag = (bpf_ntohs(ip->frag_off) & 0x1fff) != 0;
		return len;
	}

	struct ipv6hdr *ip6 = l3;
	if ((void *)(ip6 + 1) > end)
		return 0;

	__u32 off = sizeof(*ip6);
	__u8 next = ip6->nexthdr;
#pragma unroll
	for (int i = 0; i < RFM_IPV6_EXTHDRS; i++) {
		if (next != NEXTHDR_HOP && next != NEXTHDR_ROUTING &&
		    next != NEXTHDR_FRAGMENT && next != NEXTHDR_AUTH &&
		    next != NEXTHDR_DEST)
			break;

		struct {
			__u8 next, len;
			__u8 frag_off[2];
		} h;
		if (bpf_skb_load_bytes(skb, l3_off + off, &h, sizeof(h)))
			break;

		__u8 cur = next;
		next = h.next;
		if (cur == NEXTHDR_FRAGMENT) {
			off += 8;
			// only the first fragment carries the transport header
			if (h.frag_off[0] || (h.frag_off[1] & 0xf8)) {
				*later_frag = true;
				break;
			}
		} else if (cur == NEXTHDR_AUTH) {
			off += ((__u32)h.len + 2) << 2;
		} else {
			off += ((__u32)h.len + 1) << 3;
		}
	}

	*proto = next;
	return off;
}

// rfm_hdr_len is the header size of each segment, 0 when it does not parse
static __always_inline __u32 rfm_hdr_len(struct __sk_buff *skb, void *l3,
					 void *end, __u16 eth_proto,
					 __u32 l2_len)
{
	__u8 proto;
	bool later_frag;

	__u32 l3_len =
		rfm_l4(skb, l3, end, l2_len, eth_proto, &proto, &later_frag);
	if (!l3_len)
		return 0;

	if (proto == IPPROTO_TCP) {
		__u8 doff_byte;
		__u8 *doff = l3 + l3_len + 12;
		if (l3_len <= RFM_DIRECT_OFF_MAX && (void *)(doff + 1) <= end)
			doff_byte = *doff;
		else if (bpf_skb_load_bytes(skb, l2_len + l3_len + 12,
					    &doff_byte, 1))
			return 0;
		return l2_len + l3_len + rfm_tcp_hdr_len(doff_byte);
	}
	if (proto == IPPROTO_UDP)
		return l2_len + l3_len + sizeof(struct udphdr);

	// the kernel adds no transport header for other GSO types either
	return l2_len + l3_len;
}

// a tunnel skb's inner headers, from the offsets qdisc_pkt_len_segs_init reads
static __always_inline __u32 rfm_tunnel_hdr_len(struct __sk_buff *skb,
						struct sk_buff *k)
{
	__u32 nh = (__u32)k->inner_network_header - k->mac_header;
	__u32 th = (__u32)k->inner_transport_header - k->mac_header;
	__u8 b, proto;

	if (bpf_skb_load_bytes(skb, nh, &b, 1))
		return 0;
	__u32 proto_off =
		b >> 4 == 4 ? __builtin_offsetof(struct iphdr, protocol) :
		b >> 4 == 6 ? __builtin_offsetof(struct ipv6hdr, nexthdr) :
			      0;
	if (!proto_off || bpf_skb_load_bytes(skb, nh + proto_off, &proto, 1))
		return 0;

	if (proto == IPPROTO_TCP) {
		if (bpf_skb_load_bytes(skb, th + 12, &b, 1))
			return 0;
		return th + rfm_tcp_hdr_len(b);
	}
	if (proto == IPPROTO_UDP)
		return th + sizeof(struct udphdr);
	return th;
}

static __always_inline void
rfm_hash_count(__u32 ifindex, __u8 dir, __u8 iface_proto, __u32 segs, __u32 len)
{
	struct rfm_iface_key ikey = {
		.ifindex = ifindex,
		.dir = dir,
		.proto = iface_proto,
	};
	struct rfm_iface_value *val =
		bpf_map_lookup_elem(&rfm_iface_stats, &ikey);
	if (val) {
		val->packets += segs;
		val->bytes += len;
		return;
	}
	struct rfm_iface_value init = { .packets = segs, .bytes = len };
	if (bpf_map_update_elem(&rfm_iface_stats, &ikey, &init, BPF_ANY)) {
		__u32 err_key = 0;
		__u64 *errs = bpf_map_lookup_elem(&rfm_iface_errors, &err_key);
		if (errs)
			(*errs)++;
	}
}

// rfm_gap draws a skip uniform from 0 to 2n - 2, a gap of mean n to the sample
static __always_inline __u64 rfm_gap(__u32 n)
{
	// at rate 1 the gap is always 0, the draw is skipped
	if (n <= 1)
		return 0;
	return ((__u64)bpf_get_prandom_u32() * (2 * (__u64)n - 1)) >> 32;
}

// rfm_take redraws after a sample and when the rate gen changed
static __always_inline bool rfm_take(struct rfm_slot_value *s, __u32 rate)
{
	__u32 gen = rfm_cfg.gen;
	if (s->gen != gen) {
		s->gen = gen;
		s->skip = rfm_gap(rate);
	}
	if (s->skip) {
		s->skip--;
		return false;
	}
	s->skip = rfm_gap(rate);
	return true;
}

static __always_inline struct rfm_slot_value *
rfm_count(__u32 ifindex, __u8 dir, __u8 iface_proto, __u32 segs, __u32 len)
{
	struct rfm_slot_value *sval = NULL;
	if (ifindex < RFM_SLOT_IFINDEX_MAX) {
		__u32 *slot = bpf_map_lookup_elem(&rfm_iface_slot, &ifindex);
		if (slot && *slot && *slot <= RFM_SLOTS) {
			__u32 fam = iface_proto == 4 ? 1 :
				    iface_proto == 6 ? 2 :
						       0;
			__u32 idx = (*slot - 1) * 2 * RFM_FAMILIES +
				    dir * RFM_FAMILIES + fam;
			sval = bpf_map_lookup_elem(&rfm_iface_arr, &idx);
		}
	}
	if (sval) {
		sval->packets += segs;
		sval->bytes += len;
	} else {
		rfm_hash_count(ifindex, dir, iface_proto, segs, len);
	}
	return sval;
}

// out of line, the rare parse keeps the context off the per packet path
static __noinline __u32 rfm_seg_hdr_len(struct __sk_buff *skb, void *l3,
					void *end, __u16 eth_proto,
					__u32 l3_off)
{
	struct sk_buff *k = bpf_cast_to_kern_ctx(skb);
	return BPF_CORE_READ_BITFIELD(k, encapsulation) ?
		       rfm_tunnel_hdr_len(skb, k) :
		       rfm_hdr_len(skb, l3, end, eth_proto, l3_off);
}

static __always_inline void rfm_drop(__u32 n)
{
	__u32 drop_key = 0;
	__u64 *drops = bpf_map_lookup_elem(&rfm_flow_drops, &drop_key);
	if (drops)
		*drops += n;
}

// ring and stage memory hold older records, every byte of ev is written
static __always_inline void rfm_fill(struct rfm_flow_event *ev, __u64 tstamp,
				     struct __sk_buff *skb, void *l3,
				     __u16 eth_proto, __u8 proto, __u8 dir,
				     __u32 l2_len, __u32 segs, __be16 *ports,
				     __u32 len)
{
	ev->tstamp = tstamp;
	ev->ifindex = skb->ifindex;
	ev->proto = proto;
	ev->dir_l2 = RFM_DIR_L2(dir, l2_len);
	ev->segs = segs > 0xffff ? 0xffff : segs;
	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		// ipv4 mapped ipv6 address
		__builtin_memset(ev->src_addr, 0, 10);
		ev->src_addr[10] = 0xff;
		ev->src_addr[11] = 0xff;
		__builtin_memcpy(&ev->src_addr[12], &ip->saddr, 4);
		__builtin_memset(ev->dst_addr, 0, 10);
		ev->dst_addr[10] = 0xff;
		ev->dst_addr[11] = 0xff;
		__builtin_memcpy(&ev->dst_addr[12], &ip->daddr, 4);
	} else {
		struct ipv6hdr *ip6 = l3;
		__builtin_memcpy(ev->src_addr, &ip6->saddr, 16);
		__builtin_memcpy(ev->dst_addr, &ip6->daddr, 16);
	}
	ev->src_port = bpf_ntohs(ports[0]);
	ev->dst_port = bpf_ntohs(ports[1]);
	ev->len = len;
}

// rfm_stage_write writes the first n events of st to the ring of the CPU as one record
static __always_inline void rfm_stage_write(struct rfm_stage *st, __u32 n)
{
	// wake the reader once every wakeup_batch events the CPU writes, Load refuses 0
	__u32 wake = st->wake;
	__u64 flags = wake <= n ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
	__u32 cpu = bpf_get_smp_processor_id();
	void *ring = bpf_map_lookup_elem(&rfm_flow_rings, &cpu);
	// a record the ring refuses drops every event it carries
	if (!ring ||
	    bpf_ringbuf_output(ring, st->ev, n * sizeof(st->ev[0]), flags)) {
		rfm_drop(n);
		return;
	}
	st->wake = wake <= n ? rfm_cfg.wakeup_batch : wake - n;
}

// the timer and a program on one CPU never interleave, the timer expires in
// softirq and the programs run with bottom halves disabled
static int rfm_stage_tick(void *map, __u32 *key, struct rfm_stage_timer *t)
{
	// cpu hotplug moves a pinned timer, the stage of another CPU is not its own
	if (*key != bpf_get_smp_processor_id())
		return 0;
	__u32 stage_key = 0;
	struct rfm_stage *st = bpf_map_lookup_elem(&rfm_cpu_stage, &stage_key);
	if (!st)
		return 0;
	st->armed = 0;
	__u32 n = st->n;
	if (n && n <= RFM_STAGE_MAX) {
		rfm_stage_write(st, n);
		st->n = 0;
	}
	return 0;
}

// rfm_stage_arm starts the flush timer of the CPU on that CPU, false when the timer cannot be armed
static __always_inline bool rfm_stage_arm(struct rfm_stage *st, __u64 now)
{
	__u32 cpu = bpf_get_smp_processor_id();
	struct rfm_stage_timer *t =
		bpf_map_lookup_elem(&rfm_stage_timers, &cpu);
	if (!t)
		return false;
	// only the programs of a CPU arm its timer, the first arm sets it up
	if (!st->ready) {
		if (bpf_timer_init(&t->timer, &rfm_stage_timers,
				   CLOCK_BOOTTIME) ||
		    bpf_timer_set_callback(&t->timer, rfm_stage_tick))
			return false;
		st->ready = 1;
	}
	if (bpf_timer_start(&t->timer, RFM_STAGE_FLUSH_NS, BPF_F_TIMER_CPU_PIN))
		return false;
	st->armed = now;
	return true;
}

// TC_ACT_OK would end the tcx chain, every exit returns TCX_NEXT
// sampled_only and staged are constant per entry point, clang specializes each
static __always_inline int rfm_tc(struct __sk_buff *skb, __u8 dir,
				  bool sampled_only, bool staged)
{
	struct rfm_slot_value *sval = NULL;
	if (sampled_only) {
		__u32 key = 0;
		sval = bpf_map_lookup_elem(&rfm_cpu_draw, &key);
		if (!sval || !rfm_take(sval, rfm_cfg.sample_rate))
			return TCX_NEXT;
	}

	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;

	// a frame shorter than its l2 header counts as family other
	__u16 eth_proto = 0;
	__u8 iface_proto = 0;
	void *l3 = data + sizeof(struct ethhdr);
	if (l3 <= end) {
		struct ethhdr *eth = data;
		eth_proto = bpf_ntohs(eth->h_proto);
	}

#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (eth_proto != ETH_P_8021Q && eth_proto != ETH_P_8021AD)
			break;

		if (l3 + sizeof(struct rfm_vlan_hdr) > end) {
			eth_proto = 0;
			break;
		}

		struct rfm_vlan_hdr *vlan = l3;
		eth_proto = bpf_ntohs(vlan->encap_proto);
		l3 += sizeof(*vlan);
	}

	// l3_off counts ethernet and the VLAN tags in the frame
	__u32 l3_off = (__u32)(l3 - data);

	switch (eth_proto) {
	case ETH_P_IP:
		iface_proto = 4;
		break;
	case ETH_P_IPV6:
		iface_proto = 6;
		break;
	}

	// a gro or gso skb stands for gso_segs wire packets
	__u32 len = skb->len;
	__u32 segs = 1;
	if (skb->gso_size && iface_proto) {
		segs = skb->gso_segs;
		// ingress wire_len from 6.19 lacks only the ethernet headers
		bool ingress_wire =
			dir == RFM_DIR_INGRESS && segs > 1 &&
			skb->wire_len >= len - sizeof(struct ethhdr) +
						 (segs - 1) * RFM_SEG_HDR_MIN;
		__u32 hdr_len = 0;
		if ((dir == RFM_DIR_INGRESS && segs > 1 && !ingress_wire) ||
		    segs == 0) {
			hdr_len = rfm_seg_hdr_len(skb, l3, end, eth_proto,
						  l3_off);
			if (!hdr_len) {
				__u32 err_key = 0;
				__u64 *errs = bpf_map_lookup_elem(
					&rfm_gso_hdr_errors, &err_key);
				if (errs)
					(*errs)++;
			}
		}
		// SKB_GSO_DODGY leaves gso_segs 0, derive it like the kernel
		if (segs == 0 && hdr_len && len > hdr_len)
			segs = (len - hdr_len + skb->gso_size - 1) /
			       skb->gso_size;
		if (segs == 0)
			segs = 1;
		// egress wire_len holds the headers of every segment
		if (dir == RFM_DIR_EGRESS)
			len = skb->wire_len;
		else if (ingress_wire)
			len = skb->wire_len + segs * sizeof(struct ethhdr);
		else
			len += (segs - 1) * hdr_len;
	}

	// a tag held in the skb adds 4 wire bytes per segment
	__u32 l2_len = l3_off;
	if (skb->vlan_present) {
		l2_len += sizeof(struct rfm_vlan_hdr);
		len += segs * sizeof(struct rfm_vlan_hdr);
	}

	if (!sampled_only)
		sval = rfm_count(skb->ifindex, dir, iface_proto, segs, len);

	if (iface_proto == 0)
		return TCX_NEXT;

	if (!sampled_only) {
		if (!sval) {
			__u32 key = 0;
			sval = bpf_map_lookup_elem(&rfm_cpu_draw, &key);
			if (!sval)
				return TCX_NEXT;
		}
		if (!rfm_take(sval, rfm_cfg.sample_rate))
			return TCX_NEXT;
	}

	// nothing after the reservation can fail
	__u8 proto;
	bool later_frag;
	__u32 l4_off =
		rfm_l4(skb, l3, end, l3_off, eth_proto, &proto, &later_frag);
	if (!l4_off)
		return TCX_NEXT;

	__be16 ports[2] = {};
	if (!later_frag && (proto == IPPROTO_TCP || proto == IPPROTO_UDP)) {
		void *th = l3 + l4_off;
		if (l4_off <= RFM_DIRECT_OFF_MAX && th + sizeof(ports) <= end)
			__builtin_memcpy(ports, th, sizeof(ports));
		else if (bpf_skb_load_bytes(skb, l3_off + l4_off, ports,
					    sizeof(ports)))
			return TCX_NEXT;
	}

	if (staged) {
		__u32 stage_key = 0;
		struct rfm_stage *st =
			bpf_map_lookup_elem(&rfm_cpu_stage, &stage_key);
		if (!st) {
			rfm_drop(1);
			return TCX_NEXT;
		}
		__u64 now = bpf_ktime_get_boot_ns();
		// n stays below rfm_stage_events between runs, the bound is for the verifier
		__u32 n = st->n < RFM_STAGE_MAX ? st->n : 0;
		// a timer due an interval ago is late or ran on another CPU, its stage goes now
		bool pending = true;
		if (!st->armed || now - st->armed >= RFM_STAGE_FLUSH_NS) {
			if (n)
				rfm_stage_write(st, n);
			n = 0;
			pending = rfm_stage_arm(st, now);
		}
		rfm_fill(&st->ev[n], now, skb, l3, eth_proto, proto, dir,
			 l2_len, segs, ports, len);
		// no event waits in a stage without a pending flush
		if (++n >= rfm_stage_events || !pending) {
			rfm_stage_write(st, n);
			n = 0;
		}
		st->n = n;
		return TCX_NEXT;
	}

	__u32 cpu = bpf_get_smp_processor_id();
	void *ring = bpf_map_lookup_elem(&rfm_flow_rings, &cpu);
	struct rfm_flow_event *ev =
		ring ? bpf_ringbuf_reserve(ring, sizeof(*ev), 0) : NULL;
	if (!ev) {
		rfm_drop(1);
		return TCX_NEXT;
	}

	rfm_fill(ev, bpf_ktime_get_boot_ns(), skb, l3, eth_proto, proto, dir,
		 l2_len, segs, ports, len);

	// wake the reader once every wakeup_batch events the CPU writes, Load refuses 0, one countdown per ring, since countdowns per slot that run in step fill it before one comes due
	__u32 draw_key = 0;
	struct rfm_slot_value *draw =
		bpf_map_lookup_elem(&rfm_cpu_draw, &draw_key);
	__u64 flags = BPF_RB_FORCE_WAKEUP;
	if (draw && draw->wake > 1) {
		draw->wake--;
		flags = BPF_RB_NO_WAKEUP;
	} else if (draw) {
		draw->wake = rfm_cfg.wakeup_batch;
	}
	bpf_ringbuf_submit(ev, flags);

	return TCX_NEXT;
}

SEC("tc/ingress")
int rfm_tc_ingress(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_INGRESS, false, false);
}

SEC("tc/egress")
int rfm_tc_egress(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_EGRESS, false, false);
}

// the sampled only programs, Load loads them in place of the two above
SEC("tc/ingress")
int rfm_tc_ingress_sampled(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_INGRESS, true, false);
}

SEC("tc/egress")
int rfm_tc_egress_sampled(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_EGRESS, true, false);
}

// the stage programs of both modes, Load loads a pair of them for more than one event a record
SEC("tc/ingress")
int rfm_tc_ingress_staged(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_INGRESS, false, true);
}

SEC("tc/egress")
int rfm_tc_egress_staged(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_EGRESS, false, true);
}

SEC("tc/ingress")
int rfm_tc_ingress_sampled_staged(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_INGRESS, true, true);
}

SEC("tc/egress")
int rfm_tc_egress_sampled_staged(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_EGRESS, true, true);
}

static int rfm_probe_tick(void *map, __u32 *key, struct rfm_stage_timer *t)
{
	return 0;
}

// Load runs this alone before the stage programs, bpf_timer_start answers EINVAL to BPF_F_TIMER_CPU_PIN before Linux 6.7
SEC("tc")
int rfm_stage_probe(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct rfm_stage_timer *t =
		bpf_map_lookup_elem(&rfm_stage_timers, &key);
	if (!t)
		return 1;
	long err = bpf_timer_init(&t->timer, &rfm_stage_timers, CLOCK_BOOTTIME);
	if (!err)
		err = bpf_timer_set_callback(&t->timer, rfm_probe_tick);
	if (!err)
		err = bpf_timer_start(&t->timer, RFM_STAGE_FLUSH_NS,
				      BPF_F_TIMER_CPU_PIN);
	bpf_timer_cancel(&t->timer);
	return err;
}

char LICENSE[] SEC("license") = "GPL";
