// SPDX-License-Identifier: GPL-2.0
// bench only: ablation variants of bpf/rfm_tc.c timed with BPF_PROG_TEST_RUN by
// progbench, never loaded by the agent
// each knob is a compile time macro so every variant is its own object and the
// verifier sees only the code that variant runs
//
// RFM_EMPTY    1 returns TCX_NEXT at once, the floor of a program run
// RFM_SAMPLED  0 exact profile, counter on every packet then the draw
//              1 sampled profile, the draw first and no counter
// RFM_CTR      0 PERCPU_HASH counter keyed (ifindex, dir, family), as the agent
//                before 8c7130d
//              1 PERCPU_ARRAY counter at a slot read from an ifindex indexed
//                ARRAY, the hash as fallback for unknown interfaces
//              2 no counter
// RFM_DRAW     0 prandom % N, as the agent before 8c7130d
//              1 prandom < threshold, threshold written by userspace
//              2 per-CPU skip count, the gap drawn uniformly in [0, 2N-2] at
//                each sample, kept in the counter slot under RFM_CTR 1
// RFM_WAKE     0 wakeup every wakeup_batch submits through a per-CPU counter,
//                as the agent before 8c7130d
//              1 always BPF_RB_NO_WAKEUP
// RFM_LAZY     1 egress parses the GSO header only when gso_segs is 0
// RFM_XDP      1 ingress runs as an XDP program instead of TCX ingress, the
//                exact profile with the array counter, egress stays on TCX
#include "rfm_common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef RFM_EMPTY
#define RFM_EMPTY 0
#endif
#ifndef RFM_SAMPLED
#define RFM_SAMPLED 0
#endif
#ifndef RFM_CTR
#define RFM_CTR 0
#endif
#ifndef RFM_DRAW
#define RFM_DRAW 0
#endif
#ifndef RFM_WAKE
#define RFM_WAKE 0
#endif
#ifndef RFM_LAZY
#define RFM_LAZY 0
#endif
#ifndef RFM_XDP
#define RFM_XDP 0
#endif

#if RFM_XDP && RFM_CTR != 1
#error "the XDP variant uses the array counter"
#endif

#if RFM_DRAW == 2 && !RFM_SAMPLED && RFM_CTR != 1
#error "the exact profile keeps the skip count in the array counter slot"
#endif

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

#define RFM_IPV6_EXTHDRS 6

struct rfm_vlan_hdr {
	__u16 tci;
	__u16 encap_proto;
};

struct rfm_bconfig {
	__u32 sample_rate;
	__u32 flags;
	__u32 wakeup_batch;
	__u32 threshold;
};

struct rfm_cnt {
	__u64 packets, bytes, skip;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rfm_bconfig);
} rfm_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rfm_iface_key);
	__type(value, struct rfm_iface_value);
} rfm_iface_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_iface_errors SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_gso_hdr_errors SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rfm_flow_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_flow_drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_submit_count SEC(".maps");

#if RFM_CTR == 1
// value is slot + 1, 0 means the interface has no slot
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RFM_SLOT_IFINDEX_MAX);
	__type(key, __u32);
	__type(value, __u32);
} rfm_iface_slot SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, RFM_SLOTS * 6);
	__type(key, __u32);
	__type(value, struct rfm_cnt);
} rfm_iface_arr SEC(".maps");
#endif

#if RFM_SAMPLED && RFM_DRAW == 2
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rfm_skip SEC(".maps");
#endif

static __always_inline __u32 rfm_ipv4_hdr_len(struct iphdr *ip)
{
	return (__u32)(*(__u8 *)ip & 0x0f) << 2;
}

static __always_inline __u32 rfm_tcp_hdr_len(__u8 off_byte)
{
	return (__u32)(off_byte >> 4) << 2;
}

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

		__u8 h[4];
		if (bpf_skb_load_bytes(skb, l3_off + off, h, sizeof(h)))
			break;

		__u8 cur = next;
		next = h[0];
		if (cur == NEXTHDR_FRAGMENT) {
			off += 8;
			if (h[2] || (h[3] & 0xf8)) {
				*later_frag = true;
				break;
			}
		} else if (cur == NEXTHDR_AUTH) {
			off += ((__u32)h[1] + 2) << 2;
		} else {
			off += ((__u32)h[1] + 1) << 3;
		}
	}

	*proto = next;
	return off;
}

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
		__u8 off_byte;
		if (bpf_skb_load_bytes(skb, l2_len + l3_len + 12, &off_byte, 1))
			return 0;
		return l2_len + l3_len + rfm_tcp_hdr_len(off_byte);
	}
	if (proto == IPPROTO_UDP)
		return l2_len + l3_len + sizeof(struct udphdr);

	return l2_len + l3_len;
}

static __always_inline void rfm_count_err(void *map)
{
	__u32 key = 0;
	__u64 *errs = bpf_map_lookup_elem(map, &key);
	if (errs)
		(*errs)++;
}

// the uniform gap in [0, 2N-2] has mean N-1, so one packet in N is sampled on
// average, and the multiply keeps the divide off the path
static __always_inline __u64 rfm_gap(__u32 n)
{
	if (n <= 1)
		return 0;
	return ((__u64)bpf_get_prandom_u32() * (2 * (__u64)n - 1)) >> 32;
}

static __always_inline __attribute__((unused)) void
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
	} else {
		struct rfm_iface_value init = { .packets = segs, .bytes = len };
		if (bpf_map_update_elem(&rfm_iface_stats, &ikey, &init,
					BPF_ANY))
			rfm_count_err(&rfm_iface_errors);
	}
}

static __always_inline int rfm_emit(struct __sk_buff *skb, __u8 dir, void *l3,
				    void *end, __u16 eth_proto, __u32 l3_off,
				    __u32 segs, __u32 len, __u32 l2_len,
				    struct rfm_bconfig *cfg)
{
	struct rfm_flow_event ev = {
		.tstamp = bpf_ktime_get_boot_ns(),
		.ifindex = skb->ifindex,
		.dir = dir,
		.segs = segs > 0xffff ? 0xffff : segs,
		.len = len,
		.l2_len = l2_len,
	};

	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return TCX_NEXT;
		ev.src_addr[10] = 0xff;
		ev.src_addr[11] = 0xff;
		__builtin_memcpy(&ev.src_addr[12], &ip->saddr, 4);
		ev.dst_addr[10] = 0xff;
		ev.dst_addr[11] = 0xff;
		__builtin_memcpy(&ev.dst_addr[12], &ip->daddr, 4);
	} else {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > end)
			return TCX_NEXT;
		__builtin_memcpy(ev.src_addr, &ip6->saddr, 16);
		__builtin_memcpy(ev.dst_addr, &ip6->daddr, 16);
	}

	bool later_frag;
	__u32 l4_off =
		rfm_l4(skb, l3, end, l3_off, eth_proto, &ev.proto, &later_frag);
	if (!l4_off)
		return TCX_NEXT;

	if (!later_frag &&
	    (ev.proto == IPPROTO_TCP || ev.proto == IPPROTO_UDP)) {
		__be16 ports[2];
		if (bpf_skb_load_bytes(skb, l3_off + l4_off, ports,
				       sizeof(ports)))
			return TCX_NEXT;
		ev.src_port = bpf_ntohs(ports[0]);
		ev.dst_port = bpf_ntohs(ports[1]);
	}

	struct rfm_flow_event *ring_ev =
		bpf_ringbuf_reserve(&rfm_flow_events, sizeof(*ring_ev), 0);
	if (!ring_ev) {
		rfm_count_err(&rfm_flow_drops);
		return TCX_NEXT;
	}

	__builtin_memcpy(ring_ev, &ev, sizeof(ev));

	__u64 flags = BPF_RB_NO_WAKEUP;
#if RFM_WAKE == 0
	__u32 cnt_key = 0;
	__u64 *cnt = bpf_map_lookup_elem(&rfm_submit_count, &cnt_key);
	if (cfg && cnt && (++(*cnt) % cfg->wakeup_batch == 0))
		flags = BPF_RB_FORCE_WAKEUP;
#endif
	bpf_ringbuf_submit(ring_ev, flags);

	return TCX_NEXT;
}

static __always_inline int rfm_tc(struct __sk_buff *skb, __u8 dir)
{
#if RFM_EMPTY
	return TCX_NEXT;
#else
	__u32 cfg_key = 0;
	struct rfm_bconfig *cfg = NULL;

#if RFM_SAMPLED
	// the draw comes first, an unsampled packet costs only the draw
#if RFM_DRAW == 2
	__u32 skip_key = 0;
	__u64 *skip = bpf_map_lookup_elem(&rfm_skip, &skip_key);
	if (!skip)
		return TCX_NEXT;
	if (*skip) {
		(*skip)--;
		return TCX_NEXT;
	}
	cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
	if (!cfg || cfg->sample_rate == 0)
		return TCX_NEXT;
	*skip = rfm_gap(cfg->sample_rate);
#else
	cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
	if (!cfg || cfg->sample_rate == 0)
		return TCX_NEXT;
#if RFM_DRAW == 1
	if (bpf_get_prandom_u32() >= cfg->threshold)
		return TCX_NEXT;
#else
	if (bpf_get_prandom_u32() % cfg->sample_rate != 0)
		return TCX_NEXT;
#endif
#endif
#endif

	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;

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

	__u32 l3_off = (__u32)(l3 - data);

	switch (eth_proto) {
	case ETH_P_IP:
		iface_proto = 4;
		break;
	case ETH_P_IPV6:
		iface_proto = 6;
		break;
	}

#if RFM_SAMPLED
	if (iface_proto == 0)
		return TCX_NEXT;
#endif

	__u32 len = skb->len;
	__u32 segs = 1;
	if (skb->gso_size && iface_proto) {
		segs = skb->gso_segs;
		__u32 hdr_len = 0;
#if RFM_LAZY
		if (dir == RFM_DIR_INGRESS || segs == 0) {
#else
		{
#endif
			hdr_len = rfm_hdr_len(skb, l3, end, eth_proto, l3_off);
			if (!hdr_len)
				rfm_count_err(&rfm_gso_hdr_errors);
		}
		if (segs == 0 && hdr_len && len > hdr_len)
			segs = (len - hdr_len + skb->gso_size - 1) /
			       skb->gso_size;
		if (segs == 0)
			segs = 1;
		if (dir == RFM_DIR_EGRESS)
			len = skb->wire_len;
		else
			len += (segs - 1) * hdr_len;
	}

	__u32 l2_len = l3_off;
	if (skb->vlan_present) {
		l2_len += sizeof(struct rfm_vlan_hdr);
		len += segs * sizeof(struct rfm_vlan_hdr);
	}

#if !RFM_SAMPLED
#if RFM_CTR == 1
	struct rfm_cnt *slotcnt = NULL;
	__u32 ifx = skb->ifindex;
	__u32 *slot = NULL;
	if (ifx < RFM_SLOT_IFINDEX_MAX)
		slot = bpf_map_lookup_elem(&rfm_iface_slot, &ifx);
	if (slot && *slot && *slot <= RFM_SLOTS) {
		__u32 fam = iface_proto == 4 ? 1 : iface_proto == 6 ? 2 : 0;
		__u32 idx = (*slot - 1) * 6 + (__u32)dir * 3 + fam;
		slotcnt = bpf_map_lookup_elem(&rfm_iface_arr, &idx);
	}
	if (slotcnt) {
		slotcnt->packets += segs;
		slotcnt->bytes += len;
	} else {
		rfm_hash_count(skb->ifindex, dir, iface_proto, segs, len);
	}
#elif RFM_CTR == 0
	rfm_hash_count(skb->ifindex, dir, iface_proto, segs, len);
#endif

	if (iface_proto == 0)
		return TCX_NEXT;

#if RFM_DRAW == 2
	if (slotcnt) {
		if (slotcnt->skip) {
			slotcnt->skip--;
			return TCX_NEXT;
		}
		cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
		if (!cfg || cfg->sample_rate == 0)
			return TCX_NEXT;
		slotcnt->skip = rfm_gap(cfg->sample_rate);
	} else {
		cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
		if (!cfg || cfg->sample_rate == 0)
			return TCX_NEXT;
		if (bpf_get_prandom_u32() % cfg->sample_rate != 0)
			return TCX_NEXT;
	}
#else
	cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
	if (!cfg || cfg->sample_rate == 0)
		return TCX_NEXT;
#if RFM_DRAW == 1
	if (bpf_get_prandom_u32() >= cfg->threshold)
		return TCX_NEXT;
#else
	if (bpf_get_prandom_u32() % cfg->sample_rate != 0)
		return TCX_NEXT;
#endif
#endif
#endif

	return rfm_emit(skb, dir, l3, end, eth_proto, l3_off, segs, len, l2_len,
			cfg);
#endif
}

#if !RFM_XDP
SEC("tc/ingress")
int rfm_tc_ingress(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_INGRESS);
}

#endif

SEC("tc/egress")
int rfm_tc_egress(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_EGRESS);
}

#if RFM_XDP
// XDP sees each frame before GRO and before an skb exists, so a packet is one
// wire frame and its length is the whole buffer, fragments included
static __always_inline int rfm_emit_xdp(struct xdp_md *ctx, void *l3, void *end,
					__u16 eth_proto, __u32 l3_off,
					__u32 len, struct rfm_bconfig *cfg)
{
	struct rfm_flow_event ev = {
		.tstamp = bpf_ktime_get_boot_ns(),
		.ifindex = ctx->ingress_ifindex,
		.dir = RFM_DIR_INGRESS,
		.segs = 1,
		.len = len,
		.l2_len = l3_off,
	};
	__u32 l4_off;

	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return XDP_PASS;
		ev.src_addr[10] = 0xff;
		ev.src_addr[11] = 0xff;
		__builtin_memcpy(&ev.src_addr[12], &ip->saddr, 4);
		ev.dst_addr[10] = 0xff;
		ev.dst_addr[11] = 0xff;
		__builtin_memcpy(&ev.dst_addr[12], &ip->daddr, 4);
		ev.proto = ip->protocol;
		l4_off = rfm_ipv4_hdr_len(ip);
		if ((bpf_ntohs(ip->frag_off) & 0x1fff) != 0)
			l4_off = 0;
	} else {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > end)
			return XDP_PASS;
		__builtin_memcpy(ev.src_addr, &ip6->saddr, 16);
		__builtin_memcpy(ev.dst_addr, &ip6->daddr, 16);
		// bench only, no extension header walk
		ev.proto = ip6->nexthdr;
		l4_off = sizeof(*ip6);
	}

	if (l4_off && (ev.proto == IPPROTO_TCP || ev.proto == IPPROTO_UDP)) {
		__be16 ports[2];
		if (bpf_xdp_load_bytes(ctx, l3_off + l4_off, ports,
				       sizeof(ports)) == 0) {
			ev.src_port = bpf_ntohs(ports[0]);
			ev.dst_port = bpf_ntohs(ports[1]);
		}
	}

	struct rfm_flow_event *ring_ev =
		bpf_ringbuf_reserve(&rfm_flow_events, sizeof(*ring_ev), 0);
	if (!ring_ev) {
		rfm_count_err(&rfm_flow_drops);
		return XDP_PASS;
	}
	__builtin_memcpy(ring_ev, &ev, sizeof(ev));
	bpf_ringbuf_submit(ring_ev, BPF_RB_NO_WAKEUP);
	return XDP_PASS;
}

SEC("xdp")
int rfm_xdp(struct xdp_md *ctx)
{
#if RFM_EMPTY
	return XDP_PASS;
#else
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

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

	__u32 l3_off = (__u32)(l3 - data);
	if (eth_proto == ETH_P_IP)
		iface_proto = 4;
	else if (eth_proto == ETH_P_IPV6)
		iface_proto = 6;

	__u32 len = bpf_xdp_get_buff_len(ctx);

	struct rfm_cnt *slotcnt = NULL;
	__u32 ifx = ctx->ingress_ifindex;
	__u32 *slot = NULL;
	if (ifx < RFM_SLOT_IFINDEX_MAX)
		slot = bpf_map_lookup_elem(&rfm_iface_slot, &ifx);
	if (slot && *slot && *slot <= RFM_SLOTS) {
		__u32 fam = iface_proto == 4 ? 1 : iface_proto == 6 ? 2 : 0;
		__u32 idx = (*slot - 1) * 6 + fam;
		slotcnt = bpf_map_lookup_elem(&rfm_iface_arr, &idx);
	}
	if (slotcnt) {
		slotcnt->packets += 1;
		slotcnt->bytes += len;
	} else {
		rfm_hash_count(ifx, RFM_DIR_INGRESS, iface_proto, 1, len);
	}

	if (iface_proto == 0)
		return XDP_PASS;

	__u32 cfg_key = 0;
	struct rfm_bconfig *cfg = NULL;
	if (slotcnt) {
		if (slotcnt->skip) {
			slotcnt->skip--;
			return XDP_PASS;
		}
		cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
		if (!cfg || cfg->sample_rate == 0)
			return XDP_PASS;
		slotcnt->skip = rfm_gap(cfg->sample_rate);
	} else {
		cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
		if (!cfg || cfg->sample_rate == 0)
			return XDP_PASS;
		if (bpf_get_prandom_u32() % cfg->sample_rate != 0)
			return XDP_PASS;
	}

	return rfm_emit_xdp(ctx, l3, end, eth_proto, l3_off, len, cfg);
#endif
}
#endif

char LICENSE[] SEC("license") = "GPL";
