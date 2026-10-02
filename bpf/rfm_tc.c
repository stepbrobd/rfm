// SPDX-License-Identifier: GPL-2.0
#include "rfm_common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

struct rfm_vlan_hdr {
	__u16 tci;
	__u16 encap_proto;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct rfm_config);
} rfm_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct rfm_iface_key);
	__type(value, struct rfm_iface_value);
} rfm_iface_stats SEC(".maps");

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

// the IPv4 IHL and the TCP data offset are read as nibbles of whole bytes,
// bpfgen compiles the bpfel and the bpfeb object against one vmlinux.h, and
// the iphdr and tcphdr bitfields of that header fit only one byte order
static __always_inline __u32 rfm_ipv4_hdr_len(struct iphdr *ip)
{
	return (__u32)(*(__u8 *)ip & 0x0f) << 2;
}

static __always_inline __u32 rfm_tcp_hdr_len(struct tcphdr *tcp)
{
	return (__u32)(((__u8 *)tcp)[12] >> 4) << 2;
}

// rfm_hdr_len returns the L2 + L3 + L4 header size of the frame, the same
// quantity qdisc_pkt_len_init() uses to reconstruct the on-wire length of a
// GSO skb, and 0 when the headers cannot be parsed
// l2_len covers ethernet plus any VLAN tags, l3 points at the IP header
static __always_inline __u32 rfm_hdr_len(void *l3, void *end, __u16 eth_proto,
					 __u32 l2_len)
{
	__u32 l3_len;
	__u8 proto;

	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return 0;
		l3_len = rfm_ipv4_hdr_len(ip);
		if (l3_len < sizeof(*ip))
			return 0;
		proto = ip->protocol;
	} else {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > end)
			return 0;
		l3_len = sizeof(*ip6);
		proto = ip6->nexthdr;
	}

	void *l4 = l3 + l3_len;
	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > end)
			return 0;
		return l2_len + l3_len + rfm_tcp_hdr_len(tcp);
	}
	if (proto == IPPROTO_UDP)
		return l2_len + l3_len + sizeof(struct udphdr);

	// the kernel adds no transport header for other GSO types either
	return l2_len + l3_len;
}

// the programs only observe, so every exit returns TCX_NEXT (TC_ACT_UNSPEC)
// and later TCX programs and the filters of a clsact or ingress qdisc still
// run, TC_ACT_OK is TCX_PASS and would end the chain at rfm
static __always_inline int rfm_tc(struct __sk_buff *skb, __u8 dir)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;

	if (data + sizeof(struct ethhdr) > end)
		return TCX_NEXT;

	struct ethhdr *eth = data;
	__u16 eth_proto = bpf_ntohs(eth->h_proto);
	__u8 iface_proto = 0;
	void *l3 = data + sizeof(struct ethhdr);

// todo:
// - handle PPPoE session frames carrying IPv4 or IPv6
// - handle MPLS label stacks when the monitored link carries labeled IP
// - walk IPv6 extension headers when we need final L4 proto and ports
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (eth_proto != ETH_P_8021Q && eth_proto != ETH_P_8021AD)
			break;

		if (l3 + sizeof(struct rfm_vlan_hdr) > end)
			return TCX_NEXT;

		struct rfm_vlan_hdr *vlan = l3;
		eth_proto = bpf_ntohs(vlan->encap_proto);
		l3 += sizeof(*vlan);
	}

	switch (eth_proto) {
	case ETH_P_IP:
		iface_proto = 4;
		break;
	case ETH_P_IPV6:
		iface_proto = 6;
		break;
	}

	// GRO (ingress) and GSO (egress) hand the tc hook one skb that stands
	// for several wire packets, so account for the segments it carries and
	// for the headers the merge removed, this keeps the counters equal to
	// what the NIC saw on the wire instead of what the stack saw as skbs
	__u32 len = skb->len;
	__u32 segs = 1;
	if (skb->gso_size && iface_proto) {
		__u32 hdr_len =
			rfm_hdr_len(l3, end, eth_proto, (__u32)(l3 - data));
		segs = skb->gso_segs;
		// drivers that pass gso frames up unverified leave gso_segs 0
		// (SKB_GSO_DODGY), derive it from the payload like the kernel
		if (segs == 0 && hdr_len && len > hdr_len)
			segs = (len - hdr_len + skb->gso_size - 1) /
			       skb->gso_size;
		if (segs == 0)
			segs = 1;
		if (dir == RFM_DIR_EGRESS)
			// qdisc_pkt_len_init() already added the header bytes
			// of every extra segment before the egress hook ran
			len = skb->wire_len;
		else
			len += (segs - 1) * hdr_len;
	}

	// iface stats are always updated, not gated by sampling
	struct rfm_iface_key ikey = {
		.ifindex = skb->ifindex,
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
		bpf_map_update_elem(&rfm_iface_stats, &ikey, &init, BPF_ANY);
	}

	// skip non-IP traffic for flow events
	if (iface_proto == 0)
		return TCX_NEXT;

	__u32 cfg_key = 0;
	struct rfm_config *cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
	if (!cfg || cfg->sample_rate == 0)
		return TCX_NEXT;

	if (bpf_get_prandom_u32() % cfg->sample_rate != 0)
		return TCX_NEXT;

	// parse IP headers into a stack event
	struct rfm_flow_event ev = {
		.tstamp = bpf_ktime_get_boot_ns(),
		.ifindex = skb->ifindex,
		.dir = dir,
		.segs = segs > 0xffff ? 0xffff : segs,
		.len = len,
	};

	void *l4 = NULL;

	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return TCX_NEXT;

		ev.proto = ip->protocol;
		__u16 frag_off = bpf_ntohs(ip->frag_off);

		// map IPv4 to v6: ::ffff:x.x.x.x
		ev.src_addr[10] = 0xff;
		ev.src_addr[11] = 0xff;
		__builtin_memcpy(&ev.src_addr[12], &ip->saddr, 4);

		ev.dst_addr[10] = 0xff;
		ev.dst_addr[11] = 0xff;
		__builtin_memcpy(&ev.dst_addr[12], &ip->daddr, 4);

		// use actual IHL to skip IP options
		__u32 ihl = rfm_ipv4_hdr_len(ip);
		if (ihl < sizeof(*ip))
			return TCX_NEXT;

		l4 = (void *)ip + ihl;

		// only the first fragment carries the transport header
		if ((frag_off & 0x1FFF) != 0)
			l4 = NULL;
	} else {
		struct ipv6hdr *ip6 = l3;
		if ((void *)(ip6 + 1) > end)
			return TCX_NEXT;

		ev.proto = ip6->nexthdr;
		__builtin_memcpy(ev.src_addr, &ip6->saddr, 16);
		__builtin_memcpy(ev.dst_addr, &ip6->daddr, 16);

		l4 = (void *)(ip6 + 1);
	}

	// extract ports for TCP and UDP
	if (l4 && (ev.proto == IPPROTO_TCP || ev.proto == IPPROTO_UDP)) {
		if (l4 + 4 > end)
			return TCX_NEXT;
		ev.src_port = bpf_ntohs(*(__u16 *)l4);
		ev.dst_port = bpf_ntohs(*(__u16 *)(l4 + 2));
	}

	// emit to ring buffer
	struct rfm_flow_event *ring_ev =
		bpf_ringbuf_reserve(&rfm_flow_events, sizeof(*ring_ev), 0);
	if (!ring_ev) {
		__u32 drop_key = 0;
		__u64 *drops = bpf_map_lookup_elem(&rfm_flow_drops, &drop_key);
		if (drops)
			(*drops)++;
		return TCX_NEXT;
	}

	__builtin_memcpy(ring_ev, &ev, sizeof(ev));

	// batch wakeups: only wake epoll every cfg->wakeup_batch events
	// fall back to RFM_WAKEUP_BATCH when the config value is unset
	__u32 batch = cfg->wakeup_batch;
	if (batch == 0)
		batch = RFM_WAKEUP_BATCH;
	__u64 flags = BPF_RB_NO_WAKEUP;
	__u32 cnt_key = 0;
	__u64 *cnt = bpf_map_lookup_elem(&rfm_submit_count, &cnt_key);
	if (cnt && (++(*cnt) % batch == 0))
		flags = BPF_RB_FORCE_WAKEUP;
	bpf_ringbuf_submit(ring_ev, flags);

	return TCX_NEXT;
}

SEC("tc/ingress")
int rfm_tc_ingress(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_INGRESS);
}

SEC("tc/egress")
int rfm_tc_egress(struct __sk_buff *skb)
{
	return rfm_tc(skb, RFM_DIR_EGRESS);
}

char LICENSE[] SEC("license") = "GPL";
