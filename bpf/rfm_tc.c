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

#define NEXTHDR_HOP 0
#define NEXTHDR_ROUTING 43
#define NEXTHDR_FRAGMENT 44
#define NEXTHDR_AUTH 51
#define NEXTHDR_DEST 60

// RFM_IPV6_EXTHDRS bounds the IPv6 extension header walk, RFC 8200 orders
// at most six of them in front of the upper layer header
#define RFM_IPV6_EXTHDRS 6

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

// off_byte is byte 12 of the TCP header
static __always_inline __u32 rfm_tcp_hdr_len(__u8 off_byte)
{
	return (__u32)(off_byte >> 4) << 2;
}

// rfm_l4 returns the offset of the upper layer header from the IP header at
// l3, which sits l3_off bytes into the packet, IPv6 extension headers
// included, and 0 when the IP header cannot be read
// proto is set to the upper layer protocol and later_frag to whether the
// packet is a later fragment, which carries no transport header, a chain of
// more than RFM_IPV6_EXTHDRS extension headers or one that ends early leaves
// proto at the extension header the walk stopped at
// the walk reads through bpf_skb_load_bytes, a packet pointer at a variable
// offset would have the verifier track every combination of header lengths
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

		// the first byte of every extension header names the next
		// header and the second holds the length, the fragment header
		// keeps its offset in the top 13 bits of bytes 2 and 3
		__u8 h[4];
		if (bpf_skb_load_bytes(skb, l3_off + off, h, sizeof(h)))
			break;

		__u8 cur = next;
		next = h[0];
		if (cur == NEXTHDR_FRAGMENT) {
			off += 8;
			// only the first fragment goes on to the transport header
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

// rfm_hdr_len returns the L2 + L3 + L4 header size of the frame, the same
// quantity qdisc_pkt_len_init() uses to reconstruct the on-wire length of a
// GSO skb, and 0 when the headers cannot be parsed
// l2_len covers ethernet plus the VLAN tags in the frame, l3 points at the IP
// header, and the L3 size includes the IPv6 extension headers GRO merges
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

	// a frame whose L2 header runs past the linear data is still counted,
	// as family other with eth_proto 0
	__u16 eth_proto = 0;
	__u8 iface_proto = 0;
	void *l3 = data + sizeof(struct ethhdr);
	if (l3 <= end) {
		struct ethhdr *eth = data;
		eth_proto = bpf_ntohs(eth->h_proto);
	}

// todo:
// - handle PPPoE session frames carrying IPv4 or IPv6
// - handle MPLS label stacks when the monitored link carries labeled IP
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

	// GRO (ingress) and GSO (egress) hand the tc hook one skb that stands
	// for several wire packets, so account for the segments it carries and
	// for the headers the merge removed, this keeps the counters equal to
	// what the NIC saw on the wire instead of what the stack saw as skbs
	__u32 len = skb->len;
	__u32 segs = 1;
	if (skb->gso_size && iface_proto) {
		__u32 hdr_len = rfm_hdr_len(skb, l3, end, eth_proto, l3_off);
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

	// the kernel holds the outer VLAN tag of a received frame in the skb
	// from before the ingress hook, and a VLAN device hands its frames to
	// the egress hook of the lower device with the tag in the skb, either
	// way every wire packet carries the 4 tag bytes outside skb->len
	__u32 l2_len = l3_off;
	if (skb->vlan_present) {
		l2_len += sizeof(struct rfm_vlan_hdr);
		len += segs * sizeof(struct rfm_vlan_hdr);
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
		.l2_len = l2_len,
	};

	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = l3;
		if ((void *)(ip + 1) > end)
			return TCX_NEXT;

		// map IPv4 to v6: ::ffff:x.x.x.x
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

	// the actual IHL skips IPv4 options, and the walk skips IPv6
	// extension headers
	bool later_frag;
	__u32 l4_off =
		rfm_l4(skb, l3, end, l3_off, eth_proto, &ev.proto, &later_frag);
	if (!l4_off)
		return TCX_NEXT;

	// extract ports for TCP and UDP, only the first fragment carries the
	// transport header
	if (!later_frag &&
	    (ev.proto == IPPROTO_TCP || ev.proto == IPPROTO_UDP)) {
		__be16 ports[2];
		if (bpf_skb_load_bytes(skb, l3_off + l4_off, ports,
				       sizeof(ports)))
			return TCX_NEXT;
		ev.src_port = bpf_ntohs(ports[0]);
		ev.dst_port = bpf_ntohs(ports[1]);
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
