// SPDX-License-Identifier: GPL-2.0
#include "rfm_common.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1
#define TC_ACT_PIPE 3
#define TC_ACT_RECLASSIFY 1

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

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

static __always_inline int rfm_tc(struct __sk_buff *skb, __u8 dir)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;

	if (data + sizeof(struct ethhdr) > end)
		return TC_ACT_OK;

	struct ethhdr *eth = data;
	__u16 eth_proto = bpf_ntohs(eth->h_proto);
	__u8 iface_proto = 0;

	switch (eth_proto) {
	case ETH_P_IP:
		iface_proto = 4;
		break;
	case ETH_P_IPV6:
		iface_proto = 6;
		break;
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
		val->packets++;
		val->bytes += skb->len;
	} else {
		struct rfm_iface_value init = { .packets = 1,
						.bytes = skb->len };
		bpf_map_update_elem(&rfm_iface_stats, &ikey, &init, BPF_ANY);
	}

	// flow events only for IP packets
	if (iface_proto == 0)
		return TC_ACT_OK;

	__u32 cfg_key = 0;
	struct rfm_config *cfg = bpf_map_lookup_elem(&rfm_config, &cfg_key);
	if (!cfg || cfg->sample_rate == 0)
		return TC_ACT_OK;

	if (bpf_get_prandom_u32() % cfg->sample_rate != 0)
		return TC_ACT_OK;

	// parse IP headers into a stack event
	struct rfm_flow_event ev = {
		.ifindex = skb->ifindex,
		.dir = dir,
		.len = skb->len,
	};

	void *l4 = NULL;

	if (eth_proto == ETH_P_IP) {
		struct iphdr *ip = data + sizeof(struct ethhdr);
		if ((void *)(ip + 1) > end)
			return TC_ACT_OK;

		ev.proto = ip->protocol;

		// map IPv4 to v6: ::ffff:x.x.x.x
		ev.src_addr[10] = 0xff;
		ev.src_addr[11] = 0xff;
		__builtin_memcpy(&ev.src_addr[12], &ip->saddr, 4);

		ev.dst_addr[10] = 0xff;
		ev.dst_addr[11] = 0xff;
		__builtin_memcpy(&ev.dst_addr[12], &ip->daddr, 4);

		// assumes standard 20-byte header, IP options are not handled
		l4 = (void *)ip + sizeof(struct iphdr);
	} else {
		struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
		if ((void *)(ip6 + 1) > end)
			return TC_ACT_OK;

		ev.proto = ip6->nexthdr;
		__builtin_memcpy(ev.src_addr, &ip6->saddr, 16);
		__builtin_memcpy(ev.dst_addr, &ip6->daddr, 16);

		l4 = (void *)(ip6 + 1);
	}

	// extract ports for TCP and UDP
	if (ev.proto == 6 || ev.proto == 17) {
		if (l4 + 4 > end)
			return TC_ACT_OK;
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
		return TC_ACT_OK;
	}

	__builtin_memcpy(ring_ev, &ev, sizeof(ev));
	bpf_ringbuf_submit(ring_ev, 0);

	return TC_ACT_OK;
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
