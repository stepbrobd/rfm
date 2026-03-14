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

static __always_inline int rfm_tc(struct __sk_buff *skb, __u8 dir)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;

	if (data + sizeof(struct ethhdr) > end)
		return TC_ACT_OK;

	struct ethhdr *eth = data;
	__u8 proto = 0;
	switch (bpf_ntohs(eth->h_proto)) {
	case ETH_P_IP:
		proto = 4;
		break;
	case ETH_P_IPV6:
		proto = 6;
		break;
	}

	// iface stats are always updated, not gated by sampling
	struct rfm_iface_key ikey = {
		.ifindex = skb->ifindex,
		.dir = dir,
		.proto = proto,
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
