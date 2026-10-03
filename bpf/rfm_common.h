// SPDX-License-Identifier: GPL-2.0
#ifndef __RFM_COMMON_H
#define __RFM_COMMON_H

#include "vmlinux.h"

#define RFM_DIR_INGRESS 0
#define RFM_DIR_EGRESS 1

struct rfm_config {
	__u32 sample_rate;
	__u32 flags;
	__u32 wakeup_batch;
};

struct rfm_iface_key {
	__u32 ifindex;
	__u8 dir, proto;
	__u16 _pad;
};

struct rfm_iface_value {
	__u64 packets, bytes;
};

// len is the on-wire byte count and segs the on-wire packet count of the
// sampled skb, GRO on ingress and GSO on egress coalesce several wire packets
// into one skb, so both are reconstructed from gso_segs and the header size
// l2_len is the L2 header size of each of those wire packets, ethernet plus
// the VLAN tags in the frame or held in the skb, len - segs * l2_len is the
// IP byte count
// the padding keeps the layout explicit up to the 8 byte alignment the
// userspace decoder expects
struct rfm_flow_event {
	__u64 tstamp;
	__u32 ifindex;
	__u8 dir;
	__u8 proto;
	__u16 segs;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u16 src_port;
	__u16 dst_port;
	__u32 len;
	__u8 l2_len;
	__u8 _pad[7];
};

#endif
