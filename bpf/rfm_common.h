// SPDX-License-Identifier: GPL-2.0
#ifndef __RFM_COMMON_H
#define __RFM_COMMON_H

#include "vmlinux.h"

#define RFM_DIR_INGRESS 0
#define RFM_DIR_EGRESS 1

// gen changes with every sample rate, a counter slot whose skip count was
// drawn under another gen draws it again
struct rfm_config {
	__u32 sample_rate;
	__u32 flags;
	__u32 wakeup_batch;
	__u32 gen;
};

struct rfm_iface_key {
	__u32 ifindex;
	__u8 dir, proto;
	__u16 _pad;
};

struct rfm_iface_value {
	__u64 packets, bytes;
};

// an interface whose ifindex is below RFM_SLOT_IFINDEX_MAX can hold one of
// RFM_SLOTS counter slots, each with an entry per direction and family
// (non-IP, IPv4, IPv6), the rest count in the rfm_iface_stats hash
#define RFM_SLOTS 256
#define RFM_SLOT_IFINDEX_MAX 16384
#define RFM_FAMILIES 3

// a counter slot entry on one CPU, skip is the packets left before the next
// sample, gen the config gen it was drawn under and wake the events left
// before the next one that wakes the reader
struct rfm_slot_value {
	__u64 packets, bytes;
	__u64 skip;
	__u32 gen;
	__u32 wake;
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
