// SPDX-License-Identifier: GPL-2.0
#ifndef __RFM_COMMON_H
#define __RFM_COMMON_H

#include "vmlinux.h"

#define RFM_DIR_INGRESS 0
#define RFM_DIR_EGRESS 1

// a slot drawn under another gen draws its skip again
struct rfm_config {
	__u32 sample_rate;
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

// the slots count interfaces below RFM_SLOT_IFINDEX_MAX, the hash the rest
#define RFM_SLOTS 256
#define RFM_SLOT_IFINDEX_MAX 16384
#define RFM_FAMILIES 3

// skip counts skbs to the next sample, wake events to the next wakeup
struct rfm_slot_value {
	__u64 packets, bytes;
	__u64 skip;
	__u32 gen;
	__u32 wake;
};

// dir_l2 holds the direction in its top bit and the l2 header of each wire packet in the low 7
#define RFM_DIR_L2(dir, l2_len) ((__u8)((dir) << 7 | (l2_len)))

// len and segs count the wire bytes and packets
struct rfm_flow_event {
	__u64 tstamp;
	__u32 ifindex;
	__u8 proto;
	__u8 dir_l2;
	__u16 segs;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u16 src_port;
	__u16 dst_port;
	__u32 len;
};

// with the 8 byte ring header a record fills one cache line
_Static_assert(sizeof(struct rfm_flow_event) == 56,
	       "rfm_flow_event is not 56 bytes");

#endif
