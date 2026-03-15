// SPDX-License-Identifier: GPL-2.0
#ifndef __RFM_COMMON_H
#define __RFM_COMMON_H

#include "vmlinux.h"

#define RFM_DIR_INGRESS 0
#define RFM_DIR_EGRESS 1

struct rfm_config {
	__u32 sample_rate;
	__u32 flags;
};

struct rfm_iface_key {
	__u32 ifindex;
	__u8 dir, proto;
	__u16 _pad;
};

struct rfm_iface_value {
	__u64 packets, bytes;
};

struct rfm_flow_event {
	__u32 ifindex;
	__u8 dir;
	__u8 proto;
	__u16 _pad;
	__u8 src_addr[16];
	__u8 dst_addr[16];
	__u16 src_port;
	__u16 dst_port;
	__u32 len;
};

#endif
