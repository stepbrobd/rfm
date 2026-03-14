// SPDX-License-Identifier: GPL-2.0
#ifndef __RFM_COMMON_H
#define __RFM_COMMON_H

#define RFM_DIR_INGRESS 0
#define RFM_DIR_EGRESS 1

struct rfm_config {
  __u32 sample_rate;
  __u32 flags;
  __u32 inactive_timeout_ns;
  __u32 _pad;
};

struct rfm_iface_key {
  __u32 ifindex;
  __u8 dir, proto;
  __u16 _pad;
};

struct rfm_iface_value {
  __u64 packets, bytes;
};

#endif
