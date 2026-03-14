#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(void *ctx) {
  bpf_printk("sys_enter");
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
