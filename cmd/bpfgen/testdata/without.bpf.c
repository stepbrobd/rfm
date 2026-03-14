#include "vmlinux.h"

#define SEC(name) __attribute__((section(name), used))

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(void *ctx) { return 0; }

char LICENSE[] SEC("license") = "GPL";
