package probe

//go:generate go tool bpfgen --ident rfm --output-dir . --pkg-config libbpf --compdb ../compile_commands.json ../bpf/rfm_tc.c
