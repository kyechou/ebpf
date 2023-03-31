#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, pid_t);
} my_pid_map SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx __attribute__((unused))) {
    u32 index = 0;
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    pid_t *my_pid = bpf_map_lookup_elem(&my_pid_map, &index);

    if (!my_pid || pid != *my_pid)
        return 0;

    bpf_printk("BPF triggered from PID %d.", pid);

    return 0;
}
