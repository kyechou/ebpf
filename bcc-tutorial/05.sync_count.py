#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(count);

int do_trace(struct pt_regs *ctx) {
    u64 new_num_calls = 0, *num_calls, key = 0;

    // attempt to read stored count
    num_calls = count.lookup(&key);
    if (num_calls != NULL) {
        new_num_calls = *num_calls;
        count.delete(&key);
    }

    // update stored count
    new_num_calls++;
    count.update(&key, &new_num_calls);
    bpf_trace_printk("%d\\n", new_num_calls);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        printb(b"%.2f - %s syncs in total" % (ts, msg))
    except KeyboardInterrupt:
        exit()
