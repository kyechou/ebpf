#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb
import ctypes as ct

prog = """
#include <uapi/linux/ptrace.h>

BPF_HASH(last);
BPF_PERF_OUTPUT(events);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;

    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            events.perf_submit(ctx, &delta, sizeof(delta));
        }
        last.delete(&key);
    }

    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
"""

b = BPF(text=prog, cflags=['-fcf-protection'])
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")


def print_event(cpu, data, size):
    delta_ns = ct.cast(data, ct.POINTER(ct.c_ulonglong)).contents
    delta_s = float(delta_ns.value) / 1e6
    print('cpu:', cpu, ', size:', size, (', last %.6f ms ago' % delta_s))


b["events"].open_perf_buffer(print_event)

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
