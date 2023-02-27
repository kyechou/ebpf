#!/usr/bin/python

from bcc import BPF
import time

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HISTOGRAM(dist);
BPF_HASH(start_ts, struct request *, u64);

int trace_req_start(struct pt_regs *ctx, struct request *req) {
	u64 ts = bpf_ktime_get_ns();
	start_ts.update(&req, &ts);
    return 0;
}

int trace_req_done(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, latency;

	tsp = start_ts.lookup(&req);
	if (tsp != NULL) {
		latency = bpf_ktime_get_ns() - *tsp;
		start_ts.delete(&req);
        dist.increment(bpf_log2l(latency / 1000)); // usec
	}

    return 0;
}
"""

b = BPF(text=prog, cflags=['-fcf-protection'])
if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_done")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_done")

print("Tracing... Hit Ctrl-C to end.")

try:
    time.sleep(99999999)
except KeyboardInterrupt:
    print()

print("Histogram")
print("~~~~~~~~~")
b["dist"].print_log2_hist("microseconds")
