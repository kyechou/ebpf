#!/usr/bin/python

from bcc import BPF
from bcc.utils import printb
import ctypes as ct

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

struct block_rq_issue_args {
    // /sys/kernel/debug/tracing/events/block/block_rq_issue/format
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    u32 bytes;
    char rwbs[8];
    char comm[16];
};

struct block_rq_complete_args {
    // /sys/kernel/debug/tracing/events/block/block_rq_complete/format
    u64 __unused__;
    u32 dev;
    u64 sector;
    u32 nr_sector;
    u32 error;
    char rwbs[8];
};

struct req_t {
    u64 ts;
    u32 bytes;
};

BPF_HASH(requests, u32, struct req_t); // dev -> req_t

int trace_start(struct block_rq_issue_args *args) {
    u32 key = args->dev;
    struct req_t req = {};
    struct req_t *prev_req = requests.lookup(&key);

    if (prev_req != NULL) {
        prev_req->bytes += args->bytes;
    } else {
        req.ts = bpf_ktime_get_ns();
        req.bytes = args->bytes;
        requests.update(&key, &req);
    }

    return 0;
}

BPF_RINGBUF_OUTPUT(events, 8);

struct data_t {
    u64 completion_ts;
    u64 latency;
    u32 bytes;
    char type[8];
};

int trace_completion(struct block_rq_complete_args *args) {
    u32 key = args->dev;
    struct req_t *req = requests.lookup(&key);

    if (req != NULL) {
        struct data_t data = {};
        data.completion_ts = bpf_ktime_get_ns();
        data.latency = data.completion_ts - req->ts;
        data.bytes = req->bytes;
        bpf_probe_read_kernel(data.type, 8, args->rwbs);

        events.ringbuf_output(&data, sizeof(data), 0);
        requests.delete(&key);
    }

    return 0;
}
"""

b = BPF(text=prog, cflags=['-fcf-protection'])
b.attach_tracepoint(tp='block:block_rq_issue', fn_name='trace_start')
b.attach_tracepoint(tp='block:block_rq_complete', fn_name='trace_completion')


class Data(ct.Structure):
    _fields_ = [('completion_ts', ct.c_uint64), ('latency', ct.c_uint64),
                ('bytes', ct.c_uint32), ('type', ct.c_char * 8)]


def print_data(ctx, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    print('%.9f : latency %9.6f ms - %d KiB %s' %
          (float(event.completion_ts) / 1e9, float(event.latency) / 1e6,
           event.bytes / 1024, event.type.decode('utf-8')))


b["events"].open_ring_buffer(print_data)
print('Starting...')

while 1:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        exit()
