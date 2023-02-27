#!/usr/bin/python
#
# urandomread  Example of instrumenting a kernel tracepoint.
#              For Linux, uses BCC, BPF. Embedded C.
#
# REQUIRES: Linux 4.7+ (BPF_PROG_TYPE_TRACEPOINT support).
#
# Test by running this, then in another shell, run:
#     dd if=/dev/urandom of=/dev/null bs=1k count=5
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from bcc.utils import printb

# Note:
# Tracepoint random:urandom_read doesn't seem to be supported since Linux 5.17.
# https://lore.kernel.org/all/20220210155012.136485-3-Jason@zx2c4.com/
# https://lore.kernel.org/all/20220527084823.063888450@linuxfoundation.org/
#
# No relevant issues in bcc mentioned this problem. One may want to open an
# issue or suggest a new tracepoint example via a PR.
# https://github.com/iovisor/bcc/search?q=urandom_read&type=issues

prog = """
TRACEPOINT_PROBE(random, urandom_read) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("%d\\n", args->got_bits);
    return 0;
}
"""

b = BPF(text=prog, cflags=['-fcf-protection'])
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "GOTBITS"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
