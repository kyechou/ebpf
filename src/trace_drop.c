#include <stdio.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "trace_drop.h"
#include "trace_drop.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args) {
    if (level >= LIBBPF_DEBUG) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

int main(void) {
    struct trace_drop_bpf *b;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    b = trace_drop_bpf__open();
    if (!b) {
        perror("Failed to open BPF program");
        return 1;
    }

    err = trace_drop_bpf__load(b);
    if (err) {
        perror("Failed to load and verify BPF program");
        goto cleanup;
    }

    err = trace_drop_bpf__attach(b);
    if (err) {
        perror("Failed to attach BPF program");
        goto cleanup;
    }

    printf("Ready\n");

    sleep(10);

cleanup:
    trace_drop_bpf__destroy(b);
    return -err;
}
