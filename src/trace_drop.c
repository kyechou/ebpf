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

static int rb_handler(void *ctx __attribute__((unused)),
                      void *data,
                      size_t size __attribute__((unused))) {
    struct drop_data *d = data;
    printf("[%.9f] dev: %d, iif: %d, reason: %d, ip len: %d, ip proto: %d\n",
           (double)d->tstamp / 1e9, d->ifindex, d->ingress_ifindex, d->reason,
           d->tot_len, d->ip_proto);
    return 0;
}

int main(void) {
    struct trace_drop_bpf *b = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

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

    rb = ring_buffer__new(bpf_map__fd(b->maps.events), rb_handler, NULL, NULL);
    if (!rb) {
        perror("Failed to create ring buffer");
        goto cleanup;
    }

    printf("Ready\n");

    while (1) {
        // ring_buffer__epoll_fd
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        } else if (err < 0) {
            perror("ring_buffer__poll");
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    trace_drop_bpf__destroy(b);
    return -err;
}
