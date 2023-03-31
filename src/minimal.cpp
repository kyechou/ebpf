#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "minimal.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args) {
    if (level >= LIBBPF_DEBUG) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

int main(void) {
    struct minimal_bpf *skel;
    int err;
    pid_t pid = getpid();
    uint32_t index = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = minimal_bpf__open();
    if (!skel) {
        perror("Failed to open BPF skeleton");
        return 1;
    }

    /* Load & verify BPF programs */
    err = minimal_bpf__load(skel);
    if (err) {
        perror("Failed to load and verify BPF skeleton");
        goto cleanup;
    }

    // /* flags for BPF_MAP_UPDATE_ELEM command */
    // enum {
    // 	BPF_ANY		= 0, /* create new element or update existing */
    // 	BPF_NOEXIST	= 1, /* create new element if it didn't exist */
    // 	BPF_EXIST	= 2, /* update existing element */
    // 	BPF_F_LOCK	= 4, /* spin_lock-ed map_lookup/map_update */
    // };
    err = bpf_map__update_elem(skel->maps.my_pid_map, &index, sizeof(index),
                               &pid, sizeof(pid), BPF_ANY);
    if (err < 0) {
        perror("Failed to update map with pid");
        goto cleanup;
    }

    fprintf(stderr, "PID: %d\n", pid);

    /* Attach tracepoint handler */
    err = minimal_bpf__attach(skel);
    if (err) {
        perror("Failed to attach BPF skeleton");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    for (int i = 0; i < 5; ++i) {
        /* trigger our BPF program */
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    fprintf(stderr, "\nclean up\n");
    minimal_bpf__destroy(skel);
    return -err;
}
