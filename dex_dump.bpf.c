#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct dex_event {
    __u64 base;
    __u64 size;
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("uprobe/dex_file_open")
int uprobe_dex_open(struct pt_regs *ctx)
{
    __u64 base = PT_REGS_PARM2(ctx);
    __u64 size = PT_REGS_PARM3(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (size < 51200 || size > 104857600) {
        return 0;
    }

    struct dex_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->base = base;
    e->size = size;
    e->pid = pid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
