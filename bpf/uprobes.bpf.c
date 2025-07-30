#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracer.h"

// Объявляем ringbuffer и фильтры как внешние карты
extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} pid_filters SEC(".maps");

SEC("uprobe//usr/bin/python3:PyFunction_Call")
int trace_python_function(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *filter = bpf_map_lookup_elem(&pid_filters, &pid);
    if (filter && !(*filter & (1 << (EVENT_TYPE_UPROBE - 1))))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_UPROBE;
    e->pid = pid;
    e->tgid = bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    void *func_ptr = (void *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(e->uprobe.func, sizeof(e->uprobe.func), func_ptr);

    // Считываем аргументы 2–5
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        e->uprobe.args[i] = PT_REGS_PARM2(ctx + i);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}