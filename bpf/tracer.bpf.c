#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} pid_filters SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *filter = bpf_map_lookup_elem(&pid_filters, &pid);
    if (filter && !(*filter & (1 << (EVENT_TYPE_EXECVE - 1))))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_EXECVE;
    e->pid = pid;
    e->tgid = bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->execve.filename, sizeof(e->execve.filename), (void *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *filter = bpf_map_lookup_elem(&pid_filters, &pid);
    if (filter && !(*filter & (1 << (EVENT_TYPE_OPEN - 1))))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_OPEN;
    e->pid = pid;
    e->tgid = bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->open.filename, sizeof(e->open.filename), (void *)ctx->args[1]);
    e->open.flags = (int)ctx->args[2];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 *filter = bpf_map_lookup_elem(&pid_filters, &pid);
    if (filter && !(*filter & (1 << (EVENT_TYPE_TCP_CONN - 1))))
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_TCP_CONN;
    e->pid = pid;
    e->tgid = bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read_kernel(&e->tcp.saddr, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&e->tcp.daddr, sizeof(u32), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&e->tcp.sport, sizeof(u16), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&e->tcp.dport, sizeof(u16), &sk->__sk_common.skc_dport);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
