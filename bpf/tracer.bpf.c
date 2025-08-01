#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracer.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// =========== MAPS ===========
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

// Dynamic UPROBE: карта конфигурации
// Ключ: u64 key = (u64)pid << 32 | func_addr
// Значение: char[64] (имя функции) или произвольные флаги
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64);
    __type(value, char[64]);
} uprobe_configs SEC(".maps");

// =========== HELPERS ===========
static __always_inline int filter_pass(u32 pid, u32 event_type) {
    u32 *filter = bpf_map_lookup_elem(&pid_filters, &pid);
    if (filter && !(*filter & (1 << (event_type - 1))))
        return 0;
    return 1;
}
static __always_inline void fill_common(struct event *e, u32 type, u32 pid) {
    e->type = type;
    e->pid = pid;
    e->tgid = bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

// =========== SYSTEM CALLS ===========

// EXECVE
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_EXECVE))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_EXECVE, pid);
    bpf_probe_read_user_str(e->execve.filename, sizeof(e->execve.filename), (void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// OPENAT
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_OPEN))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_OPEN, pid);
    bpf_probe_read_user_str(e->open.filename, sizeof(e->open.filename), (void *)ctx->args[1]);
    e->open.flags = (int)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// READ
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_READ))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_READ, pid);
    e->io.fd = (int)ctx->args[0];
    e->io.count = (u64)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// WRITE
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_WRITE))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_WRITE, pid);
    e->io.fd = (int)ctx->args[0];
    e->io.count = (u64)ctx->args[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ACCEPT4
SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_ACCEPT))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_ACCEPT, pid);
    e->io.fd = (int)ctx->args[0];
    e->io.count = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// CONNECT
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_CONNECT))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_CONNECT, pid);
    e->io.fd = (int)ctx->args[0];
    e->io.count = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// CLONE
SEC("tracepoint/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_CLONE))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_CLONE, pid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// EXIT GROUP
SEC("tracepoint/syscalls/sys_enter_exit_group")
int handle_exit(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_EXIT))
        return 0;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_EXIT, pid);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// TCP connect (kprobe)
SEC("kprobe/tcp_connect")
int handle_tcp_connect(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!filter_pass(pid, EVENT_TYPE_TCP_CONN))
        return 0;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); if (!e) return 0;
    fill_common(e, EVENT_TYPE_TCP_CONN, pid);
    bpf_probe_read_kernel(&e->tcp.saddr, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&e->tcp.daddr, sizeof(u32), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&e->tcp.sport, sizeof(u16), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&e->tcp.dport, sizeof(u16), &sk->__sk_common.skc_dport);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// =====================
// UNIVERSAL UPROBE HANDLER (из uprobes.bpf.c)
// =====================

SEC("uprobe")
int handle_generic_uprobe(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 func_addr = PT_REGS_IP(ctx);  // IP = addr функции

    // Составляем ключ (pid << 32 | addr)
    u64 key = ((u64)pid << 32) | func_addr;
    char *func_name = bpf_map_lookup_elem(&uprobe_configs, &key);
    if (!func_name) {
        // Если имя не нашли — не шлем эвент
        return 0;
    }

    if (!filter_pass(pid, EVENT_TYPE_UPROBE))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->type = EVENT_TYPE_UPROBE;
    e->pid = pid;
    e->tgid = bpf_get_current_pid_tgid();
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Запишем имя функции из map
    __builtin_memset(e->uprobe.func, 0, sizeof(e->uprobe.func));
    bpf_probe_read_kernel_str(e->uprobe.func, sizeof(e->uprobe.func), func_name);

    // Аргументы — первые 4 (для x86_64 и aarch64)
#if defined(__x86_64__) || defined(__aarch64__)
    e->uprobe.args[0] = PT_REGS_PARM1(ctx);
    e->uprobe.args[1] = PT_REGS_PARM2(ctx);
    e->uprobe.args[2] = PT_REGS_PARM3(ctx);
    e->uprobe.args[3] = PT_REGS_PARM4(ctx);
#else
    #pragma unroll
    for (int i = 0; i < 4; i++)
        e->uprobe.args[i] = 0;
#endif

    bpf_ringbuf_submit(e, 0);
    return 0;
}
