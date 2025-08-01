#ifndef __TRACER_H
#define __TRACER_H

// Event types (enum must be in sync everywhere!)
#define EVENT_TYPE_EXECVE    1
#define EVENT_TYPE_OPEN      2
#define EVENT_TYPE_READ      3
#define EVENT_TYPE_WRITE     4
#define EVENT_TYPE_ACCEPT    5
#define EVENT_TYPE_CONNECT   6
#define EVENT_TYPE_CLONE     7
#define EVENT_TYPE_EXIT      8
#define EVENT_TYPE_TCP_CONN  9
#define EVENT_TYPE_UPROBE   10

struct event {
    u32 type;
    u32 pid;
    u32 tgid;
    u64 timestamp;
    char comm[16];
    union {
        struct { char filename[256]; } execve;
        struct { char filename[256]; int flags; } open;
        struct { int fd; u64 count; } io;          // для read, write, accept, connect
        struct { u32 saddr; u32 daddr; u16 sport; u16 dport; } tcp;
        struct { char func[64]; u64 args[4]; } uprobe;
    };
};

#endif /* __TRACER_H */
