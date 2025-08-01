package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Loader struct {
	Collection *ebpf.Collection
	Links      []link.Link
}

func NewLoader() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Загружаем единый объект, собранный из tracer.bpf.c
	spec, err := ebpf.LoadCollectionSpec("bpf/tracer.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	links := []link.Link{}

	// Линкуем все стандартные программы
	if prog := coll.Programs["handle_execve"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link execve: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_openat"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link openat: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_read"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_read", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link read: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_write"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_write", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link write: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_accept"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_accept4", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link accept4: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_connect"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link connect: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_clone"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_clone", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link clone: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_exit"]; prog != nil {
		tp, err := link.Tracepoint("syscalls", "sys_enter_exit_group", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link exit_group: %w", err)
		}
		links = append(links, tp)
	}
	if prog := coll.Programs["handle_tcp_connect"]; prog != nil {
		kp, err := link.Kprobe("tcp_connect", prog, nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("link tcp_connect: %w", err)
		}
		links = append(links, kp)
	}
	// UPROBE — только динамически, через UprobeManager

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		for _, link := range links {
			link.Close()
		}
		coll.Close()
		os.Exit(0)
	}()

	return &Loader{
		Collection: coll,
		Links:      links,
	}, nil
}

func (l *Loader) Close() {
	for _, link := range l.Links {
		link.Close()
	}
	l.Collection.Close()
}

func (l *Loader) SetFilters(pid int, eventMask uint32) error {
	if pid != 0 {
		m := l.Collection.Maps["pid_filters"]
		if m == nil {
			return fmt.Errorf("pid_filters map not found")
		}
		key := uint32(pid)
		if err := m.Put(key, eventMask); err != nil {
			return fmt.Errorf("set pid filter: %w", err)
		}
	}
	return nil
}

func parseEventFilter(filter string) uint32 {
	var mask uint32
	fields := strings.Split(filter, ",")
	if contains(fields, "execve") {
		mask |= 1 << (EVENT_TYPE_EXECVE - 1)
	}
	if contains(fields, "open") {
		mask |= 1 << (EVENT_TYPE_OPEN - 1)
	}
	if contains(fields, "read") {
		mask |= 1 << (EVENT_TYPE_READ - 1)
	}
	if contains(fields, "write") {
		mask |= 1 << (EVENT_TYPE_WRITE - 1)
	}
	if contains(fields, "accept") {
		mask |= 1 << (EVENT_TYPE_ACCEPT - 1)
	}
	if contains(fields, "connect") {
		mask |= 1 << (EVENT_TYPE_CONNECT - 1)
	}
	if contains(fields, "clone") {
		mask |= 1 << (EVENT_TYPE_CLONE - 1)
	}
	if contains(fields, "exit") {
		mask |= 1 << (EVENT_TYPE_EXIT - 1)
	}
	if contains(fields, "tcp_conn") {
		mask |= 1 << (EVENT_TYPE_TCP_CONN - 1)
	}
	if contains(fields, "uprobe") {
		mask |= 1 << (EVENT_TYPE_UPROBE - 1)
	}
	return mask
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.TrimSpace(s) == item {
			return true
		}
	}
	return false
}
