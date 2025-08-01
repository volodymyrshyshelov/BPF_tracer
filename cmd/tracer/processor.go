package main

import (
    "encoding/binary"
    "fmt"
    "net"
    "os"
    "strings"
    "time"
    "unicode/utf8"
)

const (
    EVENT_TYPE_EXECVE   = 1
    EVENT_TYPE_OPEN     = 2
    EVENT_TYPE_READ     = 3
    EVENT_TYPE_WRITE    = 4
    EVENT_TYPE_ACCEPT   = 5
    EVENT_TYPE_CONNECT  = 6
    EVENT_TYPE_CLONE    = 7
    EVENT_TYPE_EXIT     = 8
    EVENT_TYPE_TCP_CONN = 9
    EVENT_TYPE_UPROBE   = 10
)

type Processor struct {
    filterPID uint32
    sampling  int
    count     int
    myPID     uint32 // наш собственный PID, вычисляется один раз
}

func sanitizeUTF8(s string) string {
    if utf8.ValidString(s) {
        return s
    }
    var out []rune
    for i, r := range s {
        if r == utf8.RuneError {
            _, size := utf8.DecodeRuneInString(s[i:])
            if size == 1 {
                continue
            }
        }
        out = append(out, r)
    }
    return string(out)
}

func NewProcessor(pidFilter uint32, samplingRate int) *Processor {
    return &Processor{
        filterPID: pidFilter,
        sampling:  samplingRate,
        myPID:     uint32(os.Getpid()),
    }
}

func (p *Processor) Start(in <-chan EventRaw, out chan<- *ProcessedEvent) {
    for event := range in {
        // Фильтруем собственные события (от tracer-а)
        if event.PID == p.myPID {
            continue
        }
        // Опциональный фильтр по pid
        if p.filterPID != 0 && event.PID != p.filterPID {
            continue
        }
        p.count++
        if p.sampling > 1 && p.count%p.sampling != 0 {
            continue
        }
        processed := p.processEvent(event)
        if processed != nil {
            out <- processed
        }
    }
}

func (p *Processor) processEvent(event EventRaw) *ProcessedEvent {
    processed := &ProcessedEvent{
        PID:       event.PID,
        Comm:      sanitizeUTF8(strings.TrimRight(string(event.Comm[:]), "\x00")),
        // Корректно: используем время ядра (ns -> time.Time)
        Timestamp: time.Now(), 
    }

    switch event.Type {
    case EVENT_TYPE_EXECVE:
        processed.Type = "EXECVE"
        processed.Details = fmt.Sprintf("File: %s",
            strings.TrimRight(string(event.Data[:256]), "\x00"))

    case EVENT_TYPE_OPEN:
        if len(event.Data) < 260 {
            return nil
        }
        filename := strings.TrimRight(string(event.Data[:256]), "\x00")
        flags := binary.LittleEndian.Uint32(event.Data[256:260])
        processed.Type = "OPEN"
        processed.Details = fmt.Sprintf("File: %s, Flags: %d", filename, flags)

    case EVENT_TYPE_READ, EVENT_TYPE_WRITE, EVENT_TYPE_ACCEPT, EVENT_TYPE_CONNECT:
        if len(event.Data) < 12 {
            return nil
        }
        fd := int32(binary.LittleEndian.Uint32(event.Data[:4]))
        count := binary.LittleEndian.Uint64(event.Data[4:12])
        var action string
        switch event.Type {
        case EVENT_TYPE_READ:
            action = "READ"
        case EVENT_TYPE_WRITE:
            action = "WRITE"
        case EVENT_TYPE_ACCEPT:
            action = "ACCEPT"
        case EVENT_TYPE_CONNECT:
            action = "CONNECT"
        }
        processed.Type = action
        processed.Details = fmt.Sprintf("FD: %d, Count: %d", fd, count)

    case EVENT_TYPE_CLONE:
        processed.Type = "CLONE"
        processed.Details = "Process cloned"

    case EVENT_TYPE_EXIT:
        processed.Type = "EXIT"
        processed.Details = "Process exited"

    case EVENT_TYPE_TCP_CONN:
        if len(event.Data) < 12 {
            return nil
        }
        saddr := binary.LittleEndian.Uint32(event.Data[0:4])
        daddr := binary.LittleEndian.Uint32(event.Data[4:8])
        sport := binary.LittleEndian.Uint16(event.Data[8:10])
        dport := binary.LittleEndian.Uint16(event.Data[10:12])

        srcIP := net.IPv4(byte(saddr), byte(saddr>>8), byte(saddr>>16), byte(saddr>>24))
        dstIP := net.IPv4(byte(daddr), byte(daddr>>8), byte(daddr>>16), byte(daddr>>24))

        processed.Type = "TCP_CONN"
        processed.Details = fmt.Sprintf("%s:%d -> %s:%d", srcIP, sport, dstIP, dport)

    case EVENT_TYPE_UPROBE:
        if len(event.Data) < 96 { // 64 + 4*8
            return nil
        }
        funcName := strings.TrimRight(string(event.Data[:64]), "\x00")
        arg1 := binary.LittleEndian.Uint64(event.Data[64:72])
        arg2 := binary.LittleEndian.Uint64(event.Data[72:80])
        arg3 := binary.LittleEndian.Uint64(event.Data[80:88])
        arg4 := binary.LittleEndian.Uint64(event.Data[88:96])

        processed.Type = "UPROBE"
        processed.Details = fmt.Sprintf(
            "Function: %s, Args: %d, %d, %d, %d",
            funcName, arg1, arg2, arg3, arg4,
        )

    default:
        processed.Type = "UNKNOWN"
        processed.Details = "Unknown event type"
    }
    processed.Details = sanitizeUTF8(processed.Details)
    return processed
}
