package main

import (
    "encoding/binary"
    "log"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/ringbuf"
)

// НЕ определяй здесь Event! Используй EventRaw из event.go

type Reader struct {
    collection *ebpf.Collection
}

func NewReader(coll *ebpf.Collection) *Reader {
    return &Reader{collection: coll}
}

func (r *Reader) Start(out chan<- EventRaw) {
    rb := r.collection.Maps["events"]
    rd, err := ringbuf.NewReader(rb)
    if err != nil {
        log.Fatalf("ringbuf reader: %v", err)
    }
    defer rd.Close()

    for {
        record, err := rd.Read()
        if err != nil {
            log.Printf("Error reading ringbuf: %v", err)
            continue
        }

        if len(record.RawSample) < 36+len(EventRaw{}.Data) {
            log.Printf("Invalid event size: %d", len(record.RawSample))
            continue
        }

        var event EventRaw
        event.Type = binary.LittleEndian.Uint32(record.RawSample[0:4])
        event.PID = binary.LittleEndian.Uint32(record.RawSample[4:8])
        event.Tgid = binary.LittleEndian.Uint32(record.RawSample[8:12])
        event.Timestamp = binary.LittleEndian.Uint64(record.RawSample[12:20])
        copy(event.Comm[:], record.RawSample[20:36])
        copy(event.Data[:], record.RawSample[36:36+len(event.Data)])

        select {
        case out <- event:
        default:
            log.Println("Events channel full, dropping event")
        }
    }
}
