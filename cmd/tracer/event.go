package main
import "time"


// Это минимальный набор для пайплайна ringbuf → processor
type EventRaw struct {
    Type      uint32
    PID       uint32
    Tgid      uint32
    Timestamp uint64
    Comm      [16]byte
    Data      [264]byte // строго под union в C
}

type ProcessedEvent struct {
    Type      string
    PID       uint32
    Comm      string
    Timestamp time.Time
    Details   string
}
