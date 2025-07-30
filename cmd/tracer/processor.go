package main
import "unicode/utf8"
import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	EVENT_TYPE_EXECVE   = 1
	EVENT_TYPE_OPEN     = 2
	EVENT_TYPE_TCP_CONN = 3
	EVENT_TYPE_UPROBE   = 4
)

type ProcessedEvent struct {
	Type      string
	PID       uint32
	Comm      string
	Timestamp time.Time
	Details   string
}

type Processor struct {
	filterPID uint32
	sampling  int
	count     int
}
func sanitizeUTF8(s string) string {
    if utf8.ValidString(s) {
        return s
    }
    // Преобразуем в руны, отбрасывая невалидные байты
    var out []rune
    for i, r := range s {
        if r == utf8.RuneError {
            _, size := utf8.DecodeRuneInString(s[i:])
            if size == 1 {
                continue // invalid byte, skip
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
	}
}

func (p *Processor) Start(in <-chan Event, out chan<- *ProcessedEvent) {
	for event := range in {
		if p.filterPID != 0 && event.Pid != p.filterPID {
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

func (p *Processor) processEvent(event Event) *ProcessedEvent {
	processed := &ProcessedEvent{
		PID:       event.Pid,
		Comm:      sanitizeUTF8(strings.TrimRight(string(event.Comm[:]), "\x00")),
		Timestamp: time.Unix(0, int64(event.Timestamp)),
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
		if len(event.Data) < 80 {
			return nil
		}
		funcName := strings.TrimRight(string(event.Data[:64]), "\x00")
		arg1 := binary.LittleEndian.Uint64(event.Data[64:72])
		arg2 := binary.LittleEndian.Uint64(event.Data[72:80])

		processed.Type = "UPROBE"
		processed.Details = fmt.Sprintf("Function: %s, Args: %d, %d", funcName, arg1, arg2)

	default:
		processed.Type = "UNKNOWN"
		processed.Details = "Unknown event type"
	}
	processed.Details = sanitizeUTF8(processed.Details)
	return processed
}
