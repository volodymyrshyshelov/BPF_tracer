package main

import (
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
)

var (
    pidFilter    = flag.Int("pid", 0, "Filter by PID (0 for all)")
    eventFilter  = flag.String("events", "execve,open,tcp", "Comma-separated events")
    samplingRate = flag.Int("sampling", 1, "Sampling rate")
    uprobesFlag  = flag.String("uprobes", "", "Comma-separated uprobes in format 'binary:function' or 'binary:function:pid'")
)

func main() {
    flag.Parse()

    loader, err := NewLoader()
    if err != nil {
        log.Fatalf("Failed to load eBPF: %v", err)
    }
    defer loader.Close()

    for name := range loader.Collection.Programs {
        log.Println("Program in collection:", name)
    }

    // --- UPROBE MANAGER ---
    uprobeManager, err := NewUprobeManager(loader.Collection)
    if err != nil {
        log.Fatalf("Failed to create UprobeManager: %v", err)
    }
    defer uprobeManager.RemoveAll()

    if err := loader.SetFilters(*pidFilter, parseEventFilter(*eventFilter)); err != nil {
        log.Fatalf("Failed to set filters: %v", err)
    }

    // --- Динамическое добавление uprobes по флагу ---
    if *uprobesFlag != "" {
        uprobes := strings.Split(*uprobesFlag, ",")
        for _, spec := range uprobes {
            parts := strings.Split(spec, ":")
            if len(parts) < 2 {
                log.Printf("Invalid uprobe spec: %s (need binary:function or binary:function:pid)", spec)
                continue
            }
            binary, fn := parts[0], parts[1]
            pid := 0
            if len(parts) > 2 {
                fmt.Sscanf(parts[2], "%d", &pid)
            }
            if err := uprobeManager.AddUprobe(pid, binary, fn); err != nil {
                log.Printf("Failed to add uprobe %s: %v", spec, err)
            }
        }
    }

    rawEvents := make(chan EventRaw, 262144)
    processedEvents := make(chan *ProcessedEvent, 262144)

    reader := NewReader(loader.Collection)
    processor := NewProcessor(uint32(*pidFilter), *samplingRate)

    go reader.Start(rawEvents)
    go processor.Start(rawEvents, processedEvents)

    // ==== LOGGING TO FILE ====
    logFile, err := os.OpenFile("events.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }
    defer logFile.Close()
    fileLogger := log.New(logFile, "", 0)

    go func() {
        for ev := range processedEvents {
            // Корректное форматирование времени
            ts := ev.Timestamp.Local().Format("2006-01-02 15:04:05.000")
            fileLogger.Printf("%s | %s | PID=%d | COMM=%s | %s",
                ts, ev.Type, ev.PID, ev.Comm, ev.Details)
        }
    }()

    exporter := NewExporter(processedEvents)
    go StartGRPCServer(exporter)

    log.Println("Tracer started. Press Ctrl+C to stop...")

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
    <-sig
    log.Println("Shutting down tracer")
}
