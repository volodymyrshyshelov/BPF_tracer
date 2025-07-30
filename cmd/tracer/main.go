package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var (
	pidFilter    = flag.Int("pid", 0, "Filter by PID (0 for all)")
	eventFilter  = flag.String("events", "execve,open,tcp", "Comma-separated events")
	samplingRate = flag.Int("sampling", 1, "Sampling rate")
)

func main() {
	flag.Parse()

	loader, err := NewLoader()
	if err != nil {
		log.Fatalf("Failed to load eBPF: %v", err)
	}
	defer loader.Close()

	if err := loader.SetFilters(*pidFilter, parseEventFilter(*eventFilter)); err != nil {
		log.Fatalf("Failed to set filters: %v", err)
	}

	rawEvents := make(chan Event, 16384)
	processedEvents := make(chan *ProcessedEvent, 16384)

	reader := NewReader(loader.Collection)
	processor := NewProcessor(uint32(*pidFilter), *samplingRate)

	go reader.Start(rawEvents)
	go processor.Start(rawEvents, processedEvents)

	// Заменяем экспортёр на простую горутину логирования
	exporter := NewExporter(processedEvents)
	go StartGRPCServer(exporter)


	log.Println("Tracer started. Press Ctrl+C to stop...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down tracer")
}
