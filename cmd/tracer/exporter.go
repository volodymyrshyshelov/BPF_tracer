package main
import (
    "unicode/utf8"
)

import (
	"log"
	"net"

	pb "ebpf-tracer/proto" // Импорт из твоего go_package
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Exporter struct {
	pb.UnimplementedTracerServiceServer
	out chan *ProcessedEvent
}
func sanitizeString(s string) string {
    if !utf8.ValidString(s) {
        return "<invalid UTF-8>"
    }
    return s
}

func NewExporter(out chan *ProcessedEvent) *Exporter {
	return &Exporter{out: out}
}

func (e *Exporter) StreamEvents(req *pb.EventRequest, stream pb.TracerService_StreamEventsServer) error {
	for event := range e.out {
		// фильтрация по PID
		if len(req.Pids) > 0 && !containsUint32(req.Pids, event.PID) {
			continue
		}
		// фильтрация по типу
		if len(req.Types) > 0 && !containsString(req.Types, event.Type) {
			continue
		}

		resp := &pb.Event{
			Type:      event.Type,
			Pid:       event.PID,
			Comm:      sanitizeString(event.Comm),
			Timestamp: timestamppb.New(event.Timestamp),
			Details:   sanitizeString(event.Details),
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	return nil
}

func containsUint32(list []uint32, val uint32) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

func containsString(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

func StartGRPCServer(exporter *Exporter) {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterTracerServiceServer(grpcServer, exporter)

	log.Println("gRPC server listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
