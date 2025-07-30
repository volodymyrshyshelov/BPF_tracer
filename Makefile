# Detect architecture for BPF
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    BPF_ARCH := x86
else ifeq ($(ARCH),aarch64)
    BPF_ARCH := arm64
else
    $(error Unsupported architecture: $(ARCH))
endif

all: build

build-ebpf:
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I. -c bpf/tracer.bpf.c -o bpf/tracer.bpf.o
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -I. -c bpf/uprobes.bpf.c -o bpf/uprobes.bpf.o

generate-proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/tracer.proto
	python -m grpc_tools.protoc -Iproto --python_out=ui --grpc_python_out=ui proto/tracer.proto

build-go: generate-proto
	go build -o bin/tracer ./cmd/tracer

build: build-ebpf build-go

run-tracer:
	sudo ./bin/tracer --pid=0 --events=execve,open,tcp,uprobe --sampling=1

run-ui:
	python ui/main.py

clean:
	rm -rf bin/*
	rm -f bpf/*.o
	rm -f proto/*.pb.go
	rm -f ui/proto/*_pb2.py ui/proto/*_pb2_grpc.py
