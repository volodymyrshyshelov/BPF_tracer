#!/bin/bash
set -e

echo "=== [1/12] Update packages and install base dependencies ==="
sudo apt update
sudo apt install -y \
    git build-essential flex bison clang llvm \
    libelf-dev libbpf-dev zlib1g-dev pahole \
    libc6-dev-i386 gcc-multilib \
    python3 python3-pip python3-venv \
    linux-headers-$(uname -r) \
    protobuf-compiler wget

echo "=== [2/12] Upgrade pip and install Python dependencies ==="
python3 -m pip install --upgrade pip --break-system-packages
python3 -m pip install --break-system-packages grpcio grpcio-tools PyQt6

echo "=== [3/12] Check/Install Go 1.23.3 ==="
GO_VERSION="1.23.3"
INSTALLED_GO=$(go version 2>/dev/null || echo "")
if [[ "$INSTALLED_GO" != *"$GO_VERSION"* ]]; then
    echo "Installing Go $GO_VERSION"
    GO_ARCHIVE="go$GO_VERSION.linux-amd64.tar.gz"
    wget -q https://go.dev/dl/$GO_ARCHIVE -O /tmp/$GO_ARCHIVE
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/$GO_ARCHIVE
else
    echo "Go $GO_VERSION already installed"
fi
if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi
export PATH=$PATH:/usr/local/go/bin
echo "Go version: $(go version)"

echo "=== [4/12] go.mod initialization ==="
if [ ! -f go.mod ]; then
    go mod init ebpf-tracer
    echo "go.mod created"
else
    echo "go.mod already exists"
fi

echo "=== [5/12] Install protoc-gen-go and protoc-gen-go-grpc ==="
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

GOBIN=$(go env GOPATH)/bin
if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo "export PATH=\"\$PATH:$GOBIN\"" >> ~/.bashrc
    export PATH="$PATH:$GOBIN"
fi
echo "protoc-gen-go version: $($GOBIN/protoc-gen-go --version || echo 'not found')"
echo "protoc-gen-go-grpc version: $($GOBIN/protoc-gen-go-grpc --version || echo 'not found')"

echo "=== [6/12] Install bpftool if not found ==="
if ! command -v bpftool >/dev/null; then
    echo "Building bpftool from source (linux kernel tools)"
    sudo apt install -y git build-essential flex bison zlib1g-dev pahole
    git clone --depth 1 https://github.com/torvalds/linux.git /tmp/linux-src
    cd /tmp/linux-src/tools/bpf/bpftool
    make
    sudo cp ./bpftool /usr/local/bin/
    cd -
else
    echo "bpftool is already installed"
fi
bpftool version && echo "bpftool installed successfully"

echo "=== [7/12] Generate bpf/vmlinux.h ==="
if [ -f /sys/kernel/btf/vmlinux ]; then
    mkdir -p bpf
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
    echo "vmlinux.h generated"
else
    echo "ERROR: /sys/kernel/btf/vmlinux not found (BTF kernel required)"
    exit 1
fi

echo "=== [8/12] Check go_package in proto/tracer.proto ==="
PROTO_FILE="proto/tracer.proto"
if ! grep -q "option go_package" "$PROTO_FILE"; then
    sed -i '1ioption go_package = "ebpf-tracer/proto;proto";' "$PROTO_FILE"
    echo "Inserted option go_package in $PROTO_FILE"
else
    echo "go_package already present"
fi

echo "=== [9/12] Remove broken tracer.pb.go if exists ==="
PB_GO_FILE="cmd/tracer/tracer.pb.go"
if [ -f "$PB_GO_FILE" ] && [ ! -s "$PB_GO_FILE" ]; then
    echo "Broken $PB_GO_FILE found, removing..."
    rm -f "$PB_GO_FILE"
fi

echo "=== [10/12] Generate gRPC/proto files ==="
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/tracer.proto
python3 -m grpc_tools.protoc -Iproto --python_out=ui --grpc_python_out=ui proto/tracer.proto

echo "=== [11/12] go mod tidy ==="
go mod tidy

echo "=== [12/12] Build the project ==="
if ! make; then
    echo "❌ Build failed. See output above."
    exit 1
fi

echo ""
echo "✅ Install and build complete!"
echo "===================== INSTRUCTIONS ====================="
echo "1. Restart your terminal or run:"
echo "   source ~/.bashrc"
echo ""
echo "2. Run tracer (as root):"
echo "   sudo ./bin/tracer --pid=0 --events=execve,open,read,write,accept,connect,clone,exit,tcp_conn,uprobe --sampling=1"
echo ""
echo "3. Run UI (in another terminal):"
echo "   python3 ui/main.py"
echo "========================================================"

