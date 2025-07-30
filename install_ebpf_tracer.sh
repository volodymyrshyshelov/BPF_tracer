#!/bin/bash
set -e

echo "=== [1/10] Обновление пакетов и установка системных зависимостей ==="
sudo apt update
sudo apt install -y \
    clang llvm libelf-dev libbpf-dev libc6-dev-i386 gcc-multilib \
    python3-pip linux-headers-$(uname -r) protobuf-compiler

echo "=== [2/10] Установка Python-зависимостей ==="
python3 -m pip install --break-system-packages --upgrade pip
python3 -m pip install --break-system-packages grpcio grpcio-tools PyQt6

echo "=== [3/10] Проверка/установка Go $GO_VERSION ==="
GO_VERSION="1.23.3"
INSTALLED_GO=$(go version 2>/dev/null || echo "")

if [[ "$INSTALLED_GO" != *"$GO_VERSION"* ]]; then
    echo "ℹ️ Устанавливаю Go $GO_VERSION"
    GO_ARCHIVE="go$GO_VERSION.linux-amd64.tar.gz"
    wget -q https://go.dev/dl/$GO_ARCHIVE -O /tmp/$GO_ARCHIVE
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/$GO_ARCHIVE
else
    echo "✅ Go $GO_VERSION уже установлен"
fi

# Добавление в PATH, если нужно
if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi
export PATH=$PATH:/usr/local/go/bin
echo "Go версия: $(go version)"

echo "=== [4/10] Инициализация go.mod (если нужно) ==="
if [ ! -f go.mod ]; then
    go mod init ebpf-tracer
    echo "✅ go.mod создан"
else
    echo "ℹ️ go.mod уже существует"
fi

echo "=== [5/10] Установка protoc-gen-go и protoc-gen-go-grpc ==="
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

GOBIN=$(go env GOPATH)/bin
if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    echo "export PATH=\"\$PATH:$GOBIN\"" >> ~/.bashrc
    export PATH="$PATH:$GOBIN"
fi

echo "protoc-gen-go версия: $($GOBIN/protoc-gen-go --version || echo 'не найден')"
echo "protoc-gen-go-grpc версия: $($GOBIN/protoc-gen-go-grpc --version || echo 'не найден')"

echo "=== [6/10] Установка bpftool (если не установлен) ==="
if ! command -v bpftool >/dev/null; then
    sudo apt install -y linux-tools-$(uname -r) linux-tools-common || true
    if [ -x "/usr/lib/linux-tools-$(uname -r)/bpftool" ]; then
        sudo cp "/usr/lib/linux-tools-$(uname -r)/bpftool" /usr/local/bin/
        echo "✅ bpftool скопирован вручную"
    else
        echo "⚠️ Сборка bpftool из исходников"
        sudo apt install -y git build-essential flex bison libz-dev pahole
        git clone --depth=1 https://github.com/torvalds/linux.git /tmp/linux-src
        cd /tmp/linux-src/tools/bpf/bpftool
        make
        sudo cp ./bpftool /usr/local/bin/
        cd -
    fi
fi
echo "bpftool версия: $(bpftool version)"

echo "=== [7/10] Генерация bpf/vmlinux.h ==="
if [ -f /sys/kernel/btf/vmlinux ]; then
    mkdir -p bpf
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
    echo "✅ vmlinux.h успешно сгенерирован"
else
    echo "❌ Не найден /sys/kernel/btf/vmlinux — ядро без BTF"
    exit 1
fi

echo "=== [8/10] Проверка наличия go_package в proto/tracer.proto ==="
PROTO_FILE="proto/tracer.proto"
if ! grep -q "option go_package" "$PROTO_FILE"; then
    sed -i '1ioption go_package = "ebpf-tracer/proto;proto";' "$PROTO_FILE"
    echo "✅ Вставлен option go_package в $PROTO_FILE"
else
    echo "ℹ️ go_package уже указан"
fi

echo "=== [9/10] Удаление повреждённого tracer.pb.go ==="
PB_GO_FILE="cmd/tracer/tracer.pb.go"
if [ -f "$PB_GO_FILE" ] && [ ! -s "$PB_GO_FILE" ]; then
    echo "⚠️ Повреждённый $PB_GO_FILE найден — удаляю..."
    rm -f "$PB_GO_FILE"
fi

echo "=== Генерация gRPC файлов ==="
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/tracer.proto

python3 -m grpc_tools.protoc -Iproto --python_out=ui --grpc_python_out=ui proto/tracer.proto

echo "=== [10/10] Сборка проекта ==="
go mod tidy
if ! make; then
    echo "❌ Сборка не удалась. Проверь вывод ошибок."
    exit 1
fi

echo ""
echo "✅ Установка и сборка завершены!"
echo "========================= ИНСТРУКЦИЯ ========================="
echo "1. Перезапусти терминал или выполни:"
echo "   source ~/.bashrc"
echo ""
echo "2. Запуск трассировщика (от root):"
echo "   sudo ./bin/tracer --pid=0 --events=execve,open,tcp,uprobe --sampling=1"
echo ""
echo "3. Запуск UI (в другом терминале):"
echo "   python3 ui/main.py"
echo "=============================================================="
