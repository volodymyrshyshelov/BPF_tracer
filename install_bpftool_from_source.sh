#!/bin/bash

echo "=== Установка зависимостей для сборки bpftool ==="
sudo apt update
sudo apt install -y git build-essential flex bison libelf-dev libbpf-dev clang llvm libz-dev pahole

echo "=== Клонирование исходников ядра Linux ==="
git clone --depth 1 https://github.com/torvalds/linux.git /tmp/linux-src
cd /tmp/linux-src/tools/bpf/bpftool || exit 1

echo "=== Сборка bpftool ==="
make

echo "=== Установка bpftool в /usr/local/bin ==="
sudo cp bpftool /usr/local/bin/
bpftool version && echo "✅ bpftool успешно установлен"
