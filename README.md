# eBPF Tracer PoC

Advanced eBPF tracer with PyQt6 UI for system monitoring

## Features
- System call tracing (execve, open)
- Network connection monitoring (TCP)
- Uprobes for application tracing
- Filtering by PID/event type
- Sampling for performance
- PyQt6 UI with event table and details

## Requirements
- Linux kernel 5.8+
- clang 10+
- Go 1.18+
- Python 3.8+

## Installation
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y clang llvm libelf-dev libbpf-dev libc6-dev-i386 gcc-multilib

# Install Go
wget https://go.dev/dl/go1.20.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.20.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install Python dependencies
pip install PyQt6 grpcio