package main

import (
    "debug/elf"
    "errors"
    "fmt"
    "log"
    "unsafe"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

type UprobeManager struct {
    links    map[string]link.Link      // Ключ: binary:function:pid
    prog     *ebpf.Program
    uconfMap *ebpf.Map                 // карта uprobe_configs
}

func NewUprobeManager(coll *ebpf.Collection) (*UprobeManager, error) {
    prog := coll.Programs["handle_generic_uprobe"]
    if prog == nil {
        return nil, errors.New("eBPF program 'handle_generic_uprobe' not found")
    }
    uconf := coll.Maps["uprobe_configs"]
    if uconf == nil {
        return nil, errors.New("eBPF map 'uprobe_configs' not found")
    }
    return &UprobeManager{
        links:    make(map[string]link.Link),
        prog:     prog,
        uconfMap: uconf,
    }, nil
}

// Добавляет uprobe на указанную функцию указанного бинаря, с фильтром PID (0 = для всех)
func (m *UprobeManager) AddUprobe(pid int, binaryPath, functionName string) error {
    // 1. Открываем ELF для поиска смещения (адреса) функции
    ex, err := elf.Open(binaryPath)
    if err != nil {
        return fmt.Errorf("open ELF: %w", err)
    }
    defer ex.Close()

    symbols, err := ex.Symbols()
    if err != nil {
        return fmt.Errorf("get symbols: %w", err)
    }
    var funcAddr uint64
    for _, sym := range symbols {
        if sym.Name == functionName {
            funcAddr = sym.Value
            break
        }
    }
    if funcAddr == 0 {
        return fmt.Errorf("function '%s' not found in %s", functionName, binaryPath)
    }

    // 2. Подключаем eBPF-программу к этой функции через uprobe
    exe, err := link.OpenExecutable(binaryPath)
    if err != nil {
        return fmt.Errorf("open executable: %w", err)
    }
    opts := link.UprobeOptions{PID: pid}
    uprobe, err := exe.Uprobe(functionName, m.prog, &opts)
    if err != nil {
        return fmt.Errorf("attach uprobe: %w", err)
    }

    // 3. Кладем ключ/значение в eBPF map для привязки адреса к имени
    key := (uint64(pid) << 32) | funcAddr
    value := make([]byte, 64)
    copy(value, []byte(functionName))
    if err := m.uconfMap.Put(unsafe.Pointer(&key), unsafe.Pointer(&value[0])); err != nil {
        return fmt.Errorf("update uprobe_configs map: %w", err)
    }

    m.links[fmt.Sprintf("%s:%s:%d", binaryPath, functionName, pid)] = uprobe
    log.Printf("UPROBE attached: %s:%s (pid=%d, addr=0x%x)", binaryPath, functionName, pid, funcAddr)
    return nil
}

// Удаляет все активные uprobes и очищает карту
func (m *UprobeManager) RemoveAll() {
    for key, l := range m.links {
        l.Close()
        log.Printf("UPROBE detached: %s", key)
    }
    m.links = make(map[string]link.Link)
    // Очистка карты (по желанию)
    // m.uconfMap.BatchDelete(...)
}
