# eBPF Tracer (Proof of Concept)

**eBPF Tracer** is an advanced proof-of-concept tracing system with a PyQt6 GUI for monitoring Linux system events in real time. It uses eBPF kernel programs to capture various events (system calls, network connections, etc.) and a Go-based user-space daemon to collect these events and serve them via gRPC to a PyQt6 client application. This allows you to trace processes and network activity and visualize the events live with a graphical interface.

---

## Features

* **System call tracing:** Tracks various syscalls such as process execution, file opens, file reads/writes, process cloning/exiting, etc. (e.g. `execve`, `open`, `read`, `write`, `clone`, `exit_group`)
* **Network monitoring:** Captures TCP connection events (e.g. connect calls with source/destination IP and port)
* **User-space function tracing:** Supports dynamic uprobes to trace specific functions in user-space binaries (specify a binary and function to probe at runtime)
* **Event filtering:** Ability to filter events by process ID or event type, to focus on specific processes or types of events
* **Event sampling:** Configurable sampling rate to reduce overhead by processing only a fraction of events (useful under high event rates)
* **PyQt6 UI:** A graphical interface that displays a live table of events with details. The UI allows filtering by PID or event type and provides a details pane for each event (for example, showing filenames, socket addresses, function arguments, etc.)

---

## Requirements

* **Operating System:** Linux (tested on Debian 11 and Ubuntu 22.04). Other distributions have not been tested. Ensure your kernel is version 5.8 or above. The kernel must have BTF (BPF Type Format) enabled, as the eBPF code relies on `/sys/kernel/btf/vmlinux` for type information. Modern Ubuntu/Debian kernels meet this requirement.
* **System Packages:** You will need development tools and libraries installed, including clang/LLVM (10+), GCC, make, Linux kernel headers, and eBPF libraries like libelf and libbpf. On Debian/Ubuntu, these can be installed via apt (see Installation steps below).
* **Go:** Go version 1.18 or higher (project was tested with Go 1.23.3). Go is required to build and run the tracer program.
* **Python:** Python 3.8+ (tested with Python 3.10). The UI is written in Python and requires PyQt6 for the GUI and gRPC (grpcio) for communication. These Python packages will be installed via pip in the setup steps.
* **Privileges:** Root privileges are required to run the tracer (because eBPF programs need privileged access). Ensure you can use sudo or have root access on the system.

---

## Installation (Setup)

Follow these steps to download and build eBPF Tracer on a Debian/Ubuntu system:

### 1. Clone the Repository

```bash
git clone https://github.com/volodymyrshyshelov/BPF_tracer.git
cd BPF_tracer
```

### 2. Run the Install Script

```bash
chmod +x install.sh start.sh   # Ensure scripts are executable
./install.sh
```

The install script will update your package lists and install all necessary system packages (Git, build tools, clang, ELF and BPF libraries, kernel headers, etc.). It will also upgrade pip and install Python packages (PyQt6, grpcio). Next, it checks for Go (and installs Go 1.23.3 if not already installed) and sets up your PATH. The script then installs the protoc plugins for Go gRPC, ensures bpftool is available (building it from source if needed), and generates a BTF header (`vmlinux.h`) from your running kernel. Finally, it compiles the gRPC proto files and builds the project using the Makefile. This process may take a few minutes.

**Note:** If the script completes successfully, you will see a `✅ Install and build complete!` message. The binary `./bin/tracer` (the Go tracer program) and other build outputs will be ready. The script’s output also reminds you to update your shell environment and how to run the tracer and UI. In particular, it’s recommended to open a new terminal or run `source ~/.bashrc` before using the tracer. This ensures your PATH is updated (especially if Go was installed by the script). You are now ready to run the tracer.

---

## Usage

After installation, the project provides two components that work together: the tracer (command-line tool) and the UI. You will typically run the tracer in one terminal (with root privileges) and the UI in another (as a regular user). There are two ways to start them:

### Option 1: Automatic Launch via start.sh

For convenience, you can use the provided `start.sh` script to launch the tracer and UI in separate terminals automatically. Run the script in the project directory:

```bash
./start.sh
```

This will present an interactive prompt in the terminal to choose the tracer mode:

* **Full trace** – traces all supported events (`execve`, `open`, `read`, `write`, `accept`, `connect`, `clone`, `exit`, `tcp_conn`, `uprobe`)
* **Custom filter** – lets you specify which event types to trace, a PID filter, sampling rate, and any uprobes to attach
* **Uprobes only** – traces only user-space functions that you specify (via uprobes)

After you enter a choice (and any required parameters for options 2 or 3), the script will open two new terminal windows automatically. One terminal will start the tracer with the chosen options, and the second will launch the PyQt6 UI. You will see output indicating that the tracer has started and the UI is running. The UI window should appear shortly after.

> **Note:** The `start.sh` script tries to use common terminal emulators (like `gnome-terminal`, `xfce4-terminal`, `konsole`, etc.) to open new windows. Make sure you have one of these installed on your system. If no suitable terminal is found, the script will print an error "No suitable terminal emulator found!" and exit. In that case, or if you are on a headless system, use the manual launch method described below.

### Option 2: Manual Launch

You can also run the tracer and UI manually. Open two terminal windows (or tabs):

#### Terminal 1 – Run the tracer:

Start the tracer with root privileges and specify your desired options. For example, to trace all events on the entire system, use:

```bash
# Terminal 1: Start tracer (as root)
sudo ./bin/tracer --pid=0 --events=execve,open,read,write,accept,connect,clone,exit,tcp_conn,uprobe --sampling=1
```

This command runs the tracer with no PID filter (`--pid=0`) and with all event types enabled, capturing every event (`--sampling=1`). The `--events` flag accepts a comma-separated list of event types; you can adjust it to trace only specific events (for instance, use `--events=execve,open` to trace only program execs and file opens). Likewise, you can set `--pid=<PID>` to trace only a specific process by PID (or leave it as 0 for all processes).

**Advanced:** To trace user-space functions, include the `--events=uprobe` event type and use the `--uprobes` flag. For example:

```bash
sudo ./bin/tracer --pid=0 --events=uprobe --uprobes="/usr/bin/myapp:myFunction"
```

This would attach an uprobe to the function `myFunction` in the binary `/usr/bin/myapp` (for all processes). You can specify multiple uprobes by separating them with commas, and you can target a specific process by appending its PID (e.g. `--uprobes="/usr/bin/myapp:myFunction:1234"` to trace only that function in the process with PID 1234).

#### Terminal 2 – Run the UI:

In a second terminal (no root needed), launch the Python GUI:

```bash
# Terminal 2: Start the PyQt6 UI
python3 ui/main.py
```

The GUI should appear, showing an empty table initially. Once the tracer (Terminal 1) is running, you will see events streaming into the table in real time. Each row is an event with columns for Time, Type, PID, Command (process name), and Details. If you selected "Full trace", you might immediately see events like the sudo command execution or other system activity appear.

---

## While Running

* **Tracer output:** The tracer will print initialization logs (listing loaded eBPF programs). It writes all captured events to a log file `events.log` in the project directory. It will run continuously, outputting a message when it starts and when it is stopped (with Ctrl+C). You typically won’t see every event in the terminal, as events are sent to the UI and log file rather than printed to stdout. If the tracer encounters an error or is misconfigured, it will print error messages (and in many cases exit). For example, if it cannot load the eBPF program, it will log an error and terminate. Generally, if the tracer prints "Tracer started. Press Ctrl+C to stop...", it means everything is working and you can proceed to use the UI.

* **Using the UI:** The PyQt6 GUI will display incoming events in a table. You can click on an event to view more details (such as file paths, flags, socket addresses, or function arguments) in the details pane below the table. The UI also provides controls to filter the view: at the top, there are text boxes or drop-downs to filter by PID and event type, and a search box to filter by keywords in the Details. For example, you can enter a PID number to see events only from that process, or select an event type (like "OPEN") to see only file open events. You can also type text (e.g. a filename) to search within the details column. The UI will highlight new events briefly to make them easier to spot. It will automatically limit the table to a certain number of events (to avoid memory growth), but you can scroll up to see recent history. To stop the tracing session, simply close the UI window and press Ctrl+C in the terminal running the tracer. (Closing the tracer will also cause the UI to stop receiving events.)

---

## Troubleshooting & Common Issues

* **BTF/vmlinux not found:** If the install script exits with an error like `/sys/kernel/btf/vmlinux not found (BTF kernel required)`, it means your system is missing BTF debug info. The eBPF tracer needs BTF type information from the kernel. This is usually available by default on newer distributions (e.g. Ubuntu 22.04, Debian 11). If you encounter this on a custom or older kernel, ensure that the kernel is compiled with `CONFIG_DEBUG_INFO_BTF=y`. On Debian/Ubuntu, installing the appropriate `linux-headers-<version>` package and running a recent kernel should provide the `/sys/kernel/btf/vmlinux` file. Without BTF, the eBPF programs cannot be loaded.
* **No terminal emulator (`start.sh` error):** When using `start.sh`, you might see "ERROR: No suitable terminal emulator found!". This means the script couldn’t find a program to launch new terminal windows. To fix this, install one of the supported terminal programs (for example, `sudo apt install -y gnome-terminal` on Ubuntu) or simply launch the tracer and UI manually as described above. This issue typically occurs on minimal systems or headless servers. If you are running without a GUI, you should use the manual launch method and perhaps run the UI on a machine with display access (or use X11 forwarding/VNC to view the GUI remotely).
* **Permission errors:** If you run the tracer without root privileges, it will fail to load the eBPF programs (you may see an error like "Failed to load eBPF" and the program will exit). Always run bin/tracer with sudo (or as root). Likewise, the install script uses sudo internally for package installation – ensure your user is in the sudoers list. If you cannot run with root, the tracer will not function (unprivileged eBPF is not yet widely available for this use-case).
* **PyQt cannot connect or display:** The UI connects to the tracer via gRPC on localhost. If the tracer isn’t running, the UI will not show new events (and may log connection errors). Always start the tracer first, then the UI. Also, ensure you have a graphical environment for the UI. If you try to run ui/main.py on a system without an X display (GUI), it will fail to initialize the Qt GUI. In such cases, you need to run it in an environment with a display (or with proper display forwarding).
* **Build or dependency issues:** The provided install.sh script should handle all building steps. However, if the build fails (❌ you see "Build failed" in the script output), or if you choose to build manually and encounter errors, here are some tips:

  * Make sure all required packages are installed (see the apt install command in the installation step). Missing development libraries or tools will cause build errors.
  * Verify that the Go version is correct (`go version`). If it’s older than 1.18, install the newer Go as shown in the script (the code uses modern Go features).
  * If the proto generation step fails or Go complains about missing protobuf/grpc code, ensure that protoc is installed and that you have run the generation commands. The install script runs protoc and also inserts a go\_package option into the proto file if needed to fix import issues. If you update proto/tracer.proto, re-run the install script or `make generate-proto` to regenerate the gRPC code.
  * For any other build issues, clean the build (`make clean`) and try running the steps again. You can also open an issue on the repository if you need help.
* **Runtime performance:** Tracing all events with `sampling=1` can produce a lot of data, especially on a busy system. If you notice high CPU usage or the system slowing down, consider reducing the scope: use a PID filter to trace only a specific process, limit the event types, or increase the sampling rate (e.g. `--sampling=10` to process 1 out of 10 events). The UI is also buffering events; by default it keeps up to 10,000 events in the table. After long runs, older events will be dropped from the UI (but still in the events.log). These defaults can be adjusted in the code (see `ui/main.py`) if necessary.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details. You are free to use, modify, and distribute this software under the terms of the MIT license.

---

Happy tracing! If you follow the steps above, you should be able to clone the repository and get the eBPF tracer running on your system. For any questions or suggestions, feel free to reach out or open an issue on the GitHub repository. Enjoy exploring system calls and more with eBPF Tracer!
