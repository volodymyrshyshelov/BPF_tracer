#!/bin/bash

# ===== CONFIGURABLE DEFAULTS =====
TRACER_CMD="sudo ./bin/tracer"
UI_CMD="python3 ui/main.py"
WAIT_UI_SEC=3     # Wait time before launching UI (in seconds)

# ======= TERMINAL DETECTION =======
find_terminal() {
    if command -v gnome-terminal &>/dev/null; then
        echo "gnome-terminal -- bash -c"
    elif command -v xfce4-terminal &>/dev/null; then
        echo "xfce4-terminal -e"
    elif command -v konsole &>/dev/null; then
        echo "konsole -e"
    elif command -v x-terminal-emulator &>/dev/null; then
        echo "x-terminal-emulator -e"
    else
        echo ""
    fi
}

TERMINAL_CMD=$(find_terminal)
if [[ -z "$TERMINAL_CMD" ]]; then
    echo "ERROR: No suitable terminal emulator found! Please install gnome-terminal, xfce4-terminal, konsole, or x-terminal-emulator."
    exit 1
fi

# ====== MODE SELECTION ======
echo "Choose tracer mode:"
echo "  1) Full trace (all events: execve, open, read, write, accept, connect, clone, exit, tcp_conn, uprobe)"
echo "  2) Custom filter"
echo "  3) Only user-space functions (uprobes)"
echo ""
read -p "Enter your choice [1/2/3]: " MODE

TRACER_OPTS=""
UPROBES_OPT=""

case $MODE in
    1)
        TRACER_OPTS="--pid=0 --events=execve,open,read,write,accept,connect,clone,exit,tcp_conn,uprobe --sampling=1"
        ;;
    2)
        read -p "Enter event types (comma-separated, e.g. open,execve,uprobe): " EVENTS
        read -p "Enter PID filter (0 = all): " PID
        read -p "Enter sampling rate (default 1): " SAMPLING
        read -p "Enter uprobes (leave blank if not needed): " UPROBES
        [ -z "$PID" ] && PID=0
        [ -z "$SAMPLING" ] && SAMPLING=1
        TRACER_OPTS="--pid=$PID --events=$EVENTS --sampling=$SAMPLING"
        if [ -n "$UPROBES" ]; then
            UPROBES_OPT="--uprobes='$UPROBES'"
        fi
        ;;
    3)
        read -p "Enter uprobes (format: /path/to/bin:Function1,/path/to/bin:Function2): " UPROBES
        TRACER_OPTS="--pid=0 --events=uprobe --sampling=1"
        if [ -n "$UPROBES" ]; then
            UPROBES_OPT="--uprobes='$UPROBES'"
        fi
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac

# ==== LAUNCH PROCESSES ====
echo ""
echo "Starting tracer in new terminal:"
echo "$TRACER_CMD $TRACER_OPTS $UPROBES_OPT"
eval "$TERMINAL_CMD \"$TRACER_CMD $TRACER_OPTS $UPROBES_OPT; exec bash\" &"

# Wait for tracer to start before launching UI
echo "Waiting $WAIT_UI_SEC seconds for tracer to initialize..."
sleep $WAIT_UI_SEC

echo "Starting UI in new terminal:"
echo "$UI_CMD"
eval "$TERMINAL_CMD \"$UI_CMD; exec bash\" &"

echo ""
echo "Both tracer and UI started in separate terminals."
echo "If you don't see output, check that your terminal emulator supports -e/bash -c syntax."
