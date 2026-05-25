#!/system/bin/sh
set -eu

SCRIPT_DIR=${0%/*}
if [ "$SCRIPT_DIR" = "$0" ]; then
  SCRIPT_DIR=$(pwd)
fi
case "$SCRIPT_DIR" in
  /*) ;;
  *) SCRIPT_DIR="$(pwd)/$SCRIPT_DIR" ;;
esac

WORKDIR=${WORKDIR:-$SCRIPT_DIR}
BIN="$WORKDIR/dex_dump_bin"
OBJ="$WORKDIR/dex_dump.bpf.o"
LOG="$WORKDIR/dexdump.log"
PIDFILE="$WORKDIR/dexdump.pid"
LIB=${LIB:-/apex/com.android.art/lib64/libdexfile.so}
OUT=${OUT:-$WORKDIR}
MAX_DUMP=${MAX_DUMP:-0}
EXTRA_ARGS=${EXTRA_ARGS:-}

usage() {
  echo "Usage: $0 [run|start|stop|restart|status|logs]"
  echo "  run      Run in foreground; Ctrl-C stops dex_dump_bin. Default."
  echo "  start    Run in background and write $PIDFILE."
  echo "  stop     Stop the pid recorded in $PIDFILE."
  echo "  restart  Stop then start in background."
  echo "  status   Show current process status."
  echo "  logs     Follow $LOG."
  echo "Environment: WORKDIR LIB OUT MAX_DUMP EXTRA_ARGS"
}

pid_from_file() {
  [ -f "$PIDFILE" ] || return 1
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  [ -n "$pid" ] || return 1
  case "$pid" in
    *[!0-9]*) return 1 ;;
  esac
  echo "$pid"
}

is_running_pid() {
  check_pid=$1
  [ -d "/proc/$check_pid" ] || return 1
  cmdline=$(tr '\000' ' ' < "/proc/$check_pid/cmdline" 2>/dev/null || true)
  case "$cmdline" in
    *dex_dump_bin*) return 0 ;;
    *) return 1 ;;
  esac
}

running_pid() {
  pid=$(pid_from_file) || return 1
  is_running_pid "$pid" || return 1
  echo "$pid"
}

prepare_env() {
  cd "$WORKDIR"
  [ -x "$BIN" ] || { echo "missing executable: $BIN" >&2; exit 1; }
  [ -f "$OBJ" ] || { echo "missing eBPF object: $OBJ" >&2; exit 1; }

  setenforce 0 2>/dev/null || true
  mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
}

write_diag() {
  : > "$LOG"
  id >> "$LOG" 2>&1 || true
  grep '^Cap' /proc/self/status >> "$LOG" 2>&1 || true
  cat /proc/self/attr/current >> "$LOG" 2>&1 || true
  getenforce >> "$LOG" 2>&1 || true
}

clean_old_dumps() {
  find "$OUT" -mindepth 1 -maxdepth 2 -name 'dump_pid_*.dex' -delete 2>/dev/null || true
}

stop_dumper() {
  pid=$(running_pid 2>/dev/null || true)
  if [ -z "$pid" ]; then
    rm -f "$PIDFILE"
    echo "not running"
    return 0
  fi

  echo "stopping pid $pid"
  kill "$pid" 2>/dev/null || true
  i=0
  while is_running_pid "$pid" && [ "$i" -lt 30 ]; do
    sleep 1
    i=$((i + 1))
  done
  if is_running_pid "$pid"; then
    echo "pid $pid did not exit; sending SIGKILL"
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
}

start_background() {
  prepare_env
  pid=$(running_pid 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "already running: pid $pid"
    echo "log: $LOG"
    return 0
  fi

  clean_old_dumps
  write_diag
  "$BIN" \
    -obj "$OBJ" \
    -lib "$LIB" \
    -out "$OUT" \
    -max-dump "$MAX_DUMP" \
    -scan \
    $EXTRA_ARGS \
    >> "$LOG" 2>&1 &
  pid=$!
  echo "$pid" > "$PIDFILE"
  echo "started pid $pid"
  echo "log: $LOG"
  echo "stop: $0 stop"
}

run_foreground() {
  prepare_env
  pid=$(running_pid 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "already running in background: pid $pid"
    echo "stop it first: $0 stop"
    exit 1
  fi

  clean_old_dumps
  write_diag
  echo "running in foreground; press Ctrl-C to stop"
  echo "log: $LOG"

  "$BIN" \
    -obj "$OBJ" \
    -lib "$LIB" \
    -out "$OUT" \
    -max-dump "$MAX_DUMP" \
    -scan \
    $EXTRA_ARGS \
    >> "$LOG" 2>&1 &
  pid=$!
  echo "$pid" > "$PIDFILE"

  trap 'kill "$pid" 2>/dev/null || true; rm -f "$PIDFILE"; exit 130' INT TERM
  wait "$pid" || rc=$?
  rm -f "$PIDFILE"
  exit "${rc:-0}"
}

show_status() {
  pid=$(running_pid 2>/dev/null || true)
  if [ -n "$pid" ]; then
    echo "running: pid $pid"
    echo "log: $LOG"
  else
    rm -f "$PIDFILE"
    echo "not running"
  fi
}

follow_logs() {
  touch "$LOG"
  tail -f "$LOG"
}

cmd=${1:-run}
case "$cmd" in
  run) run_foreground ;;
  start) start_background ;;
  stop) stop_dumper ;;
  restart) stop_dumper; start_background ;;
  status) show_status ;;
  logs) follow_logs ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac
