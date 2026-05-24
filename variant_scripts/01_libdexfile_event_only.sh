#!/system/bin/sh
set -eu
WORKDIR=/data/local/tmp/ebpfDumpDex/variants/01_libdexfile_event_only
OUTDIR="$WORKDIR/out"
cd "$WORKDIR"
setenforce 0 2>/dev/null || true
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
pkill dex_dump_bin 2>/dev/null || true
rm -rf "$OUTDIR" "$WORKDIR/dexdump.log"
mkdir -p "$OUTDIR"
id > "$WORKDIR/dexdump.log"
cat /proc/self/status | grep '^Cap' >> "$WORKDIR/dexdump.log"
cat /proc/self/attr/current >> "$WORKDIR/dexdump.log"
getenforce >> "$WORKDIR/dexdump.log"
./dex_dump_bin -obj "$WORKDIR/dex_dump.bpf.o" -lib /apex/com.android.art/lib64/libdexfile.so -out "$OUTDIR" -max-dump 0 >> "$WORKDIR/dexdump.log" 2>&1 &
echo started:$! >> "$WORKDIR/dexdump.log"
