# android_eBPF_dump_dex

Android ARM64 eBPF uprobe DEX dumper.

## Build

GitHub Actions builds two artifacts:

- `dex_dump.bpf.o`: eBPF bytecode
- `dex_dump_bin`: Android ARM64 user-space loader/dumper

Run the `Build Android eBPF Dex Dumper` workflow manually from Actions, or push to `main`.

## Deploy

```powershell
adb push dex_dump.bpf.o /data/local/tmp/
adb push dex_dump_bin /data/local/tmp/
adb shell chmod +x /data/local/tmp/dex_dump_bin
```

## Run

```bash
adb shell
su
setenforce 0
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug
cd /data/local/tmp
./dex_dump_bin -package com.example.target
```

If the package is already running, `-package` filters events by PID. Without `-package`, all DEX load events are observed.

Dumped files are written to `/data/local/tmp/dump_pid_<pid>_<base>.dex`.

Pull results:

```powershell
adb pull /data/local/tmp/dump_pid_<pid>_<base>.dex .
```

Useful flags:

- `-obj`: path to `dex_dump.bpf.o`
- `-libart`: path to `libart.so`, default `/apex/com.android.art/lib64/libart.so`
- `-out`: dump output directory, default `/data/local/tmp`
- `-package`: optional Android package name filter
