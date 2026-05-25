# android_eBPF_dump_dex

Android ARM64 eBPF uprobe DEX dumper.

## Quick Start

Use `run_dexdump_full.sh` on the device. Put these files in the same directory:

```text
/data/local/tmp/dex_dump_bin
/data/local/tmp/dex_dump.bpf.o
/data/local/tmp/run_dexdump_full.sh
```

Deploy:

```powershell
adb push dex_dump.bpf.o /data/local/tmp/
adb push dex_dump_bin /data/local/tmp/
adb push run_dexdump_full.sh /data/local/tmp/
adb shell chmod +x /data/local/tmp/dex_dump_bin /data/local/tmp/run_dexdump_full.sh
```

Run from a device-side root shell with full capabilities:

```bash
adb shell
su
cd /data/local/tmp
./run_dexdump_full.sh run
```

Background mode:

```bash
cd /data/local/tmp
./run_dexdump_full.sh start
./run_dexdump_full.sh logs
./run_dexdump_full.sh stop
```

The script automatically:

- switches SELinux to permissive if allowed
- mounts `tracefs` or `debugfs`
- checks `dex_dump_bin` and `dex_dump.bpf.o`
- writes diagnostics to `dexdump.log`
- cleans old `dump_pid_*.dex` files
- runs with `-scan`
- dumps full DEX files by default with `MAX_DUMP=0`

Useful script environment variables:

- `EXTRA_ARGS`: extra arguments passed to `dex_dump_bin`, for example `-symbol ...` or `-offset 0x...`
- `MAX_DUMP`: max bytes to dump per DEX region. Default is `0`, meaning full dump
- `LIB`: ART DEX library path. Default is `/apex/com.android.art/lib64/libdexfile.so`
- `OUT`: dump output directory. Default is the script directory
- `WORKDIR`: directory containing `dex_dump_bin` and `dex_dump.bpf.o`. Default is the script directory

Examples:

```bash
./run_dexdump_full.sh run
MAX_DUMP=65536 ./run_dexdump_full.sh run
EXTRA_ARGS="-symbol '_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE'" ./run_dexdump_full.sh run
EXTRA_ARGS="-offset 0x19a90" ./run_dexdump_full.sh run
```

Pull results:

```powershell
adb pull /data/local/tmp .
adb pull /data/local/tmp/dexdump.log .
```

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

Run from a device-side root shell with full capabilities. On some devices, `adb shell su -c` inherits `adbd`'s limited capability bounding set and cannot load eBPF programs.

Basic run:

```bash
adb shell
su
setenforce 0
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug
cd /data/local/tmp
./dex_dump_bin -lib /apex/com.android.art/lib64/libdexfile.so -package com.example.target -max-dump 65536
```

If the package is already running, `-package` resolves the current PID and filters events to that PID. If the app starts after the dumper, either start the dumper without `-package`, or start the app first and then run the dumper with `-package`.

Without `-package`, all DEX load events are observed:

```bash
./dex_dump_bin -lib /apex/com.android.art/lib64/libdexfile.so -max-dump 65536
```

Use an explicit symbol when testing a symbol found with `readelf`:

```bash
./dex_dump_bin \
  -lib /apex/com.android.art/lib64/libdexfile.so \
  -symbol '_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE' \
  -package com.example.target \
  -max-dump 65536
```

Use a file offset if symbol lookup fails or symbols are stripped:

```bash
./dex_dump_bin \
  -lib /apex/com.android.art/lib64/libdexfile.so \
  -offset 0x19a90 \
  -package com.example.target \
  -max-dump 65536
```

Enable header scanning as a fallback. This scans readable memory ranges for DEX headers after startup and after DEX events:

```bash
./dex_dump_bin -lib /apex/com.android.art/lib64/libdexfile.so -package com.example.target -scan -max-dump 65536
```

If eBPF loading fails from ADB root, create and run a device-side script from a real root context, for example through a Magisk service or local terminal root shell:

```bash
cd /data/local/tmp
setenforce 0 2>/dev/null || true
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
./dex_dump_bin -lib /apex/com.android.art/lib64/libdexfile.so -package com.example.target -scan -max-dump 65536
```

Dumped files are written under `/data/local/tmp/<package>/`.

File name format:

```text
dump_pid_<pid>_0x<base>_<read_size>_<source>.dex
```

Pull results:

```powershell
adb pull /data/local/tmp .
adb pull /data/local/tmp/dexdump.log .
```

Useful flags:

- `-obj`: path to `dex_dump.bpf.o`
- `-lib`: path to the ART DEX library, default `/apex/com.android.art/lib64/libdexfile.so`
- `-symbol`: optional symbol name to uprobe. If not set, the program tries the built-in symbol list in `main.go`
- `-offset`: optional file offset to uprobe. If non-zero, this overrides symbol lookup
- `-out`: dump output directory, default `/data/local/tmp`
- `-max-dump`: max bytes to dump per DEX region, default `65536`. Use `0` to dump the full reported size
- `-package`: optional Android package name filter
- `-scan`: scan target process memory for DEX headers after events. Requires `-package` for initial scan

## Finding Hook Symbols

Different Android versions and ROMs put ART DEX loading code in different libraries. Do not assume `libart.so` always contains the function you need.

This project currently hooks DEX memory-open functions where the first useful arguments are:

```text
x0 = this
x1 = const uint8_t* base
x2 = size_t size
```

That matches the current eBPF program, which reads the DEX base from register `x1` and size from `x2`.

### 1. Check Which Library Has The Symbols

Start with `libdexfile.so`, then check `libart.so` if needed:

```bash
adb shell "readelf -Ws /apex/com.android.art/lib64/libdexfile.so | grep -iE 'ArtDexFileLoader|DexFileLoader|DexFileC|OpenCommon|OpenWithDataSection'"
adb shell "readelf -Ws /apex/com.android.art/lib64/libart.so | grep -iE 'ArtDexFileLoader|DexFileLoader|DexFileC|OpenCommon|OpenWithDataSection'"
```

Useful symbols usually look like one of these:

```text
art::ArtDexFileLoader::Open(const uint8_t*, size_t, ...)
art::DexFileLoader::Open(const uint8_t*, size_t, ...)
art::DexFileLoader::OpenWithDataSection(const uint8_t*, size_t, ...)
art::DexFile::DexFile(const uint8_t*, size_t, ...)
```

In mangled form, examples from one tested device were:

```text
_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE
_ZNK3art13DexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE
_ZN3art7DexFileC2EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEEb
```

The important part is `EPKhm` in the mangled name. It means the function has `const uint8_t*` and `size_t` arguments, which are the DEX base and DEX size.

### 2. Ignore Undefined Symbols

`readelf` may show `UND` entries. Those are imports, not implementations. Hook the library that contains a real address.

Good:

```text
0000000000019a90  FUNC GLOBAL PROTECTED ... _ZNK3art16ArtDexFileLoader4OpenEPKhm...
```

Bad:

```text
0000000000000000  FUNC GLOBAL DEFAULT UND _ZNK3art16ArtDexFileLoader4OpenEPKhm...
```

If the symbol is `UND` in `libart.so`, check `libdexfile.so`.

### 3. Test A Symbol Without Rebuilding


If you found a symbol in `libdexfile.so`, pass it with `-symbol`:

```bash
./dex_dump_bin \
  -lib /apex/com.android.art/lib64/libdexfile.so \
  -symbol '_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE' \
  -package com.example.target \
  -max-dump 65536
```

If symbol names are stripped or `link.Uprobe` cannot resolve them, use the symbol value from `readelf` as a file offset:

```bash
./dex_dump_bin \
  -lib /apex/com.android.art/lib64/libdexfile.so \
  -offset 0x19a90 \
  -package com.example.target \
  -max-dump 65536
```

### 4. What To Change In `main.go`

Most of the time, you only need to change the default library or the built-in symbol list.

Default library path is in `main.go`:

```go
libPath := flag.String("lib", "/apex/com.android.art/lib64/libdexfile.so", "path to target ART dex library")
```

Built-in symbols are in `attachDexOpen()`:

```go
symbols := []string{
    "_ZNK3art16ArtDexFileLoader4OpenEPKhm...",
    "_ZNK3art13DexFileLoader4OpenEPKhm...",
    "_ZN3art7DexFileC2EPKhmS2_m...",
}
```

Add the symbol you found to this list, preferably near the top if it is the best match for your ROM.

You do not need to edit `main.go` if you use `-symbol` or `-offset` from the command line.

### 5. When You Must Change `dex_dump.bpf.c`

Only change the eBPF argument registers if the function signature is different.

Current expected layout:

```text
x1 = DEX base
x2 = DEX size
```

If you hook a function where the DEX pointer and size are in different arguments, update `dex_dump.bpf.c` accordingly. For example:

```c
event.base = ctx->regs[1];
event.size = ctx->regs[2];
```

Change `regs[1]` and `regs[2]` to the correct ARM64 argument registers for the function you selected.

### 6. Practical Workflow

1. Run `readelf -Ws` on `libdexfile.so` and `libart.so`.
2. Pick a defined symbol containing `EPKhm` or an equivalent `const uint8_t*, size_t` signature.
3. Test it with `-symbol` first.
4. If symbol lookup fails, test with `-offset` using the address from `readelf`.
5. If it works, optionally add the symbol to `attachDexOpen()` in `main.go`.
6. Rebuild and redeploy.

## Root Notes

On some Magisk/rooted devices, `adb shell su -c` still lacks the capabilities required to load eBPF programs because it inherits `adbd`'s restricted capability bounding set.

If loading fails with `operation not permitted` or memlock/capability errors, run the dumper from a real device-side root context, such as a Magisk service script or local root shell with full capabilities.
