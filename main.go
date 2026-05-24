package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type dexEvent struct {
	Base uint64
	Size uint64
	Pid  uint32
	Comm [16]byte
}

func main() {
	var (
		bpfObject   = flag.String("obj", "dex_dump.bpf.o", "path to compiled eBPF object")
		libPath     = flag.String("libart", "/apex/com.android.art/lib64/libart.so", "path to target libart.so")
		outDir      = flag.String("out", "/data/local/tmp", "directory for dumped DEX files")
		maxDump     = flag.Uint64("max-dump", 64*1024, "maximum bytes to read from each DEX memory region, 0 means full size")
		packageName = flag.String("package", "", "optional Android package name filter")
	)
	flag.Parse()

	targetPid := uint32(0)
	if *packageName != "" {
		pid, err := findPidByPackage(*packageName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to resolve package %q: %v\n", *packageName, err)
			os.Exit(1)
		}
		targetPid = pid
		fmt.Printf("[+] Filtering target package %s, pid=%d\n", *packageName, targetPid)
	}

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	if err := run(*bpfObject, *libPath, *outDir, targetPid, *maxDump); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func run(bpfObject, libPath, outDir string, targetPid uint32, maxDump uint64) error {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Printf("[-] Failed to remove memlock limit, continuing: %v\n", err)
	}

	var objs struct {
		UprobeDexOpen *ebpf.Program `ebpf:"uprobe_dex_open"`
		Events        *ebpf.Map     `ebpf:"events"`
	}
	if err := loadObjects(bpfObject, &objs); err != nil {
		return fmt.Errorf("failed to load eBPF object: %w", err)
	}
	defer objs.UprobeDexOpen.Close()
	defer objs.Events.Close()

	up, err := link.OpenExecutable(libPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", libPath, err)
	}

	ln, symbol, err := attachDexFileCtor(up, objs.UprobeDexOpen)
	if err != nil {
		return err
	}
	defer ln.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create perf event reader: %w", err)
	}
	defer rd.Close()

	fmt.Printf("[+] Attached to %s:%s\n", libPath, symbol)
	fmt.Println("[+] Waiting for DEX load events...")

	go func() {
		<-stopper
		rd.Close()
	}()

	seen := make(map[string]struct{})
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("failed to read perf event: %w", err)
		}

		var event dexEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Printf("[-] Failed to parse ringbuf sample: %v\n", err)
			continue
		}

		if targetPid != 0 && event.Pid != targetPid {
			continue
		}

		key := fmt.Sprintf("%d:%x:%x", event.Pid, event.Base, event.Size)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		fmt.Printf("[*] DEX pid=%d comm=%s base=0x%x size=%d\n", event.Pid, comm, event.Base, event.Size)
		go dumpDex(outDir, event, maxDump)
	}
}

func loadObjects(path string, objs interface{}) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  1024 * 1024,
		},
	})
}

func attachDexFileCtor(ex *link.Executable, prog *ebpf.Program) (link.Link, string, error) {
	symbols := []string{
		"_ZN3art7DexFileC1EPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileE",
		"_ZN3art7DexFileC2EPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileE",
	}

	var lastErr error
	for _, symbol := range symbols {
		ln, err := ex.Uprobe(symbol, prog, nil)
		if err == nil {
			return ln, symbol, nil
		}
		lastErr = err
	}

	return nil, "", fmt.Errorf("failed to attach DexFile constructor uprobe: %w", lastErr)
}

func dumpDex(outDir string, event dexEvent, maxDump uint64) {
	memPath := fmt.Sprintf("/proc/%d/mem", event.Pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		fmt.Printf("[-] Failed to open %s: %v\n", memPath, err)
		return
	}
	defer memFile.Close()

	if _, err := memFile.Seek(int64(event.Base), io.SeekStart); err != nil {
		fmt.Printf("[-] Failed to seek %s to 0x%x: %v\n", memPath, event.Base, err)
		return
	}

	readSize := event.Size
	if maxDump > 0 && readSize > maxDump {
		readSize = maxDump
	}

	buf := make([]byte, readSize)
	if _, err := io.ReadFull(memFile, buf); err != nil {
		fmt.Printf("[-] Failed to read DEX memory for pid=%d base=0x%x: %v\n", event.Pid, event.Base, err)
		return
	}

	if !bytes.HasPrefix(buf, []byte("dex\n")) {
		fmt.Printf("[-] Skip non-DEX memory pid=%d base=0x%x\n", event.Pid, event.Base)
		return
	}

	outPath := filepath.Join(outDir, fmt.Sprintf("dump_pid_%d_0x%x_%d.dex", event.Pid, event.Base, readSize))
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("[-] Failed to create %s: %v\n", outPath, err)
		return
	}
	defer outFile.Close()

	if _, err := outFile.Write(buf); err != nil {
		fmt.Printf("[-] Failed to write %s: %v\n", outPath, err)
		return
	}

	fmt.Printf("[+] Dumped DEX: %s\n", outPath)
}

func findPidByPackage(packageName string) (uint32, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil {
			continue
		}

		name := strings.TrimRight(string(cmdline), "\x00")
		if name == packageName || strings.HasPrefix(name, packageName+":") {
			return uint32(pid64), nil
		}
	}

	return 0, os.ErrNotExist
}
