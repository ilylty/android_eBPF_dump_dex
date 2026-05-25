package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

const (
	maxDexSize         = 512 * 1024 * 1024
	dumpBufferSize     = 256 * 1024
	scanChunkSize      = 1024 * 1024
	perfReaderPages    = 64
	dumpQueueSize      = 8192
	maxConcurrentDumps = 2
	openNoFollow       = 0x20000
)

type dumpJob struct {
	outDir  string
	pid     uint32
	base    uint64
	size    uint64
	maxDump uint64
	source  string
	key     string
}

type dumpTracker struct {
	mu         sync.Mutex
	done       map[string]struct{}
	inProgress map[string]struct{}
}

func newDumpTracker() *dumpTracker {
	return &dumpTracker{
		done:       make(map[string]struct{}),
		inProgress: make(map[string]struct{}),
	}
}

func (t *dumpTracker) begin(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.done[key]; ok {
		return false
	}
	if _, ok := t.inProgress[key]; ok {
		return false
	}
	t.inProgress[key] = struct{}{}
	return true
}

func (t *dumpTracker) finish(key string, success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.inProgress, key)
	if success {
		t.done[key] = struct{}{}
	}
}

type scanTracker struct {
	mu      sync.Mutex
	running map[uint32]struct{}
	pending map[uint32]struct{}
}

func newScanTracker() *scanTracker {
	return &scanTracker{
		running: make(map[uint32]struct{}),
		pending: make(map[uint32]struct{}),
	}
}

func (t *scanTracker) request(pid uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.running[pid]; ok {
		t.pending[pid] = struct{}{}
		return false
	}
	t.running[pid] = struct{}{}
	return true
}

func (t *scanTracker) finish(pid uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.pending[pid]; ok {
		delete(t.pending, pid)
		return true
	}
	delete(t.running, pid)
	return false
}

func main() {
	var (
		bpfObject   = flag.String("obj", "dex_dump.bpf.o", "path to compiled eBPF object")
		libPath     = flag.String("lib", "/apex/com.android.art/lib64/libdexfile.so", "path to target ART dex library")
		symbolName  = flag.String("symbol", "", "optional symbol name to uprobe; defaults to known DexFile open symbols")
		offset      = flag.Uint64("offset", 0, "optional file offset to uprobe; overrides symbol lookup when non-zero")
		outDir      = flag.String("out", "/data/local/tmp", "directory for dumped DEX files")
		maxDump     = flag.Uint64("max-dump", 64*1024, "maximum bytes to read from each DEX memory region, 0 means full size")
		packageName = flag.String("package", "", "optional Android package name filter")
		scanHeaders = flag.Bool("scan", false, "scan target process memory for DEX header fields like the GG Lua script")
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

	if err := os.MkdirAll(*outDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create output directory: %v\n", err)
		os.Exit(1)
	}
	if err := ensureSafeDir(*outDir); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Unsafe output directory: %v\n", err)
		os.Exit(1)
	}

	if err := run(*bpfObject, *libPath, *symbolName, *offset, *outDir, targetPid, *maxDump, *scanHeaders); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func run(bpfObject, libPath, symbolName string, offset uint64, outDir string, targetPid uint32, maxDump uint64, scanHeaders bool) error {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopper)

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

	ln, symbol, err := attachDexOpen(up, objs.UprobeDexOpen, symbolName, offset)
	if err != nil {
		return err
	}
	defer ln.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*perfReaderPages)
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

	dumps := newDumpTracker()
	scans := newScanTracker()
	dumpQueue := make(chan dumpJob, dumpQueueSize)
	for i := 0; i < maxConcurrentDumps; i++ {
		go dumpWorker(dumpQueue, dumps)
	}
	if scanHeaders && targetPid != 0 {
		startScan(outDir, targetPid, maxDump, dumps, scans, dumpQueue)
	}

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("failed to read perf event: %w", err)
		}
		if record.LostSamples > 0 {
			fmt.Printf("[-] Lost %d perf samples; increase buffer or reduce scan/dump load\n", record.LostSamples)
			continue
		}

		var event dexEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Printf("[-] Failed to parse perf sample: %v\n", err)
			continue
		}

		if targetPid != 0 && event.Pid != targetPid {
			continue
		}

		comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
		fmt.Printf("[*] DEX pid=%d comm=%s base=0x%x size=%d\n", event.Pid, comm, event.Base, event.Size)
		enqueueDump(outDir, event.Pid, event.Base, event.Size, maxDump, "event", dumps, dumpQueue)
		if scanHeaders {
			startScan(outDir, event.Pid, maxDump, dumps, scans, dumpQueue)
		}
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

func attachDexOpen(ex *link.Executable, prog *ebpf.Program, symbolName string, offset uint64) (link.Link, string, error) {
	if offset != 0 {
		ln, err := ex.Uprobe("", prog, &link.UprobeOptions{Address: offset})
		return ln, fmt.Sprintf("offset:0x%x", offset), err
	}

	if symbolName != "" {
		ln, err := ex.Uprobe(symbolName, prog, nil)
		return ln, symbolName, err
	}

	symbols := []string{
		"_ZNK3art16ArtDexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE",
		"_ZNK3art13DexFileLoader4OpenEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEE",
		"_ZN3art7DexFileC2EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEEb",
	}

	var lastErr error
	for _, symbol := range symbols {
		ln, err := ex.Uprobe(symbol, prog, nil)
		if err == nil {
			return ln, symbol, nil
		}
		lastErr = err
	}

	return nil, "", fmt.Errorf("failed to attach DEX open uprobe: %w", lastErr)
}

func dumpWorker(queue <-chan dumpJob, dumps *dumpTracker) {
	for job := range queue {
		dumpDex(job.outDir, job.pid, job.base, job.size, job.maxDump, job.source, job.key, dumps)
	}
}

func enqueueDump(outDir string, pid uint32, base uint64, size uint64, maxDump uint64, source string, dumps *dumpTracker, queue chan<- dumpJob) {
	key := dumpKey(pid, base, size)
	if !dumps.begin(key) {
		return
	}
	queue <- dumpJob{outDir: outDir, pid: pid, base: base, size: size, maxDump: maxDump, source: source, key: key}
}

func dumpKey(pid uint32, base uint64, size uint64) string {
	return fmt.Sprintf("%d:%x:%x", pid, base, size)
}

func dumpDex(outDir string, pid uint32, base uint64, size uint64, maxDump uint64, source string, key string, dumps *dumpTracker) {
	success := false
	defer func() { dumps.finish(key, success) }()

	if size < 0x70 || size > maxDexSize {
		fmt.Printf("[-] Skip invalid DEX size pid=%d base=0x%x size=%d source=%s\n", pid, base, size, source)
		return
	}
	readSize := size
	if maxDump > 0 && readSize > maxDump {
		readSize = maxDump
	}
	if readSize < 0x70 {
		fmt.Printf("[-] Skip too-small DEX read pid=%d base=0x%x readSize=%d source=%s\n", pid, base, readSize, source)
		return
	}
	if base > math.MaxInt64 {
		fmt.Printf("[-] Skip DEX with unsupported base pid=%d base=0x%x source=%s\n", pid, base, source)
		return
	}
	if readSize > uint64(math.MaxInt64)-base {
		fmt.Printf("[-] Skip DEX with overflowing range pid=%d base=0x%x readSize=%d source=%s\n", pid, base, readSize, source)
		return
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		fmt.Printf("[-] Failed to open %s: %v\n", memPath, err)
		return
	}
	defer memFile.Close()

	header := make([]byte, 0x70)
	if _, err := memFile.ReadAt(header, int64(base)); err != nil {
		fmt.Printf("[-] Failed to read DEX header for pid=%d base=0x%x source=%s: %v\n", pid, base, source, err)
		return
	}

	if !normalizeDexHeader(header) {
		fmt.Printf("[-] Skip non-DEX memory pid=%d base=0x%x source=%s\n", pid, base, source)
		return
	}

	packageName := packageNameForPid(pid)
	packageDir := filepath.Join(outDir, sanitizePathComponent(packageName))
	if err := os.MkdirAll(packageDir, 0700); err != nil {
		fmt.Printf("[-] Failed to create output directory %s: %v\n", packageDir, err)
		return
	}
	if err := ensureSafeDir(packageDir); err != nil {
		fmt.Printf("[-] Unsafe output directory %s: %v\n", packageDir, err)
		return
	}

	outPath, outFile, err := createDumpFile(packageDir, pid, base, readSize, source)
	if err != nil {
		fmt.Printf("[-] Failed to create dump file in %s: %v\n", packageDir, err)
		return
	}
	removeIncomplete := true
	defer func() {
		outFile.Close()
		if removeIncomplete {
			os.Remove(outPath)
		}
	}()

	written, err := writeDexStream(memFile, outFile, base, readSize, header)
	if err != nil {
		fmt.Printf("[-] Failed to write %s: %v\n", outPath, err)
		return
	}
	if written != readSize {
		fmt.Printf("[-] Short DEX dump %s: wrote=%d expected=%d\n", outPath, written, readSize)
		return
	}

	removeIncomplete = false
	success = true
	fmt.Printf("[+] Dumped DEX: %s\n", outPath)
}

func createDumpFile(packageDir string, pid uint32, base uint64, readSize uint64, source string) (string, *os.File, error) {
	baseName := fmt.Sprintf("dump_pid_%d_0x%x_%d_%s", pid, base, readSize, source)
	for i := 0; i < 1000; i++ {
		name := baseName + ".dex"
		if i > 0 {
			name = fmt.Sprintf("%s_%d.dex", baseName, i)
		}
		path := filepath.Join(packageDir, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|openNoFollow, 0644)
		if err == nil {
			return path, file, nil
		}
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return "", nil, err
	}
	return "", nil, fmt.Errorf("too many existing dump files for %s", baseName)
}

func ensureSafeDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink directory")
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	return nil
}

func writeDexStream(memFile, outFile *os.File, base uint64, readSize uint64, header []byte) (uint64, error) {
	firstWrite := uint64(len(header))
	if firstWrite > readSize {
		firstWrite = readSize
	}
	if _, err := outFile.Write(header[:firstWrite]); err != nil {
		return 0, err
	}
	written := firstWrite
	buf := make([]byte, dumpBufferSize)
	for written < readSize {
		want := uint64(len(buf))
		remaining := readSize - written
		if want > remaining {
			want = remaining
		}
		n, err := memFile.ReadAt(buf[:want], int64(base+written))
		if n > 0 {
			if _, writeErr := outFile.Write(buf[:n]); writeErr != nil {
				return written, writeErr
			}
			written += uint64(n)
		}
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func packageNameForPid(pid uint32) string {
	name, err := processPackageName(pid)
	if err != nil || name == "" {
		name = fmt.Sprintf("pid_%d", pid)
	}
	return name
}

func processPackageName(pid uint32) (string, error) {
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "cmdline"))
	if err != nil {
		return "", err
	}
	name := strings.TrimRight(string(cmdline), "\x00")
	if idx := strings.IndexByte(name, '\x00'); idx >= 0 {
		name = name[:idx]
	}
	if idx := strings.IndexByte(name, ':'); idx >= 0 {
		name = name[:idx]
	}
	return name, nil
}

func sanitizePathComponent(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	clean := strings.Trim(b.String(), "._-")
	if clean == "" {
		return "unknown"
	}
	return clean
}

func normalizeDexHeader(buf []byte) bool {
	if len(buf) < 0x40 {
		return false
	}
	if bytes.HasPrefix(buf, []byte("dex\n")) {
		return true
	}
	if binary.LittleEndian.Uint32(buf[0x24:0x28]) == 0x70 &&
		binary.LittleEndian.Uint32(buf[0x28:0x2c]) == 0x12345678 &&
		binary.LittleEndian.Uint32(buf[0x2c:0x30]) == 0 &&
		binary.LittleEndian.Uint32(buf[0x3c:0x40]) == 0x70 {
		copy(buf[:8], []byte{'d', 'e', 'x', '\n', '0', '3', '5', 0})
		return true
	}
	return false
}

func startScan(outDir string, pid uint32, maxDump uint64, dumps *dumpTracker, scans *scanTracker, dumpQueue chan<- dumpJob) {
	if !scans.request(pid) {
		return
	}
	go func() {
		for {
			scanDexHeaders(outDir, pid, maxDump, dumps, dumpQueue)
			if !scans.finish(pid) {
				return
			}
		}
	}()
}

func scanDexHeaders(outDir string, pid uint32, maxDump uint64, dumps *dumpTracker, dumpQueue chan<- dumpJob) {
	ranges, err := readableRanges(pid)
	if err != nil {
		fmt.Printf("[-] Failed to read maps for pid=%d: %v\n", pid, err)
		return
	}

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		fmt.Printf("[-] Failed to open %s for scan: %v\n", memPath, err)
		return
	}
	defer memFile.Close()

	pattern := []byte{0x70, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00}
	buf := make([]byte, scanChunkSize)
	for _, r := range ranges {
		for pos := r.start; pos < r.end; {
			end := pos + scanChunkSize
			if end > r.end {
				end = r.end
			}
			if pos > math.MaxInt64 {
				break
			}
			n, err := memFile.ReadAt(buf[:end-pos], int64(pos))
			if n > 0 {
				scanChunk(outDir, pid, memFile, pos, buf[:n], pattern, maxDump, dumps, dumpQueue)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				break
			}
			if end == r.end {
				break
			}
			pos = end - uint64(len(pattern))
		}
	}
}

func scanChunk(outDir string, pid uint32, memFile *os.File, chunkBase uint64, buf []byte, pattern []byte, maxDump uint64, dumps *dumpTracker, dumpQueue chan<- dumpJob) {
	for off := 0; ; {
		idx := bytes.Index(buf[off:], pattern)
		if idx < 0 {
			return
		}
		hit := chunkBase + uint64(off+idx)
		if hit >= 0x24 {
			base := hit - 0x24
			size, ok := readDexFileSize(memFile, base)
			if ok {
				fmt.Printf("[*] Scanned DEX pid=%d base=0x%x size=%d\n", pid, base, size)
				enqueueDump(outDir, pid, base, size, maxDump, "scan", dumps, dumpQueue)
			}
		}
		off += idx + 1
	}
}

func readDexFileSize(memFile *os.File, base uint64) (uint64, bool) {
	if base > math.MaxInt64 {
		return 0, false
	}
	header := make([]byte, 0x40)
	if _, err := memFile.ReadAt(header, int64(base)); err != nil {
		return 0, false
	}
	if binary.LittleEndian.Uint32(header[0x24:0x28]) != 0x70 ||
		binary.LittleEndian.Uint32(header[0x28:0x2c]) != 0x12345678 ||
		binary.LittleEndian.Uint32(header[0x2c:0x30]) != 0 ||
		binary.LittleEndian.Uint32(header[0x3c:0x40]) != 0x70 {
		return 0, false
	}
	size := uint64(binary.LittleEndian.Uint32(header[0x20:0x24]))
	return size, size >= 0x70 && size <= maxDexSize
}

type memRange struct {
	start uint64
	end   uint64
}

func readableRanges(pid uint32) ([]memRange, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var ranges []memRange
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "r") {
			continue
		}
		parts := strings.SplitN(fields[0], "-", 2)
		if len(parts) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(parts[0], 16, 64)
		end, err2 := strconv.ParseUint(parts[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		ranges = append(ranges, memRange{start: start, end: end})
	}
	return ranges, scanner.Err()
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
