Run from device local root:

  /data/local/tmp/ebpfDumpDex/variants/run_variant.sh 1
  /data/local/tmp/ebpfDumpDex/variants/run_variant.sh 2
  /data/local/tmp/ebpfDumpDex/variants/run_variant.sh 3
  /data/local/tmp/ebpfDumpDex/variants/run_variant.sh 4
  /data/local/tmp/ebpfDumpDex/variants/run_variant.sh 5
  /data/local/tmp/ebpfDumpDex/variants/run_variant.sh 6

Each variant writes to its own directory:

  /data/local/tmp/ebpfDumpDex/variants/<variant>/dexdump.log
  /data/local/tmp/ebpfDumpDex/variants/<variant>/out/

Variants:

1: run 26355818031, libdexfile event only, no memory scan.
2: run 26356354928, first scan fallback, no dedupe.
3: run 26356657139, scan fallback with global checksum dedupe and min-scan-size support.
4: run 26357229111, package subdirectories with global checksum dedupe.
5: run 26357569272, package-scoped dedupe, scan each pid once.
6: run 26357993007, package-scoped dedupe, scan after every DEX event.

Before testing a variant, start it from local root, then launch or restart the target app and interact until unpacking should be finished.
