#!/system/bin/sh
set -eu

BASE=/data/local/tmp/ebpfDumpDex/variants
case "${1:-}" in
  1) DIR=01_libdexfile_event_only ;;
  2) DIR=02_scan_no_dedupe ;;
  3) DIR=03_scan_global_dedupe ;;
  4) DIR=04_package_dirs_global_dedupe ;;
  5) DIR=05_package_scoped_scan_once ;;
  6) DIR=06_package_scoped_scan_every_event ;;
  *)
    echo "usage: $0 <1..6>"
    echo "1: libdexfile event only"
    echo "2: scan fallback, no dedupe"
    echo "3: scan fallback, global dedupe"
    echo "4: package dirs, global dedupe"
    echo "5: package-scoped dedupe, scan once"
    echo "6: package-scoped dedupe, scan every event"
    exit 1
    ;;
esac

exec "$BASE/$DIR/run.sh"
