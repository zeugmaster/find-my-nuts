#!/bin/bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
action="${1:-console}"
case "$action" in
  build|flash|console) ;;
  *) echo "Usage: $0 [build|flash|console] [serial-port]" >&2; exit 2 ;;
esac

idf_root="${IDF_PATH:-$HOME/Developer/esp/esp-idf}"
if [ ! -f "$idf_root/export.sh" ]; then
  echo "Set IDF_PATH to your ESP-IDF 5.5.1 installation." >&2
  exit 1
fi
# ESP-IDF's environment setup references optional unset variables.
set +u
source "$idf_root/export.sh"
set -u
cd "$repo_dir"
idf_args=(-B build-heltec -D SDKCONFIG=sdkconfig.heltec
          -D SDKCONFIG_DEFAULTS=sdkconfig.heltec.defaults -D IDF_TARGET=esp32s3)
serial_port="${2:-/dev/cu.usbserial-0001}"
case "$action" in
  build) exec idf.py "${idf_args[@]}" build ;;
  flash) exec idf.py "${idf_args[@]}" -p "$serial_port" -b 115200 flash ;;
  console) exec idf.py "${idf_args[@]}" -p "$serial_port" monitor ;;
esac
