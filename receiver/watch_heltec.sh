#!/bin/bash
set -euo pipefail

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 [message-id [token-bytes]]"
  echo "Watches one Heltec message (default 0). Get both values with 'findmy list'."
  exit 0
fi
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
receiver_python="$repo_dir/receiver/.venv/bin/python"
if [ ! -x "$receiver_python" ]; then
  echo "Create receiver/.venv and install receiver/requirements.txt first." >&2
  exit 1
fi
# Read the public namespace from the firmware profile; never silently query
# the historical T-Display namespace when starting a fresh Heltec attempt.
firmware_config="$repo_dir/sdkconfig.heltec"
if [ ! -f "$firmware_config" ]; then firmware_config="$repo_dir/sdkconfig.heltec.defaults"; fi
modem_id="$("$receiver_python" - "$firmware_config" <<'PY'
import re, sys
from pathlib import Path
match = re.search(r'^CONFIG_FIND_MY_TRANSPORT_MODEM_ID=(0x[0-9A-Fa-f]+)$',
                  Path(sys.argv[1]).read_text(), re.MULTILINE)
if match is None:
    raise SystemExit('No modem ID in the Heltec firmware profile')
print(f'{int(match[1], 16):08X}')
PY
)"
receiver_args=(--modem-id "$modem_id" --message-id "${1:-0}" --count 1 --watch)
if [ "$#" -ge 2 ]; then receiver_args+=(--token-bytes "$2"); fi
exec "$receiver_python" "$repo_dir/receiver/find_my_receiver.py" \
  "${receiver_args[@]}"
