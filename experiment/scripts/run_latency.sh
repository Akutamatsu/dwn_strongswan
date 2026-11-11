#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 OUTPUT_LOG [ITERATIONS] [SETTLE_SECONDS] [TERMINATE_TIMEOUT]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 4 ]] || usage
output_log="$1"
iterations="${2:-1000}"
settle_seconds="${3:-1}"
terminate_timeout="${4:-2}"

[[ "$iterations" =~ ^[1-9][0-9]*$ ]] || usage
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root on a dedicated test initiator" >&2; exit 1; }
command -v swanctl >/dev/null || { echo "ERROR: swanctl not found" >&2; exit 1; }
command -v timeout >/dev/null || { echo "ERROR: timeout not found" >&2; exit 1; }

source_log=/var/log/charon_rtt.log
lock=/tmp/pqike-artifact-latency.lock
[[ ! -e "$lock" ]] || { echo "ERROR: another latency run is active" >&2; exit 1; }
printf '%s\n' "$$" > "$lock"

collector_pid=""
start_time=$(date +%s)
cleanup() {
  [[ -z "$collector_pid" ]] || kill "$collector_pid" 2>/dev/null || true
  rm -f "$lock"
}
trap cleanup EXIT INT TERM

: > "$source_log"
: > "$output_log"
chmod 0644 "$output_log"
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
  chown "$SUDO_UID:$SUDO_GID" "$output_log"
fi
stdbuf -oL tail -n 0 -F "$source_log" | while IFS= read -r line; do
  printf '%s %s\n' "$(date +%s.%3N)" "$line"
done >> "$output_log" &
collector_pid=$!

for ((iteration=1; iteration<=iterations; iteration++)); do
  swanctl --initiate --ike ikev2-test >/dev/null 2>&1 || true
  sleep "$settle_seconds"
  timeout "$terminate_timeout" swanctl --terminate --ike ikev2-test >/dev/null 2>&1 || true
  while swanctl --list-sas 2>/dev/null | grep -q ikev2-test; do
    sleep 0.2
    swanctl --terminate --ike ikev2-test >/dev/null 2>&1 || true
  done
  elapsed=$(( $(date +%s) - start_time ))
  percent=$(( iteration * 100 / iterations ))
  filled=$(( percent * 30 / 100 ))
  empty=$(( 30 - filled ))
  printf -v progress_filled '%*s' "$filled" ''
  printf -v progress_empty '%*s' "$empty" ''
  progress_filled=${progress_filled// /#}
  progress_empty=${progress_empty// /-}
  printf -v elapsed_display '%02d:%02d:%02d' $((elapsed / 3600)) $(((elapsed % 3600) / 60)) $((elapsed % 60))
  printf '\r[%s%s] %3d%% (%d/%d) elapsed %s' \
    "$progress_filled" "$progress_empty" "$percent" "$iteration" "$iterations" "$elapsed_display"
done

printf '\n'
sleep 1
echo "PASS: collected timestamped log in $output_log"
