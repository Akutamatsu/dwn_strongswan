#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo bash $0 OUTPUT_PCAP [INTERFACE]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
output_pcap="$1"
interface="${2:-any}"

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root on the initiator" >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "ERROR: tcpdump not found" >&2; exit 1; }
command -v swanctl >/dev/null || { echo "ERROR: swanctl not found" >&2; exit 1; }

mkdir -p "$(dirname "$output_pcap")"
capture_pid=""
cleanup() {
  [[ -z "$capture_pid" ]] || kill -INT "$capture_pid" 2>/dev/null || true
  [[ -z "$capture_pid" ]] || wait "$capture_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

tcpdump -U -i "$interface" -n -s 0 -w "$output_pcap" \
  'ip6 and udp and (port 500 or port 4500)' &
capture_pid=$!
sleep 1

swanctl --initiate --ike ikev2-test >/dev/null
sleep 2
swanctl --terminate --ike ikev2-test >/dev/null 2>&1 || true
sleep 1

cleanup
capture_pid=""
[[ -s "$output_pcap" ]] || { echo "ERROR: capture is empty" >&2; exit 1; }
echo "PASS: wrote IKEv2 capture to $output_pcap"
