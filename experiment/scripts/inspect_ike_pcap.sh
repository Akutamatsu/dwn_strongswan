#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: bash $0 CAPTURE_PCAP" >&2
  exit 2
fi
command -v tshark >/dev/null || {
  echo "ERROR: tshark not found; install the Wireshark CLI package" >&2
  exit 1
}

echo "IKE_SA_INIT packets (IKE length excludes the 48-byte IPv6+UDP headers):"
tshark -r "$1" \
  -Y 'isakmp.exchangetype == 34' \
  -T fields \
  -E header=y -E separator=, \
  -e frame.number \
  -e ipv6.src \
  -e ipv6.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e udp.length \
  -e isakmp.length

echo
echo "For the Table 2 field breakdown, inspect the same two packets with:"
echo "  tshark -r '$1' -Y 'isakmp.exchangetype == 34' -V"
echo "or open the capture in Wireshark and expand Internet Key Exchange v2."
