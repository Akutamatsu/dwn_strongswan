#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: bash experiment/scripts/generate_swanctl_configs.sh ROLE IPV6_ADDRESS

ROLE must be init or resp.
  init: IPV6_ADDRESS is the responder IPv6 address.
  resp: IPV6_ADDRESS is this responder's IPv6 address.

Generates one configuration per experiment proposal in experiment/config/.
EOF
  exit 2
}

[[ $# -eq 2 ]] || usage
role="$1"
ipv6_address="$2"

case "$role" in
  init)
    template_name="initiator-swanctl.conf.in"
    output_prefix="initiator"
    placeholder="@RESPONDER_IPV6@"
    ;;
  resp)
    template_name="responder-swanctl.conf.in"
    output_prefix="responder"
    placeholder="@RESPONDER_IPV6@"
    ;;
  *)
    usage
    ;;
esac

[[ "$ipv6_address" == *:* ]] || {
  echo "ERROR: IPV6_ADDRESS must contain an IPv6 address." >&2
  exit 2
}
[[ "$ipv6_address" != *$'\n'* && "$ipv6_address" != *$'\r'* ]] || {
  echo "ERROR: IPV6_ADDRESS must not contain a newline." >&2
  exit 2
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
config_dir="$(cd -- "$script_dir/../config" && pwd)"
template="$config_dir/$template_name"

[[ -f "$template" ]] || {
  echo "ERROR: template not found: $template" >&2
  exit 1
}

proposals=(
  aes192-sha256-ecp384
  aes192-sha256-emlkem768
  aes256-sha256-mlkem1024
  aes256-sha256-emlkem1024
)

for proposal in "${proposals[@]}"; do
  output="$config_dir/$output_prefix-$proposal.swanctl.conf"
  sed \
    -e "s|@PROPOSAL@|$proposal|g" \
    -e "s|$placeholder|$ipv6_address|g" \
    "$template" > "$output"
  echo "Wrote $output"
done

echo "PASS: generated ${#proposals[@]} $role configuration files."
