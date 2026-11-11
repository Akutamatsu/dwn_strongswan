#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_dir="$root/strongswan_6.0.4"
increment_dir="$root/strongswan_6.0.4_inc"
upstream_url="https://github.com/strongswan/strongswan.git"
base_commit="6856bfe"

if [[ ! -d "$increment_dir" ]]; then
	printf 'ERROR: incremental source directory not found: %s\n' "$increment_dir" >&2
	exit 1
fi

if [[ ! -e "$source_dir" ]]; then
	git clone --filter=blob:none --no-checkout "$upstream_url" "$source_dir"
	git -C "$source_dir" checkout --detach "$base_commit"
elif [[ ! -d "$source_dir/.git" ]]; then
	printf 'ERROR: refusing to overwrite non-Git path: %s\n' "$source_dir" >&2
	exit 1
fi

actual_commit="$(git -C "$source_dir" rev-parse HEAD)"
resolved_base="$(git -C "$source_dir" rev-parse "$base_commit^{commit}")"
if [[ "$actual_commit" != "$resolved_base" ]]; then
	printf 'ERROR: %s is at %s, expected %s\n' \
		"$source_dir" "$actual_commit" "$resolved_base" >&2
	exit 1
fi

cp -a "$increment_dir/." "$source_dir/"

while IFS= read -r -d '' relative; do
	if ! cmp -s "$increment_dir/$relative" "$source_dir/$relative"; then
		printf 'ERROR: failed to install incremental file: %s\n' "$relative" >&2
		exit 1
	fi
done < <(cd "$increment_dir" && find . -type f -printf '%P\0')

printf 'PASS: checked out strongSwan %s and applied strongswan_6.0.4_inc\n' \
	"$resolved_base"
