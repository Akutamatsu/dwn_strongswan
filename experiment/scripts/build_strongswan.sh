#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_dir="$root/strongswan_6.0.4"

bash "$root/experiment/scripts/prepare_strongswan.sh"

cd "$source_dir"
chmod +x autogen.sh scripts/git-version
./autogen.sh
./configure \
  --prefix=/usr \
  --sysconfdir=/etc \
  --enable-swanctl \
  --enable-openssl \
  --enable-ml \
  --enable-mlex \
  --enable-vici \
  --disable-systemd
make -j"$(nproc)"

echo "PASS: strongSwan built; review experiment/README.md before running 'sudo make install'"
