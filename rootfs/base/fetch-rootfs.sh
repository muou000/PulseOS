#!/usr/bin/env bash
# Fetch the base rootfs tarballs from GitHub Release, since they are no
# longer stored in the git repository. Existing files are only verified.
# Usage: ./fetch-rootfs.sh
set -euo pipefail

cd "$(dirname "$0")"

REPO="muou000/PulseOS"
TAG="rootfs-base-20260929"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

checksums=(
  "3d7768d6c923a7b0fc1b4398ac46dd25a8f298da9daf8006a0e7c52234033752  base-rootfs-loongarch64.tar.xz"
  "d63b167e60e1f9b09932645b0e32aa2deca5ae6aba1c29f69b22ca879cfce60b  rootfs-riscv64.tar.gz"
)

for line in "${checksums[@]}"; do
  file="${line##*  }"
  if [[ -f "$file" ]]; then
    echo "$file already present, verifying checksum"
  else
    echo "Downloading $file from ${BASE_URL}/${file}"
    curl -fL --retry 3 -o "$file" "${BASE_URL}/${file}"
  fi
  echo "$line" | sha256sum -c -
done
