#!/usr/bin/env bash
# Use of this source code is governed by the MIT license in /LICENSE.
#
# barnard#56, #80, and #81: packages/swift/barnard is the native origin for
# shared platform adapters and deterministic BarnardCore sources. The Flutter
# plugin keeps byte-for-byte Dart-package mirrors so pub.dev releases remain
# self-contained. Fails with a diff if any Dart mirror no longer matches its
# native origin.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
origin_dir="$repo_root/packages/swift/barnard/Sources"
mirror_dir="$repo_root/packages/dart/barnard/ios/barnard/Sources/barnard"
source "$repo_root/scripts/mirror-manifest.sh"

status=0
for pair in "${swift_mirrored_pairs[@]}"; do
  origin_relative="${pair%%|*}"
  mirror_relative="${pair#*|}"
  origin_file="$origin_dir/$origin_relative"
  mirror_file="$mirror_dir/$mirror_relative"
  if [[ ! -f "$origin_file" ]]; then
    echo "MISSING native origin: $origin_file"
    status=1
    continue
  fi
  if [[ ! -f "$mirror_file" ]]; then
    echo "MISSING Dart mirror: $mirror_file"
    echo "Fix the native origin, then run ./scripts/sync-mirrors.sh; do not edit the Dart mirror directly."
    status=1
    continue
  fi
  if ! diff -q "$origin_file" "$mirror_file" >/dev/null 2>&1; then
    echo "DRIFT: Dart mirror $mirror_file differs from native origin $origin_file"
    echo "Fix the native origin, then run ./scripts/sync-mirrors.sh; do not edit the Dart mirror directly."
    diff -u "$origin_file" "$mirror_file" || true
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "OK: Dart Swift mirrors match their native origins byte-for-byte."
fi
exit "$status"
