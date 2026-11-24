#!/usr/bin/env bash
# Use of this source code is governed by the MIT license in /LICENSE.
#
# barnard#56 and #81: packages/android/barnard is the native origin for shared
# Flutter-free crypto/RPID sources. The Flutter plugin keeps byte-for-byte
# Dart-package mirrors so pub.dev releases remain self-contained. Fails with a
# diff if any Dart mirror or explicitly listed React Native mirror drifts.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
origin_dir="$repo_root/packages/android/barnard/src/main/kotlin/org/levarac/barnard"
mirror_dir="$repo_root/packages/dart/barnard/android/src/main/kotlin/org/levarac/barnard"
react_native_mirror_dir="$repo_root/packages/react-native/barnard/android/src/main/kotlin/org/levarac/barnard"
source "$repo_root/scripts/mirror-manifest.sh"

status=0
for f in "${android_mirrored_files[@]}"; do
  origin_file="$origin_dir/$f"
  mirror_file="$mirror_dir/$f"
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

for f in "${android_react_native_mirrored_files[@]}"; do
  origin_file="$origin_dir/$f"
  mirror_file="$react_native_mirror_dir/$f"
  if [[ ! -f "$origin_file" ]]; then
    echo "MISSING native origin: $origin_file"
    status=1
    continue
  fi
  if [[ ! -f "$mirror_file" ]]; then
    echo "MISSING React Native mirror: $mirror_file"
    echo "Fix the native origin, then run ./scripts/sync-mirrors.sh; do not edit the React Native mirror directly."
    status=1
    continue
  fi
  if ! diff -q "$origin_file" "$mirror_file" >/dev/null 2>&1; then
    echo "DRIFT: React Native mirror $mirror_file differs from native origin $origin_file"
    echo "Fix the native origin, then run ./scripts/sync-mirrors.sh; do not edit the React Native mirror directly."
    diff -u "$origin_file" "$mirror_file" || true
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "OK: Dart Android mirrors match their native origins byte-for-byte."
  echo "OK: React Native Android mirrors match their native origins byte-for-byte."
  python3 "$repo_root/scripts/check-mirror-type-references.py" android || status=$?
fi
exit "$status"
