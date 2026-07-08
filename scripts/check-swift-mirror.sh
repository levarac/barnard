#!/usr/bin/env bash
# Copyright 2024-2026 The Greeting Inc. All rights reserved.
# Use of this source code is governed by a BSD-style license.
#
# barnard#56: packages/swift/barnard mirrors the Flutter-free crypto/RPID
# sources from packages/dart/barnard/ios/barnard/Sources/barnard (byte-for-
# byte, not re-implemented) so the two packages cannot silently drift.
# Fails with a diff if any mirrored file no longer matches its origin.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
origin_dir="$repo_root/packages/dart/barnard/ios/barnard/Sources/barnard"
mirror_dir="$repo_root/packages/swift/barnard/Sources/Barnard"

mirrored_files=(
  "BarnardCrypto.swift"
  "Secp256k1.swift"
  "BarnardSigning.swift"
  "BarnardRpidGenerator.swift"
  "BarnardV2Policy.swift"
  "PrivacyInfo.xcprivacy"
)

status=0
for f in "${mirrored_files[@]}"; do
  origin_file="$origin_dir/$f"
  mirror_file="$mirror_dir/$f"
  if [[ ! -f "$origin_file" ]]; then
    echo "MISSING origin: $origin_file"
    status=1
    continue
  fi
  if [[ ! -f "$mirror_file" ]]; then
    echo "MISSING mirror: $mirror_file"
    status=1
    continue
  fi
  if ! diff -q "$origin_file" "$mirror_file" >/dev/null 2>&1; then
    echo "DRIFT: $origin_file != $mirror_file"
    diff -u "$origin_file" "$mirror_file" || true
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "OK: packages/swift/barnard mirrors match their origin byte-for-byte."
fi
exit $status
