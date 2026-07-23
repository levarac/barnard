#!/usr/bin/env bash
# Copyright 2024-2026 The Greeting Inc. All rights reserved.
# Use of this source code is governed by a BSD-style license.
#
# barnard#56 and #80: packages/swift/barnard mirrors the Flutter-free
# platform adapters and deterministic BarnardCore sources from
# packages/dart/barnard/ios/barnard/Sources/barnard (byte-for-byte, not
# re-implemented) so the two packages cannot silently drift.
# Fails with a diff if any mirrored file no longer matches its origin.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
plugin_dir="$repo_root/packages/dart/barnard/ios/barnard/Sources/barnard"
package_dir="$repo_root/packages/swift/barnard/Sources"

mirrored_pairs=(
  "BarnardCrypto.swift|Barnard/BarnardCrypto.swift"
  "Secp256k1.swift|Barnard/Secp256k1.swift"
  "BarnardSigning.swift|Barnard/BarnardSigning.swift"
  "BarnardRpidGenerator.swift|Barnard/BarnardRpidGenerator.swift"
  "BarnardV2Policy.swift|Barnard/BarnardV2Policy.swift"
  "BarnardPlatformDependencies.swift|Barnard/BarnardPlatformDependencies.swift"
  "PrivacyInfo.xcprivacy|Barnard/PrivacyInfo.xcprivacy"
  "BarnardCore/BarnardCoreCrypto.swift|BarnardCore/BarnardCoreCrypto.swift"
  "BarnardCore/BarnardCorePolicy.swift|BarnardCore/BarnardCorePolicy.swift"
  "BarnardCore/BarnardCorePrimitives.swift|BarnardCore/BarnardCorePrimitives.swift"
  "BarnardCore/BarnardCoreSigning.swift|BarnardCore/BarnardCoreSigning.swift"
  "BarnardCore/Secp256k1.swift|BarnardCore/Secp256k1.swift"
)

status=0
for pair in "${mirrored_pairs[@]}"; do
  plugin_relative="${pair%%|*}"
  package_relative="${pair#*|}"
  plugin_file="$plugin_dir/$plugin_relative"
  package_file="$package_dir/$package_relative"
  if [[ ! -f "$plugin_file" ]]; then
    echo "MISSING plugin source: $plugin_file"
    status=1
    continue
  fi
  if [[ ! -f "$package_file" ]]; then
    echo "MISSING package source: $package_file"
    status=1
    continue
  fi
  if ! diff -q "$plugin_file" "$package_file" >/dev/null 2>&1; then
    echo "DRIFT: $plugin_file != $package_file"
    diff -u "$plugin_file" "$package_file" || true
    status=1
  fi
done

if [[ $status -eq 0 ]]; then
  echo "OK: packages/swift/barnard mirrors match their origin byte-for-byte."
fi
exit $status
