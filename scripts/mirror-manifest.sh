#!/usr/bin/env bash
# Use of this source code is governed by the MIT license in /LICENSE.
#
# Explicit allowlists shared by the mirror checks and sync helper. Each Swift
# pair is ordered native-origin-relative|Dart-mirror-relative.

# shellcheck disable=SC2034  # This file is sourced by the check and sync scripts.
swift_mirrored_pairs=(
  "Barnard/BarnardCrypto.swift|BarnardCrypto.swift"
  "Barnard/Secp256k1.swift|Secp256k1.swift"
  "Barnard/BarnardSigning.swift|BarnardSigning.swift"
  "Barnard/BarnardRpidGenerator.swift|BarnardRpidGenerator.swift"
  "Barnard/BarnardV2Policy.swift|BarnardV2Policy.swift"
  "Barnard/BarnardPlatformDependencies.swift|BarnardPlatformDependencies.swift"
  "Barnard/PrivacyInfo.xcprivacy|PrivacyInfo.xcprivacy"
  "BarnardCore/BarnardCoreCrypto.swift|BarnardCore/BarnardCoreCrypto.swift"
  "BarnardCore/BarnardCorePolicy.swift|BarnardCore/BarnardCorePolicy.swift"
  "BarnardCore/BarnardCorePrimitives.swift|BarnardCore/BarnardCorePrimitives.swift"
  "BarnardCore/BarnardCoreOwnerKey.swift|BarnardCore/BarnardCoreOwnerKey.swift"
  "BarnardCore/BarnardCoreSigning.swift|BarnardCore/BarnardCoreSigning.swift"
  "BarnardCore/Secp256k1.swift|BarnardCore/Secp256k1.swift"
)

android_mirrored_files=(
  "BarnardCrypto.kt"
  "BarnardSigning.kt"
  "Secp256k1Backend.kt"
  "BouncyCastleSecp256k1Backend.kt"
  "BarnardV2Policy.kt"
  "BarnardIso8601.kt"
)
