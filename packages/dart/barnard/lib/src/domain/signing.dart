// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

/// Per-event device signing identity (barnard#65).
///
/// Key derivation chain:
/// ```
/// DeviceSecret (32 bytes)
///      |
///      +-- signSeed = HKDF(DeviceSecret || EventCode, "barnard-sign", 32)
///                          |
///                          v
///                     secp256k1 keypair (signSeed reduced mod curve order)
/// ```
///
/// This mirrors the TEK event-mode derivation shape
/// (`TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)`, see
/// [deriveTek]) so the signing key is diversified by `eventCode` the same
/// way the TEK is, but uses a distinct HKDF `info` string ("barnard-sign"
/// vs "barnard-tek") so the two derivation chains are not cross-computable
/// from one another.
library;

import "dart:convert";
import "dart:typed_data";

import "crypto.dart";
import "secp256k1.dart";

/// HKDF `info` tag for the per-event signing key. Distinct from
/// `"barnard-tek"` / `"barnard-tek-anonymous"` / `"EN-RPIK"` so the signing
/// key and the TEK/RPIK chain are domain-separated.
const String signingKeyInfo = "barnard-sign";

/// Derive the per-event signing keypair from [deviceSecret] and
/// [eventCode].
///
/// - Deterministic and re-derivable offline from `DeviceSecret` alone.
/// - Stable within one `eventCode`, different across `eventCode`s.
/// - Domain-separated from the TEK/RPIK chain (distinct HKDF `info`).
Secp256k1KeyPair deriveSigningKeyPair(Uint8List deviceSecret, String eventCode) {
  final eventCodeBytes = utf8.encode(eventCode);
  final combined = Uint8List(deviceSecret.length + eventCodeBytes.length);
  combined.setRange(0, deviceSecret.length, deviceSecret);
  combined.setRange(deviceSecret.length, combined.length, eventCodeBytes);

  final seed = hkdfSha256(
    ikm: combined,
    info: Uint8List.fromList(utf8.encode(signingKeyInfo)),
    length: 32,
  );

  return secp256k1KeyPairFromSeed(seed);
}

/// Sign [message] with the per-event signing key derived from
/// [deviceSecret] and [eventCode].
///
/// [message] is SHA-256 hashed before ECDSA signing (a message hash, not
/// raw bytes, is required for ecrecover-style recovery).
RecoverableSignature signWithDeviceSecret({
  required Uint8List deviceSecret,
  required String eventCode,
  required Uint8List message,
}) {
  final keyPair = deriveSigningKeyPair(deviceSecret, eventCode);
  final messageHash = sha256(message);
  return signRecoverable(keyPair.privateKey, messageHash);
}
