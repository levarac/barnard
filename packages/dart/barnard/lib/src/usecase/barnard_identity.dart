// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import "dart:typed_data";

/// A recoverable ECDSA (secp256k1) signature: `(r, s, v)`.
///
/// `v` is the recovery id (`0` or `1`) that lets a verifier recover the
/// signing public key from `(r, s)` and the message hash alone
/// ("ecrecover"-compatible).
class BarnardSignature {
  const BarnardSignature({required this.r, required this.s, required this.v});

  /// 32-byte big-endian `r`.
  final Uint8List r;

  /// 32-byte big-endian `s` (canonical / low-S form).
  final Uint8List s;

  /// Recovery id: `0` or `1`.
  final int v;
}

/// Barnard's per-event device signing identity (barnard#65).
///
/// This is a **sibling module to [BarnardClient]**, not part of it — the
/// sensing SDK is transport-only by charter
/// (`specs/001-barnard-core-sdk/spec.md`). `BarnardIdentity` owns the
/// device's signing capability instead: a per-event, `DeviceSecret`-rooted
/// secp256k1 keypair whose private key never leaves the SDK (the opposite
/// of `BarnardClient.exportCurrentTek`).
///
/// The signing public key is **not** a cross-event-stable identifier: it
/// is stable only within one `eventCode` and differs across `eventCode`s,
/// so it cannot be used to correlate a participant's activity across
/// events (see barnard#65 for the threat this avoids).
abstract class BarnardIdentity {
  /// The per-event signing public key, SEC1-compressed (33 bytes).
  ///
  /// Same value for every call with the same [eventCode]; a different
  /// value for every other [eventCode]. Re-derivable offline at any time
  /// from `DeviceSecret` — it never "expires".
  Future<Uint8List> signingPublicKey(String eventCode);

  /// Sign [bytes] with the per-event signing key for [eventCode].
  ///
  /// The private key never leaves the SDK; only the resulting signature is
  /// returned. [bytes] is hashed (SHA-256) before ECDSA signing.
  Future<BarnardSignature> sign(String eventCode, Uint8List bytes);
}
