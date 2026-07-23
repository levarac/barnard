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

/// A verifier-checkable proof that the caller owns a given RPID, without
/// disclosing the TEK/RPIK it was derived from (barnard#63).
///
/// A verifier checks: (1) `sig` verifies under `signingPublicKey` for the
/// message `"barnard-rpid-proof:v1" ‖ eventIdHash ‖ enin ‖ rpi ‖ challenge`;
/// (2) `signingPublicKey` is the identity bound to the participant (see
/// [BarnardIdentity.proveKeyBinding]); (3) `rpi` matches the counterparty's
/// signed observation.
class RpidOwnershipProof {
  const RpidOwnershipProof({
    required this.rpi,
    required this.enin,
    required this.eventIdHash,
    required this.signingPublicKey,
    required this.sig,
  });

  /// 16-byte inner RPI (`AES128-ECB(RPIK, pad(ENIN))`) — the same value
  /// [BarnardClient.getCurrentRpi] returns for this `enin`.
  final Uint8List rpi;

  /// ENIN this RPI was generated for.
  final int enin;

  /// 32 bytes, binds the claim to a single event (prevents cross-event
  /// stitching; ENIN alone is a global, event-independent counter).
  final Uint8List eventIdHash;

  /// SEC1-compressed signing public key (33 bytes), same as
  /// [BarnardIdentity.signingPublicKey] for this `eventCode`.
  final Uint8List signingPublicKey;

  /// Recoverable signature over the canonical proof message.
  final BarnardSignature sig;
}

/// Barnard's per-event device signing identity (barnard#65) and RPID
/// ownership attestation (barnard#63).
///
/// This is a **sibling module to [BarnardClient]**, not part of it — the
/// sensing SDK is transport-only by charter
/// (`specs/001-barnard-core-sdk/spec.md`). `BarnardIdentity` owns the
/// device's signing capability instead: a per-event, `DeviceSecret`-rooted
/// secp256k1 keypair whose private key never leaves the SDK (the opposite
/// of `BarnardClient.exportCurrentTek`, which is deprecated in favor of
/// [proveRpidOwnership]).
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

  /// Prove ownership of the RPID generated for [enin] within [eventCode],
  /// bound to [eventIdHash] and (optionally) a verifier-supplied
  /// [challenge] for replay resistance, without disclosing the TEK/RPIK
  /// or any other ENIN's RPI (barnard#63).
  ///
  /// Deviation from the issue's literal signature: [eventCode] is
  /// required here (not implicit "current event" state) because
  /// [BarnardIdentity] is a module separate from [BarnardClient] and does
  /// not track live sensing state — see barnard#63 PR description.
  Future<RpidOwnershipProof> proveRpidOwnership({
    required String eventCode,
    required int enin,
    required Uint8List eventIdHash,
    Uint8List? challenge,
  });

  /// Bind [signingPublicKey] to [displayId] for [eventCode]: a
  /// self-signed statement a verifier can check to establish
  /// "signingPublicKey ↔ device" at join time, before any
  /// [proveRpidOwnership] call (barnard#63 acceptance criterion 3).
  ///
  /// `sig = sign_deviceKey("barnard-key-binding:v1" ‖ EventCodeHash ‖ displayId)`.
  Future<BarnardSignature> proveKeyBinding({
    required String eventCode,
    required Uint8List displayId,
  });
}
