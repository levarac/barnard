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

/// Domain-separation tag for [buildRpidProofMessage] (barnard#63).
const String rpidProofDomainTag = "barnard-rpid-proof:v1";

/// Domain-separation tag for [buildKeyBindingMessage] (barnard#63).
const String keyBindingDomainTag = "barnard-key-binding:v1";

/// Canonical, fixed-order/length-prefixed encoding of an RPID ownership
/// proof claim:
/// ```
/// "barnard-rpid-proof:v1" (ASCII, fixed) ‖ eventIdHash(32) ‖ enin(8, BE)
///   ‖ rpi(16) ‖ len(challenge) as u16 BE ‖ challenge
/// ```
Uint8List buildRpidProofMessage({
  required Uint8List eventIdHash,
  required int enin,
  required Uint8List rpi,
  Uint8List? challenge,
}) {
  if (eventIdHash.length != 32) {
    throw ArgumentError("eventIdHash must be 32 bytes, got ${eventIdHash.length}");
  }
  if (rpi.length != 16) {
    throw ArgumentError("rpi must be 16 bytes, got ${rpi.length}");
  }
  final challengeBytes = challenge ?? Uint8List(0);
  if (challengeBytes.length > 0xffff) {
    throw ArgumentError("challenge too long: ${challengeBytes.length} bytes");
  }

  final tagBytes = utf8.encode(rpidProofDomainTag);
  final builder = BytesBuilder();
  builder.add(tagBytes);
  builder.add(eventIdHash);
  builder.add((ByteData(8)..setUint64(0, enin, Endian.big)).buffer.asUint8List());
  builder.add(rpi);
  builder.add((ByteData(2)..setUint16(0, challengeBytes.length, Endian.big)).buffer.asUint8List());
  builder.add(challengeBytes);
  return builder.toBytes();
}

/// Canonical encoding of a signing-key-to-device-identity binding claim:
/// ```
/// "barnard-key-binding:v1" (ASCII, fixed) ‖ EventCodeHash(8) ‖ displayId
/// ```
Uint8List buildKeyBindingMessage({
  required Uint8List eventCodeHash,
  required Uint8List displayId,
}) {
  final builder = BytesBuilder();
  builder.add(utf8.encode(keyBindingDomainTag));
  builder.add(eventCodeHash);
  builder.add(displayId);
  return builder.toBytes();
}

/// Compute the RPID ownership proof for [enin] within [eventCode], per
/// barnard#63. Derives the TEK/RPIK/RPI internally from [deviceSecret] —
/// only the resulting `rpi` (not the TEK/RPIK) appears in the output.
RecoverableSignature signRpidOwnershipProof({
  required Uint8List deviceSecret,
  required String eventCode,
  required Uint8List eventIdHash,
  required int enin,
  required Uint8List rpi,
  Uint8List? challenge,
}) {
  final message = buildRpidProofMessage(
    eventIdHash: eventIdHash,
    enin: enin,
    rpi: rpi,
    challenge: challenge,
  );
  final keyPair = deriveSigningKeyPair(deviceSecret, eventCode);
  final messageHash = sha256(message);
  return signRecoverable(keyPair.privateKey, messageHash);
}

/// Sign the key-binding claim per barnard#63 acceptance criterion 3.
RecoverableSignature signKeyBinding({
  required Uint8List deviceSecret,
  required String eventCode,
  required Uint8List eventCodeHash,
  required Uint8List displayId,
}) {
  final message = buildKeyBindingMessage(eventCodeHash: eventCodeHash, displayId: displayId);
  final keyPair = deriveSigningKeyPair(deviceSecret, eventCode);
  final messageHash = sha256(message);
  return signRecoverable(keyPair.privateKey, messageHash);
}
