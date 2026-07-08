// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import CryptoKit
import Foundation

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
/// Mirrors the TEK event-mode derivation shape
/// (`TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)`, see
/// `BarnardCrypto.deriveTekForEvent`) but uses a distinct HKDF `info`
/// string ("barnard-sign" vs "barnard-tek" / "EN-RPIK") so the signing key
/// and the TEK/RPIK chain are not cross-computable.
///
/// iOS has no system-provided secp256k1 (CryptoKit only covers P-256/384/521
/// and Curve25519), so this implements the minimal field/point arithmetic
/// and RFC 6979 deterministic ECDSA directly on a fixed-width 256-bit
/// integer. It has been cross-verified byte-for-byte against the Dart
/// (`package:pointycastle`) and Kotlin (`java.math.BigInteger`)
/// implementations of the same algorithm for the same test vectors.
enum BarnardSigning {
  static let signingKeyInfo = "barnard-sign"

  /// Domain-separation tag for `buildRpidProofMessage` (barnard#63).
  static let rpidProofDomainTag = "barnard-rpid-proof:v1"

  /// Domain-separation tag for `buildKeyBindingMessage` (barnard#63).
  static let keyBindingDomainTag = "barnard-key-binding:v1"

  struct SigningKeyPair {
    let privateKey: Secp256k1.UInt256
    let publicKeyCompressed: Data
  }

  struct RecoverableSignature {
    let r: Data
    let s: Data
    let v: Int
  }

  /// Derive the per-event signing keypair from `deviceSecret` and `eventCode`.
  static func deriveSigningKeyPair(deviceSecret: Data, eventCode: String) -> SigningKeyPair {
    let eventCodeData = eventCode.data(using: .utf8) ?? Data()
    var combined = deviceSecret
    combined.append(eventCodeData)

    let key = SymmetricKey(data: combined)
    var seed = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      info: signingKeyInfo.data(using: .utf8)!,
      outputByteCount: 32
    ).withUnsafeBytes { Data($0) }

    var d = Secp256k1.Field.reduceOnce(Secp256k1.UInt256(data: seed), Secp256k1.N)
    while d.isZero {
      seed = Data(SHA256.hash(data: seed))
      d = Secp256k1.Field.reduceOnce(Secp256k1.UInt256(data: seed), Secp256k1.N)
    }

    let q = Secp256k1.scalarMult(d, Secp256k1.G)
    return SigningKeyPair(privateKey: d, publicKeyCompressed: Secp256k1.compress(q))
  }

  /// Sign a 32-byte message hash with `privateKey`, returning a recoverable
  /// signature `(r, s, v)`. Deterministic (RFC 6979 / HMAC-SHA256 `k`),
  /// normalizes `s` to the lower half of the curve order (canonical /
  /// "low-S" form), and searches for the recovery id (`0` or `1`) against
  /// the caller's own public key.
  static func signRecoverable(privateKey: Secp256k1.UInt256, messageHash32: Data) -> RecoverableSignature {
    precondition(messageHash32.count == 32, "messageHash must be 32 bytes")

    let e = Secp256k1.Field.reduceOnce(Secp256k1.UInt256(data: messageHash32), Secp256k1.N)
    let expectedPub = Secp256k1.compress(Secp256k1.scalarMult(privateKey, Secp256k1.G))

    var r = Secp256k1.UInt256.zero
    var s = Secp256k1.UInt256.zero
    while true {
      let k = deterministicK(privateKey: privateKey, messageHash32: messageHash32)
      let rPoint = Secp256k1.scalarMult(k, Secp256k1.G)
      guard let rx = rPoint.x else { continue }
      r = Secp256k1.Field.reduceOnce(rx, Secp256k1.N)
      if r.isZero { continue }
      let kInv = Secp256k1.Field.invMod(k, Secp256k1.N)
      s = Secp256k1.Field.mulMod(
        kInv,
        Secp256k1.Field.addMod(e, Secp256k1.Field.mulMod(privateKey, r, Secp256k1.N), Secp256k1.N),
        Secp256k1.N
      )
      if s.isZero { continue }
      break
    }

    let halfOrder = Secp256k1.N.shiftedRight1()
    if s > halfOrder {
      s = Secp256k1.N.subtracting(s)
    }

    var recoveryId = -1
    for id in 0..<4 {
      if let candidate = recoverPublicKey(recId: id, r: r, s: s, messageHash32: messageHash32),
        candidate == expectedPub
      {
        recoveryId = id
        break
      }
    }
    precondition(recoveryId != -1, "signRecoverable: could not determine recovery id")

    return RecoverableSignature(r: r.data, s: s.data, v: recoveryId)
  }

  /// Recover the SEC1-compressed public key from `(recId, r, s)` and the
  /// signed message hash. Returns nil if the signature/recovery id is
  /// invalid.
  static func recoverPublicKey(recId: Int, r: Secp256k1.UInt256, s: Secp256k1.UInt256, messageHash32: Data) -> Data? {
    guard recId / 2 == 0 else { return nil }
    if r >= Secp256k1.P { return nil }
    guard let rPoint = Secp256k1.decompress(x: r, yIsOdd: (recId & 1) == 1) else { return nil }
    // secp256k1 has cofactor 1: every point satisfying the curve equation
    // already has order N, so the "N*R == infinity" order check other
    // implementations run here is mathematically redundant and skipped.

    let e = Secp256k1.Field.reduceOnce(Secp256k1.UInt256(data: messageHash32), Secp256k1.N)
    let eNeg = Secp256k1.N.subtracting(e)
    let rInv = Secp256k1.Field.invMod(r, Secp256k1.N)
    let srInv = Secp256k1.Field.mulMod(rInv, s, Secp256k1.N)
    let eInvrInv = Secp256k1.Field.mulMod(rInv, eNeg, Secp256k1.N)

    let term1 = Secp256k1.scalarMult(eInvrInv, Secp256k1.G)
    let term2 = Secp256k1.scalarMult(srInv, rPoint)
    let point = Secp256k1.pointAdd(term1, term2)
    if point.isInfinity { return nil }
    return Secp256k1.compress(point)
  }

  // MARK: - RPID ownership proof / key binding (barnard#63)

  struct RpidOwnershipProof {
    let rpi: Data
    let enin: UInt64
    let eventIdHash: Data
    let signingPublicKey: Data
    let sig: RecoverableSignature
  }

  /// Canonical, fixed-order/length-prefixed encoding of an RPID ownership
  /// proof claim:
  /// `"barnard-rpid-proof:v1" ‖ eventIdHash(32) ‖ enin(8, BE) ‖ rpi(16) ‖ len(challenge) as u16 BE ‖ challenge`.
  static func buildRpidProofMessage(eventIdHash: Data, enin: UInt64, rpi: Data, challenge: Data?) -> Data {
    precondition(eventIdHash.count == 32, "eventIdHash must be 32 bytes")
    precondition(rpi.count == 16, "rpi must be 16 bytes")
    let challengeBytes = challenge ?? Data()
    precondition(challengeBytes.count <= 0xffff, "challenge too long")

    var message = Data(rpidProofDomainTag.utf8)
    message.append(eventIdHash)
    message.append(contentsOf: withUnsafeBytes(of: enin.bigEndian) { Data($0) })
    message.append(rpi)
    message.append(contentsOf: withUnsafeBytes(of: UInt16(challengeBytes.count).bigEndian) { Data($0) })
    message.append(challengeBytes)
    return message
  }

  /// Canonical encoding of a signing-key-to-device-identity binding claim.
  static func buildKeyBindingMessage(eventCodeHash: Data, displayId: Data) -> Data {
    var message = Data(keyBindingDomainTag.utf8)
    message.append(eventCodeHash)
    message.append(displayId)
    return message
  }

  /// Compute the RPID ownership proof for `enin` within `eventCode`, per
  /// barnard#63. Derives the TEK/RPIK/RPI internally from `deviceSecret`
  /// (via `BarnardCrypto`) — only the resulting `rpi` (not the TEK/RPIK)
  /// appears in the output.
  static func proveRpidOwnership(
    deviceSecret: Data,
    eventCode: String,
    eventIdHash: Data,
    enin: UInt64,
    challenge: Data?
  ) -> RpidOwnershipProof {
    let tek = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: eventCode)
    let rpik = BarnardCrypto.deriveRpik(from: tek)
    let rpi = BarnardCrypto.generateRpi(rpik: rpik, enin: UInt32(truncatingIfNeeded: enin))

    let message = buildRpidProofMessage(eventIdHash: eventIdHash, enin: enin, rpi: rpi, challenge: challenge)
    let keyPair = deriveSigningKeyPair(deviceSecret: deviceSecret, eventCode: eventCode)
    let sig = signRecoverable(privateKey: keyPair.privateKey, messageHash32: Data(SHA256.hash(data: message)))

    return RpidOwnershipProof(
      rpi: rpi,
      enin: enin,
      eventIdHash: eventIdHash,
      signingPublicKey: keyPair.publicKeyCompressed,
      sig: sig
    )
  }

  /// Sign the key-binding claim per barnard#63 acceptance criterion 3.
  static func signKeyBinding(
    deviceSecret: Data,
    eventCode: String,
    eventCodeHash: Data,
    displayId: Data
  ) -> RecoverableSignature {
    let message = buildKeyBindingMessage(eventCodeHash: eventCodeHash, displayId: displayId)
    let keyPair = deriveSigningKeyPair(deviceSecret: deviceSecret, eventCode: eventCode)
    return signRecoverable(privateKey: keyPair.privateKey, messageHash32: Data(SHA256.hash(data: message)))
  }

  /// RFC 6979 deterministic `k` (HMAC-SHA256; qlen == hlen == 32 bytes for secp256k1/SHA-256).
  private static func deterministicK(privateKey: Secp256k1.UInt256, messageHash32: Data) -> Secp256k1.UInt256 {
    let x = privateKey.data
    let h1 = Secp256k1.Field.reduceOnce(Secp256k1.UInt256(data: messageHash32), Secp256k1.N).data

    func hmac(_ key: Data, _ data: Data) -> Data {
      Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    var v = Data(repeating: 0x01, count: 32)
    var k = Data(repeating: 0x00, count: 32)

    k = hmac(k, v + Data([0x00]) + x + h1)
    v = hmac(k, v)
    k = hmac(k, v + Data([0x01]) + x + h1)
    v = hmac(k, v)

    while true {
      v = hmac(k, v)
      let candidate = Secp256k1.UInt256(data: v)
      if !candidate.isZero && candidate < Secp256k1.N {
        return candidate
      }
      k = hmac(k, v + Data([0x00]))
      v = hmac(k, v)
    }
  }
}
