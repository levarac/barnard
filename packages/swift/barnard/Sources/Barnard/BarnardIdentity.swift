// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import CryptoKit
import Foundation

/// Recoverable secp256k1 signature `(r, s, v)`, Swift-first mirror of
/// `BarnardSigning.RecoverableSignature`.
public struct BarnardRecoverableSignature {
  public let r: Data
  public let s: Data
  public let v: Int
}

/// Result of `BarnardIdentity.proveRpidOwnership`.
public struct BarnardRpidOwnershipProof {
  public let rpi: Data
  public let signingPublicKey: Data
  public let signature: BarnardRecoverableSignature
}

/// Barnard per-event device signing identity (barnard#65), Flutter-free
/// port of `BarnardIdentityController`.
///
/// A module separate from `BarnardEngine` (the sensing client) — it shares
/// the same on-device `DeviceSecret` storage (`UserDefaults` key
/// `barnard.rpidSeed`) as `BarnardEngine`/`BarnardRpidGenerator` so the
/// signing identity is rooted in the same secret as the sensing client's
/// TEK, but the private signing key it derives never leaves this type —
/// only the public key and signatures do.
public final class BarnardIdentity {
  private let deviceSecretKey = "barnard.rpidSeed"

  public init() {}

  public func signingPublicKey(eventCode: String) -> Data {
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
    return keyPair.publicKeyCompressed
  }

  /// Signs `SHA256(bytes)` with the per-event signing key derived from
  /// `eventCode`.
  public func sign(eventCode: String, bytes: Data) -> BarnardRecoverableSignature {
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
    let messageHash = Data(SHA256.hash(data: bytes))
    let sig = BarnardSigning.signRecoverable(privateKey: keyPair.privateKey, messageHash32: messageHash)
    return BarnardRecoverableSignature(r: sig.r, s: sig.s, v: sig.v)
  }

  public func proveRpidOwnership(
    eventCode: String,
    enin: UInt64,
    eventIdHash: Data,
    challenge: Data? = nil
  ) -> BarnardRpidOwnershipProof {
    let proof = BarnardSigning.proveRpidOwnership(
      deviceSecret: getOrCreateDeviceSecret(),
      eventCode: eventCode,
      eventIdHash: eventIdHash,
      enin: enin,
      challenge: challenge
    )
    return BarnardRpidOwnershipProof(
      rpi: proof.rpi,
      signingPublicKey: proof.signingPublicKey,
      signature: BarnardRecoverableSignature(r: proof.sig.r, s: proof.sig.s, v: proof.sig.v)
    )
  }

  public func proveKeyBinding(eventCode: String, displayId: Data) -> BarnardRecoverableSignature {
    let eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
    let sig = BarnardSigning.signKeyBinding(
      deviceSecret: getOrCreateDeviceSecret(),
      eventCode: eventCode,
      eventCodeHash: eventCodeHash,
      displayId: displayId
    )
    return BarnardRecoverableSignature(r: sig.r, s: sig.s, v: sig.v)
  }

  // MARK: - DeviceSecret Management
  //
  // Same storage key as BarnardRpidGenerator.getOrCreateDeviceSecret — the
  // signing identity and the sensing client are rooted in the same
  // DeviceSecret, but this type never exposes it (unlike
  // BarnardEngine.exportCurrentTek, which is the TEK, not the raw secret).

  private func getOrCreateDeviceSecret() -> Data {
    let defaults = UserDefaults.standard
    if let existing = defaults.data(forKey: deviceSecretKey), existing.count >= 32 {
      return existing
    }
    let newSecret = BarnardCrypto.generateRandomBytes(32)
    defaults.set(newSecret, forKey: deviceSecretKey)
    return newSecret
  }
}
