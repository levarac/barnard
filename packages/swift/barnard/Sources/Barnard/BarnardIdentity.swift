// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

#if canImport(BarnardCore)
import BarnardCore
#endif
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
  private let keyStorage: any BarnardCoreKeyStorage
  private let randomSource: any BarnardCoreRandomSource

  public init() {
    keyStorage = BarnardUserDefaultsKeyStorage()
    randomSource = BarnardSystemRandomSource()
  }

  public func signingPublicKey(eventCode: String) -> Data {
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
    return keyPair.publicKeyCompressed
  }

  /// Signs `SHA256(bytes)` with the per-event signing key derived from
  /// `eventCode`.
  public func sign(eventCode: String, bytes: Data) -> BarnardRecoverableSignature {
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
    let messageHash = BarnardCrypto.sha256(bytes)
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
    Data(BarnardCoreKeyManager.loadOrCreate(
      key: deviceSecretKey,
      minimumByteCount: 32,
      generatedByteCount: 32,
      storage: keyStorage,
      randomSource: randomSource
    ))
  }
}
