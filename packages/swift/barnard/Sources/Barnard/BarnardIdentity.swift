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
/// the same on-device `DeviceSecret` storage key (`barnard.rpidSeed`) as
/// `BarnardEngine`/`BarnardRpidGenerator` so the signing identity is rooted
/// in the same secret as the sensing client's TEK. The default initializer
/// uses `UserDefaults`; hosts can inject another `BarnardCoreKeyStorage`.
/// The private signing key this type derives never leaves it — only the
/// public key and signatures do.
///
/// Deriving that key costs one secp256k1 scalar multiplication, so an
/// instance keeps the most recent derivation in memory
/// (`BarnardSigningKeyCache`). The derived private key is therefore resident
/// for as long as the instance is alive and its inputs are unchanged, rather
/// than only for the duration of a call. Hosts that want a narrower window
/// can release the instance.
public final class BarnardIdentity {
  private let deviceSecretKey = "barnard.rpidSeed"
  private let keyStorage: any BarnardCoreKeyStorage
  private let randomSource: any BarnardCoreRandomSource
  private let signingKeyCache = BarnardSigningKeyCache()

  public init() {
    keyStorage = BarnardUserDefaultsKeyStorage()
    randomSource = BarnardSystemRandomSource()
  }

  /// Creates an identity that reads and creates its DeviceSecret through
  /// `keyStorage` under the `barnard.rpidSeed` key.
  ///
  /// Inject the same storage instance into `BarnardEngine` to keep the
  /// signing-identity and TEK roots aligned.
  public init(keyStorage: any BarnardCoreKeyStorage) {
    self.keyStorage = keyStorage
    randomSource = BarnardSystemRandomSource()
  }

  public func signingPublicKey(eventCode: String) -> Data {
    signingKeyPair(eventCode: eventCode).publicKeyCompressed
  }

  /// Signs `SHA256(bytes)` with the per-event signing key derived from
  /// `eventCode`.
  public func sign(eventCode: String, bytes: Data) -> BarnardRecoverableSignature {
    let keyPair = signingKeyPair(eventCode: eventCode)
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

  // MARK: - Per-event Signing Key

  /// The signing key pair for `eventCode`, reusing the cached derivation
  /// when the device secret and event code are unchanged (barnard#124).
  ///
  /// The device secret is re-read on every call, and the cache is keyed on
  /// it: that is what makes a rotated or cleared secret take effect
  /// immediately. Do not hoist the read out of this method.
  private func signingKeyPair(eventCode: String) -> BarnardSigning.SigningKeyPair {
    signingKeyCache.keyPair(
      deviceSecret: getOrCreateDeviceSecret(),
      eventCode: eventCode
    ) { deviceSecret, eventCode in
      BarnardSigning.deriveSigningKeyPair(deviceSecret: deviceSecret, eventCode: eventCode)
    }
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
