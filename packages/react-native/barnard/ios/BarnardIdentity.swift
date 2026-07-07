import CryptoKit
import Foundation
import React

/// Barnard per-event device signing identity (barnard#65).
///
/// A **module separate from the sensing client** (`Barnard`) — its own RN
/// native module, not part of `Barnard`. It shares the same on-device
/// `DeviceSecret` storage (`UserDefaults` key `barnard.rpidSeed`) as
/// `BarnardRpidGenerator`, so the signing identity is rooted in the same
/// secret as the sensing client's TEK, but the private signing key it
/// derives never crosses the RN bridge — only the public key and
/// signatures do.
@objc(BarnardIdentity)
class BarnardIdentity: NSObject {
  private let deviceSecretKey = "barnard.rpidSeed"

  @objc static func requiresMainQueueSetup() -> Bool { false }

  @objc(signingPublicKey:resolve:reject:)
  func signingPublicKey(_ eventCode: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
    resolve(keyPair.publicKeyCompressed.hexString)
  }

  @objc(sign:bytesHex:resolve:reject:)
  func sign(
    _ eventCode: String,
    bytesHex: String,
    resolve: RCTPromiseResolveBlock,
    reject: RCTPromiseRejectBlock
  ) {
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
    let messageHash = Data(SHA256.hash(data: hexToBytes(bytesHex)))
    let sig = BarnardSigning.signRecoverable(privateKey: keyPair.privateKey, messageHash32: messageHash)
    resolve([
      "r": sig.r.hexString,
      "s": sig.s.hexString,
      "v": sig.v,
    ])
  }

  @objc(proveRpidOwnership:enin:eventIdHashHex:challengeHex:resolve:reject:)
  func proveRpidOwnership(
    _ eventCode: String,
    enin: NSNumber,
    eventIdHashHex: String,
    challengeHex: String?,
    resolve: RCTPromiseResolveBlock,
    reject: RCTPromiseRejectBlock
  ) {
    let proof = BarnardSigning.proveRpidOwnership(
      deviceSecret: getOrCreateDeviceSecret(),
      eventCode: eventCode,
      eventIdHash: hexToBytes(eventIdHashHex),
      enin: enin.uint64Value,
      challenge: challengeHex.map { hexToBytes($0) }
    )
    resolve([
      "rpi": proof.rpi.hexString,
      "signingPublicKey": proof.signingPublicKey.hexString,
      "r": proof.sig.r.hexString,
      "s": proof.sig.s.hexString,
      "v": proof.sig.v,
    ])
  }

  @objc(proveKeyBinding:displayIdHex:resolve:reject:)
  func proveKeyBinding(
    _ eventCode: String,
    displayIdHex: String,
    resolve: RCTPromiseResolveBlock,
    reject: RCTPromiseRejectBlock
  ) {
    let eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
    let sig = BarnardSigning.signKeyBinding(
      deviceSecret: getOrCreateDeviceSecret(),
      eventCode: eventCode,
      eventCodeHash: eventCodeHash,
      displayId: hexToBytes(displayIdHex)
    )
    resolve([
      "r": sig.r.hexString,
      "s": sig.s.hexString,
      "v": sig.v,
    ])
  }

  private func hexToBytes(_ hex: String) -> Data {
    var clean = hex
    if clean.count % 2 != 0 { clean = "0" + clean }
    var bytes = [UInt8]()
    var idx = clean.startIndex
    while idx < clean.endIndex {
      let next = clean.index(idx, offsetBy: 2)
      bytes.append(UInt8(clean[idx..<next], radix: 16) ?? 0)
      idx = next
    }
    return Data(bytes)
  }

  // Same storage key as BarnardRpidGenerator.getOrCreateDeviceSecret — see
  // that class for the rationale (shared DeviceSecret, never exposed).
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
