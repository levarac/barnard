// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import CryptoKit
import Flutter
import Foundation

/// Barnard per-event device signing identity (barnard#65).
///
/// A **module separate from the sensing client** — its own
/// `barnard/identity` method channel, not `barnard/methods` (owned by
/// `BarnardBleController`). It shares the same on-device `DeviceSecret`
/// storage (`UserDefaults` key `barnard.rpidSeed`) as `BarnardRpidGenerator`
/// so the signing identity is rooted in the same secret as the sensing
/// client's TEK, but the private signing key it derives never crosses the
/// method channel — only the public key and signatures do.
final class BarnardIdentityController: NSObject, FlutterPlugin {
  private let deviceSecretKey = "barnard.rpidSeed"

  static func register(with _: FlutterPluginRegistrar) {
    // Registered directly by BarnardPlugin.register(with:); this
    // conformance only exists to satisfy `addMethodCallDelegate`'s
    // `FlutterPlugin` requirement.
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "signingPublicKey":
      guard let args = call.arguments as? [String: Any], let eventCode = args["eventCode"] as? String else {
        result(FlutterError(code: "E_ARGS", message: "eventCode is required", details: nil))
        return
      }
      let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
      result(keyPair.publicKeyCompressed.hexString)

    case "sign":
      guard let args = call.arguments as? [String: Any],
        let eventCode = args["eventCode"] as? String,
        let bytesHex = args["bytes"] as? String
      else {
        result(FlutterError(code: "E_ARGS", message: "eventCode and bytes are required", details: nil))
        return
      }
      let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: getOrCreateDeviceSecret(), eventCode: eventCode)
      let messageHash = Data(SHA256.hash(data: hexToBytes(bytesHex)))
      let sig = BarnardSigning.signRecoverable(privateKey: keyPair.privateKey, messageHash32: messageHash)
      result([
        "r": sig.r.hexString,
        "s": sig.s.hexString,
        "v": sig.v,
      ])

    case "proveRpidOwnership":
      guard let args = call.arguments as? [String: Any],
        let eventCode = args["eventCode"] as? String,
        let eninNumber = args["enin"] as? NSNumber,
        let eventIdHashHex = args["eventIdHash"] as? String
      else {
        result(FlutterError(code: "E_ARGS", message: "eventCode, enin and eventIdHash are required", details: nil))
        return
      }
      let challengeHex = args["challenge"] as? String
      let proof = BarnardSigning.proveRpidOwnership(
        deviceSecret: getOrCreateDeviceSecret(),
        eventCode: eventCode,
        eventIdHash: hexToBytes(eventIdHashHex),
        enin: eninNumber.uint64Value,
        challenge: challengeHex.map { hexToBytes($0) }
      )
      result([
        "rpi": proof.rpi.hexString,
        "signingPublicKey": proof.signingPublicKey.hexString,
        "r": proof.sig.r.hexString,
        "s": proof.sig.s.hexString,
        "v": proof.sig.v,
      ])

    case "proveKeyBinding":
      guard let args = call.arguments as? [String: Any],
        let eventCode = args["eventCode"] as? String,
        let displayIdHex = args["displayId"] as? String
      else {
        result(FlutterError(code: "E_ARGS", message: "eventCode and displayId are required", details: nil))
        return
      }
      let eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
      let sig = BarnardSigning.signKeyBinding(
        deviceSecret: getOrCreateDeviceSecret(),
        eventCode: eventCode,
        eventCodeHash: eventCodeHash,
        displayId: hexToBytes(displayIdHex)
      )
      result([
        "r": sig.r.hexString,
        "s": sig.s.hexString,
        "v": sig.v,
      ])

    default:
      result(FlutterMethodNotImplemented)
    }
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

  // MARK: - DeviceSecret Management
  //
  // Same storage key as BarnardRpidGenerator.getOrCreateDeviceSecret — the
  // signing identity and the sensing client are rooted in the same
  // DeviceSecret, but this module never exposes it (unlike
  // BarnardClient.exportCurrentTek, which is the TEK, not the raw secret).

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
