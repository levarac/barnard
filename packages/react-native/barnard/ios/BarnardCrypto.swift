// Use of this source code is governed by a BSD-style license.

import CommonCrypto
import CryptoKit
import Foundation

/// GAEN v1.2-compatible cryptographic utilities for Resolvable ID.
///
/// Key derivation chain:
/// ```
/// DeviceSecret (32 bytes)
///      |
///      +-- Anonymous Mode: TEK = HKDF(DeviceSecret, "barnard-tek-anonymous", 16)
///      |
///      +-- Event Mode: TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)
///                           |
///                           v
///                      RPIK = HKDF(TEK, "EN-RPIK", 16)
///                           |
///                           v
///                      RPI = AES128-ECB(RPIK, PaddedData)
/// ```
enum BarnardCrypto {
  enum EninMode {
    case fixedLength
    case beaconSlot
  }

  static let rpidBoundaryRetryDelaySeconds: TimeInterval = 0.25

  struct BeaconChainConfig {
    let chainId: String
    let genesisUnixSeconds: Int
    let slotSeconds: Int

    static let ethereumMainnet = BeaconChainConfig(
      chainId: "mainnet",
      genesisUnixSeconds: 1_606_824_023,
      slotSeconds: 12
    )

    var effectiveGenesisUnixSeconds: Int {
      max(0, genesisUnixSeconds)
    }

    var effectiveSlotSeconds: Int {
      max(1, slotSeconds)
    }
  }

  // MARK: - TEK Derivation

  static func deriveTekForEvent(deviceSecret: Data, eventCode: String) -> Data {
    guard let eventCodeData = eventCode.data(using: .utf8) else {
      return generateRandomBytes(16)
    }

    var combined = deviceSecret
    combined.append(eventCodeData)

    let key = SymmetricKey(data: combined)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      info: "barnard-tek".data(using: .utf8)!,
      outputByteCount: 16
    )

    return derived.withUnsafeBytes { Data($0) }
  }

  static func deriveTekForAnonymous(deviceSecret: Data) -> Data {
    let key = SymmetricKey(data: deviceSecret)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      info: "barnard-tek-anonymous".data(using: .utf8)!,
      outputByteCount: 16
    )
    return derived.withUnsafeBytes { Data($0) }
  }

  // MARK: - RPIK Derivation

  static func deriveRpik(from tek: Data) -> Data {
    guard tek.count == 16 else {
      return Data(count: 16)
    }

    let key = SymmetricKey(data: tek)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      info: "EN-RPIK".data(using: .utf8)!,
      outputByteCount: 16
    )

    return derived.withUnsafeBytes { Data($0) }
  }

  // MARK: - RPI Generation

  static func generateRpi(rpik: Data, enin: UInt32) -> Data {
    guard rpik.count == 16 else {
      return Data(count: 16)
    }

    var paddedData = Data(count: 16)

    let prefix = "EN-RPI".data(using: .utf8)!
    paddedData.replaceSubrange(0 ..< 6, with: prefix)

    var eninBE = enin.bigEndian
    let eninBytes = Data(bytes: &eninBE, count: 4)
    paddedData.replaceSubrange(12 ..< 16, with: eninBytes)

    return aes128EcbEncrypt(key: rpik, plaintext: paddedData)
  }

  private static func aes128EcbEncrypt(key: Data, plaintext: Data) -> Data {
    guard key.count == 16, plaintext.count == 16 else {
      return Data(count: 16)
    }

    var outputBuffer = [UInt8](repeating: 0, count: 16)
    var dataOutMoved = 0

    let status = key.withUnsafeBytes { keyPtr in
      plaintext.withUnsafeBytes { inputPtr in
        CCCrypt(
          CCOperation(kCCEncrypt),
          CCAlgorithm(kCCAlgorithmAES128),
          CCOptions(kCCOptionECBMode),
          keyPtr.baseAddress, key.count,
          nil,
          inputPtr.baseAddress, plaintext.count,
          &outputBuffer, outputBuffer.count,
          &dataOutMoved
        )
      }
    }

    return status == kCCSuccess ? Data(outputBuffer) : Data(count: 16)
  }

  // MARK: - ENIN Calculation

  static func calculateEnin(
    for date: Date = Date(),
    mode: EninMode = .fixedLength,
    eninSeconds: Int = 300,
    beaconChain: BeaconChainConfig = .ethereumMainnet
  ) -> UInt32 {
    let unixSeconds = Int(date.timeIntervalSince1970)
    switch mode {
    case .fixedLength:
      let effectiveSeconds = min(max(eninSeconds, 12), 3600)
      return UInt32(unixSeconds / effectiveSeconds)
    case .beaconSlot:
      let elapsed = unixSeconds - beaconChain.effectiveGenesisUnixSeconds
      return elapsed <= 0 ? 0 : UInt32(elapsed / beaconChain.effectiveSlotSeconds)
    }
  }

  static func stableReadEnin(
    startedAt: Date,
    completedAt: Date,
    mode: EninMode = .fixedLength,
    eninSeconds: Int = 300,
    beaconChain: BeaconChainConfig = .ethereumMainnet
  ) -> UInt32? {
    let startedEnin = calculateEnin(
      for: startedAt,
      mode: mode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain
    )
    let completedEnin = calculateEnin(
      for: completedAt,
      mode: mode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain
    )
    return startedEnin == completedEnin ? completedEnin : nil
  }

  // MARK: - EventCodeHash

  static func computeEventCodeHash(_ eventCode: String) -> Data {
    guard let eventCodeData = eventCode.data(using: .utf8) else {
      return Data(count: 8)
    }

    let hash = SHA256.hash(data: eventCodeData)
    return Data(hash).prefix(8)
  }

  // MARK: - Display ID (v2)

  /// v2 displayId: `SHA256(TEK)[0:4]` = 4 bytes.
  static func displayId4(from tek: Data) -> Data {
    let hash = SHA256.hash(data: tek)
    return Data(hash).prefix(4)
  }

  /// v2 displayId hex: 8 lowercase hex chars.
  static func displayIdString(from tek: Data) -> String {
    displayId4(from: tek).hexString
  }

  // MARK: - Random Bytes

  static func generateRandomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
  }
}

/// Lowercase-hex helpers for the RN bridge boundary.
extension Data {
  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
