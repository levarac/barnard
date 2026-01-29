// Copyright 2024-2026 The Greeting Inc. All rights reserved.
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
  // MARK: - TEK Derivation

  /// Derive TEK for Event Mode from DeviceSecret and EventCode.
  ///
  /// `TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)`
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

  /// Derive TEK for Anonymous Mode from DeviceSecret.
  ///
  /// `TEK = HKDF(DeviceSecret, "barnard-tek-anonymous", 16)`
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

  /// Derive RPIK (Rolling Proximity Identifier Key) from TEK.
  ///
  /// `RPIK = HKDF(TEK, "EN-RPIK", 16)`
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

  /// Generate RPI from RPIK and ENIN.
  ///
  /// `RPI = AES128-ECB(RPIK, PaddedData)`
  ///
  /// Where PaddedData = "EN-RPI" (6 bytes) + 0x000000000000 (6 bytes) + ENIN (4 bytes big-endian)
  static func generateRpi(rpik: Data, enin: UInt32) -> Data {
    guard rpik.count == 16 else {
      return Data(count: 16)
    }

    // Build PaddedData: "EN-RPI" + 6 zero bytes + ENIN (4 bytes big-endian)
    var paddedData = Data(count: 16)

    // "EN-RPI" (6 bytes)
    let prefix = "EN-RPI".data(using: .utf8)!
    paddedData.replaceSubrange(0 ..< 6, with: prefix)

    // 6 zero bytes (already initialized to 0)

    // ENIN as 4 bytes big-endian at offset 12
    var eninBE = enin.bigEndian
    let eninBytes = Data(bytes: &eninBE, count: 4)
    paddedData.replaceSubrange(12 ..< 16, with: eninBytes)

    // AES-128-ECB encryption
    return aes128EcbEncrypt(key: rpik, plaintext: paddedData)
  }

  /// AES-128-ECB encryption of a single 16-byte block.
  private static func aes128EcbEncrypt(key: Data, plaintext: Data) -> Data {
    guard key.count == 16, plaintext.count == 16 else {
      return Data(count: 16)
    }

    var outputBuffer = [UInt8](repeating: 0, count: 16)
    var dataOutMoved = 0

    // Use CommonCrypto for AES-ECB (CryptoKit doesn't support ECB)
    let status = key.withUnsafeBytes { keyPtr in
      plaintext.withUnsafeBytes { inputPtr in
        CCCrypt(
          CCOperation(kCCEncrypt),
          CCAlgorithm(kCCAlgorithmAES128),
          CCOptions(kCCOptionECBMode),
          keyPtr.baseAddress, key.count,
          nil, // No IV for ECB
          inputPtr.baseAddress, plaintext.count,
          &outputBuffer, outputBuffer.count,
          &dataOutMoved
        )
      }
    }

    return status == kCCSuccess ? Data(outputBuffer) : Data(count: 16)
  }

  // MARK: - ENIN Calculation

  /// Calculate ENIN (EN Interval Number) for a given timestamp.
  ///
  /// `ENIN = floor(unix_timestamp_seconds / 600)`
  ///
  /// Each ENIN represents a 10-minute interval.
  static func calculateEnin(for date: Date = Date()) -> UInt32 {
    UInt32(Int(date.timeIntervalSince1970) / 600)
  }

  // MARK: - EventCodeHash

  /// Calculate EventCodeHash from EventCode.
  ///
  /// `EventCodeHash = SHA256(EventCode)[0:8]`
  static func computeEventCodeHash(_ eventCode: String) -> Data {
    guard let eventCodeData = eventCode.data(using: .utf8) else {
      return Data(count: 8)
    }

    let hash = SHA256.hash(data: eventCodeData)
    return Data(hash).prefix(8)
  }

  // MARK: - RPI Resolution

  /// Attempt to resolve an RPI to a known TEK.
  ///
  /// Searches within a time window around the current ENIN (±6 past + 1 future).
  ///
  /// - Parameters:
  ///   - rpi: The 16-byte RPI to resolve
  ///   - knownTeks: List of known TEKs to search
  ///   - currentEnin: Current ENIN (defaults to now)
  /// - Returns: The matching TEK if found, nil otherwise
  static func resolveRpi(_ rpi: Data, knownTeks: [Data], currentEnin: UInt32? = nil) -> Data? {
    guard rpi.count == 16 else { return nil }

    let enin = currentEnin ?? calculateEnin()

    for tek in knownTeks {
      guard tek.count == 16 else { continue }

      let rpik = deriveRpik(from: tek)

      // Search window: 6 intervals past + current + 1 future
      for offset in -6 ... 1 {
        let testEnin = UInt32(Int(enin) + offset)
        let candidate = generateRpi(rpik: rpik, enin: testEnin)

        if candidate == rpi {
          return tek
        }
      }
    }

    return nil
  }

  // MARK: - Display ID

  /// Get displayId from TEK (first 3 bytes as lowercase hex).
  static func displayId(from tek: Data) -> String {
    tek.prefix(3).map { String(format: "%02x", $0) }.joined()
  }

  // MARK: - Random Bytes

  /// Generate cryptographically secure random bytes.
  static func generateRandomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
  }
}
