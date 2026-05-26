// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import CryptoKit
import Foundation
import Security

/// GAEN v1.2-compatible RPI generator with Event Mode support.
///
/// Two modes of operation:
/// - **Anonymous Mode** (default): Deterministic TEK derived from DeviceSecret
/// - **Event Mode**: Deterministic TEK derived from DeviceSecret + EventCode
final class BarnardRpidGenerator {
  // MARK: - Storage Keys

  private let deviceSecretKey = "barnard.rpidSeed"
  private let eventCodeKey = "barnard.eventCode"

  // MARK: - State

  /// Current Event Code (nil for Anonymous Mode)
  private(set) var eventCode: String? {
    didSet {
      if eventCode != oldValue {
        regenerateTek()
      }
    }
  }

  /// Current TEK (Temporary Exposure Key)
  private var currentTek: Data

  // MARK: - Initialization

  init() {
    // Load persisted event code
    let defaults = UserDefaults.standard
    eventCode = defaults.string(forKey: eventCodeKey)
    currentTek = Data()

    // Initialize TEK based on mode
    regenerateTek()
  }

  // MARK: - Mode Control

  /// Join an event, switching to Event Mode.
  ///
  /// - Parameter code: The event code to join
  func joinEvent(_ code: String) {
    let defaults = UserDefaults.standard
    defaults.set(code, forKey: eventCodeKey)
    eventCode = code
  }

  /// Leave the current event, switching to Anonymous Mode.
  func leaveEvent() {
    let defaults = UserDefaults.standard
    defaults.removeObject(forKey: eventCodeKey)
    eventCode = nil
  }

  /// Check if currently in Event Mode.
  var isEventMode: Bool {
    eventCode != nil
  }

  // MARK: - TEK Management

  /// Get the current TEK.
  func getCurrentTek() -> Data {
    currentTek
  }

  /// Regenerate TEK based on current mode.
  private func regenerateTek() {
    if let code = eventCode {
      // Event Mode: derive TEK from DeviceSecret + EventCode
      let deviceSecret = getOrCreateDeviceSecret()
      currentTek = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: code)
    } else {
      // Anonymous Mode: derive TEK from DeviceSecret
      let deviceSecret = getOrCreateDeviceSecret()
      currentTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret: deviceSecret)
    }
  }

  // MARK: - EventCodeHash

  /// Get the EventCodeHash for GATT characteristic (8 bytes, or empty for Anonymous Mode).
  func getEventCodeHash() -> Data {
    guard let code = eventCode else {
      return Data() // Empty for Anonymous Mode
    }
    return BarnardCrypto.computeEventCodeHash(code)
  }

  // MARK: - RPID Payload Generation

  /// Generate the current RPID payload for BLE advertisement/GATT.
  ///
  /// - Parameters:
  ///   - formatVersion: Protocol version byte (default: 1)
  ///   - now: Current timestamp (default: now)
  /// - Returns: 17 bytes: [formatVersion(1) + RPI(16)]
  func currentPayload(
    formatVersion: UInt8 = 1,
    now: Date = Date(),
    eninMode: BarnardCrypto.EninMode = .fixedLength,
    eninSeconds: Int = 120,
    beaconChain: BarnardCrypto.BeaconChainConfig = .ethereumMainnet
  ) -> Data {
    let enin = BarnardCrypto.calculateEnin(
      for: now,
      mode: eninMode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain
    )
    let rpik = BarnardCrypto.deriveRpik(from: currentTek)
    let rpi = BarnardCrypto.generateRpi(rpik: rpik, enin: enin)

    var payload = Data([formatVersion])
    payload.append(rpi)
    return payload
  }

  // MARK: - DeviceSecret Management

  /// Get or create the DeviceSecret (32 bytes, device-unique, never transmitted).
  private func getOrCreateDeviceSecret() -> Data {
    let defaults = UserDefaults.standard

    if let existing = defaults.data(forKey: deviceSecretKey), existing.count >= 32 {
      return existing
    }

    // Generate new 32-byte DeviceSecret
    let newSecret = BarnardCrypto.generateRandomBytes(32)
    defaults.set(newSecret, forKey: deviceSecretKey)
    return newSecret
  }

  /// Get the DeviceSecret (for platform channel access).
  func getDeviceSecret() -> Data {
    getOrCreateDeviceSecret()
  }

  // MARK: - Display IDs

  /// v2 displayId for the current TEK: `SHA256(TEK)[0:4]` as 8 hex chars.
  func getCurrentDisplayId() -> String {
    BarnardCrypto.displayIdString(from: currentTek)
  }
}
