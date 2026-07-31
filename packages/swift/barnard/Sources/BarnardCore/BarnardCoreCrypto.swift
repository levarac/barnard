// Use of this source code is governed by a BSD-style license.

public protocol BarnardCoreRandomSource {
  func randomBytes(count: Int) -> [UInt8]
}

public protocol BarnardCoreKeyStorage {
  func bytes(forKey key: String) -> [UInt8]?
  func setBytes(_ bytes: [UInt8], forKey key: String)
}

public protocol BarnardCoreClock {
  func currentUnixSeconds() -> Int64
}

public enum BarnardCoreEninMode {
  case fixedLength
  case beaconSlot
}

public struct BarnardCoreBeaconChain {
  public let chainId: String
  public let genesisUnixSeconds: Int64
  public let slotSeconds: Int64

  public static let ethereumMainnet = BarnardCoreBeaconChain(
    chainId: "mainnet",
    genesisUnixSeconds: 1_606_824_023,
    slotSeconds: 12
  )

  public init(chainId: String, genesisUnixSeconds: Int64, slotSeconds: Int64) {
    self.chainId = chainId
    self.genesisUnixSeconds = genesisUnixSeconds
    self.slotSeconds = slotSeconds
  }

  public var effectiveGenesisUnixSeconds: Int64 {
    max(0, genesisUnixSeconds)
  }

  public var effectiveSlotSeconds: Int64 {
    max(1, slotSeconds)
  }
}

public enum BarnardCoreKeyManager {
  public static func loadOrCreate(
    key: String,
    minimumByteCount: Int,
    generatedByteCount: Int,
    storage: any BarnardCoreKeyStorage,
    randomSource: any BarnardCoreRandomSource
  ) -> [UInt8] {
    if let existing = storage.bytes(forKey: key), existing.count >= minimumByteCount {
      return existing
    }
    let generated = randomSource.randomBytes(count: generatedByteCount)
    storage.setBytes(generated, forKey: key)
    return generated
  }
}

public enum BarnardCoreCrypto {
  /// Calculates ENIN without trapping when an input cannot fit in `UInt32`.
  ///
  /// This is the boundary-safe counterpart to `calculateEnin`. It shares the
  /// fixed-length clamps and beacon-chain normalization used by the core
  /// calculation, so foreign-function callers do not need to duplicate them.
  public static func calculateEninIfRepresentable(
    unixSeconds: Int64,
    mode: BarnardCoreEninMode = .fixedLength,
    eninSeconds: Int64 = 300,
    beaconChain: BarnardCoreBeaconChain = .ethereumMainnet
  ) -> UInt32? {
    let window: Int64
    switch mode {
    case .fixedLength:
      guard unixSeconds >= 0 else { return nil }
      let effectiveSeconds = min(max(eninSeconds, 12), 3_600)
      window = unixSeconds / effectiveSeconds
    case .beaconSlot:
      let (elapsed, overflow) = unixSeconds.subtractingReportingOverflow(
        beaconChain.effectiveGenesisUnixSeconds
      )
      guard !overflow else { return 0 }
      guard elapsed > 0 else { return 0 }
      window = elapsed / beaconChain.effectiveSlotSeconds
    }
    guard window <= Int64(UInt32.max) else { return nil }
    return UInt32(window)
  }

  public static func deriveTekForEvent(
    deviceSecret: [UInt8],
    eventCode: String
  ) -> [UInt8] {
    BarnardCorePrimitives.hkdfSha256(
      inputKeyMaterial: deviceSecret + Array(eventCode.utf8),
      info: Array("barnard-tek".utf8),
      outputByteCount: 16
    )
  }

  public static func deriveTekForAnonymous(deviceSecret: [UInt8]) -> [UInt8] {
    BarnardCorePrimitives.hkdfSha256(
      inputKeyMaterial: deviceSecret,
      info: Array("barnard-tek-anonymous".utf8),
      outputByteCount: 16
    )
  }

  public static func deriveRpik(from tek: [UInt8]) -> [UInt8] {
    guard tek.count == 16 else {
      return [UInt8](repeating: 0, count: 16)
    }
    return BarnardCorePrimitives.hkdfSha256(
      inputKeyMaterial: tek,
      info: Array("EN-RPIK".utf8),
      outputByteCount: 16
    )
  }

  public static func generateRpi(rpik: [UInt8], enin: UInt32) -> [UInt8] {
    guard rpik.count == 16 else {
      return [UInt8](repeating: 0, count: 16)
    }
    var paddedData = Array("EN-RPI".utf8)
    paddedData += [UInt8](repeating: 0, count: 6)
    paddedData.append(UInt8((enin >> 24) & 0xff))
    paddedData.append(UInt8((enin >> 16) & 0xff))
    paddedData.append(UInt8((enin >> 8) & 0xff))
    paddedData.append(UInt8(enin & 0xff))
    return BarnardCorePrimitives.aes128EcbEncrypt(key: rpik, plaintext: paddedData)
  }

  public static func calculateEnin(
    unixSeconds: Int64,
    mode: BarnardCoreEninMode = .fixedLength,
    eninSeconds: Int64 = 300,
    beaconChain: BarnardCoreBeaconChain = .ethereumMainnet
  ) -> UInt32 {
    guard let result = calculateEninIfRepresentable(
      unixSeconds: unixSeconds,
      mode: mode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain
    ) else {
      preconditionFailure("ENIN input is outside the UInt32 representable domain")
    }
    return result
  }

  public static func stableReadEnin(
    startedAtUnixSeconds: Int64,
    completedAtUnixSeconds: Int64,
    mode: BarnardCoreEninMode = .fixedLength,
    eninSeconds: Int64 = 300,
    beaconChain: BarnardCoreBeaconChain = .ethereumMainnet
  ) -> UInt32? {
    let startedEnin = calculateEnin(
      unixSeconds: startedAtUnixSeconds,
      mode: mode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain
    )
    let completedEnin = calculateEnin(
      unixSeconds: completedAtUnixSeconds,
      mode: mode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain
    )
    return startedEnin == completedEnin ? completedEnin : nil
  }

  public static func computeEventCodeHash(_ eventCode: String) -> [UInt8] {
    Array(BarnardCorePrimitives.sha256(Array(eventCode.utf8)).prefix(8))
  }

  public static func displayId4(from tek: [UInt8]) -> [UInt8] {
    Array(BarnardCorePrimitives.sha256(tek).prefix(4))
  }

  public static func currentPayload(
    tek: [UInt8],
    formatVersion: UInt8 = 1,
    clock: any BarnardCoreClock,
    mode: BarnardCoreEninMode = .fixedLength,
    eninSeconds: Int64 = 300,
    beaconChain: BarnardCoreBeaconChain = .ethereumMainnet
  ) -> [UInt8] {
    let enin = calculateEnin(
      unixSeconds: clock.currentUnixSeconds(),
      mode: mode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain
    )
    return [formatVersion] + generateRpi(rpik: deriveRpik(from: tek), enin: enin)
  }

  public static func sha256(_ bytes: [UInt8]) -> [UInt8] {
    BarnardCorePrimitives.sha256(bytes)
  }

  /// Ethereum Keccak-256 (legacy Keccak padding, not NIST SHA3-256).
  public static func keccak256(_ bytes: [UInt8]) -> [UInt8] {
    BarnardCorePrimitives.keccak256(bytes)
  }
}
