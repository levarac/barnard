// Use of this source code is governed by a BSD-style license.

#if canImport(BarnardCore)
import BarnardCore
#endif
import Foundation

/// Apple-facing adapters for the deterministic cryptographic logic in
/// `BarnardCore`.
enum BarnardCrypto {
  enum EninMode {
    case fixedLength
    case beaconSlot

    var coreValue: BarnardCoreEninMode {
      switch self {
      case .fixedLength: return .fixedLength
      case .beaconSlot: return .beaconSlot
      }
    }
  }

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

    var coreValue: BarnardCoreBeaconChain {
      BarnardCoreBeaconChain(
        chainId: chainId,
        genesisUnixSeconds: Int64(genesisUnixSeconds),
        slotSeconds: Int64(slotSeconds)
      )
    }
  }

  static func deriveTekForEvent(deviceSecret: Data, eventCode: String) -> Data {
    Data(BarnardCoreCrypto.deriveTekForEvent(
      deviceSecret: Array(deviceSecret),
      eventCode: eventCode
    ))
  }

  static func deriveTekForAnonymous(deviceSecret: Data) -> Data {
    Data(BarnardCoreCrypto.deriveTekForAnonymous(
      deviceSecret: Array(deviceSecret)
    ))
  }

  static func deriveRpik(from tek: Data) -> Data {
    Data(BarnardCoreCrypto.deriveRpik(from: Array(tek)))
  }

  static func generateRpi(rpik: Data, enin: UInt32) -> Data {
    Data(BarnardCoreCrypto.generateRpi(rpik: Array(rpik), enin: enin))
  }

  static func calculateEnin(
    for date: Date = Date(),
    mode: EninMode = .fixedLength,
    eninSeconds: Int = 300,
    beaconChain: BeaconChainConfig = .ethereumMainnet
  ) -> UInt32 {
    BarnardCoreCrypto.calculateEnin(
      unixSeconds: Int64(Int(date.timeIntervalSince1970)),
      mode: mode.coreValue,
      eninSeconds: Int64(eninSeconds),
      beaconChain: beaconChain.coreValue
    )
  }

  static func stableReadEnin(
    startedAt: Date,
    completedAt: Date,
    mode: EninMode = .fixedLength,
    eninSeconds: Int = 300,
    beaconChain: BeaconChainConfig = .ethereumMainnet
  ) -> UInt32? {
    BarnardCoreCrypto.stableReadEnin(
      startedAtUnixSeconds: Int64(Int(startedAt.timeIntervalSince1970)),
      completedAtUnixSeconds: Int64(Int(completedAt.timeIntervalSince1970)),
      mode: mode.coreValue,
      eninSeconds: Int64(eninSeconds),
      beaconChain: beaconChain.coreValue
    )
  }

  static func computeEventCodeHash(_ eventCode: String) -> Data {
    Data(BarnardCoreCrypto.computeEventCodeHash(eventCode))
  }

  static func displayId4(from tek: Data) -> Data {
    Data(BarnardCoreCrypto.displayId4(from: Array(tek)))
  }

  static func displayIdString(from tek: Data) -> String {
    displayId4(from: tek).hexString
  }

  static func sha256(_ bytes: Data) -> Data {
    Data(BarnardCoreCrypto.sha256(Array(bytes)))
  }

  static func generateRandomBytes(_ count: Int) -> Data {
    Data(BarnardSystemRandomSource().randomBytes(count: count))
  }
}

extension Data {
  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
