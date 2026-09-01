// Use of this source code is governed by a BSD-style license.

import BarnardCore
import XCTest
@testable import Barnard

final class BarnardDeviceSecretStorageInjectionTests: XCTestCase {
  func testIdentityUsesInjectedDeviceSecretStorage() {
    let secret = [UInt8](repeating: 0x61, count: 32)
    let storage = RecordingKeyStorage(values: ["barnard.rpidSeed": secret])

    let identity = BarnardIdentity(keyStorage: storage)

    XCTAssertEqual(
      identity.signingPublicKey(eventCode: "EVT1"),
      BarnardSigning.deriveSigningKeyPair(
        deviceSecret: Data(secret),
        eventCode: "EVT1"
      ).publicKeyCompressed
    )
    XCTAssertEqual(storage.setBytesCalls.count, 0)
  }

  func testEngineUsesInjectedDeviceSecretStorageForTek() {
    let secret = [UInt8](repeating: 0x62, count: 32)
    let storage = RecordingKeyStorage(values: ["barnard.rpidSeed": secret])

    let engine = BarnardEngine(keyStorage: storage)

    XCTAssertEqual(
      engine.exportCurrentTek(),
      BarnardCrypto.deriveTekForAnonymous(deviceSecret: Data(secret)).hexString
    )
    XCTAssertEqual(storage.setBytesCalls.count, 0)
  }

  func testIdentityAndEngineShareOneInjectedDeviceSecret() throws {
    let storage = RecordingKeyStorage()
    let identity = BarnardIdentity(keyStorage: storage)

    let signingPublicKey = identity.signingPublicKey(eventCode: "EVT1")
    let engine = BarnardEngine(keyStorage: storage)

    XCTAssertEqual(storage.setBytesCalls.count, 1)
    XCTAssertEqual(storage.setBytesCalls.first?.key, "barnard.rpidSeed")

    let storedSecret = try XCTUnwrap(storage.values["barnard.rpidSeed"])
    XCTAssertEqual(storage.setBytesCalls.first?.bytes, storedSecret)
    XCTAssertEqual(storedSecret.count, 32)
    XCTAssertEqual(
      signingPublicKey,
      BarnardSigning.deriveSigningKeyPair(
        deviceSecret: Data(storedSecret),
        eventCode: "EVT1"
      ).publicKeyCompressed
    )
    XCTAssertEqual(
      engine.exportCurrentTek(),
      BarnardCrypto.deriveTekForAnonymous(deviceSecret: Data(storedSecret)).hexString
    )
  }
}

private final class RecordingKeyStorage: BarnardCoreKeyStorage {
  struct SetBytesCall {
    let key: String
    let bytes: [UInt8]
  }

  var values: [String: [UInt8]]
  private(set) var setBytesCalls: [SetBytesCall] = []

  init(values: [String: [UInt8]] = [:]) {
    self.values = values
  }

  func bytes(forKey key: String) -> [UInt8]? {
    values[key]
  }

  func setBytes(_ bytes: [UInt8], forKey key: String) {
    setBytesCalls.append(SetBytesCall(key: key, bytes: bytes))
    values[key] = bytes
  }
}
