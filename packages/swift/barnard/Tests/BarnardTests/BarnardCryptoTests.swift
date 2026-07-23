// Use of this source code is governed by a BSD-style license.

import XCTest
@testable import Barnard

final class BarnardCryptoTests: XCTestCase {
  func testDeriveTekForEventIsDeterministic() {
    let deviceSecret = Data(repeating: 0xAB, count: 32)
    let tek1 = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: "EVT1")
    let tek2 = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: "EVT1")
    XCTAssertEqual(tek1, tek2)
    XCTAssertEqual(tek1.count, 16)
  }

  func testDeriveTekForEventDependsOnEventCode() {
    let deviceSecret = Data(repeating: 0xAB, count: 32)
    let tekA = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: "EVT-A")
    let tekB = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: "EVT-B")
    XCTAssertNotEqual(tekA, tekB)
  }

  func testDeriveTekForAnonymousDiffersFromEventMode() {
    let deviceSecret = Data(repeating: 0xCD, count: 32)
    let anonymousTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret: deviceSecret)
    let eventTek = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: "EVT1")
    XCTAssertEqual(anonymousTek.count, 16)
    XCTAssertNotEqual(anonymousTek, eventTek)
  }

  func testDeriveRpikRequires16ByteTek() {
    let shortTek = Data(repeating: 0x01, count: 8)
    XCTAssertEqual(BarnardCrypto.deriveRpik(from: shortTek), Data(count: 16))

    let tek = Data(repeating: 0x02, count: 16)
    let rpik = BarnardCrypto.deriveRpik(from: tek)
    XCTAssertEqual(rpik.count, 16)
  }

  func testGenerateRpiIsDeterministicForSameEnin() {
    let rpik = Data(repeating: 0x03, count: 16)
    let rpi1 = BarnardCrypto.generateRpi(rpik: rpik, enin: 42)
    let rpi2 = BarnardCrypto.generateRpi(rpik: rpik, enin: 42)
    XCTAssertEqual(rpi1, rpi2)
    XCTAssertEqual(rpi1.count, 16)
  }

  func testGenerateRpiChangesWithEnin() {
    let rpik = Data(repeating: 0x03, count: 16)
    let rpiA = BarnardCrypto.generateRpi(rpik: rpik, enin: 1)
    let rpiB = BarnardCrypto.generateRpi(rpik: rpik, enin: 2)
    XCTAssertNotEqual(rpiA, rpiB)
  }

  func testCalculateEninFixedLengthFloorsToWindow() {
    // 300s window: unix seconds 900...1199 all map to ENIN 3.
    let date = Date(timeIntervalSince1970: 1000)
    let enin = BarnardCrypto.calculateEnin(for: date, mode: .fixedLength, eninSeconds: 300)
    XCTAssertEqual(enin, 3)
  }

  func testCalculateEninFixedLengthClampsSeconds() {
    let date = Date(timeIntervalSince1970: 1_000_000)
    // Request an out-of-range window; must clamp to [12, 3600].
    let eninTooSmall = BarnardCrypto.calculateEnin(for: date, mode: .fixedLength, eninSeconds: 1)
    let eninAt12 = BarnardCrypto.calculateEnin(for: date, mode: .fixedLength, eninSeconds: 12)
    XCTAssertEqual(eninTooSmall, eninAt12)

    let eninTooLarge = BarnardCrypto.calculateEnin(for: date, mode: .fixedLength, eninSeconds: 999_999)
    let eninAt3600 = BarnardCrypto.calculateEnin(for: date, mode: .fixedLength, eninSeconds: 3600)
    XCTAssertEqual(eninTooLarge, eninAt3600)
  }

  func testCalculateEninBeaconSlotBeforeGenesisIsZero() {
    let chain = BarnardCrypto.BeaconChainConfig(chainId: "test", genesisUnixSeconds: 1_000_000, slotSeconds: 12)
    let beforeGenesis = Date(timeIntervalSince1970: 500_000)
    XCTAssertEqual(BarnardCrypto.calculateEnin(for: beforeGenesis, mode: .beaconSlot, beaconChain: chain), 0)
  }

  func testCalculateEninBeaconSlotAfterGenesis() {
    let chain = BarnardCrypto.BeaconChainConfig(chainId: "test", genesisUnixSeconds: 1_000_000, slotSeconds: 12)
    let date = Date(timeIntervalSince1970: 1_000_000 + 36)
    XCTAssertEqual(BarnardCrypto.calculateEnin(for: date, mode: .beaconSlot, beaconChain: chain), 3)
  }

  func testStableReadEninReturnsNilAcrossBoundary() {
    let startedAt = Date(timeIntervalSince1970: 899)
    let completedAt = Date(timeIntervalSince1970: 901)
    XCTAssertNil(BarnardCrypto.stableReadEnin(startedAt: startedAt, completedAt: completedAt, eninSeconds: 300))
  }

  func testStableReadEninReturnsEninWithinSameWindow() {
    let startedAt = Date(timeIntervalSince1970: 905)
    let completedAt = Date(timeIntervalSince1970: 907)
    XCTAssertEqual(
      BarnardCrypto.stableReadEnin(startedAt: startedAt, completedAt: completedAt, eninSeconds: 300),
      3
    )
  }

  func testComputeEventCodeHashIs8BytesAndDeterministic() {
    let hash1 = BarnardCrypto.computeEventCodeHash("EVT1")
    let hash2 = BarnardCrypto.computeEventCodeHash("EVT1")
    XCTAssertEqual(hash1, hash2)
    XCTAssertEqual(hash1.count, 8)

    let otherHash = BarnardCrypto.computeEventCodeHash("EVT2")
    XCTAssertNotEqual(hash1, otherHash)
  }

  func testDisplayId4Is4BytesAndDeterministic() {
    let tek = Data(repeating: 0x09, count: 16)
    let id1 = BarnardCrypto.displayId4(from: tek)
    let id2 = BarnardCrypto.displayId4(from: tek)
    XCTAssertEqual(id1, id2)
    XCTAssertEqual(id1.count, 4)
  }

  func testDisplayIdStringIs8LowercaseHexChars() {
    let tek = Data(repeating: 0x0A, count: 16)
    let str = BarnardCrypto.displayIdString(from: tek)
    XCTAssertEqual(str.count, 8)
    XCTAssertEqual(str, str.lowercased())
    XCTAssertNotNil(UInt32(str, radix: 16))
  }

  func testGenerateRandomBytesProducesRequestedLengthAndVaries() {
    let a = BarnardCrypto.generateRandomBytes(32)
    let b = BarnardCrypto.generateRandomBytes(32)
    XCTAssertEqual(a.count, 32)
    XCTAssertEqual(b.count, 32)
    // Astronomically unlikely to collide; guards against a broken/stubbed RNG.
    XCTAssertNotEqual(a, b)
  }

  // MARK: - On-wire invariant

  /// Barnard's core privacy invariant (AGENTS.md, issue #56): no
  /// device-unique persistent identifier may appear on the wire. RPI must
  /// rotate every ENIN window instead of staying fixed per device.
  func testRpiRotatesAcrossEninWindowsForSameDevice() {
    let deviceSecret = Data(repeating: 0x11, count: 32)
    let tek = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: "EVT1")
    let rpik = BarnardCrypto.deriveRpik(from: tek)

    let rpiWindow1 = BarnardCrypto.generateRpi(rpik: rpik, enin: 100)
    let rpiWindow2 = BarnardCrypto.generateRpi(rpik: rpik, enin: 101)
    XCTAssertNotEqual(rpiWindow1, rpiWindow2, "RPI must not stay constant across ENIN windows")
  }
}
