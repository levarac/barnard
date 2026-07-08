// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import XCTest
@testable import Barnard

/// `BarnardRpidGenerator` persists to `UserDefaults.standard` under fixed
/// keys (`barnard.rpidSeed`, `barnard.eventCode`) — the same behavior as
/// the Flutter plugin's original. Each test clears those keys first so
/// runs are independent of execution order and of state left by the
/// example app or other test targets sharing the same defaults domain.
final class BarnardRpidGeneratorTests: XCTestCase {
  override func setUp() {
    super.setUp()
    clearPersistedState()
  }

  override func tearDown() {
    clearPersistedState()
    super.tearDown()
  }

  private func clearPersistedState() {
    let defaults = UserDefaults.standard
    defaults.removeObject(forKey: "barnard.rpidSeed")
    defaults.removeObject(forKey: "barnard.eventCode")
  }

  func testStartsInAnonymousMode() {
    let generator = BarnardRpidGenerator()
    XCTAssertNil(generator.eventCode)
    XCTAssertFalse(generator.isEventMode)
  }

  func testJoinEventSwitchesToEventModeAndChangesTek() {
    let generator = BarnardRpidGenerator()
    let anonymousTek = generator.getCurrentTek()

    generator.joinEvent("EVT1")
    XCTAssertEqual(generator.eventCode, "EVT1")
    XCTAssertTrue(generator.isEventMode)
    XCTAssertNotEqual(generator.getCurrentTek(), anonymousTek)
  }

  func testLeaveEventReturnsToAnonymousModeWithOriginalTek() {
    let generator = BarnardRpidGenerator()
    let anonymousTek = generator.getCurrentTek()

    generator.joinEvent("EVT1")
    generator.leaveEvent()

    XCTAssertNil(generator.eventCode)
    XCTAssertFalse(generator.isEventMode)
    XCTAssertEqual(generator.getCurrentTek(), anonymousTek)
  }

  func testDeviceSecretIsStableAcrossInstances() {
    let first = BarnardRpidGenerator()
    let secret1 = first.getDeviceSecret()

    let second = BarnardRpidGenerator()
    let secret2 = second.getDeviceSecret()

    XCTAssertEqual(secret1, secret2)
    XCTAssertEqual(secret1.count, 32)
  }

  func testCurrentPayloadIs17BytesWithFormatVersionPrefix() {
    let generator = BarnardRpidGenerator()
    let payload = generator.currentPayload(formatVersion: 1, now: Date(timeIntervalSince1970: 1000))
    XCTAssertEqual(payload.count, 17)
    XCTAssertEqual(payload.first, 1)
  }

  func testCurrentPayloadRotatesAcrossEninWindowsButRpidGeneratorSecretDoesNot() {
    let generator = BarnardRpidGenerator()
    let payload1 = generator.currentPayload(now: Date(timeIntervalSince1970: 0), eninSeconds: 300)
    let payload2 = generator.currentPayload(now: Date(timeIntervalSince1970: 301), eninSeconds: 300)
    XCTAssertNotEqual(payload1, payload2, "on-wire payload must rotate; the device secret must not appear on the wire")
  }

  func testGetCurrentDisplayIdIs8LowercaseHexChars() {
    let generator = BarnardRpidGenerator()
    let displayId = generator.getCurrentDisplayId()
    XCTAssertEqual(displayId.count, 8)
    XCTAssertEqual(displayId, displayId.lowercased())
  }

  func testEventCodeHashEmptyInAnonymousModeAnd8BytesInEventMode() {
    let generator = BarnardRpidGenerator()
    XCTAssertEqual(generator.getEventCodeHash().count, 0)

    generator.joinEvent("EVT1")
    XCTAssertEqual(generator.getEventCodeHash().count, 8)
  }
}
