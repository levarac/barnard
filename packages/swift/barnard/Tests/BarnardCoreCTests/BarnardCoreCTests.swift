// Use of this source code is governed by a BSD-style license.

import Foundation
import XCTest
@testable import BarnardCoreC

/// Replays the issue #80 golden behavior vector (BarnardBehaviorVectorTests)
/// exclusively through the exported C ABI entry points, so any drift between
/// the C surface and BarnardCore fails byte-identically here.
final class BarnardCoreCTests: XCTestCase {
  private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }

  func testCAbiReproducesIssue80GoldenVector() {
    let deviceSecret = (0..<32).map(UInt8.init)
    let eventCode = Array("CORE-SPLIT-80".utf8)
    let enin: UInt32 = 123_456

    var eventTek = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(
      barnard_core_derive_tek_for_event(
        deviceSecret, 32, eventCode, Int32(eventCode.count), &eventTek
      ),
      0
    )
    XCTAssertEqual(hex(eventTek), "51c9263c4fbfc28fb28a76ab0d5d83d6")

    var anonymousTek = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_derive_tek_for_anonymous(deviceSecret, 32, &anonymousTek), 0)
    XCTAssertEqual(hex(anonymousTek), "1fc47c788289a03f2fbc8382f80b060c")

    var rpik = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_derive_rpik(eventTek, &rpik), 0)
    XCTAssertEqual(hex(rpik), "9c20d41985cc258c21e11f10f764b954")

    var rpi = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_generate_rpi(rpik, enin, &rpi), 0)
    XCTAssertEqual(hex(rpi), "be601a7b45035ec4c85f8e203679d5ae")
    XCTAssertEqual(hex([1] + rpi), "01be601a7b45035ec4c85f8e203679d5ae")

    var displayId = [UInt8](repeating: 0, count: 4)
    XCTAssertEqual(barnard_core_display_id4(eventTek, &displayId), 0)
    XCTAssertEqual(hex(displayId), "c0fab611")

    var eventCodeHash = [UInt8](repeating: 0, count: 8)
    XCTAssertEqual(
      barnard_core_compute_event_code_hash(eventCode, Int32(eventCode.count), &eventCodeHash),
      0
    )
    XCTAssertEqual(hex(eventCodeHash), "0b9f14789f13968f")

    XCTAssertEqual(
      barnard_core_calculate_enin(1_700_000_123, 0, 300, 0, 0),
      5_666_667
    )
    XCTAssertEqual(
      barnard_core_calculate_enin(1_700_000_123, 1, 300, 1_600_000_000, 12),
      8_333_343
    )

    var stableEnin: UInt32 = 0
    XCTAssertEqual(barnard_core_stable_read_enin(899, 899, 0, 300, 0, 0, &stableEnin), 1)
    XCTAssertEqual(stableEnin, 2)
    XCTAssertEqual(barnard_core_stable_read_enin(899, 900, 0, 300, 0, 0, &stableEnin), 0)

    XCTAssertEqual(barnard_core_should_serve_gatt_display_id(eventCode, 0), 0)
    XCTAssertEqual(
      barnard_core_should_serve_gatt_display_id(eventCode, Int32(eventCode.count)),
      1
    )
    XCTAssertEqual(barnard_core_should_emit_rssi_update(enin, enin + 1), 0)
    XCTAssertEqual(barnard_core_should_emit_rssi_update(enin, enin), 1)

    var privateKey = [UInt8](repeating: 0, count: 32)
    var publicKey = [UInt8](repeating: 0, count: 33)
    XCTAssertEqual(
      barnard_core_derive_signing_keypair(
        deviceSecret, 32, eventCode, Int32(eventCode.count), &privateKey, &publicKey
      ),
      0
    )
    XCTAssertEqual(
      hex(privateKey),
      "054e89de8696ef821cd60963bf0d2980ce1392241a1606ed3bed32983448f404"
    )
    XCTAssertEqual(
      hex(publicKey),
      "036548e454f2b65bf3dc9676d64f8f22517caf0a07af7f33e0710fda7b8efd9e0c"
    )

    let message = Array("issue-80-signing".utf8)
    var messageHash = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(barnard_core_sha256(message, Int32(message.count), &messageHash), 0)

    var r = [UInt8](repeating: 0, count: 32)
    var s = [UInt8](repeating: 0, count: 32)
    var v: Int32 = -1
    XCTAssertEqual(barnard_core_sign_recoverable(privateKey, messageHash, &r, &s, &v), 0)
    XCTAssertEqual(hex(r), "e7df5948c76c2c0c3397dcdbf72fed1cf87e5d2379cb0831e4d2f1f2b3f262f5")
    XCTAssertEqual(hex(s), "51760b12ac9be31472f61ca68574e7d1c950ca68504d7dd37bff1bba97e3e7d8")
    XCTAssertEqual(v, 0)
  }

  func testOutOfDomainTimestampsDoNotTrap() {
    // calculate_enin has no error channel: out-of-domain saturates.
    XCTAssertEqual(barnard_core_calculate_enin(-400, 0, 300, 0, 0), 0)
    XCTAssertEqual(barnard_core_calculate_enin(.max, 0, 300, 0, 0), .max)
    XCTAssertEqual(barnard_core_calculate_enin(.max, 1, 300, 0, 1), .max)
    XCTAssertEqual(barnard_core_calculate_enin(-400, 1, 300, 0, 12), 0)

    // stable_read_enin has an error channel: out-of-domain is rejected.
    var enin: UInt32 = 0
    XCTAssertEqual(barnard_core_stable_read_enin(-1, 899, 0, 300, 0, 0, &enin), -1)
    XCTAssertEqual(barnard_core_stable_read_enin(899, .max, 0, 300, 0, 0, &enin), -1)
    XCTAssertEqual(barnard_core_stable_read_enin(-1, -1, 1, 300, 0, 12, &enin), 1)
    XCTAssertEqual(enin, 0)
  }

  func testInvalidArgumentsAreRejected() {
    var out = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_derive_tek_for_event(nil, 32, nil, 0, &out), -1)
    XCTAssertEqual(barnard_core_derive_tek_for_anonymous(nil, 1, &out), -1)
    XCTAssertEqual(barnard_core_derive_rpik(nil, &out), -1)
    XCTAssertEqual(barnard_core_sha256(nil, 4, &out), -1)
    XCTAssertEqual(barnard_core_stable_read_enin(0, 0, 0, 300, 0, 0, nil), -1)
    XCTAssertEqual(barnard_core_should_serve_gatt_display_id(nil, 5), 0)
  }
}
