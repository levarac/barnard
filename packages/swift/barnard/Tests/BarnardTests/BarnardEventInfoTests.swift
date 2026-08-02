// Use of this source code is governed by a BSD-style license.

import Foundation
import XCTest
@testable import Barnard

final class BarnardEventInfoTests: XCTestCase {
  func testGoldenVectorsSerializeAndParseByteForByte() throws {
    let vectors: [(String, String, String, String)] = [
      ("CORE-SPLIT-80", "Barnard Core Split", "0b9f14789f13968f", "010100124261726e61726420436f72652053706c69740200080b9f14789f13968f"),
      ("東京-2026", "東京 2026", "34dc60f26d21cb94", "0101000be69db1e4baac203230323602000834dc60f26d21cb94"),
    ]

    for (eventCode, displayName, expectedHash, expectedPayload) in vectors {
      let b004 = BarnardCrypto.computeEventCodeHash(eventCode)
      XCTAssertEqual(b004.hexString, expectedHash)
      let payload = try BarnardEventInfoCodec.serialize(
        eventCode: eventCode,
        eventDisplayName: displayName,
        b004EventCodeHash: b004
      )
      XCTAssertEqual(payload.hexString, expectedPayload)
      XCTAssertEqual(try BarnardEventInfoCodec.parse(payload), BarnardEventInfo(
        eventDisplayName: displayName,
        eventCodeHash: b004
      ))
    }
  }

  func testParserSkipsWellFormedUnknownTlvButRejectsMalformedCorpus() throws {
    let validWithUnknown = Data(hex: "010100124261726e61726420436f72652053706c69740200080b9f14789f13968f100001ff")!
    XCTAssertEqual(try BarnardEventInfoCodec.parse(validWithUnknown).eventDisplayName, "Barnard Core Split")

    let malformed = [
      "", // below minimum length
      "020100124261726e61726420436f72652053706c69740200080b9f14789f13968f", // version
      "010100124261726e61726420436f72652053706c69740200080b9f14789f1396", // truncation
      "010200080b9f14789f13968f0100124261726e61726420436f72652053706c6974", // ordering
      "01010001410200080b9f14789f13968f020000", // unordered repeat of type 0x02
      "01010001ff0200080b9f14789f13968f", // invalid UTF-8
      "0101000241010200080b9f14789f13968f", // control character
      "0101000341cc8a0200080b9f14789f13968f", // non-NFC A + ring
    ]
    for hex in malformed {
      guard let payload = Data(hex: hex) else {
        XCTFail("malformed fixture must remain byte-decodable: \(hex)")
        continue
      }
      XCTAssertThrowsError(try BarnardEventInfoCodec.parse(payload), "expected malformed B005 to fail: \(hex)")
    }
  }

  func testSerializerRejectsB004MismatchAndDisabledPolicy() throws {
    let b004 = BarnardCrypto.computeEventCodeHash("CORE-SPLIT-80")
    XCTAssertThrowsError(try BarnardEventInfoCodec.serialize(
      eventCode: "CORE-SPLIT-80",
      eventDisplayName: "Barnard Core Split",
      b004EventCodeHash: Data(repeating: 0, count: 8)
    ))
    XCTAssertNil(try BarnardEventInfoCodec.payloadIfServing(
      policy: BarnardEventInfoServePolicy(),
      eventCode: "CORE-SPLIT-80",
      eventDisplayName: "Barnard Core Split",
      b004EventCodeHash: b004
    ))
    XCTAssertNotNil(try BarnardEventInfoCodec.payloadIfServing(
      policy: BarnardEventInfoServePolicy(organizerDesignated: true, eventActiveForDiscovery: true),
      eventCode: "CORE-SPLIT-80",
      eventDisplayName: "Barnard Core Split",
      b004EventCodeHash: b004
    ))
  }

  func testDiscoveryRetentionCapsNamesHashesAndResetsAtFiveMinutes() {
    let session = BarnardEventInfoDiscoverySession(startedAt: 0)
    for index in 0..<32 {
      _ = session.observe(BarnardEventInfo(eventDisplayName: "Event \(index)", eventCodeHash: Data(repeating: UInt8(index), count: 8)), now: 1)
    }
    XCTAssertEqual(session.retainedHashCount, 32)
    let overflow = session.observe(BarnardEventInfo(eventDisplayName: "Overflow", eventCodeHash: Data(repeating: 0xff, count: 8)), now: 2)
    XCTAssertTrue(overflow.additionalEventsOmitted)
    XCTAssertTrue(overflow.shouldEmitGenericHint)
    XCTAssertEqual(session.retainedHashCount, 32)
    let genericHint = eventInfoForDiscoveryHint(
      BarnardEventInfo(eventDisplayName: "Overflow", eventCodeHash: Data(repeating: 0xff, count: 8)),
      shouldEmitGenericHint: overflow.shouldEmitGenericHint
    )
    XCTAssertEqual(genericHint.eventDisplayName, "")
    XCTAssertEqual(genericHint.eventCodeHash, Data())

    let names = BarnardEventInfoDiscoverySession(startedAt: 0)
    let hash = Data(repeating: 0x42, count: 8)
    for index in 0..<4 {
      _ = names.observe(BarnardEventInfo(eventDisplayName: "Name \(index)", eventCodeHash: hash), now: 1)
    }
    XCTAssertTrue(names.observe(BarnardEventInfo(eventDisplayName: "Name 4", eventCodeHash: hash), now: 2).additionalNamesOmitted)
    _ = names.observe(BarnardEventInfo(eventDisplayName: "Fresh", eventCodeHash: hash), now: 300)
    XCTAssertEqual(names.retainedHashCount, 1)
    XCTAssertFalse(names.additionalNamesOmitted)
    XCTAssertFalse(names.additionalEventsOmitted)
  }

  func testRetryBudgetAllowsOnlyTwoTransportAttemptsWithThirtySecondBackoff() {
    let retries = BarnardEventInfoRetryBudget()
    let peer = UUID()
    XCTAssertTrue(retries.canStart(peer, now: 0))
    XCTAssertEqual(retries.recordRecoverableFailure(peer, now: 0), 30)
    XCTAssertFalse(retries.canStart(peer, now: 29))
    XCTAssertTrue(retries.canStart(peer, now: 30))
    XCTAssertEqual(retries.recordRecoverableFailure(peer, now: 30), nil)
    XCTAssertFalse(retries.canStart(peer, now: 60))

    retries.clear(peer)
    XCTAssertTrue(retries.canStart(peer, now: 0))
    retries.recordSuccessfulAttempt(peer, now: 0)
    XCTAssertTrue(retries.canStart(peer, now: 1))
    retries.recordSuccessfulAttempt(peer, now: 1)
    XCTAssertFalse(retries.canStart(peer, now: 2))

    retries.recordSemanticUnavailable(peer)
    XCTAssertFalse(retries.canStart(peer, now: 999))

    retries.clear(peer)
    XCTAssertTrue(retries.canStart(peer, now: 0))
    _ = retries.recordRecoverableFailure(peer, now: 0)
    retries.recordSemanticUnavailable(UUID())
    retries.clearAll()
    XCTAssertTrue(retries.canStart(peer, now: 0))

    retries.recordSemanticUnavailable(peer, now: 0)
    XCTAssertTrue(retries.canStart(peer, now: 300))
  }

  func testCodecAcceptsExactBoundsAndRejectsAdjacentValues() throws {
    XCTAssertNoThrow(try BarnardEventInfoCodec.validateEventDisplayName(String(repeating: "a", count: 64)))
    XCTAssertThrowsError(try BarnardEventInfoCodec.validateEventDisplayName(String(repeating: "a", count: 65)))
    XCTAssertNoThrow(try BarnardEventInfoCodec.validateEventDisplayName("a"))

    XCTAssertNoThrow(try BarnardEventInfoCodec.parse(b005Payload(totalLength: 16)))
    XCTAssertThrowsError(try BarnardEventInfoCodec.parse(Data(repeating: 0, count: 15)))
    XCTAssertNoThrow(try BarnardEventInfoCodec.parse(b005Payload(totalLength: 512)))
    XCTAssertThrowsError(try BarnardEventInfoCodec.parse(Data(repeating: 0, count: 513)))
  }

  func testB005HintMustMatchThePeripheralsB004Value() throws {
    let info = try BarnardEventInfoCodec.parse(b005Payload(totalLength: 16))
    XCTAssertTrue(BarnardEventInfoCodec.matchesB004(info, b004EventCodeHash: Data(repeating: 0x42, count: 8)))
    XCTAssertFalse(BarnardEventInfoCodec.matchesB004(info, b004EventCodeHash: Data(repeating: 0x43, count: 8)))
  }

  func testEventInfoEqualityIncludesReservedCensus() {
    let eventCodeHash = Data(repeating: 0x42, count: 8)
    XCTAssertNotEqual(
      BarnardEventInfo(eventDisplayName: "Event", eventCodeHash: eventCodeHash),
      BarnardEventInfo(eventDisplayName: "Event", eventCodeHash: eventCodeHash, census: Data([0x01]))
    )
    XCTAssertEqual(
      BarnardEventInfo(eventDisplayName: "Event", eventCodeHash: eventCodeHash, census: Data([0x01, 0x02])),
      BarnardEventInfo(eventDisplayName: "Event", eventCodeHash: eventCodeHash, census: Data([0x01, 0x02]))
    )
    XCTAssertNotEqual(
      BarnardEventInfo(eventDisplayName: "Event", eventCodeHash: eventCodeHash, census: Data([0x01, 0x02])),
      BarnardEventInfo(eventDisplayName: "Event", eventCodeHash: eventCodeHash, census: Data([0x01, 0x03]))
    )
  }

  private func b005Payload(totalLength: Int) -> Data {
    var payload = Data([1, 0x01, 0x00, 0x01, 0x61, 0x02, 0x00, 0x08])
    payload.append(Data(repeating: 0x42, count: 8))
    let extensionLength = totalLength - payload.count - 3
    if extensionLength > 0 {
      payload.append(0x10)
      payload.append(UInt8((extensionLength >> 8) & 0xff))
      payload.append(UInt8(extensionLength & 0xff))
      payload.append(Data(repeating: 0, count: extensionLength))
    }
    return payload
  }
}

private extension Data {
  init?(hex: String) {
    guard hex.count.isMultiple(of: 2) else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self.init(bytes)
  }
}
