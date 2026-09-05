import Foundation
import XCTest
@testable import BarnardCore

final class BarnardB005EnvelopeV2Tests: XCTestCase {
  func testSharedVectorsAndBoundaries() throws {
    let v = try load()
    let key = hex(v["authority_public_key"]!)
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.eventKeySetBytes([key])!), v["event_key_set_bytes"])
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.keySetDigest([key])!), v["event_key_set_digest"])
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.computeEventId(registrar: hex(v["registrar"]!), anchorOperator: hex(v["anchor_operator"]!), nonce: hex(v["nonce"]!), keySetDigest: hex(v["event_key_set_digest"]!))!), v["event_id"])
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.openEventCodeHash(eventId: Array(0...31))!), "6c86c6aac5fb24bc")
    let first = hex(v["v1_container"]!), second = hex(v["v2_container"]!)
    XCTAssertEqual(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 6_000_000)?.receiverState, .RADIO_SELF_VERIFIED)
    XCTAssertEqual(BarnardB005EnvelopeV2.verify(container: second, currentEnin: 6_000_000)?.receiverState, .RADIO_SELF_VERIFIED)
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 5_999_989))
    XCTAssertNotNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 6_000_001))
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 6_000_002))
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: nil))
    for i in 4..<first.count {
      var mutation = first; mutation[i] ^= 1
      XCTAssertNil(BarnardB005EnvelopeV2.verify(container: mutation, currentEnin: 6_000_000), "mutation at \(i)")
    }
  }

  private func load() throws -> [String: String] {
    var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0..<20 {
      let candidate = directory.appendingPathComponent("test-vectors/b005-envelope-v2.txt")
      if FileManager.default.fileExists(atPath: candidate.path) {
        let text = try String(contentsOf: candidate, encoding: .utf8)
        return Dictionary(uniqueKeysWithValues: text.split(separator: "\n").compactMap { line in
          let s = line.trimmingCharacters(in: .whitespaces); guard !s.isEmpty, !s.hasPrefix("#"), let i = s.firstIndex(of: "=") else { return nil }
          return (String(s[..<i]), String(s[s.index(after: i)...]))
        })
      }
      directory.deleteLastPathComponent()
    }
    throw NSError(domain: "vectors", code: 1)
  }
  private func hex(_ s: String) -> [UInt8] { stride(from: 0, to: s.count, by: 2).map { UInt8(s.dropFirst($0).prefix(2), radix: 16)! } }
  private func hexString(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
}
