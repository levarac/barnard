import Foundation
import XCTest
@testable import B005EnvelopeVerifierKit

final class B005EnvelopeVerifierTests: XCTestCase {
  private let failure = "B005_ENVELOPE_VERIFICATION_FAILED"

  func testValidVectorEmitsVerifiedReceipt() throws {
    let result = run(input: request(signedEnvelopeHex: vector("v1_envelope"), currentEnin: 6_000_000))

    XCTAssertEqual(result.status, 0)
    XCTAssertEqual(result.stderr, "")
    let json = try outputObject(result.stdout)
    XCTAssertEqual(Set(json.keys), ["kind", "eventIdHex", "joinMode", "validFromEnin", "validThroughEnin", "relayExpiresAtEnin"])
    XCTAssertEqual(json["kind"] as? String, "BARNARD_B005_VERIFIED_V1")
    XCTAssertEqual(json["eventIdHex"] as? String, vector("event_id"))
    XCTAssertEqual(json["joinMode"] as? Int, 0)
    XCTAssertEqual(json["validFromEnin"] as? Int, 5_999_990)
    XCTAssertEqual(json["validThroughEnin"] as? Int, 6_000_010)
    XCTAssertEqual(json["relayExpiresAtEnin"] as? Int, 6_000_002)
  }

  func testPublishedReceiptSchemaMatchesSuccessOutput() throws {
    let result = run(input: request(signedEnvelopeHex: vector("v1_envelope"), currentEnin: 6_000_000))
    XCTAssertEqual(result.status, 0)
    let output = try outputObject(result.stdout)

    let schemaURL = packageRoot
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("schema/barnard/v2/b005-envelope-verifier.schema.json")
    let schemaData = try Data(contentsOf: schemaURL)
    let document = try XCTUnwrap(JSONSerialization.jsonObject(with: schemaData) as? [String: Any])
    let definitions = try XCTUnwrap(document["$defs"] as? [String: Any])
    let receipt = try XCTUnwrap(definitions["Receipt"] as? [String: Any])
    let properties = try XCTUnwrap(receipt["properties"] as? [String: [String: Any]])
    let required = try XCTUnwrap(receipt["required"] as? [String])

    XCTAssertEqual(Set(required), Set(output.keys))
    XCTAssertEqual(Set(properties.keys), Set(output.keys))
    XCTAssertEqual(receipt["additionalProperties"] as? Bool, false)
    XCTAssertEqual(properties["kind"]?["const"] as? String, output["kind"] as? String)
    for name in ["validFromEnin", "validThroughEnin", "relayExpiresAtEnin"] {
      XCTAssertEqual(properties[name]?["type"] as? String, "integer")
      XCTAssertEqual(properties[name]?["minimum"] as? Int, 0)
    }
  }

  func testMutatedSignatureFailsWithOnlySanitizedMessage() throws {
    var signedEnvelope = vector("v1_envelope")
    let last = signedEnvelope.removeLast()
    signedEnvelope.append(last == "0" ? "1" : "0")

    let result = run(input: request(signedEnvelopeHex: signedEnvelope, currentEnin: 6_000_000))

    XCTAssertNotEqual(result.status, 0)
    XCTAssertEqual(result.stdout, "")
    XCTAssertEqual(result.stderr, failure + "\n")
  }

  func testOutsideRelayWindowFailsWithOnlySanitizedMessage() throws {
    for currentEnin in [5_999_989, 6_000_002] {
      let result = run(input: request(signedEnvelopeHex: vector("v1_envelope"), currentEnin: currentEnin))
      XCTAssertNotEqual(result.status, 0, "ENIN \(currentEnin)")
      XCTAssertEqual(result.stdout, "", "ENIN \(currentEnin)")
      XCTAssertEqual(result.stderr, failure + "\n", "ENIN \(currentEnin)")
    }
  }

  func testMalformedAndOversizedInputFailWithOnlySanitizedMessage() throws {
    let malformed = #"{"signedEnvelopeHex":"zz","currentEnin":6000000}"#
    let oversized = #"{"signedEnvelopeHex":"# + String(repeating: "0", count: 4_096) + #"","currentEnin":6000000}"#

    for input in [malformed, oversized] {
      let result = run(input: input)
      XCTAssertNotEqual(result.status, 0)
      XCTAssertEqual(result.stdout, "")
      XCTAssertEqual(result.stderr, failure + "\n")
    }
  }

  func testDuplicateRequestKeysFailWithOnlySanitizedMessage() throws {
    let signedEnvelope = vector("v1_envelope")
    let inputs = [
      #"{"signedEnvelopeHex":"\#(signedEnvelope)","currentEnin":6000000,"currentEnin":6000000}"#,
      #"{"signedEnvelopeHex":"\#(signedEnvelope)","signedEnvelopeHex":"\#(signedEnvelope)","currentEnin":6000000}"#,
      #"{"signedEnvelopeHex":"\#(signedEnvelope)","currentEnin":6000000,"\u0063urrentEnin":6000000}"#
    ]

    for input in inputs {
      let result = run(input: input)
      XCTAssertNotEqual(result.status, 0)
      XCTAssertEqual(result.stdout, "")
      XCTAssertEqual(result.stderr, failure + "\n")
    }
  }

  func testMissingExtraAndInvalidEninRequestsFailClosed() throws {
    let signedEnvelope = vector("v1_envelope")
    let inputs = [
      #"{"signedEnvelopeHex":"\#(signedEnvelope)"}"#,
      #"{"signedEnvelopeHex":"\#(signedEnvelope)","currentEnin":6000000,"extra":1}"#,
      #"{"signedEnvelopeHex":"\#(signedEnvelope)","currentEnin":-1}"#,
      #"{"signedEnvelopeHex":"\#(signedEnvelope)","currentEnin":6000000.5}"#
    ]

    for input in inputs {
      let result = run(input: input)
      XCTAssertNotEqual(result.status, 0)
      XCTAssertEqual(result.stdout, "")
      XCTAssertEqual(result.stderr, failure + "\n")
    }
  }

  func testNoncanonicalEnvelopeHexFailsClosed() throws {
    let signedEnvelope = vector("v1_envelope")
    let inputs = [
      signedEnvelope.uppercased(),
      "0x" + signedEnvelope,
      signedEnvelope + "0",
      signedEnvelope + String(repeating: "0", count: 1_016)
    ]

    for signedEnvelopeHex in inputs {
      let result = run(input: request(signedEnvelopeHex: signedEnvelopeHex, currentEnin: 6_000_000))
      XCTAssertNotEqual(result.status, 0)
      XCTAssertEqual(result.stdout, "")
      XCTAssertEqual(result.stderr, failure + "\n")
    }
  }

  private func request(signedEnvelopeHex: String, currentEnin: Int) -> String {
    #"{"signedEnvelopeHex":"\#(signedEnvelopeHex)","currentEnin":\#(currentEnin)}"#
  }

  private func run(input: String) -> B005EnvelopeVerifierResult {
    B005EnvelopeVerifier.run(input: Data(input.utf8))
  }

  private func outputObject(_ output: String) throws -> [String: Any] {
    XCTAssertTrue(output.hasSuffix("\n"))
    let data = try XCTUnwrap(output.data(using: .utf8))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
  }

  private var packageRoot: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
  }

  private func vector(_ key: String) -> String {
    let path = packageRoot
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("test-vectors/b005-envelope-v2.txt")
    let text = try! String(contentsOf: path, encoding: .utf8)
    let values = Dictionary(uniqueKeysWithValues: text.split(separator: "\n").compactMap { line -> (String, String)? in
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), let index = trimmed.firstIndex(of: "=") else { return nil }
      return (String(trimmed[..<index]), String(trimmed[trimmed.index(after: index)...]))
    })
    return values[key]!
  }
}
