import Foundation
import XCTest
@testable import B005EnvelopeVerifierKit
import Barnard
import BarnardCore

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
      #"{"signedEnvelopeHex":"\#(signedEnvelope)","currentEnin":6000000.5}"#,
      request(signedEnvelopeHex: signedEnvelope, currentEnin: 6_000_000) + " {}"
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
      String(repeating: "00", count: 509)
    ]

    for signedEnvelopeHex in inputs {
      let result = run(input: request(signedEnvelopeHex: signedEnvelopeHex, currentEnin: 6_000_000))
      XCTAssertNotEqual(result.status, 0)
      XCTAssertEqual(result.stdout, "")
      XCTAssertEqual(result.stderr, failure + "\n")
    }
  }

  func testAuthorityOperationValidSignerAndRole() throws {
    let result = authorityRun(enin: 6_000_000)
    XCTAssertEqual(result.status, 0)
    let json = try outputObject(result.stdout)
    XCTAssertEqual(json["kind"] as? String, "BARNARD_B005_AUTHORITY_VERIFIED_V1")
    XCTAssertEqual(json["eventIdHex"] as? String, vector("event_id"))
    XCTAssertEqual(json["signerPublicKeyHex"] as? String, vector("authority_public_key"))
    XCTAssertEqual(json["signerRole"] as? String, "authority-direct")
    XCTAssertEqual(json["relayExpiresAtEnin"] as? Int, 6_000_002)
    let expectedDigest = BarnardCoreCrypto.sha256(hexBytes(vector("v1_envelope")))
      .map { String(format: "%02x", $0) }.joined()
    XCTAssertEqual(json["envelopeSha256Hex"] as? String, expectedDigest)
  }

  func testAuthorityOperationAuthenticatesDelegateRole() throws {
    let key = vector("v2_delegate_public_key")
    let result = authorityRun(enin: 6_000_000, publicKey: key, role: "delegate", envelope: vector("v2_envelope"))
    XCTAssertEqual(result.status, 0)
    let json = try outputObject(result.stdout)
    XCTAssertEqual(json["signerPublicKeyHex"] as? String, key)
    XCTAssertEqual(json["signerRole"] as? String, "delegate")
  }

  func testAuthorityOperationRejectsUnauthorizedSigner() {
    let result = authorityRun(enin: 6_000_000, publicKey: vector("v2_delegate_public_key"))
    XCTAssertEqual(result.stderr, "B005_AUTH_SIGNER_UNAUTHORIZED\n")
    let wrongRole = authorityRun(enin: 6_000_000, role: "delegate")
    XCTAssertEqual(wrongRole.stderr, "B005_AUTH_SIGNER_UNAUTHORIZED\n")
  }

  func testAuthorityOperationRejectsInvalidContext() {
    let result = authorityRun(enin: 6_000_000, corruptDigest: true)
    XCTAssertEqual(result.status, 1)
    XCTAssertEqual(result.stderr, "B005_AUTH_INVALID_CONTEXT\n")
    XCTAssertEqual(result.stdout, "")
  }

  func testAuthorityOperationRejectsDuplicateMembersAtAnyLevel() {
    let entries = [
      #""kind":"BARNARD_B005_AUTHORITY_VERIFY_REQUEST_V1""#,
      #""eventIdHex":"\#(vector("event_id"))""#,
      #""role":"authority-direct""#
    ]
    for entry in entries {
      let result = authorityRun(enin: 6_000_000, transform: {
        $0.replacingOccurrences(of: entry, with: entry + "," + entry)
      })
      XCTAssertEqual(result.status, 1)
      XCTAssertEqual(result.stdout, "")
      XCTAssertEqual(result.stderr, "B005_AUTH_INVALID_CONTEXT\n")
    }
    let escaped = authorityRun(enin: 6_000_000, transform: {
      $0.replacingOccurrences(of: #""role":"authority-direct""#,
        with: #""role":"authority-direct","r\u006fle":"authority-direct""#)
    })
    XCTAssertEqual(escaped.stderr, "B005_AUTH_INVALID_CONTEXT\n")
  }

  func testAuthorityOperationReportsExpiredSignedWindow() {
    let result = authorityRun(enin: 6_000_002)
    XCTAssertEqual(result.stderr, "B005_AUTH_SIGNED_WINDOW_EXPIRED\n")
    let notAuthorized = authorityRun(enin: 6_000_002, role: "delegate")
    XCTAssertEqual(notAuthorized.stderr, "B005_AUTH_SIGNER_UNAUTHORIZED\n")
  }

  func testThreeEnvelopeSyntheticScheduleVerifiesEndToEnd() {
    for enin in [6_000_000, 6_000_001, 6_000_002] {
      let envelope = syntheticEnvelope(validFrom: enin, expires: enin + 1)
      XCTAssertEqual(authorityRun(enin: enin, envelope: envelope).status, 0, "ENIN \(enin)")
    }
  }

  private func authorityRun(
    enin: Int, publicKey: String? = nil, role: String = "authority-direct",
    corruptDigest: Bool = false, envelope: String? = nil, transform: (String) -> String = { $0 }
  ) -> B005EnvelopeVerifierResult {
    let key = publicKey ?? vector("authority_public_key")
    let definitionDigest = String(repeating: "11", count: 32)
    let eventId = vector("event_id")
    var bytes = Array("barnard-b005-authorization-context:v1\0".utf8)
    bytes.append(contentsOf: hexBytes(definitionDigest))
    bytes.append(contentsOf: hexBytes(eventId))
    bytes.append(1)
    bytes.append(contentsOf: hexBytes(key))
    bytes.append(role == "authority-direct" ? 0 : 1)
    var digest = BarnardCoreCrypto.sha256(bytes).map { String(format: "%02x", $0) }.joined()
    if corruptDigest { digest = String(repeating: "00", count: 32) }
    let input = #"{"kind":"BARNARD_B005_AUTHORITY_VERIFY_REQUEST_V1","signedEnvelopeHex":"\#(envelope ?? vector("v1_envelope"))","verificationEnin":\#(enin),"authorizationContext":{"eventIdHex":"\#(eventId)","definitionSha256Hex":"\#(definitionDigest)","contextDigestHex":"\#(digest)","signers":[{"publicKeyHex":"\#(key)","role":"\#(role)"}]}}"#
    return B005AuthorityVerifier.run(input: Data(transform(input).utf8))
  }

  private func syntheticEnvelope(validFrom: Int, expires: Int) -> String {
    let key = hexBytes(vector("authority_public_key"))
    let eventId = BarnardB005EnvelopeV2.computeEventId(registrar: [UInt8](repeating: 0x11, count: 20), anchorOperator: [UInt8](repeating: 0x22, count: 20), nonce: [UInt8](repeating: 0x33, count: 32), keySetDigest: BarnardB005EnvelopeV2.keySetDigest([key])!)!
    let fields = BarnardB005EnvelopeFields(registrar: [UInt8](repeating: 0x11, count: 20), anchorOperator: [UInt8](repeating: 0x22, count: 20), nonce: [UInt8](repeating: 0x33, count: 32), authorityKeys: [key], joinMode: 0, eninSeconds: 300, validFromEnin: UInt32(validFrom), validThroughEnin: UInt32(expires + 5), relayExpiresAtEnin: UInt32(expires), eventCodeHash: BarnardB005EnvelopeV2.openEventCodeHash(eventId: eventId)!, eventDisplayName: "Synthetic Schedule")
    guard case .success(let unsigned) = BarnardB005EnvelopeV2.encodeUnsignedEnvelope(fields, nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: BarnardB005NativeRecoverer()) else { fatalError("fixture encode") }
    let signature = BarnardCoreSigning.signRecoverable(privateKey: [UInt8](repeating: 0, count: 31) + [3], messageHash32: unsigned.signatureDigest)
    guard case .success(let envelope) = BarnardB005EnvelopeV2.assembleSignedEnvelope(toBeSigned: unsigned.toBeSigned, signature: signature.r + signature.s + [UInt8(signature.v)]) else { fatalError("fixture assemble") }
    return envelope.map { String(format: "%02x", $0) }.joined()
  }

  private func hexBytes(_ value: String) -> [UInt8] {
    stride(from: 0, to: value.count, by: 2).map { offset in
      let start = value.index(value.startIndex, offsetBy: offset)
      return UInt8(value[start..<value.index(start, offsetBy: 2)], radix: 16)!
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
