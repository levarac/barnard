import Foundation
import XCTest
@testable import BarnardCore

private struct TestNameValidator: BarnardB005DisplayNameNormalizing {
  func isNormalizedNFC(_ value: String) -> Bool {
    // Mirrors the production `BarnardB005NativeDisplayNameNormalizer`: Swift's `String.==`
    // compares Unicode canonical equivalence, so it never rejects decomposed input. Compare
    // UTF-8 bytes instead to actually detect a non-NFC form.
    Array(value.precomposedStringWithCanonicalMapping.utf8) == Array(value.utf8)
  }
}

final class BarnardB005EnvelopeV2Tests: XCTestCase {
  private let nameValidator = TestNameValidator()
  func testSharedVectorsAndBoundaries() throws {
    let v = try load()
    let key = hex(v["authority_public_key"]!)
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.eventKeySetBytes([key])!), v["event_key_set_bytes"])
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.keySetDigest([key])!), v["event_key_set_digest"])
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.computeEventId(registrar: hex(v["registrar"]!), anchorOperator: hex(v["anchor_operator"]!), nonce: hex(v["nonce"]!), keySetDigest: hex(v["event_key_set_digest"]!))!), v["event_id"])
    XCTAssertEqual(hexString(BarnardB005EnvelopeV2.openEventCodeHash(eventId: Array(0...31))!), "6c86c6aac5fb24bc")
    let first = hex(v["v1_container"]!), second = hex(v["v2_container"]!)
    XCTAssertEqual(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 6_000_000, nameValidator: nameValidator)?.receiverState, .RADIO_SELF_VERIFIED)
    XCTAssertEqual(BarnardB005EnvelopeV2.verify(container: second, currentEnin: 6_000_000, nameValidator: nameValidator)?.receiverState, .RADIO_SELF_VERIFIED)
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 5_999_989, nameValidator: nameValidator))
    XCTAssertNotNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 6_000_001, nameValidator: nameValidator))
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: 6_000_002, nameValidator: nameValidator))
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: first, currentEnin: nil, nameValidator: nameValidator))
    for i in 4..<first.count {
      var mutation = first; mutation[i] ^= 1
      XCTAssertNil(BarnardB005EnvelopeV2.verify(container: mutation, currentEnin: 6_000_000, nameValidator: nameValidator), "mutation at \(i)")
    }
    for i in 4..<second.count {
      var mutation = second; mutation[i] ^= 1
      XCTAssertNil(BarnardB005EnvelopeV2.verify(container: mutation, currentEnin: 6_000_000, nameValidator: nameValidator), "v2 mutation at \(i)")
    }
  }

  func testNegativeCensusV2PayloadIsRejected() throws {
    let v = try load()
    let length = Int(v["neg_census_v2_payload_length"]!)!
    var payload = hex(v["neg_census_v2_prefix"]!)
    payload += [UInt8](repeating: 0, count: length - payload.count)
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: payload, currentEnin: 6_000_000, nameValidator: nameValidator))
  }

  func testDisplayNameRejectsInvalidUTF8WithoutThrowing() throws {
    let v = try load()
    var container = hex(v["v1_container"]!)
    // Name starts at container offset 4 (container header) + 1 (envelopeVersion) + 20 + 20 + 32 + 1 (n)
    // + 33*n (keys) + 25 (a offset into fixed window fields) = 136 for vector 1 (n = 1).
    let nameStart = 136
    container[nameStart] = 0xff // invalid UTF-8 lead byte, same length as the original name
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: nameValidator))
  }

  func testDisplayNameRejectsNonNFCFormWithoutFalsePositive() throws {
    let v = try load()
    var container = hex(v["v1_container"]!)
    let nameStart = 136, nameLength = 58
    // Decomposed Hangul jamo U+1100 U+1161 (6 bytes) normalizes under NFC to the single
    // precomposed syllable U+AC00 (3 bytes) -- neither codepoint falls in the U+0300-U+036F
    // combining-diacritic range the old ad-hoc check used, so this is a case the old check
    // would have wrongly accepted. The correct NFC check MUST reject it.
    let decomposedJamo: [UInt8] = [0xe1, 0x84, 0x80, 0xe1, 0x85, 0xa1]
    var name = decomposedJamo
    name += [UInt8](repeating: UInt8(ascii: "x"), count: nameLength - decomposedJamo.count)
    container.replaceSubrange(nameStart..<(nameStart + nameLength), with: name)
    // Discriminating: `verify` calls `strictDisplayName` (which consults `nameValidator`)
    // before it ever computes the signature digest, so this rejection can only come from the
    // name check, never from a signature mismatch caused by the mutated name bytes.
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: nameValidator))
  }

  func testParallaxSubstitutedKeySetIsRejected() throws {
    let v = try load()
    // Spec 122's parallax negative list also names "substituted key set": swap the single
    // authority key embedded in vector 2's own envelope for Parallax's substitutedEventKeySetHex
    // key (same 33-byte compressed layout, same cert kept verbatim) so the cert's own eventId
    // no longer matches the eventId recomputed from the (now different) embedded key set.
    let neg = try loadFile("test-vectors/parallax-delegation-cert-v1.txt")
    let originalKeyHex = v["authority_public_key"]!
    let substitutedKeyHex = neg["neg_substituted_event_key"]!
    let container = v["v2_container"]!
    XCTAssertEqual(container.components(separatedBy: originalKeyHex).count - 1, 1, "expected exactly one occurrence of the authority key")
    let mutated = hex(container.replacingOccurrences(of: originalKeyHex, with: substitutedKeyHex))
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: mutated, currentEnin: 6_000_000, nameValidator: nameValidator))
  }

  func testParallaxDelegationCertPositiveAndNegativeVectors() throws {
    let v = try load()
    let neg = try loadFile("test-vectors/parallax-delegation-cert-v1.txt")
    let second = v["v2_container"]!
    let envelopeHex = v["v2_envelope"]!
    let oldCert = v["v2_delegation_cert"]!

    func container(withCertHex certHex: String) -> [UInt8]? {
      guard let range = envelopeHex.range(of: oldCert) else { return nil }
      var replaced = envelopeHex
      replaced.replaceSubrange(range, with: certHex)
      var envelope = hex(replaced)
      let certByteOffset = envelopeHex.distance(from: envelopeHex.startIndex, to: range.lowerBound) / 2
      envelope[certByteOffset - 1] = UInt8(certHex.count / 2)
      return BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 1, signedEnvelope: envelope)
    }

    // Positive: the parallax bundle's positive fixture is byte-identical to vector 2's own cert.
    XCTAssertEqual(neg["pos_signed_delegation_cert"], oldCert)
    XCTAssertNotNil(BarnardB005EnvelopeV2.verify(container: hex(second), currentEnin: 6_000_000, nameValidator: nameValidator))

    for key in ["neg_inverted_window", "neg_zero_roles", "neg_unassigned_role", "neg_unknown_version",
                "neg_unknown_field", "neg_missing_window", "neg_wrong_event", "neg_foreign_signer",
                "neg_corrupt_signature"] {
      guard let container = container(withCertHex: neg[key]!) else {
        XCTFail("\(key): could not build substitute container")
        continue
      }
      XCTAssertNil(BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: nameValidator), key)
    }
  }

  private func loadFile(_ relativePath: String) throws -> [String: String] {
    var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0..<20 {
      let candidate = directory.appendingPathComponent(relativePath)
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

  private func load() throws -> [String: String] {
    try loadFile("test-vectors/b005-envelope-v2.txt")
  }
  private func hex(_ s: String) -> [UInt8] { stride(from: 0, to: s.count, by: 2).map { UInt8(s.dropFirst($0).prefix(2), radix: 16)! } }
  private func hexString(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
}
