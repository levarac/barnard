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

  // MARK: - Registry-tier confirmation (P1: cannot be forged from a bare bool)

  func testConfirmAgainstRegistryRequiresFullAgreement() throws {
    let v = try load()
    let container = hex(v["v1_container"]!)
    guard let verified = BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: nameValidator) else {
      return XCTFail("expected RADIO_SELF_VERIFIED baseline")
    }
    XCTAssertEqual(verified.receiverState, .RADIO_SELF_VERIFIED)
    func agreeing() -> BarnardEventDefinitionV1 {
      BarnardEventDefinitionV1(eventId: verified.eventId, keySetDigest: verified.keySetDigest, joinMode: verified.joinMode, eventCodeHash: verified.eventCodeHash, validFromUnixSeconds: verified.validFromEnin * Int64(verified.eninSeconds), validUntilUnixSeconds: verified.validThroughEnin * Int64(verified.eninSeconds))
    }
    // Positive: an actually-agreeing definition raises the tier.
    let confirmed = BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, against: agreeing())
    XCTAssertEqual(confirmed.receiverState, .REGISTRY_VERIFIED)

    // Negative: each single-field disagreement must hold the tier at RADIO_SELF_VERIFIED, never REGISTRY_VERIFIED.
    var wrongEventId = agreeing().eventId; wrongEventId[0] ^= 1
    XCTAssertEqual(BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, against: BarnardEventDefinitionV1(eventId: wrongEventId, keySetDigest: verified.keySetDigest, joinMode: verified.joinMode, eventCodeHash: verified.eventCodeHash, validFromUnixSeconds: verified.validFromEnin * Int64(verified.eninSeconds), validUntilUnixSeconds: verified.validThroughEnin * Int64(verified.eninSeconds))).receiverState, .RADIO_SELF_VERIFIED)

    XCTAssertEqual(BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, against: BarnardEventDefinitionV1(eventId: verified.eventId, keySetDigest: verified.keySetDigest, joinMode: verified.joinMode == 0 ? 1 : 0, eventCodeHash: verified.eventCodeHash, validFromUnixSeconds: verified.validFromEnin * Int64(verified.eninSeconds), validUntilUnixSeconds: verified.validThroughEnin * Int64(verified.eninSeconds))).receiverState, .RADIO_SELF_VERIFIED, "joinMode mismatch")

    XCTAssertEqual(BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, against: BarnardEventDefinitionV1(eventId: verified.eventId, keySetDigest: verified.keySetDigest, joinMode: verified.joinMode, eventCodeHash: verified.eventCodeHash, validFromUnixSeconds: (verified.validThroughEnin + 1) * Int64(verified.eninSeconds), validUntilUnixSeconds: verified.validThroughEnin * Int64(verified.eninSeconds))).receiverState, .RADIO_SELF_VERIFIED, "window mismatch")

    var wrongKeySetDigest = verified.keySetDigest; wrongKeySetDigest[0] ^= 1
    XCTAssertEqual(BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, against: BarnardEventDefinitionV1(eventId: verified.eventId, keySetDigest: wrongKeySetDigest, joinMode: verified.joinMode, eventCodeHash: verified.eventCodeHash, validFromUnixSeconds: verified.validFromEnin * Int64(verified.eninSeconds), validUntilUnixSeconds: verified.validThroughEnin * Int64(verified.eninSeconds))).receiverState, .RADIO_SELF_VERIFIED, "signer-authority (keySetDigest) mismatch")
  }

  // MARK: - Recover-once and low-S (P1)

  private struct CountingNonMemberRecoverer: BarnardB005PublicKeyRecovering {
    let counter: Counter
    func recover(recoveryId: Int, r: [UInt8], s: [UInt8], digest: [UInt8]) -> [UInt8]? {
      counter.count += 1
      return [UInt8](repeating: 0xff, count: 33) // never a member of the synthetic key set below.
    }
    func isValidCompressedKey(_ key: [UInt8]) -> Bool { true }
  }
  private final class Counter { var count = 0 }

  private struct AlwaysAcceptingRecoverer: BarnardB005PublicKeyRecovering {
    let key: [UInt8]
    func recover(recoveryId: Int, r: [UInt8], s: [UInt8], digest: [UInt8]) -> [UInt8]? { key }
    func isValidCompressedKey(_ key: [UInt8]) -> Bool { true }
  }

  /// Builds a structurally-valid authority-direct-mode container with `n` synthetic authority
  /// keys, no delegation certificate, and a caller-supplied raw signature so tests can drive
  /// `signatureMatches`/`recoverMember` with arbitrary r/s/v without real ECDSA math -- the
  /// injected fake recoverer stands in for signature validity.
  private func buildSyntheticContainer(keyCount: Int, signature: [UInt8]) -> [UInt8] {
    let keys = (0..<keyCount).map { [UInt8](repeating: UInt8($0 + 1), count: 33) }
    var envelope: [UInt8] = [1] + [UInt8](repeating: 0, count: 20) + [UInt8](repeating: 0, count: 20) + [UInt8](repeating: 0, count: 32)
    envelope += [UInt8(keyCount)]
    for key in keys { envelope += key }
    envelope += [1] // joinMode = gated (skip open-code binding)
    envelope += [0x01, 0x2c] // eninSeconds = 300
    envelope += [0, 0, 0x03, 0xe8] // validFrom = 1000
    envelope += [0, 0, 0x03, 0xe9] // validThrough = 1001
    envelope += [0, 0, 0x03, 0xe9] // relayExpiresAtEnin = 1001
    envelope += [2] // fixed marker byte
    envelope += [UInt8](repeating: 0, count: 8) // eventCodeHash (unchecked under gated mode)
    envelope += [1] // nameLength
    envelope += Array("X".utf8)
    envelope += [0] // certLength = 0
    envelope += signature
    return BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 0, signedEnvelope: envelope)!
  }

  func testAuthorityDirectVerificationRecoversExactlyOnce() throws {
    let counter = Counter()
    let signature = [UInt8](repeating: 0, count: 31) + [1] + [UInt8](repeating: 0, count: 31) + [1] + [0] // r=1, s=1, v=0
    let container = buildSyntheticContainer(keyCount: 8, signature: signature)
    let result = BarnardB005EnvelopeV2.verify(container: container, currentEnin: 1000, nameValidator: nameValidator, recoverer: CountingNonMemberRecoverer(counter: counter))
    XCTAssertNil(result, "recovered key is never a set member")
    XCTAssertEqual(counter.count, 1, "authority-direct mode must recover exactly once regardless of key-set size")
  }

  func testHighSSignatureRejectedEvenWithAnAcceptingRecoverer() throws {
    // s = N - 1 (maximal, definitely > N/2): a fake recoverer that never checks S itself would
    // happily "match" this, so the rejection MUST come from signatureMatches's own low-S gate.
    let highS: [UInt8] = [
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
      0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
    ]
    let r = [UInt8](repeating: 0, count: 31) + [1]
    let acceptingKey = [UInt8](repeating: 7, count: 33)
    let signature = r + highS + [0]
    let container = buildSyntheticContainer(keyCount: 1, signature: signature)
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: container, currentEnin: 1000, nameValidator: nameValidator, recoverer: AlwaysAcceptingRecoverer(key: acceptingKey)))
  }

  func testHighSCertificateSignatureRejectedEvenWithAnAcceptingRecoverer() throws {
    // Same claim as above but for the certificate's own COSE signature path (hasRecoveryByte:
    // false, the two-attempt branch), which is a separate code path from the envelope signature.
    let v = try load()
    let envelopeHex = v["v2_envelope"]!
    let oldCert = v["v2_delegation_cert"]!
    guard let range = envelopeHex.range(of: oldCert) else { return XCTFail("cert not found") }
    // We only need the certificate's shape (its 64-byte inner COSE signature) with a high-S
    // value substituted in, and an AlwaysAcceptingRecoverer standing in for a permissive backend.
    var envelope = hex(envelopeHex)
    let certByteOffset = envelopeHex.distance(from: envelopeHex.startIndex, to: range.lowerBound) / 2
    let certEnd = certByteOffset + oldCert.count / 2
    let highS: [UInt8] = [
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
      0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40,
    ]
    // Certificate signature is the last 64 bytes of the cert byte range (COSE_Sign1 bstr .size 64).
    let sigStart = certEnd - 64
    let r = [UInt8](repeating: 0, count: 31) + [1]
    envelope.replaceSubrange(sigStart..<(sigStart + 32), with: r)
    envelope.replaceSubrange((sigStart + 32)..<certEnd, with: highS)
    let container = BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 1, signedEnvelope: envelope)!
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: nameValidator, recoverer: AlwaysAcceptingRecoverer(key: [UInt8](repeating: 7, count: 33))))
  }

  // MARK: - CBOR builder overflow (P2)

  func testBuildSigStructureHandlesFieldsAtAndBeyond256Bytes() throws {
    let protected300 = [UInt8](repeating: 0x11, count: 300)
    let payload10 = [UInt8](repeating: 0x22, count: 10)
    guard let structure = BarnardB005EnvelopeV2.buildSigStructure(protected: protected300, payload: payload10) else {
      return XCTFail("300-byte field must not trap or fail")
    }
    // Sig_structure header (2) + "Signature1" (10) + protected field: 0x59 hi lo + 300 bytes.
    let headerEnd = 2 + 10
    XCTAssertEqual(Array(structure[headerEnd..<(headerEnd + 3)]), [0x59, 0x01, 0x2c], "canonical 2-byte length for 300")
    XCTAssertEqual(structure.count, 2 + 10 + 3 + 300 + 1 + 1 + 10)
    XCTAssertEqual(Array(structure[(headerEnd + 3)..<(headerEnd + 3 + 300)]), protected300)
  }

  func testBuildSigStructureRejectsOversizedField() throws {
    let tooLarge = [UInt8](repeating: 0, count: 65536)
    XCTAssertNil(BarnardB005EnvelopeV2.buildSigStructure(protected: tooLarge, payload: []))
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
