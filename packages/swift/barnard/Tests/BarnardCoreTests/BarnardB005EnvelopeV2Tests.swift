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

  // MARK: - Signed relay expiry and the structural scheduling accessor (barnard#197, #203)

  /// `verify` parses `relayExpiresAtEnin`, enforces `currentEnin < relayExpiresAtEnin <=
  /// validThroughEnin` and the 12-ENIN cap against it, and now carries it on the receipt instead
  /// of discarding it. Asserted against the committed conformance vector, so a value that
  /// disagrees with the vector fails.
  func testVerifiedEnvelopeExposesSignedWindowFromVector() throws {
    let v = try load()
    guard let verified = BarnardB005EnvelopeV2.verify(container: hex(v["v1_container"]!), currentEnin: 6_000_000, nameValidator: nameValidator) else {
      return XCTFail("expected the v1 vector container to verify")
    }
    XCTAssertEqual(verified.relayExpiresAtEnin, Int64(v["v1_relay_expires_at_enin"]!)!, "relayExpiresAtEnin must match the vector")
    XCTAssertEqual(verified.validFromEnin, Int64(v["v1_valid_from_enin"]!)!, "validFromEnin must match the vector")
    XCTAssertEqual(verified.validThroughEnin, Int64(v["v1_valid_through_enin"]!)!, "validThroughEnin must match the vector")
    XCTAssertEqual(verified.eninSeconds, UInt16(v["v1_enin_seconds"]!)!, "eninSeconds must match the vector")

    // The relay window is half-open, so the expiry ENIN itself is outside it while the one before
    // it is inside -- the property a host leases against.
    XCTAssertNotNil(BarnardB005EnvelopeV2.verify(container: hex(v["v1_container"]!), currentEnin: verified.relayExpiresAtEnin - 1, nameValidator: nameValidator), "the ENIN before expiry is still relayable")
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: hex(v["v1_container"]!), currentEnin: verified.relayExpiresAtEnin, nameValidator: nameValidator), "the expiry ENIN itself is not relayable")
  }

  /// The structural accessor reads the same four fields without a signature, a key recovery, a
  /// registry read or a clock. Both vector containers are checked, and each is cross-checked
  /// against `verify`'s own result: the untrusted read and the trusted read go through one offset
  /// table, so they must agree on every field.
  func testSchedulingFieldsMatchVectorAndAgreeWithVerify() throws {
    let v = try load()
    guard let v1 = BarnardB005EnvelopeV2.schedulingFields(container: hex(v["v1_container"]!)) else {
      return XCTFail("expected scheduling fields for the v1 vector container")
    }
    XCTAssertEqual(v1.validFromEnin, Int64(v["v1_valid_from_enin"]!)!)
    XCTAssertEqual(v1.validThroughEnin, Int64(v["v1_valid_through_enin"]!)!)
    XCTAssertEqual(v1.relayExpiresAtEnin, Int64(v["v1_relay_expires_at_enin"]!)!)
    XCTAssertEqual(v1.eninSeconds, UInt16(v["v1_enin_seconds"]!)!)

    for key in ["v1_container", "v2_container"] {
      let container = hex(v[key]!)
      guard let structural = BarnardB005EnvelopeV2.schedulingFields(container: container) else {
        return XCTFail("expected scheduling fields for \(key)")
      }
      guard let verified = BarnardB005EnvelopeV2.verify(container: container, currentEnin: structural.validFromEnin, nameValidator: nameValidator) else {
        return XCTFail("expected \(key) to verify at its own validFromEnin")
      }
      XCTAssertEqual(structural.validFromEnin, verified.validFromEnin, "\(key): validFromEnin")
      XCTAssertEqual(structural.validThroughEnin, verified.validThroughEnin, "\(key): validThroughEnin")
      XCTAssertEqual(structural.relayExpiresAtEnin, verified.relayExpiresAtEnin, "\(key): relayExpiresAtEnin")
      XCTAssertEqual(structural.eninSeconds, verified.eninSeconds, "\(key): eninSeconds")
    }
  }

  /// A malformed container yields no accessor result rather than partial fields. Both a first-guard
  /// rejection (truncation) and a LAST-guard rejection (the length arithmetic, which is the final
  /// check `validateStructure` runs) are exercised, so "no partial fields" is not tested only at
  /// the point where nothing has been read yet.
  func testSchedulingFieldsRejectsMalformedContainerWithoutPartialFields() throws {
    let v = try load()
    let container = hex(v["v1_container"]!)

    XCTAssertNil(BarnardB005EnvelopeV2.schedulingFields(container: []), "empty container")
    XCTAssertNil(BarnardB005EnvelopeV2.schedulingFields(container: Array(container.prefix(120))), "truncated container")

    // Last guard: 165 + 33n + nameLength + certLength must equal the envelope length. The vector
    // is n=1, nameLength=58, certLength=0 summing to 256; raising the certLength byte breaks only
    // that final equality, so every earlier structural check still passes.
    var badCertLength = container
    let certLengthContainerOffset = 4 + 74 + 33 * Int(container[4 + 73]) + 25 + Int(container[4 + 74 + 33 * Int(container[4 + 73]) + 24])
    XCTAssertEqual(BarnardB005EnvelopeV2.validateStructure(container: container), nil, "the unmodified vector container is structurally valid")
    badCertLength[certLengthContainerOffset] = 1
    XCTAssertEqual(BarnardB005EnvelopeV2.validateStructure(container: badCertLength), .fieldLayout, "expected the final length-arithmetic guard to reject")
    XCTAssertNil(BarnardB005EnvelopeV2.schedulingFields(container: badCertLength), "a container failing the last structural guard yields no fields")
  }

  // MARK: - Registry agreement (pure comparison; this SDK never assigns REGISTRY_VERIFIED)

  func testRegistryAgreementRequiresFullAgreement() throws {
    let v = try load()
    let container = hex(v["v1_container"]!)
    guard let verified = BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: nameValidator) else {
      return XCTFail("expected RADIO_SELF_VERIFIED baseline")
    }
    XCTAssertEqual(verified.receiverState, .RADIO_SELF_VERIFIED)
    // The exact ENIN window is the INCLUSIVE [validFromEnin, validThroughEnin] (see
    // registryAgreement's doc comment); an aligned registry seconds window covers exactly that
    // ENIN range, i.e. seconds [validFromEnin * eninSeconds, (validThroughEnin + 1) * eninSeconds - 1].
    func agreeing() -> BarnardEventDefinitionV1 {
      BarnardEventDefinitionV1(eventId: verified.eventId, keySetDigest: verified.keySetDigest, joinMode: verified.joinMode, eventCodeHash: verified.eventCodeHash, validFromUnixSeconds: verified.validFromEnin * Int64(verified.eninSeconds), validUntilUnixSeconds: (verified.validThroughEnin + 1) * Int64(verified.eninSeconds) - 1)
    }
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(verified, definition: agreeing()), .agrees)

    var wrongEventId = agreeing().eventId; wrongEventId[0] ^= 1
    let a1 = agreeing()
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(verified, definition: BarnardEventDefinitionV1(eventId: wrongEventId, keySetDigest: a1.keySetDigest, joinMode: a1.joinMode, eventCodeHash: a1.eventCodeHash, validFromUnixSeconds: a1.validFromUnixSeconds, validUntilUnixSeconds: a1.validUntilUnixSeconds)), .mismatched(mismatchedFields: [.EVENT_ID]), "eventId mismatch")

    let a2 = agreeing()
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(verified, definition: BarnardEventDefinitionV1(eventId: a2.eventId, keySetDigest: a2.keySetDigest, joinMode: verified.joinMode == 0 ? 1 : 0, eventCodeHash: a2.eventCodeHash, validFromUnixSeconds: a2.validFromUnixSeconds, validUntilUnixSeconds: a2.validUntilUnixSeconds)), .mismatched(mismatchedFields: [.JOIN_MODE]), "joinMode mismatch")

    let a3 = agreeing()
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(verified, definition: BarnardEventDefinitionV1(eventId: a3.eventId, keySetDigest: a3.keySetDigest, joinMode: a3.joinMode, eventCodeHash: a3.eventCodeHash, validFromUnixSeconds: verified.validThroughEnin * Int64(verified.eninSeconds), validUntilUnixSeconds: a3.validUntilUnixSeconds)), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "window mismatch")

    var wrongKeySetDigest = verified.keySetDigest; wrongKeySetDigest[0] ^= 1
    let a4 = agreeing()
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(verified, definition: BarnardEventDefinitionV1(eventId: a4.eventId, keySetDigest: wrongKeySetDigest, joinMode: a4.joinMode, eventCodeHash: a4.eventCodeHash, validFromUnixSeconds: a4.validFromUnixSeconds, validUntilUnixSeconds: a4.validUntilUnixSeconds)), .mismatched(mismatchedFields: [.KEY_SET_DIGEST]), "signer-authority (keySetDigest) mismatch")
  }

  func testRegistryAgreementRejectsMisalignedValidityWindowExample() throws {
    // eninSeconds=300, envelope declares the inclusive ENIN window [10, 11] (validFromEnin=10,
    // validThroughEnin=11 -- see registryAgreement's doc comment on the inclusive convention).
    // Registry inclusive-seconds window [3001, 3299]: ceil(3001/300)=11 for the start, mismatching
    // the envelope's declared validFromEnin=10 -- rejected.
    let misaligned = synthesizeWindow(eninSeconds: 300, validFromEnin: 10, validThroughEnin: 11)
    let registryDefinition = BarnardEventDefinitionV1(eventId: misaligned.eventId, keySetDigest: misaligned.keySetDigest, joinMode: misaligned.joinMode, eventCodeHash: misaligned.eventCodeHash, validFromUnixSeconds: 3001, validUntilUnixSeconds: 3299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(misaligned, definition: registryDefinition), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "misaligned window must not agree")

    // Aligned: registry inclusive seconds [3000, 3599] covers exactly ENIN 10 ([3000, 3299]) and
    // ENIN 11 ([3300, 3599]), i.e. the inclusive ENIN range [10, 11] -- accepted. expectedFrom =
    // ceilDiv(3000, 300) = 10. expectedThrough = floorDiv(3599 + 1, 300) - 1 = 12 - 1 = 11.
    let aligned = BarnardEventDefinitionV1(eventId: misaligned.eventId, keySetDigest: misaligned.keySetDigest, joinMode: misaligned.joinMode, eventCodeHash: misaligned.eventCodeHash, validFromUnixSeconds: 3000, validUntilUnixSeconds: 3599)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(misaligned, definition: aligned), .agrees, "aligned window must agree")

    // Reviewer's exact single-ENIN counter-example: registry inclusive seconds [3000, 3299] is
    // exactly ENIN 10 alone, so expectedThrough = floorDiv(3299 + 1, 300) - 1 = 11 - 1 = 10, not
    // 11. This same `misaligned` envelope (validThroughEnin=11) must be rejected against it.
    let singleEnin = BarnardEventDefinitionV1(eventId: aligned.eventId, keySetDigest: aligned.keySetDigest, joinMode: aligned.joinMode, eventCodeHash: aligned.eventCodeHash, validFromUnixSeconds: aligned.validFromUnixSeconds, validUntilUnixSeconds: 3299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(misaligned, definition: singleEnin), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "validThroughEnin=11 must not agree with [3000, 3299]")

    // Widening the registry window at the START is exactly the refresh case spec 134's
    // validity-window containment erratum (2026-09-10) admits: "definitionStart <= validFromEnin".
    // Registry seconds [2700, 3599] is ENIN [9, 11]; the envelope's [10, 11] sits inside it, so it
    // agrees. This assertion states the erratum, not a relaxation of the old one -- under exact
    // agreement a definition that merely started earlier was rejected, which is what made every
    // refresh envelope unservable past the 12-ENIN cap.
    let startWidened = BarnardEventDefinitionV1(eventId: aligned.eventId, keySetDigest: aligned.keySetDigest, joinMode: aligned.joinMode, eventCodeHash: aligned.eventCodeHash, validFromUnixSeconds: 2700, validUntilUnixSeconds: aligned.validUntilUnixSeconds)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(misaligned, definition: startWidened), .agrees, "a definition starting before validFromEnin contains the envelope window")

    // Narrowing at the END is still rejected: containment requires validThroughEnin <= definitionEnd.
    let endOffByOne = BarnardEventDefinitionV1(eventId: aligned.eventId, keySetDigest: aligned.keySetDigest, joinMode: aligned.joinMode, eventCodeHash: aligned.eventCodeHash, validFromUnixSeconds: aligned.validFromUnixSeconds, validUntilUnixSeconds: 3299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(misaligned, definition: endOffByOne), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "end off-by-one must not agree")
  }

  // MARK: - Validity-window containment (spec 134 erratum 2026-09-10; barnard#200)

  /// The refresh case the erratum exists for. One definition covers ENIN [10, 40] -- 31 ENINs,
  /// well past the 12-ENIN relay lifetime cap -- and an envelope re-issued for the slice [22, 33]
  /// sits inside it. Under the old exact-agreement rule this envelope was rejected as a
  /// `.VALIDITY_WINDOW` mismatch, which is precisely why nothing was servable after the first 12
  /// ENINs of any longer event.
  ///
  /// Registry seconds are the inclusive ENIN window scaled by `eninSeconds`: ENIN [10, 40] is
  /// seconds [10 * 300, (40 + 1) * 300 - 1] = [3000, 12299].
  func testRegistryAgreementAcceptsRefreshedEnvelopeInsideDefinitionWindow() throws {
    let refreshed = synthesizeWindow(eninSeconds: 300, validFromEnin: 22, validThroughEnin: 33)
    let definition = BarnardEventDefinitionV1(eventId: refreshed.eventId, keySetDigest: refreshed.keySetDigest, joinMode: refreshed.joinMode, eventCodeHash: refreshed.eventCodeHash, validFromUnixSeconds: 3000, validUntilUnixSeconds: 12_299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(refreshed, definition: definition), .agrees, "a later validFromEnin inside the definition window must agree")
  }

  /// The two containment failures, each isolating one side of
  /// `definitionStart <= validFromEnin` and `validThroughEnin <= definitionEnd`.
  func testRegistryAgreementRejectsEnvelopeOutsideDefinitionWindow() throws {
    let refreshed = synthesizeWindow(eninSeconds: 300, validFromEnin: 22, validThroughEnin: 33)

    // validFromEnin < definitionStart: definition ENIN [25, 40] is seconds [7500, 12299]; the
    // envelope starts at 22, three ENINs before the definition does.
    let startsTooEarly = BarnardEventDefinitionV1(eventId: refreshed.eventId, keySetDigest: refreshed.keySetDigest, joinMode: refreshed.joinMode, eventCodeHash: refreshed.eventCodeHash, validFromUnixSeconds: 7_500, validUntilUnixSeconds: 12_299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(refreshed, definition: startsTooEarly), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "validFromEnin before definitionStart must not agree")

    // validThroughEnin > definitionEnd: definition ENIN [10, 30] is seconds [3000, 9299]; the
    // envelope runs through 33, three ENINs past the definition's end.
    let endsTooLate = BarnardEventDefinitionV1(eventId: refreshed.eventId, keySetDigest: refreshed.keySetDigest, joinMode: refreshed.joinMode, eventCodeHash: refreshed.eventCodeHash, validFromUnixSeconds: 3_000, validUntilUnixSeconds: 9_299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(refreshed, definition: endsTooLate), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "validThroughEnin past definitionEnd must not agree")
  }

  /// The 12-ENIN relay lifetime cap is unchanged by the erratum, and it is enforced in `verify`,
  /// not in `registryAgreement` -- so containment does not let a long-lived envelope through some
  /// other door. `synthesizeWindowContainer` sets `relayExpiresAtEnin = validThroughEnin`, so a
  /// window of [0, 13] is a lifetime of 13 and must be refused at the wire.
  func testVerifyRejectsRelayLifetimeOverTwelveEnins() throws {
    let recoverer = AlwaysAcceptingRecoverer(key: [UInt8](repeating: 1, count: 33))
    let atCap = synthesizeWindowContainer(eninSeconds: 300, validFromEnin: 0, validThroughEnin: 12)
    XCTAssertNotNil(BarnardB005EnvelopeV2.verify(container: atCap, currentEnin: 0, nameValidator: nameValidator, recoverer: recoverer), "a lifetime of exactly 12 is still accepted")
    let overCap = synthesizeWindowContainer(eninSeconds: 300, validFromEnin: 0, validThroughEnin: 13)
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: overCap, currentEnin: 0, nameValidator: nameValidator, recoverer: recoverer), "a lifetime of 13 must still be rejected")
  }

  /// Containment makes an inverted ENVELOPE window reachable in a way exact agreement did not.
  /// Under equality, a registry window that does not fall on ENIN boundaries converts to an empty
  /// range and could never equal anything, whatever the envelope carried. Under containment,
  /// `registryStart <= validFromEnin && validThroughEnin <= registryEnd` is satisfiable by an
  /// empty range exactly when `validThroughEnin < validFromEnin` -- so the emptiness argument now
  /// depends on the envelope's own window being ordered. `verify` guarantees that ordering, but
  /// `registryAgreement` is a separate function, so it re-checks rather than inherits, on the same
  /// footing as its `eninSeconds <= 0` branch. Built through the internal initializer because
  /// `verify` will not produce an inverted window.
  func testRegistryAgreementRejectsInvertedEnvelopeWindow() throws {
    let envelope = synthesizeWindow(eninSeconds: 300, validFromEnin: 22, validThroughEnin: 33)
    // validFromEnin=22, validThroughEnin=10; `relayExpiresAtEnin` is not read by
    // `registryAgreement` and carries no meaning for this case. Both bounds below are chosen so that each side of
    // the containment test passes on its own and only the ordering check refuses them, which is
    // what makes this a witness for the guard rather than for the arithmetic.
    let inverted = BarnardB005VerifiedEnvelope(receiverState: .RADIO_SELF_VERIFIED, relayHopCount: 0, eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, eventDisplayName: envelope.eventDisplayName, validFromEnin: 22, validThroughEnin: 10, relayExpiresAtEnin: 22, eninSeconds: 300, signedEnvelope: envelope.signedEnvelope)

    // A well-formed definition, ENIN [10, 40] as seconds [3000, 12299]: 10 <= 22 and 10 <= 40 both
    // hold, so without the ordering check this inverted envelope would agree.
    let wide = BarnardEventDefinitionV1(eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, validFromUnixSeconds: 3_000, validUntilUnixSeconds: 12_299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(inverted, definition: wide), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "an inverted envelope window must not agree with a window that spans it")

    // And the empty range an off-boundary registry window converts to: seconds [3001, 3299] is
    // ENIN start ceil(3001/300) = 11, end floorDiv(3300, 300) - 1 = 10, i.e. the empty [11, 10].
    // 11 <= 22 and 10 <= 10 both hold, so this is the exact shape that would let an EMPTY registry
    // range agree with something -- the claim the rationale comment makes -- if the envelope's own
    // window were not required to be ordered.
    let emptyRange = BarnardEventDefinitionV1(eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, validFromUnixSeconds: 3_001, validUntilUnixSeconds: 3_299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(inverted, definition: emptyRange), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "an empty registry range must still agree with nothing")
  }

  func testRegistryAgreementFailsClosedOnInvalidRegistryWindow() throws {
    let envelope = synthesizeWindow(eninSeconds: 300, validFromEnin: 0, validThroughEnin: 1)

    // A negative validFromUnixSeconds must not agree.
    let negativeFrom = BarnardEventDefinitionV1(eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, validFromUnixSeconds: -1, validUntilUnixSeconds: 299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(envelope, definition: negativeFrom), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "negative validFromUnixSeconds must not agree")

    // Int64.min must not crash the negation in the ceil-division of the start bound (Swift traps
    // on negating Int64.min).
    let minFrom = BarnardEventDefinitionV1(eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, validFromUnixSeconds: Int64.min, validUntilUnixSeconds: 299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(envelope, definition: minFrom), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "Int64.min validFrom must not crash and must not agree")

    // validFrom > validUntil is an invalid definition.
    let inverted = BarnardEventDefinitionV1(eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, validFromUnixSeconds: 300, validUntilUnixSeconds: 0)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(envelope, definition: inverted), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "validFrom > validUntil must not agree")

    // eninSeconds=0 is an invalid definition (division by zero). verify() itself already rejects a
    // wire envelope with eninSeconds=0, so build the verified envelope directly via the internal
    // initializer to exercise registryAgreement's own defense in depth.
    let zeroEninEnvelope = BarnardB005VerifiedEnvelope(receiverState: .RADIO_SELF_VERIFIED, relayHopCount: 0, eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, eventDisplayName: envelope.eventDisplayName, validFromEnin: 0, validThroughEnin: 0, relayExpiresAtEnin: 0, eninSeconds: 0, signedEnvelope: envelope.signedEnvelope)
    let zeroEninDefinition = BarnardEventDefinitionV1(eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, validFromUnixSeconds: 0, validUntilUnixSeconds: 299)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(zeroEninEnvelope, definition: zeroEninDefinition), .mismatched(mismatchedFields: [.VALIDITY_WINDOW]), "eninSeconds=0 must not agree")
  }

  func testRegistryAgreementEndConversionIsOverflowSafeAtInt64Max() throws {
    // eninPerSecond=1 makes floorMod(Int64.max, 1)==0==eninPerSecond-1, which is exactly the
    // branch that would try to compute Int64.max + 1 (overflowing/trapping) without the
    // floorMod-identity guard in registryAgreement.
    //
    // Under spec 134's containment erratum (2026-09-10) the expected verdict here is `.agrees`,
    // and that is the STRONGER assertion, not a weakened one. Registry seconds [10, Int64.max] at
    // eninSeconds=1 is ENIN [10, Int64.max], which genuinely contains the envelope's [10, 11], so
    // containment holds -- but only if the end conversion did not wrap. Had it overflowed to a
    // negative registryEndEnin, `validThroughEnin <= registryEndEnin` would fail and this would
    // report a mismatch. So `.agrees` is precisely the statement that no wrap occurred; under the
    // old exact rule the same probe could only say "did not wrap INTO an equality".
    let envelope = synthesizeWindow(eninSeconds: 1, validFromEnin: 10, validThroughEnin: 11)
    let definition = BarnardEventDefinitionV1(eventId: envelope.eventId, keySetDigest: envelope.keySetDigest, joinMode: envelope.joinMode, eventCodeHash: envelope.eventCodeHash, validFromUnixSeconds: 10, validUntilUnixSeconds: Int64.max)
    XCTAssertEqual(BarnardB005EnvelopeV2.registryAgreement(envelope, definition: definition), .agrees, "an unwrapped Int64.max end contains ENIN [10, 11]")
  }

  /// Builds a structurally-valid `RADIO_SELF_VERIFIED` envelope with a caller-chosen
  /// `eninSeconds`/window, using an `AlwaysAcceptingRecoverer` to stand in for real ECDSA math
  /// (same technique as `buildSyntheticContainer` below), so `registryAgreement`'s window logic
  /// can be exercised against known, exact ENIN values. Requires `validThroughEnin >
  /// validFromEnin`: a verified envelope's `expires` field must satisfy `validFromEnin <=
  /// currentEnin < expires <= validThroughEnin`, which is unsatisfiable when the two are equal.
  private func synthesizeWindow(eninSeconds: UInt16, validFromEnin: Int64, validThroughEnin: Int64) -> BarnardB005VerifiedEnvelope {
    let container = synthesizeWindowContainer(eninSeconds: eninSeconds, validFromEnin: validFromEnin, validThroughEnin: validThroughEnin)
    guard let result = BarnardB005EnvelopeV2.verify(container: container, currentEnin: validFromEnin, nameValidator: nameValidator, recoverer: AlwaysAcceptingRecoverer(key: [UInt8](repeating: 1, count: 33))) else {
      fatalError("expected synthetic window container to verify")
    }
    return result
  }

  /// The container half of `synthesizeWindow`, without the verification step, so a test can assert
  /// that `verify` REJECTS a window (the 12-ENIN relay lifetime cap) rather than only exercising
  /// windows it accepts.
  private func synthesizeWindowContainer(eninSeconds: UInt16, validFromEnin: Int64, validThroughEnin: Int64) -> [UInt8] {
    var envelope: [UInt8] = [1] + [UInt8](repeating: 0, count: 20) + [UInt8](repeating: 0, count: 20) + [UInt8](repeating: 0, count: 32) + [1]
    envelope += [UInt8](repeating: 1, count: 33)
    envelope += [1] // joinMode = gated
    envelope += [UInt8(eninSeconds >> 8), UInt8(eninSeconds & 0xff)]
    envelope += [UInt8((validFromEnin >> 24) & 0xff), UInt8((validFromEnin >> 16) & 0xff), UInt8((validFromEnin >> 8) & 0xff), UInt8(validFromEnin & 0xff)]
    envelope += [UInt8((validThroughEnin >> 24) & 0xff), UInt8((validThroughEnin >> 16) & 0xff), UInt8((validThroughEnin >> 8) & 0xff), UInt8(validThroughEnin & 0xff)]
    envelope += [UInt8((validThroughEnin >> 24) & 0xff), UInt8((validThroughEnin >> 16) & 0xff), UInt8((validThroughEnin >> 8) & 0xff), UInt8(validThroughEnin & 0xff)] // expires = validThroughEnin
    envelope += [2] // fixed marker byte
    envelope += [UInt8](repeating: 0, count: 8) // eventCodeHash (unchecked under gated mode)
    envelope += [1] // nameLength
    envelope += Array("X".utf8)
    envelope += [0] // certLength = 0
    envelope += [UInt8](repeating: 0, count: 31) + [1] + [UInt8](repeating: 0, count: 31) + [1] + [0] // r=1, s=1, v=0
    return BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 0, signedEnvelope: envelope)!
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

  // MARK: - Delegation certificate ENIN upper bound (parallax parity: 2^53-1, not 2^53)

  private func cborUintMajor(_ major: UInt8, _ value: Int64) -> [UInt8] {
    let v = UInt64(value)
    switch v {
    case ..<24: return [(major << 5) | UInt8(v)]
    case ..<256: return [(major << 5) | 24, UInt8(v)]
    case ..<65_536: return [(major << 5) | 25, UInt8(v >> 8), UInt8(v & 0xff)]
    case ..<4_294_967_296:
      var out: [UInt8] = [(major << 5) | 26]
      for i in 0..<4 { out.append(UInt8((v >> UInt64(8 * (3 - i))) & 0xff)) }
      return out
    default:
      var out: [UInt8] = [(major << 5) | 27]
      for i in 0..<8 { out.append(UInt8((v >> UInt64(8 * (7 - i))) & 0xff)) }
      return out
    }
  }
  private func cborUint(_ value: Int64) -> [UInt8] { cborUintMajor(0, value) }
  private func cborBytesField(_ b: [UInt8]) -> [UInt8] { cborUintMajor(2, Int64(b.count)) + b }
  private func cborTextField(_ s: String) -> [UInt8] { let b = Array(s.utf8); return cborUintMajor(3, Int64(b.count)) + b }
  private func cborNegative47() -> [UInt8] { [0x38, 46] } // major 1, ai=24, value 46 -> -(46+1) = -47

  /// Hand-encodes a delegation certificate with a caller-chosen `eninEnd`, using an
  /// `AlwaysAcceptingRecoverer` for both the cert's COSE signature and the envelope signature so
  /// the boundary on `eninEnd` (parallax parity: at most `2^53-1`) can be exercised without real
  /// ECDSA math. `kid` is computed the same way production code derives it so the single
  /// authority key is found as the unique candidate signer; `eventId` is the real
  /// `computeEventId` output for the envelope's own registrar/anchor/nonce/key-set, so the cert's
  /// own `eventId` tie-in check passes independent of the field under test.
  private func buildCertContainer(eninEnd: Int64) -> [UInt8] {
    // Same key for both roles: the fixed AlwaysAcceptingRecoverer must satisfy the cert's own
    // COSE signature check (against the candidate authority key) and the envelope signature
    // check (against the cert's delegateKey) with one fixed return value.
    let authorityKey = [UInt8](repeating: 1, count: 33)
    let delegateKey = authorityKey
    let registrar = [UInt8](repeating: 4, count: 20)
    let anchor = [UInt8](repeating: 5, count: 20)
    let nonce = [UInt8](repeating: 6, count: 32)
    let ksDigest = BarnardB005EnvelopeV2.keySetDigest([authorityKey])!
    let eventId = BarnardB005EnvelopeV2.computeEventId(registrar: registrar, anchorOperator: anchor, nonce: nonce, keySetDigest: ksDigest)!
    let kid = Array(BarnardCoreCrypto.sha256(Array("levarac:cose-kid:v1\0".utf8) + authorityKey).prefix(8))

    var protectedHeader: [UInt8] = [0xa3, 0x01]
    protectedHeader += cborNegative47()
    protectedHeader.append(0x03)
    protectedHeader += cborTextField("application/vnd.levarac.delegation-cert+cbor")
    protectedHeader.append(0x04)
    protectedHeader += cborBytesField(kid)
    var payload: [UInt8] = [0xa6, 0x01]
    payload += cborUint(1)
    payload.append(0x02)
    payload += cborBytesField(eventId)
    payload.append(0x03)
    payload += cborBytesField(delegateKey)
    payload.append(0x04)
    payload += cborUint(1)
    payload.append(0x05)
    payload += cborUint(1000)
    payload.append(0x06)
    payload += cborUint(eninEnd)
    // r=1, s=1: isLowSInRange rejects an all-zero r/s regardless of the injected recoverer.
    let certSignature = [UInt8](repeating: 0, count: 31) + [1] + [UInt8](repeating: 0, count: 31) + [1]
    var cert: [UInt8] = [0xd2, 0x84]
    cert += cborBytesField(protectedHeader)
    cert.append(0xa0)
    cert += cborBytesField(payload)
    cert += cborBytesField(certSignature)
    precondition(cert.count <= 255, "synthetic cert too large: \(cert.count)")

    var envelope: [UInt8] = [1] + registrar + anchor + nonce + [1]
    envelope += authorityKey
    envelope += [1] // joinMode = gated
    envelope += [0x01, 0x2c] // eninSeconds = 300
    envelope += [0x00, 0x5b, 0x8d, 0x7b] // validFrom = 5_999_995
    envelope += [0x00, 0x5b, 0x8d, 0x85] // validThrough = 6_000_005
    envelope += [0x00, 0x5b, 0x8d, 0x81] // relayExpiresAtEnin = 6_000_001 (lifetime 6 <= 12)
    envelope += [2] // fixed marker byte
    envelope += [UInt8](repeating: 0, count: 8) // eventCodeHash (unchecked under gated mode)
    envelope += [1] // nameLength
    envelope += Array("X".utf8)
    envelope += [UInt8(cert.count)]
    envelope += cert
    envelope += [UInt8](repeating: 0, count: 31) + [1] + [UInt8](repeating: 0, count: 31) + [1] + [0] // envelope signature r=1, s=1, v=0
    return BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 0, signedEnvelope: envelope)!
  }

  func testDelegationCertEninEndAcceptsMaxAndRejectsOneAboveMax() throws {
    // Parallax's verifier allows at most 2^53-1; both must match exactly.
    let recoverer = AlwaysAcceptingRecoverer(key: [UInt8](repeating: 1, count: 33))
    let atMax = buildCertContainer(eninEnd: 9_007_199_254_740_991)
    XCTAssertNotNil(BarnardB005EnvelopeV2.verify(container: atMax, currentEnin: 6_000_000, nameValidator: nameValidator, recoverer: recoverer), "2^53-1 must be accepted")
    let overMax = buildCertContainer(eninEnd: 9_007_199_254_740_992)
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: overMax, currentEnin: 6_000_000, nameValidator: nameValidator, recoverer: recoverer), "2^53 must be rejected")
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
