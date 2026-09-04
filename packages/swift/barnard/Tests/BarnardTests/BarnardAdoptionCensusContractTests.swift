// Use of this source code is governed by a BSD-style license.

import Foundation
import XCTest
@testable import Barnard

/// Contract-first RED coverage for Barnard issues #123 and #128.
///
/// These tests intentionally name the public protocol seam before production
/// implementation exists. They load the same fixed inputs as Kotlin and
/// exercise byte canonicalization, registry gating, cross-event majority,
/// bounded relay conflict handling, and the implementable GATT self-check.
final class BarnardAdoptionCensusContractTests: XCTestCase {
  func testCanonicalUnsignedCredentialAndCensusUseStableCredentialID() throws {
    let vectors = try AdoptionCensusVectors.load()
    let unsignedCredential = try vectors.bytes("credential_unsigned_body")
    let credential = try BarnardAdoptionCredential.UnsignedBody.decode(unsignedCredential)

    XCTAssertEqual(credential.canonicalBytes(), unsignedCredential)
    XCTAssertEqual(hex(credential.credentialId), try vectors.string("credential_id"))

    let rotated = try BarnardAdoptionCredential.UnsignedBody.decode(
      try vectors.bytes("rotated_credential_unsigned_body")
    )
    XCTAssertEqual(hex(rotated.credentialId), try vectors.string("rotated_credential_id"))
    XCTAssertNotEqual(rotated.credentialId, credential.credentialId)

    let fullCredential = try vectors.bytes("credential_full")
    let verifiedCredential = try BarnardAdoptionCredential.decode(fullCredential)
    XCTAssertEqual(verifiedCredential.canonicalBytes, fullCredential)
    XCTAssertEqual(verifiedCredential.authorityPublicKey, try vectors.bytes("credential_authority_public_key"))
    XCTAssertEqual(
      try BarnardAdoptionCredential.encodeSigned(
        unsignedBody: credential,
        authorityPrivateKey: try vectors.bytes("credential_authority_test_private_key")
      ),
      fullCredential
    )

    let highSFullCredential = unsignedCredential + (try vectors.bytes("credential_signature_high_s"))
    XCTAssertThrowsError(try BarnardAdoptionCredential.decode(highSFullCredential)) { error in
      XCTAssertEqual(error as? BarnardAdoptionProtocolError, .nonCanonicalSignature)
    }

    // The same unsigned body must retain the same credentialId across two
    // independently-nonced but equally *valid* signatures over it - not just
    // two decodes of identical signature bytes, which can never disagree
    // regardless of whether re-signing actually preserves identity.
    let secondSignedCredential = unsignedCredential + (try vectors.bytes("credential_signature_second_valid"))
    let secondVerifiedCredential = try BarnardAdoptionCredential.decode(secondSignedCredential)
    XCTAssertNotEqual(secondVerifiedCredential.canonicalBytes, fullCredential)
    XCTAssertEqual(secondVerifiedCredential.credentialId, verifiedCredential.credentialId)

    let census = try BarnardSignedWindowCensus.UnsignedBody(
      credentialId: credential.credentialId,
      windowIndex: try vectors.uint64("census_window_index"),
      qualifiedVoterCount: try vectors.uint16("qualified_voter_count"),
      eligibleVoterCount: try vectors.uint16("eligible_voter_count"),
      countedSetMerkleRoot: try vectors.bytes("counted_set_merkle_root_v1")
    )
    XCTAssertEqual(census.canonicalBytes(), try vectors.bytes("census_unsigned_body"))

    let fullCensus = try vectors.bytes("census_full")
    let verifiedCensus = try BarnardSignedWindowCensus.decode(fullCensus)
    XCTAssertEqual(verifiedCensus.canonicalBytes, fullCensus)
    XCTAssertEqual(verifiedCensus.authorityPublicKey, try vectors.bytes("census_authority_public_key"))
    XCTAssertEqual(
      try BarnardSignedWindowCensus.encodeSigned(
        unsignedBody: census,
        authorityPrivateKey: try vectors.bytes("census_authority_test_private_key")
      ),
      fullCensus
    )

    XCTAssertThrowsError(try BarnardSignedWindowCensus.UnsignedBody(
      credentialId: credential.credentialId,
      windowIndex: try vectors.uint64("census_window_index"),
      qualifiedVoterCount: try vectors.uint16("qualified_voter_count"),
      eligibleVoterCount: try vectors.uint16("eligible_voter_count"),
      countedSetMerkleRoot: try vectors.bytes("counted_set_merkle_root_nonzero")
    )) { error in
      XCTAssertEqual(error as? BarnardAdoptionProtocolError, .nonCanonicalMerkleRoot)
    }

    let structurallyMaximalV2 = b005V2(
      displayName: String(repeating: "A", count: 64),
      scopeHash: try vectors.bytes("b004_adoption_scope_hash"),
      credential: unsignedCredential + Data(repeating: 0, count: 65),
      census: census.canonicalBytes() + Data(repeating: 0, count: 65)
    )
    XCTAssertEqual(structurallyMaximalV2.count, try vectors.int("maximum_b005_v2_bytes"))
    XCTAssertThrowsError(try BarnardB005V2Codec.decode(structurallyMaximalV2)) { error in
      XCTAssertEqual(error as? BarnardAdoptionProtocolError, .invalidCredentialSignature)
    }

    let b005 = try BarnardB005V2Codec.decode(try vectors.bytes("b005_v2_positive"))
    XCTAssertEqual(b005.eventDisplayName, try vectors.string("display_name"))
    XCTAssertEqual(try BarnardB005V2Codec.serialize(b005), try vectors.bytes("b005_v2_positive"))
    XCTAssertEqual(
      try BarnardAdoptionKeyDerivation.deriveTek(
        deviceSecret: try vectors.bytes("adoption_device_secret"),
        credentialId: verifiedCredential.credentialId
      ),
      try vectors.bytes("adoption_tek")
    )
    XCTAssertEqual(
      BarnardAdoptionKeyDerivation.deriveSigningPublicKey(
        deviceSecret: try vectors.bytes("adoption_device_secret"),
        credentialId: verifiedCredential.credentialId
      ),
      try vectors.bytes("adoption_signing_public_key")
    )

    let registryDefinition = BarnardRegistryEventDefinition(
      eventId: verifiedCredential.unsignedBody.eventId,
      credentialId: verifiedCredential.credentialId,
      b004AdoptionScopeHash: verifiedCredential.unsignedBody.b004AdoptionScopeHash,
      displayNameHash: verifiedCredential.unsignedBody.displayNameHash,
      validFromUnixSeconds: verifiedCredential.unsignedBody.validFromUnixSeconds,
      validUntilUnixSeconds: verifiedCredential.unsignedBody.validUntilUnixSeconds,
      admissionMode: verifiedCredential.unsignedBody.admissionMode,
      censusDomainPolicy: try domainPolicy(vectors)
    )
    XCTAssertEqual(
      registryDefinition.verify(
        credential: verifiedCredential,
        census: verifiedCensus,
        nowUnixSeconds: verifiedCredential.unsignedBody.validFromUnixSeconds + 1
      ),
      .verified
    )

    let selfReferentialRotation = BarnardRegistryEventDefinition(
      eventId: verifiedCredential.unsignedBody.eventId,
      credentialId: verifiedCredential.credentialId,
      b004AdoptionScopeHash: verifiedCredential.unsignedBody.b004AdoptionScopeHash,
      displayNameHash: verifiedCredential.unsignedBody.displayNameHash,
      validFromUnixSeconds: verifiedCredential.unsignedBody.validFromUnixSeconds,
      validUntilUnixSeconds: verifiedCredential.unsignedBody.validUntilUnixSeconds,
      admissionMode: verifiedCredential.unsignedBody.admissionMode,
      censusDomainPolicy: try domainPolicy(vectors),
      replacesCredentialId: verifiedCredential.credentialId,
      effectiveWindowIndex: 6
    )
    XCTAssertEqual(
      selfReferentialRotation.verify(
        credential: verifiedCredential,
        census: verifiedCensus,
        nowUnixSeconds: verifiedCredential.unsignedBody.validFromUnixSeconds + 1
      ),
      .unverified
    )
  }

  func testLegacyV1B005AndEventCodeB004RemainLegacyOnly() throws {
    let legacyCode = "LEGACY-123"
    let legacyB004 = BarnardCrypto.computeEventCodeHash(legacyCode)
    let legacyPayload = try BarnardEventInfoCodec.serialize(
      eventCode: legacyCode,
      eventDisplayName: "Legacy Event",
      b004EventCodeHash: legacyB004
    )

    XCTAssertEqual(
      try BarnardEventInfoCodec.parse(legacyPayload),
      BarnardEventInfo(eventDisplayName: "Legacy Event", eventCodeHash: legacyB004)
    )
    XCTAssertEqual(legacyPayload.first, 0x01)
    XCTAssertNotEqual(legacyB004, try AdoptionCensusVectors.load().bytes("b004_adoption_scope_hash"))
  }

  func testRegistryGateAndCrossEventMajorityChooseOnlyAQualifiedOpenWinner() throws {
    let vectors = try AdoptionCensusVectors.load()
    let policy = try domainPolicy(vectors)
    let winner = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    let runnerUp = try candidate(
      vectors,
      qualified: 3,
      eligible: 7,
      observedAt: 1_545,
      credentialAuthorityKey: 2
    )

    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [winner, runnerUp],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .autoAdopt(credentialId: winner.credentialId)
    )

    let unbound = try candidateInput(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    let definition = unbound.registryDefinition
    let mismatchedDefinition = BarnardRegistryEventDefinition(
      eventId: Data(repeating: 0, count: 32),
      credentialId: definition.credentialId,
      b004AdoptionScopeHash: definition.b004AdoptionScopeHash,
      displayNameHash: definition.displayNameHash,
      validFromUnixSeconds: definition.validFromUnixSeconds,
      validUntilUnixSeconds: definition.validUntilUnixSeconds,
      admissionMode: definition.admissionMode,
      censusDomainPolicy: definition.censusDomainPolicy
    )
    XCTAssertThrowsError(
      try BarnardVerifiedCensusCandidate.decodeAndBind(
        b005Bytes: unbound.b005Bytes,
        registryDefinition: mismatchedDefinition,
        observedAtUnixSeconds: 1_540
      )
    )

    let gated = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      admissionMode: .gated,
      credentialAuthorityKey: 1
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [gated],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.gated)
    )

    let noMajority = try candidate(
      vectors,
      qualified: 3,
      eligible: 6,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [noMajority],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.noClearMajority)
    )

    let stale = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_489,
      credentialAuthorityKey: 1
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [stale],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.staleCandidate)
    )

    let wrongWindow = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1,
      windowIndex: winner.windowIndex + 1
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [wrongWindow],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.wrongCensusWindow)
    )
  }

  func testRotationAndDomainAuthorityConflictsFailClosed() throws {
    let vectors = try AdoptionCensusVectors.load()
    let policy = try domainPolicy(vectors)
    let active = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    let rotatedId = try vectors.bytes("rotated_credential_id")

    XCTAssertEqual(
      BarnardCredentialRotation.validate(
        activeCredentialId: active.credentialId,
        replacementCredentialId: rotatedId,
        replacesCredentialId: nil,
        activeWindowIndex: active.windowIndex,
        effectiveWindowIndex: active.windowIndex
      ),
      .credentialRotationInconsistency
    )

    XCTAssertEqual(
      BarnardCredentialRotation.validate(
        activeCredentialId: active.credentialId,
        replacementCredentialId: rotatedId,
        replacesCredentialId: active.credentialId,
        activeWindowIndex: active.windowIndex,
        effectiveWindowIndex: active.windowIndex + 1
      ),
      .validBoundaryReplacement
    )

    let otherAuthority = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 2,
      censusAuthorityKey: 1
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [active, otherAuthority],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .domainAuthorityInconsistency
    )
  }

  func testVerifiedCandidateFactoryPreservesSignedCountsAndRejectsUnboundBytes() throws {
    let vectors = try AdoptionCensusVectors.load()
    let policy = try domainPolicy(vectors)
    let signedZero = try candidate(
      vectors,
      qualified: 0,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )

    XCTAssertEqual(signedZero.qualifiedVoterCount, 0)
    XCTAssertEqual(signedZero.eligibleVoterCount, 7)
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [signedZero],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.noClearMajority)
    )

    let bound = try candidateInput(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    var tamperedBytes = bound.b005Bytes
    tamperedBytes[tamperedBytes.index(before: tamperedBytes.endIndex)] ^= 0x01
    XCTAssertThrowsError(
      try BarnardVerifiedCensusCandidate.decodeAndBind(
        b005Bytes: tamperedBytes,
        registryDefinition: bound.registryDefinition,
        observedAtUnixSeconds: 1_540
      )
    )
  }

  func testRelayCacheUsesBoundArtifactsExpiryWatermarkAndTwoPayloadHardCap() throws {
    let vectors = try AdoptionCensusVectors.load()
    let first = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    let conflict = try candidate(
      vectors,
      qualified: 5,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    let thirdPayload = try candidate(
      vectors,
      qualified: 6,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    let conflictCache = BarnardCensusRelayCache(
      maximumActiveTuples: 4,
      maximumPayloadsPerConflict: 99
    )
    XCTAssertEqual(conflictCache.record(first), .acceptedForRelay)
    XCTAssertEqual(conflictCache.record(first), .duplicate)
    XCTAssertEqual(conflictCache.record(conflict), .censusEquivocation)
    XCTAssertEqual(conflictCache.record(thirdPayload), .censusEquivocation)
    XCTAssertEqual(conflictCache.relayDisposition(for: first.censusTuple), .blockedByEquivocation)
    XCTAssertEqual(conflictCache.retainedPayloadCount(for: first.censusTuple), 2)

    let replayCache = BarnardCensusRelayCache(
      maximumActiveTuples: 1,
      maximumPayloadsPerConflict: 99
    )
    let laterWindow = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_840,
      credentialAuthorityKey: 1,
      windowIndex: first.windowIndex + 1
    )
    XCTAssertEqual(replayCache.record(first), .acceptedForRelay)
    replayCache.prune(expiredThroughWindow: first.windowIndex + 1)
    XCTAssertEqual(replayCache.record(laterWindow), .acceptedForRelay)
    replayCache.prune(expiredThroughWindow: laterWindow.windowIndex + 1)
    XCTAssertEqual(replayCache.record(first), .expired)
  }

  func testB005RejectsC1UnicodeControlInDisplayName() throws {
    let vectors = try AdoptionCensusVectors.load()
    let c1DisplayName = "Barnard\u{0085}Tap"
    let malformed = b005V2(
      displayName: c1DisplayName,
      scopeHash: try vectors.bytes("b004_adoption_scope_hash"),
      credential: try vectors.bytes("credential_full"),
      census: try vectors.bytes("census_full")
    )

    XCTAssertThrowsError(try BarnardB005V2Codec.decode(malformed)) { error in
      XCTAssertEqual(error as? BarnardAdoptionProtocolError, .invalidDisplayName)
    }
  }

  /// A payload invalid in two independent ways at once (bad display name AND
  /// wrong-length scope hash) must report the *same* rejection reason on both
  /// platforms, so frozen cross-platform negative test vectors can pin a
  /// single reason code. Swift checks the display name (0x01 TLV) before the
  /// scope hash (0x02 TLV); Android must match this order.
  func testB005ChecksDisplayNameBeforeScopeLength() throws {
    let vectors = try AdoptionCensusVectors.load()
    let malformed = b005V2(
      displayName: "Barnard\u{0085}Tap",
      scopeHash: Data(repeating: 0xAB, count: 7),
      credential: try vectors.bytes("credential_full"),
      census: try vectors.bytes("census_full")
    )

    XCTAssertThrowsError(try BarnardB005V2Codec.decode(malformed)) { error in
      XCTAssertEqual(error as? BarnardAdoptionProtocolError, .invalidDisplayName)
    }
  }

  /// `Data` slices preserve the original buffer's indices instead of
  /// renumbering from zero (e.g. `someData.dropFirst(n)`), which is a
  /// completely normal shape for a TLV value a host extracted from a larger
  /// scan-record buffer upstream. `decode` must normalize offsets internally
  /// rather than assume a zero-based buffer.
  func testDecodeAcceptsNonZeroBasedDataSlice() throws {
    let vectors = try AdoptionCensusVectors.load()
    let validB005 = try vectors.bytes("b005_v2_positive")

    let prefixJunk = Data(repeating: 0xFF, count: 16)
    let slicedB005 = (prefixJunk + validB005).dropFirst(prefixJunk.count)
    XCTAssertEqual(slicedB005.startIndex, prefixJunk.count)
    XCTAssertEqual(Data(slicedB005), validB005)

    let payload = try BarnardB005V2Codec.decode(slicedB005)
    XCTAssertEqual(payload.eventDisplayName, try vectors.string("display_name"))
    XCTAssertEqual(try BarnardB005V2Codec.serialize(payload), validB005)
  }

  func testVectorParserDecodesEscapesAndRejectsDuplicateKeys() throws {
    let escaped = try AdoptionCensusVectors(contents: "value=first\\nsecond\\\\tail\n")
    XCTAssertEqual(try escaped.string("value"), "first\nsecond\\tail")
    XCTAssertThrowsError(try AdoptionCensusVectors(contents: "same=one\nsame=two\n"))
    XCTAssertThrowsError(try AdoptionCensusVectors(contents: "value=bad\\q\n"))
  }

  func testSelfCheckRequiresVerifiedSameCredentialPeerWithoutCrossDeviceTEKResolution() throws {
    let vectors = try AdoptionCensusVectors.load()
    let local = try candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      credentialAuthorityKey: 1
    )
    let tracker = BarnardAutoAdoptionSelfCheck(
      credentialId: local.credentialId,
      b004AdoptionScopeHash: try vectors.bytes("b004_adoption_scope_hash"),
      requiredCompleteWindows: try vectors.int("self_check_complete_windows")
    )

    let validPeer = BarnardDirectGattPeerObservation(
      ephemeralPeerHandle: "session-peer-1",
      b004Value: try vectors.bytes("b004_adoption_scope_hash"),
      b002Value: try vectors.bytes("valid_peer_b002"),
      verifiedB005CredentialId: local.credentialId,
      registryVerification: .verified
    )
    XCTAssertEqual(tracker.observe(validPeer, inWindow: local.windowIndex + 1), .peerConfirmed)

    let invalidPeer = BarnardDirectGattPeerObservation(
      ephemeralPeerHandle: "session-peer-2",
      b004Value: try vectors.bytes("b004_adoption_scope_hash"),
      b002Value: try vectors.bytes("malformed_peer_b002"),
      verifiedB005CredentialId: local.credentialId,
      registryVerification: .verified
    )
    XCTAssertEqual(tracker.observe(invalidPeer, inWindow: local.windowIndex + 2), .ignored)

    let wrongCredentialPeer = BarnardDirectGattPeerObservation(
      ephemeralPeerHandle: "session-peer-3",
      b004Value: try vectors.bytes("b004_adoption_scope_hash"),
      b002Value: try vectors.bytes("valid_peer_b002"),
      verifiedB005CredentialId: try vectors.bytes("rotated_credential_id"),
      registryVerification: .verified
    )
    XCTAssertEqual(tracker.observe(wrongCredentialPeer, inWindow: local.windowIndex + 2), .ignored)

    let unverifiedPeer = BarnardDirectGattPeerObservation(
      ephemeralPeerHandle: "session-peer-4",
      b004Value: try vectors.bytes("b004_adoption_scope_hash"),
      b002Value: try vectors.bytes("valid_peer_b002"),
      verifiedB005CredentialId: local.credentialId,
      registryVerification: .unverified
    )
    XCTAssertEqual(tracker.observe(unverifiedPeer, inWindow: local.windowIndex + 2), .ignored)

    let noPeerTracker = BarnardAutoAdoptionSelfCheck(
      credentialId: local.credentialId,
      b004AdoptionScopeHash: try vectors.bytes("b004_adoption_scope_hash"),
      requiredCompleteWindows: try vectors.int("self_check_complete_windows")
    )
    XCTAssertEqual(noPeerTracker.completeWindow(local.windowIndex + 1), .continueChecking)
    XCTAssertEqual(noPeerTracker.completeWindow(local.windowIndex + 2), .continueChecking)
    XCTAssertEqual(noPeerTracker.completeWindow(local.windowIndex + 3), .presentSwitchPrompt)
  }

  private func domainPolicy(
    _ vectors: AdoptionCensusVectors,
    authorityPublicKey: Data? = nil
  ) throws -> BarnardCensusDomainPolicy {
    BarnardCensusDomainPolicy(
      censusDomainId: try vectors.bytes("census_domain_id"),
      censusWindowSeconds: UInt32(try vectors.int("census_window_seconds")),
      authorityPolicyEpoch: UInt32(try vectors.int("census_authority_policy_epoch")),
      authorizedAuthorityKeyHash: BarnardCrypto.sha256(
        authorityPublicKey ?? (try vectors.bytes("census_authority_public_key"))
      ),
      minimumEligibleVoterCount: UInt16(try vectors.int("minimum_eligible_voters")),
      minimumQualifiedVoterCount: UInt16(try vectors.int("minimum_qualified_voters"))
    )
  }

  private struct BoundCandidateInput {
    let b005Bytes: Data
    let registryDefinition: BarnardRegistryEventDefinition
  }

  private func candidate(
    _ vectors: AdoptionCensusVectors,
    qualified: UInt16,
    eligible: UInt16,
    observedAt: UInt64,
    admissionMode: BarnardAdoptionAdmissionMode = .open,
    credentialAuthorityKey: Int,
    censusAuthorityKey: Int = 2,
    windowIndex: UInt64? = nil
  ) throws -> BarnardVerifiedCensusCandidate {
    let input = try candidateInput(
      vectors,
      qualified: qualified,
      eligible: eligible,
      observedAt: observedAt,
      admissionMode: admissionMode,
      credentialAuthorityKey: credentialAuthorityKey,
      censusAuthorityKey: censusAuthorityKey,
      windowIndex: windowIndex
    )
    return try BarnardVerifiedCensusCandidate.decodeAndBind(
      b005Bytes: input.b005Bytes,
      registryDefinition: input.registryDefinition,
      observedAtUnixSeconds: observedAt
    )
  }

  private func candidateInput(
    _ vectors: AdoptionCensusVectors,
    qualified: UInt16,
    eligible: UInt16,
    observedAt: UInt64,
    admissionMode: BarnardAdoptionAdmissionMode = .open,
    credentialAuthorityKey: Int,
    censusAuthorityKey: Int = 2,
    windowIndex: UInt64? = nil
  ) throws -> BoundCandidateInput {
    let credentialAuthority = try authorityKey(vectors, index: credentialAuthorityKey)
    let censusAuthority = try authorityKey(vectors, index: censusAuthorityKey)
    let displayName = try vectors.string("display_name")
    let unsignedCredential = try BarnardAdoptionCredential.UnsignedBody(
      admissionMode: admissionMode,
      eventId: BarnardCrypto.sha256(credentialAuthority.publicKey),
      b004AdoptionScopeHash: try vectors.bytes("b004_adoption_scope_hash"),
      displayNameHash: BarnardCrypto.sha256(Data(displayName.utf8)),
      validFromUnixSeconds: 0,
      validUntilUnixSeconds: 10_000,
      censusWindowSeconds: UInt32(try vectors.int("census_window_seconds"))
    )
    let credential = try BarnardAdoptionCredential.decode(
      BarnardAdoptionCredential.encodeSigned(
        unsignedBody: unsignedCredential,
        authorityPrivateKey: credentialAuthority.privateKey
      )
    )
    let census = try BarnardSignedWindowCensus.decode(
      BarnardSignedWindowCensus.encodeSigned(
        unsignedBody: try BarnardSignedWindowCensus.UnsignedBody(
          credentialId: credential.credentialId,
          windowIndex: windowIndex ?? (try vectors.uint64("census_window_index")),
          qualifiedVoterCount: qualified,
          eligibleVoterCount: eligible,
          countedSetMerkleRoot: try vectors.bytes("counted_set_merkle_root_v1")
        ),
        authorityPrivateKey: censusAuthority.privateKey
      )
    )
    let b005Bytes = try BarnardB005V2Codec.serialize(
      BarnardB005V2Payload(
        eventDisplayName: displayName,
        b004AdoptionScopeHash: try vectors.bytes("b004_adoption_scope_hash"),
        credential: credential,
        census: census
      )
    )
    let registryDefinition = BarnardRegistryEventDefinition(
      eventId: credential.unsignedBody.eventId,
      credentialId: credential.credentialId,
      b004AdoptionScopeHash: credential.unsignedBody.b004AdoptionScopeHash,
      displayNameHash: credential.unsignedBody.displayNameHash,
      validFromUnixSeconds: credential.unsignedBody.validFromUnixSeconds,
      validUntilUnixSeconds: credential.unsignedBody.validUntilUnixSeconds,
      admissionMode: credential.unsignedBody.admissionMode,
      censusDomainPolicy: try domainPolicy(vectors, authorityPublicKey: censusAuthority.publicKey)
    )
    return BoundCandidateInput(b005Bytes: b005Bytes, registryDefinition: registryDefinition)
  }

  private func authorityKey(
    _ vectors: AdoptionCensusVectors,
    index: Int
  ) throws -> (privateKey: Data, publicKey: Data) {
    switch index {
    case 1:
      return (
        try vectors.bytes("credential_authority_test_private_key"),
        try vectors.bytes("credential_authority_public_key")
      )
    case 2:
      return (
        try vectors.bytes("census_authority_test_private_key"),
        try vectors.bytes("census_authority_public_key")
      )
    default:
      fatalError("unsupported deterministic authority test key")
    }
  }

  private func b005V2(displayName: String, scopeHash: Data, credential: Data, census: Data) -> Data {
    var payload = Data([0x02])
    appendTlv(type: 0x01, value: Data(displayName.utf8), to: &payload)
    appendTlv(type: 0x02, value: scopeHash, to: &payload)
    appendTlv(type: 0x20, value: credential, to: &payload)
    appendTlv(type: 0x21, value: census, to: &payload)
    return payload
  }

  private func appendTlv(type: UInt8, value: Data, to payload: inout Data) {
    payload.append(type)
    payload.append(UInt8((value.count >> 8) & 0xff))
    payload.append(UInt8(value.count & 0xff))
    payload.append(value)
  }
}

private struct AdoptionCensusVectors {
  private let values: [String: String]

  static func load() throws -> AdoptionCensusVectors {
    var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0..<20 {
      let candidate = directory.appendingPathComponent("test-vectors/adoption-census-v1.txt")
      if FileManager.default.fileExists(atPath: candidate.path) {
        return try AdoptionCensusVectors(contents: String(contentsOf: candidate, encoding: .utf8))
      }
      let parent = directory.deletingLastPathComponent()
      if parent.path == directory.path { break }
      directory = parent
    }
    throw VectorError.missingFile
  }

  func string(_ key: String) throws -> String {
    guard let value = values[key] else { throw VectorError.missingKey(key) }
    return value
  }

  func bytes(_ key: String) throws -> Data {
    let value = try string(key)
    guard value.count.isMultiple(of: 2) else { throw VectorError.malformedHex(key) }
    var bytes = Data()
    var index = value.startIndex
    while index < value.endIndex {
      let next = value.index(index, offsetBy: 2)
      guard let byte = UInt8(value[index..<next], radix: 16) else {
        throw VectorError.malformedHex(key)
      }
      bytes.append(byte)
      index = next
    }
    return bytes
  }

  func int(_ key: String) throws -> Int {
    guard let value = Int(try string(key)) else { throw VectorError.malformedInteger(key) }
    return value
  }

  func uint16(_ key: String) throws -> UInt16 {
    guard let value = UInt16(try string(key)) else { throw VectorError.malformedInteger(key) }
    return value
  }

  func uint64(_ key: String) throws -> UInt64 {
    guard let value = UInt64(try string(key)) else { throw VectorError.malformedInteger(key) }
    return value
  }

  fileprivate init(contents: String) throws {
    var parsed: [String: String] = [:]
    for line in contents.split(separator: "\n", omittingEmptySubsequences: false) {
      guard !line.isEmpty, !line.hasPrefix("#") else { continue }
      guard let separator = line.firstIndex(of: "=") else { throw VectorError.malformedLine(String(line)) }
      let key = String(line[..<separator])
      guard !key.isEmpty, key.utf8.allSatisfy({
        (0x41...0x5a).contains($0) || (0x61...0x7a).contains($0)
          || (0x30...0x39).contains($0) || $0 == 0x5f
      }) else {
        throw VectorError.malformedLine(String(line))
      }
      guard parsed[key] == nil else { throw VectorError.malformedLine(String(line)) }
      parsed[key] = try Self.decodeValue(
        String(line[line.index(after: separator)...]),
        line: String(line)
      )
    }
    values = parsed
  }

  private static func decodeValue(_ rawValue: String, line: String) throws -> String {
    var decoded = ""
    var escaping = false
    for scalar in rawValue.unicodeScalars {
      if escaping {
        switch scalar.value {
        case 0x6e:
          decoded.append(contentsOf: "\n")
        case 0x5c:
          decoded.append(contentsOf: "\\")
        default:
          throw VectorError.malformedLine(line)
        }
        escaping = false
      } else if scalar.value == 0x5c {
        escaping = true
      } else {
        decoded.unicodeScalars.append(scalar)
      }
    }
    guard !escaping else { throw VectorError.malformedLine(line) }
    return decoded
  }

  private enum VectorError: Error {
    case missingFile
    case missingKey(String)
    case malformedHex(String)
    case malformedInteger(String)
    case malformedLine(String)
  }
}

private func hex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}
