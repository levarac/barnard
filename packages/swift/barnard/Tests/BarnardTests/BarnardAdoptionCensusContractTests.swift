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

    // A re-signature changes no unsigned byte and therefore cannot split the
    // TEK, signing, census, relay, or equivocation identity.
    let reissued = try BarnardAdoptionCredential.UnsignedBody.decode(unsignedCredential)
    XCTAssertEqual(reissued.credentialId, credential.credentialId)

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
      BarnardAdoptionKeyDerivation.deriveTek(
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
      censusDomainPolicy: domainPolicy(vectors)
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
      censusDomainPolicy: domainPolicy(vectors),
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
    XCTAssertNotEqual(legacyPayload.first, 0x02)
    XCTAssertNotEqual(legacyB004, try AdoptionCensusVectors.load().bytes("b004_adoption_scope_hash"))
  }

  func testRegistryGateAndCrossEventMajorityChooseOnlyAQualifiedOpenWinner() throws {
    let vectors = try AdoptionCensusVectors.load()
    let policy = domainPolicy(vectors)
    let winner = candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      eventMarker: 0x41
    )
    let runnerUp = candidate(
      vectors,
      qualified: 3,
      eligible: 7,
      observedAt: 1_545,
      eventMarker: 0x42
    )

    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [winner, runnerUp],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .autoAdopt(credentialId: winner.credentialId)
    )

    let selfCertifiedOnly = candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      eventMarker: 0x43,
      registryVerification: .unverified
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [selfCertifiedOnly],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.registryUnverified)
    )

    let gated = candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      eventMarker: 0x44,
      admissionMode: .gated
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [gated],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.gated)
    )

    let noMajority = candidate(
      vectors,
      qualified: 3,
      eligible: 6,
      observedAt: 1_540,
      eventMarker: 0x45
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [noMajority],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.noClearMajority)
    )

    let stale = candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_489,
      eventMarker: 0x46
    )
    XCTAssertEqual(
      BarnardAdoptionDecision.evaluate(
        candidates: [stale],
        domainPolicy: policy,
        nowUnixSeconds: 1_550
      ),
      .requiresChooser(.staleCandidate)
    )

    let wrongWindow = winner.withWindowIndex(winner.windowIndex + 1)
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
    let policy = domainPolicy(vectors)
    let active = candidate(vectors, qualified: 4, eligible: 7, observedAt: 1_540, eventMarker: 0x51)
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

    let otherAuthority = candidate(
      vectors,
      qualified: 4,
      eligible: 7,
      observedAt: 1_540,
      eventMarker: 0x52,
      authorityKeyHash: try vectors.bytes("authority_key_hash_conflict")
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

  func testRelayDedupUsesStableTupleAndReportsEquivocation() throws {
    let vectors = try AdoptionCensusVectors.load()
    let candidate = candidate(vectors, qualified: 4, eligible: 7, observedAt: 1_540, eventMarker: 0x61)
    let cache = BarnardCensusRelayCache(maximumActiveTuples: 32, maximumPayloadsPerConflict: 2)
    let original = Data(repeating: 0x61, count: try vectors.int("maximum_b005_v2_bytes"))
    let replayWithDifferentTransportMetadata = BarnardRelayObservation(
      candidate: candidate,
      exactB005Bytes: original,
      directGattPeerHandle: "ephemeral-a",
      observedRpi: Data(repeating: 0xa1, count: 16),
      rawObservationCount: 1,
      relayerCount: 1
    )
    XCTAssertEqual(cache.record(replayWithDifferentTransportMetadata), .acceptedForRelay)

    let duplicate = BarnardRelayObservation(
      candidate: candidate,
      exactB005Bytes: original,
      directGattPeerHandle: "ephemeral-b",
      observedRpi: Data(repeating: 0xb2, count: 16),
      rawObservationCount: 999,
      relayerCount: 999
    )
    XCTAssertEqual(cache.record(duplicate), .duplicate)

    let conflictingCandidate = candidate.withCounts(qualifiedVoterCount: 5, eligibleVoterCount: 7)
    let conflict = BarnardRelayObservation(
      candidate: conflictingCandidate,
      exactB005Bytes: Data(repeating: 0x62, count: try vectors.int("maximum_b005_v2_bytes")),
      directGattPeerHandle: "ephemeral-c",
      observedRpi: Data(repeating: 0xc3, count: 16),
      rawObservationCount: 2,
      relayerCount: 2
    )
    XCTAssertEqual(cache.record(conflict), .censusEquivocation)
    XCTAssertEqual(cache.relayDisposition(for: candidate.censusTuple), .blockedByEquivocation)
    XCTAssertEqual(cache.retainedPayloadCount(for: candidate.censusTuple), 2)
    cache.prune(expiredThroughWindow: candidate.windowIndex + 1)
    XCTAssertEqual(cache.relayDisposition(for: candidate.censusTuple), .expired)
  }

  func testSelfCheckRequiresVerifiedSameCredentialPeerWithoutCrossDeviceTEKResolution() throws {
    let vectors = try AdoptionCensusVectors.load()
    let local = candidate(vectors, qualified: 4, eligible: 7, observedAt: 1_540, eventMarker: 0x71)
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

  private func domainPolicy(_ vectors: AdoptionCensusVectors) -> BarnardCensusDomainPolicy {
    BarnardCensusDomainPolicy(
      censusDomainId: try! vectors.bytes("census_domain_id"),
      censusWindowSeconds: UInt32(try! vectors.int("census_window_seconds")),
      authorityPolicyEpoch: UInt32(try! vectors.int("census_authority_policy_epoch")),
      authorizedAuthorityKeyHash: try! vectors.bytes("authority_key_hash_primary"),
      minimumEligibleVoterCount: UInt16(try! vectors.int("minimum_eligible_voters")),
      minimumQualifiedVoterCount: UInt16(try! vectors.int("minimum_qualified_voters"))
    )
  }

  private func candidate(
    _ vectors: AdoptionCensusVectors,
    qualified: UInt16,
    eligible: UInt16,
    observedAt: UInt64,
    eventMarker: UInt8,
    admissionMode: BarnardAdoptionAdmissionMode = .open,
    registryVerification: BarnardRegistryVerification = .verified,
    authorityKeyHash: Data? = nil
  ) -> BarnardVerifiedCensusCandidate {
    BarnardVerifiedCensusCandidate(
      credentialId: try! vectors.bytes("credential_id"),
      eventId: Data(repeating: eventMarker, count: 32),
      admissionMode: admissionMode,
      censusDomainId: try! vectors.bytes("census_domain_id"),
      censusWindowSeconds: UInt32(try! vectors.int("census_window_seconds")),
      authorityPolicyEpoch: UInt32(try! vectors.int("census_authority_policy_epoch")),
      censusAuthorityKeyHash: authorityKeyHash ?? (try! vectors.bytes("authority_key_hash_primary")),
      windowIndex: try! vectors.uint64("census_window_index"),
      qualifiedVoterCount: qualified,
      eligibleVoterCount: eligible,
      observedAtUnixSeconds: observedAt,
      registryVerification: registryVerification
    )
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

  private init(contents: String) throws {
    var parsed: [String: String] = [:]
    for line in contents.split(separator: "\n", omittingEmptySubsequences: false) {
      guard !line.isEmpty, !line.hasPrefix("#") else { continue }
      guard let separator = line.firstIndex(of: "=") else { throw VectorError.malformedLine(String(line)) }
      let key = String(line[..<separator])
      guard key.utf8.allSatisfy({
        (0x41...0x5a).contains($0) || (0x61...0x7a).contains($0)
          || (0x30...0x39).contains($0) || $0 == 0x5f
      }) else {
        throw VectorError.malformedLine(String(line))
      }
      parsed[key] = String(line[line.index(after: separator)...])
    }
    values = parsed
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
