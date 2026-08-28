// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import org.levarac.barnard.BarnardCrypto.toHex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Contract-first RED coverage for Barnard issues #123 and #128.
 *
 * This test names the Kotlin protocol seam before production implementation
 * exists. Its fixed inputs are shared with Swift so eventual green coverage
 * checks canonical bytes and security behavior rather than Kotlin-only
 * self-consistency.
 */
class BarnardAdoptionCensusContractTest {
    @Test
    fun canonicalUnsignedCredentialAndCensus_useStableCredentialId() {
        val vectors = AdoptionCensusVectors.load()
        val unsignedCredential = vectors.bytes("credential_unsigned_body")
        val credential = BarnardAdoptionCredential.UnsignedBody.decode(unsignedCredential)

        assertArrayEquals(unsignedCredential, credential.canonicalBytes())
        assertEquals(vectors.string("credential_id"), credential.credentialId.toHex())

        // A re-signature changes no unsigned byte and therefore cannot split
        // TEK, signing, census, relay, or equivocation identity.
        val reissued = BarnardAdoptionCredential.UnsignedBody.decode(unsignedCredential)
        assertArrayEquals(credential.credentialId, reissued.credentialId)

        val rotated = BarnardAdoptionCredential.UnsignedBody.decode(
            vectors.bytes("rotated_credential_unsigned_body"),
        )
        assertEquals(vectors.string("rotated_credential_id"), rotated.credentialId.toHex())
        assertFalse(rotated.credentialId.contentEquals(credential.credentialId))

        val fullCredential = vectors.bytes("credential_full")
        val verifiedCredential = BarnardAdoptionCredential.decode(fullCredential)
        assertArrayEquals(fullCredential, verifiedCredential.canonicalBytes())
        assertArrayEquals(vectors.bytes("credential_authority_public_key"), verifiedCredential.authorityPublicKey)
        assertArrayEquals(
            fullCredential,
            BarnardAdoptionCredential.encodeSigned(
                credential,
                vectors.bytes("credential_authority_test_private_key"),
            ),
        )

        val highS = unsignedCredential + vectors.bytes("credential_signature_high_s")
        val highSError = assertThrows(BarnardAdoptionProtocolException::class.java) {
            BarnardAdoptionCredential.decode(highS)
        }
        assertEquals(BarnardAdoptionProtocolError.NON_CANONICAL_SIGNATURE, highSError.reason)

        val census = BarnardSignedWindowCensus.UnsignedBody(
            credentialId = credential.credentialId,
            windowIndex = vectors.ulong("census_window_index"),
            qualifiedVoterCount = vectors.ushort("qualified_voter_count"),
            eligibleVoterCount = vectors.ushort("eligible_voter_count"),
            countedSetMerkleRoot = vectors.bytes("counted_set_merkle_root_v1"),
        )
        assertArrayEquals(vectors.bytes("census_unsigned_body"), census.canonicalBytes())

        val fullCensus = vectors.bytes("census_full")
        val verifiedCensus = BarnardSignedWindowCensus.decode(fullCensus)
        assertArrayEquals(fullCensus, verifiedCensus.canonicalBytes())
        assertArrayEquals(vectors.bytes("census_authority_public_key"), verifiedCensus.authorityPublicKey)
        assertArrayEquals(
            fullCensus,
            BarnardSignedWindowCensus.encodeSigned(
                census,
                vectors.bytes("census_authority_test_private_key"),
            ),
        )

        val rootError = assertThrows(BarnardAdoptionProtocolException::class.java) {
            BarnardSignedWindowCensus.UnsignedBody(
                credentialId = credential.credentialId,
                windowIndex = vectors.ulong("census_window_index"),
                qualifiedVoterCount = vectors.ushort("qualified_voter_count"),
                eligibleVoterCount = vectors.ushort("eligible_voter_count"),
                countedSetMerkleRoot = vectors.bytes("counted_set_merkle_root_nonzero"),
            )
        }
        assertEquals(BarnardAdoptionProtocolError.NON_CANONICAL_MERKLE_ROOT, rootError.reason)

        val structurallyMaximalV2 = b005V2(
            displayName = "A".repeat(64),
            scopeHash = vectors.bytes("b004_adoption_scope_hash"),
            credential = unsignedCredential + ByteArray(65),
            census = census.canonicalBytes() + ByteArray(65),
        )
        assertEquals(vectors.int("maximum_b005_v2_bytes"), structurallyMaximalV2.size)
        val invalidCredentialError = assertThrows(BarnardAdoptionProtocolException::class.java) {
            BarnardB005V2Codec.decode(structurallyMaximalV2)
        }
        assertEquals(BarnardAdoptionProtocolError.INVALID_CREDENTIAL_SIGNATURE, invalidCredentialError.reason)

        val b005 = BarnardB005V2Codec.decode(vectors.bytes("b005_v2_positive"))
        assertEquals(vectors.string("display_name"), b005.eventDisplayName)
        assertArrayEquals(vectors.bytes("b005_v2_positive"), BarnardB005V2Codec.serialize(b005))
        assertArrayEquals(
            vectors.bytes("adoption_tek"),
            BarnardAdoptionKeyDerivation.deriveTek(
                vectors.bytes("adoption_device_secret"),
                verifiedCredential.credentialId,
            ),
        )
        assertArrayEquals(
            vectors.bytes("adoption_signing_public_key"),
            BarnardAdoptionKeyDerivation.deriveSigningPublicKey(
                vectors.bytes("adoption_device_secret"),
                verifiedCredential.credentialId,
            ),
        )

        val registryDefinition = BarnardRegistryEventDefinition(
            eventId = verifiedCredential.unsignedBody.eventId,
            credentialId = verifiedCredential.credentialId,
            b004AdoptionScopeHash = verifiedCredential.unsignedBody.b004AdoptionScopeHash,
            displayNameHash = verifiedCredential.unsignedBody.displayNameHash,
            validFromUnixSeconds = verifiedCredential.unsignedBody.validFromUnixSeconds,
            validUntilUnixSeconds = verifiedCredential.unsignedBody.validUntilUnixSeconds,
            admissionMode = verifiedCredential.unsignedBody.admissionMode,
            censusDomainPolicy = domainPolicy(vectors),
        )
        assertEquals(
            BarnardRegistryVerification.VERIFIED,
            registryDefinition.verify(
                verifiedCredential,
                verifiedCensus,
                verifiedCredential.unsignedBody.validFromUnixSeconds + 1uL,
            ),
        )

        val selfReferentialRotation = BarnardRegistryEventDefinition(
            eventId = verifiedCredential.unsignedBody.eventId,
            credentialId = verifiedCredential.credentialId,
            b004AdoptionScopeHash = verifiedCredential.unsignedBody.b004AdoptionScopeHash,
            displayNameHash = verifiedCredential.unsignedBody.displayNameHash,
            validFromUnixSeconds = verifiedCredential.unsignedBody.validFromUnixSeconds,
            validUntilUnixSeconds = verifiedCredential.unsignedBody.validUntilUnixSeconds,
            admissionMode = verifiedCredential.unsignedBody.admissionMode,
            censusDomainPolicy = domainPolicy(vectors),
            replacesCredentialId = verifiedCredential.credentialId,
            effectiveWindowIndex = 6uL,
        )
        assertEquals(
            BarnardRegistryVerification.UNVERIFIED,
            selfReferentialRotation.verify(
                verifiedCredential,
                verifiedCensus,
                verifiedCredential.unsignedBody.validFromUnixSeconds + 1uL,
            ),
        )
    }

    @Test
    fun legacyV1B005AndEventCodeB004_remainLegacyOnly() {
        val legacyCode = "LEGACY-123"
        val legacyB004 = BarnardCrypto.computeEventCodeHash(legacyCode)
        val legacyPayload = BarnardEventInfoCodec.serialize(
            legacyCode,
            "Legacy Event",
            legacyB004,
        )

        val parsed = BarnardEventInfoCodec.parse(legacyPayload)
        assertEquals("Legacy Event", parsed.eventDisplayName)
        assertArrayEquals(legacyB004, parsed.eventCodeHash)
        assertEquals(0x01, legacyPayload[0].toInt() and 0xff)
        assertFalse(legacyB004.contentEquals(AdoptionCensusVectors.load().bytes("b004_adoption_scope_hash")))
    }

    @Test
    fun registryGateAndCrossEventMajority_chooseOnlyQualifiedOpenWinner() {
        val vectors = AdoptionCensusVectors.load()
        val policy = domainPolicy(vectors)
        val winner = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val runnerUp = candidate(
            vectors,
            qualified = 3u,
            eligible = 7u,
            observedAt = 1_545u,
            credentialAuthorityKey = 2,
        )

        val winnerDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(winner, runnerUp),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertTrue(winnerDecision is BarnardAdoptionDecisionResult.AutoAdopt)
        assertArrayEquals(winner.credentialId, (winnerDecision as BarnardAdoptionDecisionResult.AutoAdopt).credentialId)

        val unbound = candidateInput(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val definition = unbound.registryDefinition
        val mismatchedDefinition = BarnardRegistryEventDefinition(
            eventId = ByteArray(32),
            credentialId = definition.credentialId,
            b004AdoptionScopeHash = definition.b004AdoptionScopeHash,
            displayNameHash = definition.displayNameHash,
            validFromUnixSeconds = definition.validFromUnixSeconds,
            validUntilUnixSeconds = definition.validUntilUnixSeconds,
            admissionMode = definition.admissionMode,
            censusDomainPolicy = definition.censusDomainPolicy,
        )
        assertThrows(BarnardAdoptionProtocolException::class.java) {
            BarnardVerifiedCensusCandidate.decodeAndBind(
                b005Bytes = unbound.b005Bytes,
                registryDefinition = mismatchedDefinition,
                observedAtUnixSeconds = 1_540uL,
            )
        }

        val gated = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
            admissionMode = BarnardAdoptionAdmissionMode.GATED,
        )
        val gatedDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(gated),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.GATED,
            (gatedDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )

        val noMajority = candidate(
            vectors,
            qualified = 3u,
            eligible = 6u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val noMajorityDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(noMajority),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.NO_CLEAR_MAJORITY,
            (noMajorityDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )

        val stale = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_489u,
            credentialAuthorityKey = 1,
        )
        val staleDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(stale),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.STALE_CANDIDATE,
            (staleDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )

        val wrongWindow = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
            windowIndex = winner.windowIndex + 1uL,
        )
        val wrongWindowDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(wrongWindow),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.WRONG_CENSUS_WINDOW,
            (wrongWindowDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )
    }

    @Test
    fun rotationAndDomainAuthorityConflicts_failClosed() {
        val vectors = AdoptionCensusVectors.load()
        val policy = domainPolicy(vectors)
        val active = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val rotatedId = vectors.bytes("rotated_credential_id")

        assertEquals(
            BarnardCredentialRotationResult.CREDENTIAL_ROTATION_INCONSISTENCY,
            BarnardCredentialRotation.validate(
                activeCredentialId = active.credentialId,
                replacementCredentialId = rotatedId,
                replacesCredentialId = null,
                activeWindowIndex = active.windowIndex,
                effectiveWindowIndex = active.windowIndex,
            ),
        )
        assertEquals(
            BarnardCredentialRotationResult.VALID_BOUNDARY_REPLACEMENT,
            BarnardCredentialRotation.validate(
                activeCredentialId = active.credentialId,
                replacementCredentialId = rotatedId,
                replacesCredentialId = active.credentialId,
                activeWindowIndex = active.windowIndex,
                effectiveWindowIndex = active.windowIndex + 1uL,
            ),
        )

        val otherAuthority = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 2,
            censusAuthorityKey = 1,
        )
        assertEquals(
            BarnardAdoptionDecisionResult.DOMAIN_AUTHORITY_INCONSISTENCY,
            BarnardAdoptionDecision.evaluate(
                candidates = listOf(active, otherAuthority),
                domainPolicy = policy,
                nowUnixSeconds = 1_550uL,
            ),
        )
    }

    @Test
    fun verifiedCandidateFactory_preservesSignedCountsAndRejectsUnboundBytes() {
        val vectors = AdoptionCensusVectors.load()
        val policy = domainPolicy(vectors)
        val signedZero = candidate(
            vectors,
            qualified = 0u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )

        assertEquals(0u.toUShort(), signedZero.qualifiedVoterCount)
        assertEquals(7u.toUShort(), signedZero.eligibleVoterCount)
        val zeroDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(signedZero),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.NO_CLEAR_MAJORITY,
            (zeroDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )

        val bound = candidateInput(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val tampered = bound.b005Bytes.copyOf().also { bytes ->
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
        }
        assertThrows(BarnardAdoptionProtocolException::class.java) {
            BarnardVerifiedCensusCandidate.decodeAndBind(
                b005Bytes = tampered,
                registryDefinition = bound.registryDefinition,
                observedAtUnixSeconds = 1_540uL,
            )
        }
    }

    @Test
    fun relayCache_usesBoundArtifactsExpiryWatermarkAndTwoPayloadHardCap() {
        val vectors = AdoptionCensusVectors.load()
        val first = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val conflict = candidate(
            vectors,
            qualified = 5u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val thirdPayload = candidate(
            vectors,
            qualified = 6u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val conflictCache = BarnardCensusRelayCache(maximumActiveTuples = 4, maximumPayloadsPerConflict = 99)
        assertEquals(BarnardRelayCacheResult.ACCEPTED_FOR_RELAY, conflictCache.record(first))
        assertEquals(BarnardRelayCacheResult.DUPLICATE, conflictCache.record(first))
        assertEquals(BarnardRelayCacheResult.CENSUS_EQUIVOCATION, conflictCache.record(conflict))
        assertEquals(BarnardRelayCacheResult.CENSUS_EQUIVOCATION, conflictCache.record(thirdPayload))
        assertEquals(BarnardRelayDisposition.BLOCKED_BY_EQUIVOCATION, conflictCache.relayDisposition(first.censusTuple))
        assertEquals(2, conflictCache.retainedPayloadCount(first.censusTuple))

        val replayCache = BarnardCensusRelayCache(maximumActiveTuples = 1, maximumPayloadsPerConflict = 99)
        val laterWindow = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_840u,
            credentialAuthorityKey = 1,
            windowIndex = first.windowIndex + 1uL,
        )
        assertEquals(BarnardRelayCacheResult.ACCEPTED_FOR_RELAY, replayCache.record(first))
        replayCache.prune(expiredThroughWindow = first.windowIndex + 1uL)
        assertEquals(BarnardRelayCacheResult.ACCEPTED_FOR_RELAY, replayCache.record(laterWindow))
        replayCache.prune(expiredThroughWindow = laterWindow.windowIndex + 1uL)
        assertEquals(BarnardRelayCacheResult.EXPIRED, replayCache.record(first))
    }

    @Test
    fun b005_rejectsC1UnicodeControlInDisplayName() {
        val vectors = AdoptionCensusVectors.load()
        val malformed = b005V2(
            displayName = "Barnard\u0085Tap",
            scopeHash = vectors.bytes("b004_adoption_scope_hash"),
            credential = vectors.bytes("credential_full"),
            census = vectors.bytes("census_full"),
        )
        val error = assertThrows(BarnardAdoptionProtocolException::class.java) {
            BarnardB005V2Codec.decode(malformed)
        }
        assertEquals(BarnardAdoptionProtocolError.INVALID_DISPLAY_NAME, error.reason)
    }

    @Test
    fun vectorParser_decodesEscapesAndRejectsDuplicateKeys() {
        assertEquals("first\nsecond\\tail", parseVectorText("value=first\\nsecond\\\\tail\n").getValue("value"))
        assertThrows(IllegalArgumentException::class.java) {
            parseVectorText("same=one\nsame=two\n")
        }
        assertThrows(IllegalArgumentException::class.java) {
            parseVectorText("value=bad\\q\n")
        }
    }

    @Test
    fun selfCheckRequiresVerifiedSameCredentialPeer_withoutCrossDeviceTekResolution() {
        val vectors = AdoptionCensusVectors.load()
        val local = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            credentialAuthorityKey = 1,
        )
        val tracker = BarnardAutoAdoptionSelfCheck(
            credentialId = local.credentialId,
            b004AdoptionScopeHash = vectors.bytes("b004_adoption_scope_hash"),
            requiredCompleteWindows = vectors.int("self_check_complete_windows"),
        )

        // The API deliberately receives no local TEK. B002 is only a
        // supported-format 17-byte opaque value on the same GATT session.
        val validPeer = BarnardDirectGattPeerObservation(
            ephemeralPeerHandle = "session-peer-1",
            b004Value = vectors.bytes("b004_adoption_scope_hash"),
            b002Value = vectors.bytes("valid_peer_b002"),
            verifiedB005CredentialId = local.credentialId,
            registryVerification = BarnardRegistryVerification.VERIFIED,
        )
        assertEquals(BarnardSelfCheckObservationResult.PEER_CONFIRMED, tracker.observe(validPeer, local.windowIndex + 1uL))

        val invalidPeer = BarnardDirectGattPeerObservation(
            ephemeralPeerHandle = "session-peer-2",
            b004Value = vectors.bytes("b004_adoption_scope_hash"),
            b002Value = vectors.bytes("malformed_peer_b002"),
            verifiedB005CredentialId = local.credentialId,
            registryVerification = BarnardRegistryVerification.VERIFIED,
        )
        assertEquals(BarnardSelfCheckObservationResult.IGNORED, tracker.observe(invalidPeer, local.windowIndex + 2uL))

        val wrongCredentialPeer = BarnardDirectGattPeerObservation(
            ephemeralPeerHandle = "session-peer-3",
            b004Value = vectors.bytes("b004_adoption_scope_hash"),
            b002Value = vectors.bytes("valid_peer_b002"),
            verifiedB005CredentialId = vectors.bytes("rotated_credential_id"),
            registryVerification = BarnardRegistryVerification.VERIFIED,
        )
        assertEquals(BarnardSelfCheckObservationResult.IGNORED, tracker.observe(wrongCredentialPeer, local.windowIndex + 2uL))

        val unverifiedPeer = BarnardDirectGattPeerObservation(
            ephemeralPeerHandle = "session-peer-4",
            b004Value = vectors.bytes("b004_adoption_scope_hash"),
            b002Value = vectors.bytes("valid_peer_b002"),
            verifiedB005CredentialId = local.credentialId,
            registryVerification = BarnardRegistryVerification.UNVERIFIED,
        )
        assertEquals(BarnardSelfCheckObservationResult.IGNORED, tracker.observe(unverifiedPeer, local.windowIndex + 2uL))

        val noPeerTracker = BarnardAutoAdoptionSelfCheck(
            credentialId = local.credentialId,
            b004AdoptionScopeHash = vectors.bytes("b004_adoption_scope_hash"),
            requiredCompleteWindows = vectors.int("self_check_complete_windows"),
        )
        assertEquals(BarnardSelfCheckWindowResult.CONTINUE_CHECKING, noPeerTracker.completeWindow(local.windowIndex + 1uL))
        assertEquals(BarnardSelfCheckWindowResult.CONTINUE_CHECKING, noPeerTracker.completeWindow(local.windowIndex + 2uL))
        assertEquals(BarnardSelfCheckWindowResult.PRESENT_SWITCH_PROMPT, noPeerTracker.completeWindow(local.windowIndex + 3uL))
    }

    private fun domainPolicy(
        vectors: AdoptionCensusVectors,
        authorityPublicKey: ByteArray? = null,
    ): BarnardCensusDomainPolicy =
        BarnardCensusDomainPolicy(
            censusDomainId = vectors.bytes("census_domain_id"),
            censusWindowSeconds = vectors.int("census_window_seconds").toUInt(),
            authorityPolicyEpoch = vectors.int("census_authority_policy_epoch").toUInt(),
            authorizedAuthorityKeyHash = sha256(
                authorityPublicKey ?: vectors.bytes("census_authority_public_key"),
            ),
            minimumEligibleVoterCount = vectors.int("minimum_eligible_voters").toUShort(),
            minimumQualifiedVoterCount = vectors.int("minimum_qualified_voters").toUShort(),
        )

    private data class BoundCandidateInput(
        val b005Bytes: ByteArray,
        val registryDefinition: BarnardRegistryEventDefinition,
    )

    private data class AuthorityKey(
        val privateKey: ByteArray,
        val publicKey: ByteArray,
    )

    private fun candidate(
        vectors: AdoptionCensusVectors,
        qualified: UInt,
        eligible: UInt,
        observedAt: UInt,
        admissionMode: BarnardAdoptionAdmissionMode = BarnardAdoptionAdmissionMode.OPEN,
        credentialAuthorityKey: Int,
        censusAuthorityKey: Int = 2,
        windowIndex: ULong? = null,
    ): BarnardVerifiedCensusCandidate {
        val input = candidateInput(
            vectors = vectors,
            qualified = qualified,
            eligible = eligible,
            observedAt = observedAt,
            admissionMode = admissionMode,
            credentialAuthorityKey = credentialAuthorityKey,
            censusAuthorityKey = censusAuthorityKey,
            windowIndex = windowIndex,
        )
        return BarnardVerifiedCensusCandidate.decodeAndBind(
            b005Bytes = input.b005Bytes,
            registryDefinition = input.registryDefinition,
            observedAtUnixSeconds = observedAt.toULong(),
        )
    }

    private fun candidateInput(
        vectors: AdoptionCensusVectors,
        qualified: UInt,
        eligible: UInt,
        observedAt: UInt,
        admissionMode: BarnardAdoptionAdmissionMode = BarnardAdoptionAdmissionMode.OPEN,
        credentialAuthorityKey: Int,
        censusAuthorityKey: Int = 2,
        windowIndex: ULong? = null,
    ): BoundCandidateInput {
        val credentialAuthority = authorityKey(vectors, credentialAuthorityKey)
        val censusAuthority = authorityKey(vectors, censusAuthorityKey)
        val displayName = vectors.string("display_name")
        val unsignedCredential = BarnardAdoptionCredential.UnsignedBody(
            admissionMode = admissionMode,
            eventId = sha256(credentialAuthority.publicKey),
            b004AdoptionScopeHash = vectors.bytes("b004_adoption_scope_hash"),
            displayNameHash = sha256(displayName.toByteArray(Charsets.UTF_8)),
            validFromUnixSeconds = 0uL,
            validUntilUnixSeconds = 10_000uL,
            censusWindowSeconds = vectors.int("census_window_seconds").toUInt(),
        )
        val credential = BarnardAdoptionCredential.decode(
            BarnardAdoptionCredential.encodeSigned(unsignedCredential, credentialAuthority.privateKey),
        )
        val census = BarnardSignedWindowCensus.decode(
            BarnardSignedWindowCensus.encodeSigned(
                BarnardSignedWindowCensus.UnsignedBody(
                    credentialId = credential.credentialId,
                    windowIndex = windowIndex ?: vectors.ulong("census_window_index"),
                    qualifiedVoterCount = qualified.toUShort(),
                    eligibleVoterCount = eligible.toUShort(),
                    countedSetMerkleRoot = vectors.bytes("counted_set_merkle_root_v1"),
                ),
                censusAuthority.privateKey,
            ),
        )
        val b005Bytes = BarnardB005V2Codec.serialize(
            BarnardB005V2Payload(
                eventDisplayName = displayName,
                b004AdoptionScopeHash = vectors.bytes("b004_adoption_scope_hash"),
                credential = credential,
                census = census,
            ),
        )
        val registryDefinition = BarnardRegistryEventDefinition(
            eventId = credential.unsignedBody.eventId,
            credentialId = credential.credentialId,
            b004AdoptionScopeHash = credential.unsignedBody.b004AdoptionScopeHash,
            displayNameHash = credential.unsignedBody.displayNameHash,
            validFromUnixSeconds = credential.unsignedBody.validFromUnixSeconds,
            validUntilUnixSeconds = credential.unsignedBody.validUntilUnixSeconds,
            admissionMode = credential.unsignedBody.admissionMode,
            censusDomainPolicy = domainPolicy(vectors, censusAuthority.publicKey),
        )
        return BoundCandidateInput(b005Bytes, registryDefinition)
    }

    private fun authorityKey(vectors: AdoptionCensusVectors, index: Int): AuthorityKey =
        when (index) {
            1 -> AuthorityKey(
                vectors.bytes("credential_authority_test_private_key"),
                vectors.bytes("credential_authority_public_key"),
            )
            2 -> AuthorityKey(
                vectors.bytes("census_authority_test_private_key"),
                vectors.bytes("census_authority_public_key"),
            )
            else -> error("unsupported deterministic authority test key")
        }

    private fun sha256(value: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value)

    private fun parseVectorText(contents: String): Map<String, String> {
        val file = File.createTempFile("barnard-adoption-census-", ".txt")
        return try {
            file.writeText(contents, Charsets.UTF_8)
            AdoptionCensusVectors.parse(file)
        } finally {
            file.delete()
        }
    }

    private fun b005V2(
        displayName: String,
        scopeHash: ByteArray,
        credential: ByteArray,
        census: ByteArray,
    ): ByteArray = ByteArrayOutputStream().use { output ->
        output.write(0x02)
        appendTlv(output, 0x01, displayName.toByteArray(Charsets.UTF_8))
        appendTlv(output, 0x02, scopeHash)
        appendTlv(output, 0x20, credential)
        appendTlv(output, 0x21, census)
        output.toByteArray()
    }

    private fun appendTlv(output: ByteArrayOutputStream, type: Int, value: ByteArray) {
        output.write(type)
        output.write((value.size ushr 8) and 0xff)
        output.write(value.size and 0xff)
        output.write(value)
    }
}

private class AdoptionCensusVectors private constructor(private val values: Map<String, String>) {
    companion object {
        fun load(): AdoptionCensusVectors {
            var directory: File? = File(System.getProperty("user.dir")).absoluteFile
            repeat(20) {
                val current = directory ?: error("could not locate test-vectors/adoption-census-v1.txt")
                val fixture = File(current, "test-vectors/adoption-census-v1.txt")
                if (fixture.isFile) return AdoptionCensusVectors(parse(fixture))
                directory = current.parentFile
            }
            error("could not locate test-vectors/adoption-census-v1.txt")
        }

        fun parse(file: File): Map<String, String> {
            val result = linkedMapOf<String, String>()
            val keyPattern = Regex("[A-Za-z0-9_]+")
            file.readLines(Charsets.UTF_8).forEach { line ->
                if (line.isEmpty() || line.startsWith("#")) return@forEach
                val separator = line.indexOf('=')
                require(separator > 0) { "malformed vector line: $line" }
                val key = line.substring(0, separator)
                require(keyPattern.matches(key)) { "malformed vector key: $key" }
                require(key !in result) { "duplicate vector key: $key" }
                result[key] = decodeValue(line.substring(separator + 1), line)
            }
            return result
        }

        private fun decodeValue(rawValue: String, line: String): String {
            val decoded = StringBuilder()
            var escaping = false
            rawValue.forEach { character ->
                if (escaping) {
                    when (character) {
                        'n' -> decoded.append('\n')
                        '\\' -> decoded.append('\\')
                        else -> throw IllegalArgumentException("malformed vector escape: $line")
                    }
                    escaping = false
                } else if (character == '\\') {
                    escaping = true
                } else {
                    decoded.append(character)
                }
            }
            require(!escaping) { "malformed vector escape: $line" }
            return decoded.toString()
        }
    }

    fun string(key: String): String = values[key] ?: error("missing vector key: $key")

    fun bytes(key: String): ByteArray {
        val value = string(key)
        require(value.length % 2 == 0) { "odd-length hex vector: $key" }
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    fun int(key: String): Int = string(key).toInt()
    fun ushort(key: String): UShort = string(key).toUShort()
    fun ulong(key: String): ULong = string(key).toULong()
}
