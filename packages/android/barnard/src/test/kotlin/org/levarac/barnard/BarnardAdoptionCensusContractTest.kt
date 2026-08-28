// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.io.ByteArrayOutputStream
import java.io.File
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
        val winner = candidate(vectors, qualified = 4u, eligible = 7u, observedAt = 1_540u, eventMarker = 0x41)
        val runnerUp = candidate(vectors, qualified = 3u, eligible = 7u, observedAt = 1_545u, eventMarker = 0x42)

        val winnerDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(winner, runnerUp),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertTrue(winnerDecision is BarnardAdoptionDecisionResult.AutoAdopt)
        assertArrayEquals(winner.credentialId, (winnerDecision as BarnardAdoptionDecisionResult.AutoAdopt).credentialId)

        val selfCertifiedOnly = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            eventMarker = 0x43,
            registryVerification = BarnardRegistryVerification.UNVERIFIED,
        )
        val unverifiedDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(selfCertifiedOnly),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.REGISTRY_UNVERIFIED,
            (unverifiedDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )

        val gated = candidate(
            vectors,
            qualified = 4u,
            eligible = 7u,
            observedAt = 1_540u,
            eventMarker = 0x44,
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

        val noMajority = candidate(vectors, qualified = 3u, eligible = 6u, observedAt = 1_540u, eventMarker = 0x45)
        val noMajorityDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(noMajority),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.NO_CLEAR_MAJORITY,
            (noMajorityDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )

        val stale = candidate(vectors, qualified = 4u, eligible = 7u, observedAt = 1_489u, eventMarker = 0x46)
        val staleDecision = BarnardAdoptionDecision.evaluate(
            candidates = listOf(stale),
            domainPolicy = policy,
            nowUnixSeconds = 1_550uL,
        )
        assertEquals(
            BarnardAdoptionFallbackReason.STALE_CANDIDATE,
            (staleDecision as BarnardAdoptionDecisionResult.RequiresChooser).reason,
        )

        val wrongWindow = winner.withWindowIndex(winner.windowIndex + 1uL)
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
        val active = candidate(vectors, qualified = 4u, eligible = 7u, observedAt = 1_540u, eventMarker = 0x51)
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
            eventMarker = 0x52,
            authorityKeyHash = vectors.bytes("authority_key_hash_conflict"),
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
    fun relayDedupUsesStableTuple_andReportsEquivocation() {
        val vectors = AdoptionCensusVectors.load()
        val candidate = candidate(vectors, qualified = 4u, eligible = 7u, observedAt = 1_540u, eventMarker = 0x61)
        val cache = BarnardCensusRelayCache(maximumActiveTuples = 32, maximumPayloadsPerConflict = 2)
        val original = ByteArray(vectors.int("maximum_b005_v2_bytes")) { 0x61 }
        val first = BarnardRelayObservation(
            candidate = candidate,
            exactB005Bytes = original,
            directGattPeerHandle = "ephemeral-a",
            observedRpi = ByteArray(16) { 0xa1.toByte() },
            rawObservationCount = 1,
            relayerCount = 1,
        )
        assertEquals(BarnardRelayCacheResult.ACCEPTED_FOR_RELAY, cache.record(first))

        val duplicate = BarnardRelayObservation(
            candidate = candidate,
            exactB005Bytes = original,
            directGattPeerHandle = "ephemeral-b",
            observedRpi = ByteArray(16) { 0xb2.toByte() },
            rawObservationCount = 999,
            relayerCount = 999,
        )
        assertEquals(BarnardRelayCacheResult.DUPLICATE, cache.record(duplicate))

        val conflict = BarnardRelayObservation(
            candidate = candidate.withCounts(
                qualifiedVoterCount = 5u.toUShort(),
                eligibleVoterCount = 7u.toUShort(),
            ),
            exactB005Bytes = ByteArray(vectors.int("maximum_b005_v2_bytes")) { 0x62 },
            directGattPeerHandle = "ephemeral-c",
            observedRpi = ByteArray(16) { 0xc3.toByte() },
            rawObservationCount = 2,
            relayerCount = 2,
        )
        assertEquals(BarnardRelayCacheResult.CENSUS_EQUIVOCATION, cache.record(conflict))
        assertEquals(BarnardRelayDisposition.BLOCKED_BY_EQUIVOCATION, cache.relayDisposition(candidate.censusTuple))
        assertEquals(2, cache.retainedPayloadCount(candidate.censusTuple))
        cache.prune(expiredThroughWindow = candidate.windowIndex + 1uL)
        assertEquals(BarnardRelayDisposition.EXPIRED, cache.relayDisposition(candidate.censusTuple))
    }

    @Test
    fun selfCheckRequiresVerifiedSameCredentialPeer_withoutCrossDeviceTekResolution() {
        val vectors = AdoptionCensusVectors.load()
        val local = candidate(vectors, qualified = 4u, eligible = 7u, observedAt = 1_540u, eventMarker = 0x71)
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

    private fun domainPolicy(vectors: AdoptionCensusVectors): BarnardCensusDomainPolicy =
        BarnardCensusDomainPolicy(
            censusDomainId = vectors.bytes("census_domain_id"),
            censusWindowSeconds = vectors.int("census_window_seconds").toUInt(),
            authorityPolicyEpoch = vectors.int("census_authority_policy_epoch").toUInt(),
            authorizedAuthorityKeyHash = vectors.bytes("authority_key_hash_primary"),
            minimumEligibleVoterCount = vectors.int("minimum_eligible_voters").toUShort(),
            minimumQualifiedVoterCount = vectors.int("minimum_qualified_voters").toUShort(),
        )

    private fun candidate(
        vectors: AdoptionCensusVectors,
        qualified: UInt,
        eligible: UInt,
        observedAt: UInt,
        eventMarker: Int,
        admissionMode: BarnardAdoptionAdmissionMode = BarnardAdoptionAdmissionMode.OPEN,
        registryVerification: BarnardRegistryVerification = BarnardRegistryVerification.VERIFIED,
        authorityKeyHash: ByteArray? = null,
    ): BarnardVerifiedCensusCandidate =
        BarnardVerifiedCensusCandidate(
            credentialId = vectors.bytes("credential_id"),
            eventId = ByteArray(32) { eventMarker.toByte() },
            admissionMode = admissionMode,
            censusDomainId = vectors.bytes("census_domain_id"),
            censusWindowSeconds = vectors.int("census_window_seconds").toUInt(),
            authorityPolicyEpoch = vectors.int("census_authority_policy_epoch").toUInt(),
            censusAuthorityKeyHash = authorityKeyHash ?: vectors.bytes("authority_key_hash_primary"),
            windowIndex = vectors.ulong("census_window_index"),
            qualifiedVoterCount = qualified.toUShort(),
            eligibleVoterCount = eligible.toUShort(),
            observedAtUnixSeconds = observedAt.toULong(),
            registryVerification = registryVerification,
        )

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

        private fun parse(file: File): Map<String, String> {
            val result = linkedMapOf<String, String>()
            val keyPattern = Regex("[A-Za-z0-9_]+")
            file.readLines(Charsets.UTF_8).forEach { line ->
                if (line.isEmpty() || line.startsWith("#")) return@forEach
                val separator = line.indexOf('=')
                require(separator > 0) { "malformed vector line: $line" }
                val key = line.substring(0, separator)
                require(keyPattern.matches(key)) { "malformed vector key: $key" }
                result[key] = line.substring(separator + 1)
            }
            return result
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
