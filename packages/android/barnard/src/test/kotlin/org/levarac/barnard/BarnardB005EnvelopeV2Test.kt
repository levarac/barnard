package org.levarac.barnard

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BarnardB005EnvelopeV2Test {
    private val vectors by lazy { parseVectors(File(findRepoRoot(), "test-vectors/b005-envelope-v2.txt")) }
    private val parallaxNegVectors by lazy { parseVectors(File(findRepoRoot(), "test-vectors/parallax-delegation-cert-v1.txt")) }
    private fun v(name: String) = vectors[name] ?: error("missing $name")
    @Test fun sharedVectorsAndBoundaries() {
        val key = hex(v("authority_public_key"))
        assertContentEquals(hex(v("event_key_set_bytes")), BarnardB005EnvelopeV2.eventKeySetBytes(listOf(key)))
        assertContentEquals(hex(v("event_key_set_digest")), BarnardB005EnvelopeV2.keySetDigest(listOf(key)))
        assertContentEquals(hex(v("event_id")), BarnardB005EnvelopeV2.computeEventId(hex(v("registrar")), hex(v("anchor_operator")), hex(v("nonce")), hex(v("event_key_set_digest"))))
        assertContentEquals(hex("6c86c6aac5fb24bc"), BarnardB005EnvelopeV2.openEventCodeHash(ByteArray(32) { it.toByte() }))
        val first = hex(v("v1_container")); val second = hex(v("v2_container"))
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.verify(first, 6_000_000)?.receiverState)
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.verify(second, 6_000_000)?.receiverState)
        assertNull(BarnardB005EnvelopeV2.verify(first, 5_999_989)); assertNotNull(BarnardB005EnvelopeV2.verify(first, 6_000_001)); assertNull(BarnardB005EnvelopeV2.verify(first, 6_000_002)); assertNull(BarnardB005EnvelopeV2.verify(first, null))
        for (i in 4 until first.size) { val m = first.copyOf(); m[i] = (m[i].toInt() xor 1).toByte(); assertNull(BarnardB005EnvelopeV2.verify(m, 6_000_000), "mutation $i") }
        for (i in 4 until second.size) { val m = second.copyOf(); m[i] = (m[i].toInt() xor 1).toByte(); assertNull(BarnardB005EnvelopeV2.verify(m, 6_000_000), "v2 mutation $i") }
    }

    @Test fun negativeCensusV2PayloadIsRejected() {
        val length = v("neg_census_v2_payload_length").toInt()
        val payload = hex(v("neg_census_v2_prefix")) + ByteArray(length - hex(v("neg_census_v2_prefix")).size)
        assertNull(BarnardB005EnvelopeV2.verify(payload, 6_000_000))
    }

    @Test fun displayNameRejectsInvalidUtf8WithoutThrowing() {
        val container = hex(v("v1_container"))
        // Name starts at container offset 4 (container header) + 1 (envelopeVersion) + 20 + 20 + 32 + 1 (n)
        // + 33*n (keys) + 25 (a offset into fixed window fields) = 136 for vector 1 (n = 1).
        val nameStart = 136
        container[nameStart] = 0xff.toByte() // invalid UTF-8 lead byte, same length as the original name
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000))
    }

    @Test fun displayNameRejectsNonNfcFormWithoutFalsePositive() {
        val container = hex(v("v1_container"))
        val nameStart = 136; val nameLength = 58
        // Decomposed Hangul jamo U+1100 U+1161 (6 bytes) normalizes under NFC to the single
        // precomposed syllable U+AC00 (3 bytes) -- neither codepoint falls in the U+0300-U+036F
        // combining-diacritic range the old ad-hoc check used, so this is a case the old check
        // would have wrongly accepted. The correct NFC check MUST reject it.
        val decomposedJamo = byteArrayOf(0xe1.toByte(), 0x84.toByte(), 0x80.toByte(), 0xe1.toByte(), 0x85.toByte(), 0xa1.toByte())
        val name = decomposedJamo + ByteArray(nameLength - decomposedJamo.size) { 'x'.code.toByte() }
        name.copyInto(container, nameStart)
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000))
    }

    @Test fun parallaxDelegationCertPositiveAndNegativeVectors() {
        val second = v("v2_container")
        val envelopeHex = v("v2_envelope")
        val oldCert = v("v2_delegation_cert")

        fun containerWithCert(certHex: String): ByteArray? {
            val idx = envelopeHex.indexOf(oldCert)
            if (idx < 0) return null
            val replacedHex = envelopeHex.substring(0, idx) + certHex + envelopeHex.substring(idx + oldCert.length)
            val envelope = hex(replacedHex)
            val certByteOffset = idx / 2
            envelope[certByteOffset - 1] = (certHex.length / 2).toByte()
            return BarnardB005EnvelopeV2.encodeContainer(1, envelope)
        }

        // Positive: the parallax bundle's positive fixture is byte-identical to vector 2's own cert.
        assertEquals(oldCert, parallaxNegVectors["pos_signed_delegation_cert"])
        assertNotNull(BarnardB005EnvelopeV2.verify(hex(second), 6_000_000))

        for (key in listOf("neg_inverted_window", "neg_zero_roles", "neg_unassigned_role", "neg_unknown_version",
            "neg_unknown_field", "neg_missing_window", "neg_wrong_event", "neg_foreign_signer", "neg_corrupt_signature")) {
            val certHex = parallaxNegVectors[key] ?: error("missing $key")
            val container = containerWithCert(certHex) ?: error("$key: could not build substitute container")
            assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000), key)
        }
    }

    @Test fun certContentTypeRejectsInvalidUtf8WithoutThrowing() {
        // Regression for the CborReader.text() call parsing the delegation cert's COSE
        // content-type header: an invalid UTF-8 lead byte there must fail closed (verify()
        // returns null), not escape as an unguarded CharacterCodingException.
        val envelopeHex = v("v2_envelope")
        val oldCert = v("v2_delegation_cert")
        val contentTypeHex = "6170706c69636174696f6e2f766e642e6c6576617261632e64656c65676174696f6e2d636572742b63626f72"
        val idxInCert = oldCert.indexOf(contentTypeHex)
        check(idxInCert >= 0)
        val corruptedCert = oldCert.substring(0, idxInCert) + "ff" + oldCert.substring(idxInCert + 2, oldCert.length)
        val idx = envelopeHex.indexOf(oldCert)
        val replacedHex = envelopeHex.substring(0, idx) + corruptedCert + envelopeHex.substring(idx + oldCert.length)
        val envelope = hex(replacedHex)
        val container = BarnardB005EnvelopeV2.encodeContainer(1, envelope) ?: error("could not build container")
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000))
    }

    @Test fun parallaxSubstitutedKeySetIsRejected() {
        // Spec 122's parallax negative list also names "substituted key set": swap the single
        // authority key embedded in vector 2's own envelope for Parallax's substitutedEventKeySetHex
        // key (same 33-byte compressed layout, same cert kept verbatim) so the cert's own eventId
        // no longer matches the eventId recomputed from the (now different) embedded key set.
        val originalKeyHex = v("authority_public_key")
        val substitutedKeyHex = parallaxNegVectors["neg_substituted_event_key"] ?: error("missing neg_substituted_event_key")
        val container = v("v2_container")
        assertEquals(1, container.split(originalKeyHex).size - 1, "expected exactly one occurrence of the authority key")
        val mutated = hex(container.replace(originalKeyHex, substitutedKeyHex))
        assertNull(BarnardB005EnvelopeV2.verify(mutated, 6_000_000))
    }

    // --- Registry agreement (pure comparison; this SDK never assigns REGISTRY_VERIFIED) ---

    @Test fun registryAgreementRequiresFullAgreement() {
        val container = hex(v("v1_container"))
        val verified = BarnardB005EnvelopeV2.verify(container, 6_000_000) ?: error("expected RADIO_SELF_VERIFIED baseline")
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, verified.receiverState)
        // The exact half-open ENIN window is [validFromEnin, validThroughEnin) (validThroughEnin
        // is already the exclusive end -- see registryAgreement's doc comment); an aligned
        // registry seconds window is exactly that range times eninSeconds.
        fun agreeing() = BarnardEventDefinitionV1(
            verified.eventId, verified.keySetDigest, verified.joinMode, verified.eventCodeHash,
            verified.validFromEnin * verified.eninSeconds, verified.validThroughEnin * verified.eninSeconds,
        )
        assertEquals(BarnardRegistryAgreement.Agrees, BarnardB005EnvelopeV2.registryAgreement(verified, agreeing()))

        val wrongEventId = agreeing().eventId.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.EVENT_ID)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(eventId = wrongEventId)), "eventId mismatch")

        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.JOIN_MODE)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(joinMode = if (verified.joinMode == 0) 1 else 0)), "joinMode mismatch")

        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(validFromUnixSeconds = verified.validThroughEnin * verified.eninSeconds)), "window mismatch")

        val wrongKeySetDigest = verified.keySetDigest.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.KEY_SET_DIGEST)), BarnardB005EnvelopeV2.registryAgreement(verified, agreeing().copy(keySetDigest = wrongKeySetDigest)), "signer-authority (keySetDigest) mismatch")
    }

    @Test fun registryAgreementRejectsMisalignedValidityWindowExample() {
        // eninSeconds=300, envelope declares the inclusive ENIN window [10, 11] (validFromEnin=10,
        // validThroughEnin=11 -- see registryAgreement's doc comment on the inclusive convention).
        // Registry inclusive-seconds window [3001, 3299]: ceil(3001/300)=11 for the start, mismatching
        // the envelope's declared validFromEnin=10 -- rejected.
        val misaligned = synthesizeWindow(eninSeconds = 300, validFromEnin = 10, validThroughEnin = 11)
        val registryDefinition = BarnardEventDefinitionV1(
            misaligned.eventId, misaligned.keySetDigest, misaligned.joinMode, misaligned.eventCodeHash,
            validFromUnixSeconds = 3001, validUntilUnixSeconds = 3299,
        )
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(misaligned, registryDefinition), "misaligned window must not agree")

        // Aligned: registry inclusive [3000, 3299] exactly matches the inclusive ENIN [10, 11] range -- accepted.
        val aligned = BarnardEventDefinitionV1(
            misaligned.eventId, misaligned.keySetDigest, misaligned.joinMode, misaligned.eventCodeHash,
            validFromUnixSeconds = 3000, validUntilUnixSeconds = 3299,
        )
        assertEquals(BarnardRegistryAgreement.Agrees, BarnardB005EnvelopeV2.registryAgreement(misaligned, aligned), "aligned window must agree")

        // Off-by-one ENIN at both ends of the aligned registry window must still be rejected.
        val startOffByOne = aligned.copy(validFromUnixSeconds = 2700)
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(misaligned, startOffByOne), "start off-by-one must not agree")
        val endOffByOne = aligned.copy(validUntilUnixSeconds = 3599)
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(misaligned, endOffByOne), "end off-by-one must not agree")
    }

    @Test fun registryAgreementEndConversionIsOverflowSafeAtLongMaxValue() {
        // eninPerSecond=1 makes floorMod(Long.MAX_VALUE, 1)==0==eninPerSecond-1, which is exactly
        // the branch that would try to compute Long.MAX_VALUE + 1 (overflowing to Long.MIN_VALUE)
        // without the floorMod-identity guard in registryAgreement. Must not throw or wrap to a
        // negative "registryEndEnin" that could spuriously agree with a small validThroughEnin.
        val envelope = synthesizeWindow(eninSeconds = 1, validFromEnin = 10, validThroughEnin = 11)
        val definition = BarnardEventDefinitionV1(
            envelope.eventId, envelope.keySetDigest, envelope.joinMode, envelope.eventCodeHash,
            validFromUnixSeconds = 10, validUntilUnixSeconds = Long.MAX_VALUE,
        )
        assertEquals(BarnardRegistryAgreement.Mismatched(setOf(BarnardRegistryMismatchField.VALIDITY_WINDOW)), BarnardB005EnvelopeV2.registryAgreement(envelope, definition), "must not overflow into a spurious agreement")
    }

    @Test fun verifiedEnvelopeHasNoPublicConstructorOrCopy() {
        // P1: a `data class` would generate a public `copy()` (and, from Java, a directly
        // callable constructor) letting a caller fabricate `receiverState = REGISTRY_VERIFIED`.
        // Assert via reflection that neither escape hatch exists on the compiled class.
        //
        // Kotlin's codegen for "private constructor + companion factory" unconditionally emits a
        // second, JVM-`public` constructor overload carrying a trailing
        // `kotlin.jvm.internal.DefaultConstructorMarker` parameter (a synthetic bridge letting the
        // companion, a distinct JVM class, reach the private constructor -- confirmed empirically
        // via javap; no combination of Kotlin visibility keywords avoids it once a companion
        // touches the private constructor). That bridge is `ACC_SYNTHETIC`: real (non-synthetic)
        // constructors must all be private.
        val constructors = BarnardB005VerifiedEnvelope::class.java.declaredConstructors
        val realConstructors = constructors.filter { !it.isSynthetic }
        assertEquals(1, realConstructors.size, "expected exactly one non-synthetic constructor")
        assertTrue(!java.lang.reflect.Modifier.isPublic(realConstructors[0].modifiers), "the real constructor must not be public")
        for (ctor in constructors) {
            if (java.lang.reflect.Modifier.isPublic(ctor.modifiers)) {
                assertTrue(ctor.isSynthetic, "a public constructor must be the synthetic companion-access bridge, not a real one")
            }
        }
        val hasCopy = BarnardB005VerifiedEnvelope::class.java.methods.any { it.name == "copy" }
        assertTrue(!hasCopy, "must not expose a public copy() method")
    }

    /**
     * Builds a structurally-valid `RADIO_SELF_VERIFIED` envelope with a caller-chosen
     * `eninSeconds`/window, using an `AlwaysAcceptingRecoverer` to stand in for real ECDSA math
     * (same technique as [buildSyntheticContainer] below), so `registryAgreement`'s window
     * logic can be exercised against known, exact ENIN values. Requires `validThroughEnin >
     * validFromEnin`: a verified envelope's `expires` field must satisfy `validFromEnin <=
     * currentEnin < expires <= validThroughEnin`, which is unsatisfiable when the two are equal.
     */
    private fun synthesizeWindow(eninSeconds: Int, validFromEnin: Int, validThroughEnin: Int): BarnardB005VerifiedEnvelope {
        var envelope = byteArrayOf(1) + ByteArray(20) + ByteArray(20) + ByteArray(32) + byteArrayOf(1)
        envelope += ByteArray(33) { 1 }
        envelope += byteArrayOf(1) // joinMode = gated
        envelope += byteArrayOf((eninSeconds shr 8).toByte(), eninSeconds.toByte())
        envelope += byteArrayOf((validFromEnin shr 24).toByte(), (validFromEnin shr 16).toByte(), (validFromEnin shr 8).toByte(), validFromEnin.toByte())
        envelope += byteArrayOf((validThroughEnin shr 24).toByte(), (validThroughEnin shr 16).toByte(), (validThroughEnin shr 8).toByte(), validThroughEnin.toByte())
        envelope += byteArrayOf((validThroughEnin shr 24).toByte(), (validThroughEnin shr 16).toByte(), (validThroughEnin shr 8).toByte(), validThroughEnin.toByte()) // expires = validThroughEnin
        envelope += byteArrayOf(2) // fixed marker byte
        envelope += ByteArray(8) // eventCodeHash (unchecked under gated mode)
        envelope += byteArrayOf(1) // nameLength
        envelope += "X".encodeToByteArray()
        envelope += byteArrayOf(0) // certLength = 0
        envelope += ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1) + byteArrayOf(0) // r=1, s=1, v=0
        val container = BarnardB005EnvelopeV2.encodeContainer(0, envelope) ?: error("container build failed")
        val recoverer = AlwaysAcceptingRecoverer(ByteArray(33) { 1 })
        return BarnardB005EnvelopeV2.verify(container, validFromEnin.toLong(), recoverer) ?: error("expected synthetic window container to verify")
    }

    // --- Recover-once and low-S (P1) ---

    private class CountingNonMemberRecoverer : BarnardB005PublicKeyRecovering {
        var count = 0
        override fun recover(recoveryId: Int, r: ByteArray, s: ByteArray, digest: ByteArray): ByteArray? {
            count++
            return ByteArray(33) { 0xff.toByte() } // never a member of the synthetic key set below.
        }
        override fun isValidCompressedKey(key: ByteArray) = true
    }

    private class AlwaysAcceptingRecoverer(private val key: ByteArray) : BarnardB005PublicKeyRecovering {
        override fun recover(recoveryId: Int, r: ByteArray, s: ByteArray, digest: ByteArray) = key
        override fun isValidCompressedKey(key: ByteArray) = true
    }

    // --- Delegation certificate ENIN upper bound (parallax parity: 2^53-1, not 2^53) ---

    private fun cborUintMajor(major: Int, value: Long): ByteArray {
        val v = value.toULong()
        return when {
            v < 24UL -> byteArrayOf(((major shl 5) or v.toInt()).toByte())
            v < 256UL -> byteArrayOf(((major shl 5) or 24).toByte(), v.toByte())
            v < 65_536UL -> byteArrayOf(((major shl 5) or 25).toByte(), (v shr 8).toByte(), v.toByte())
            v < 4_294_967_296UL -> byteArrayOf(((major shl 5) or 26).toByte()) + ByteArray(4) { (v shr (8 * (3 - it))).toByte() }
            else -> byteArrayOf(((major shl 5) or 27).toByte()) + ByteArray(8) { (v shr (8 * (7 - it))).toByte() }
        }
    }
    private fun cborUint(value: Long) = cborUintMajor(0, value)
    private fun cborBytesField(b: ByteArray) = cborUintMajor(2, b.size.toLong()) + b
    private fun cborTextField(s: String): ByteArray { val b = s.encodeToByteArray(); return cborUintMajor(3, b.size.toLong()) + b }
    private fun cborNegative47() = byteArrayOf(0x38, 46) // major 1, ai=24, value 46 -> -(46+1) = -47

    /**
     * Hand-encodes a delegation certificate with a caller-chosen `eninEnd`, using an
     * [AlwaysAcceptingRecoverer] for both the cert's COSE signature and the envelope signature so
     * the boundary on `eninEnd` (parallax parity: at most `2^53-1`) can be exercised without real
     * ECDSA math. `kid` is computed the same way production code derives it so the single
     * authority key is found as the unique candidate signer; `eventId` is the real
     * `computeEventId` output for the envelope's own registrar/anchor/nonce/key-set, so the
     * cert's own `eventId` tie-in check passes independent of the field under test.
     */
    private fun buildCertContainer(eninEnd: Long): ByteArray {
        val authorityKey = ByteArray(33) { 1 }
        val delegateKey = authorityKey
        val registrar = ByteArray(20) { 4 }
        val anchor = ByteArray(20) { 5 }
        val nonce = ByteArray(32) { 6 }
        val ksDigest = BarnardB005EnvelopeV2.keySetDigest(listOf(authorityKey)) ?: error("keySetDigest failed")
        val eventId = BarnardB005EnvelopeV2.computeEventId(registrar, anchor, nonce, ksDigest) ?: error("computeEventId failed")
        val kid = MessageDigest.getInstance("SHA-256").digest("levarac:cose-kid:v1 ".encodeToByteArray() + authorityKey).copyOf(8)

        val protectedHeader = byteArrayOf(0xa3.toByte()) + byteArrayOf(0x01) + cborNegative47() +
            byteArrayOf(0x03) + cborTextField("application/vnd.levarac.delegation-cert+cbor") +
            byteArrayOf(0x04) + cborBytesField(kid)
        val payload = byteArrayOf(0xa6.toByte()) +
            byteArrayOf(0x01) + cborUint(1) +
            byteArrayOf(0x02) + cborBytesField(eventId) +
            byteArrayOf(0x03) + cborBytesField(delegateKey) +
            byteArrayOf(0x04) + cborUint(1) +
            byteArrayOf(0x05) + cborUint(1000) +
            byteArrayOf(0x06) + cborUint(eninEnd)
        // r=1, s=1: isLowSInRange rejects an all-zero r/s regardless of the injected recoverer.
        val certSignature = ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1)
        val cert = byteArrayOf(0xd2.toByte()) + byteArrayOf(0x84.toByte()) +
            cborBytesField(protectedHeader) + byteArrayOf(0xa0.toByte()) +
            cborBytesField(payload) + cborBytesField(certSignature)
        check(cert.size <= 255) { "synthetic cert too large: ${cert.size}" }

        var envelope = byteArrayOf(1) + registrar + anchor + nonce + byteArrayOf(1)
        envelope += authorityKey
        envelope += byteArrayOf(1) // joinMode = gated
        envelope += byteArrayOf(0x01, 0x2c) // eninSeconds = 300
        envelope += byteArrayOf(0x00, 0x5b.toByte(), 0x8d.toByte(), 0x7b.toByte()) // validFrom = 5_999_995
        envelope += byteArrayOf(0x00, 0x5b.toByte(), 0x8d.toByte(), 0x85.toByte()) // validThrough = 6_000_005
        envelope += byteArrayOf(0x00, 0x5b.toByte(), 0x8d.toByte(), 0x81.toByte()) // relayExpiresAtEnin = 6_000_001 (lifetime 6 <= 12)
        envelope += byteArrayOf(2) // fixed marker byte
        envelope += ByteArray(8) // eventCodeHash (unchecked under gated mode)
        envelope += byteArrayOf(1) // nameLength
        envelope += "X".encodeToByteArray()
        envelope += byteArrayOf(cert.size.toByte())
        envelope += cert
        envelope += ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1) + byteArrayOf(0) // envelope signature r=1, s=1, v=0
        return BarnardB005EnvelopeV2.encodeContainer(0, envelope) ?: error("container build failed")
    }

    @Test fun delegationCertEninEndAcceptsMaxAndRejectsOneAboveMax() {
        // Parallax's verifier allows at most 2^53-1; both must match exactly.
        val recoverer = AlwaysAcceptingRecoverer(ByteArray(33) { 1 })
        val atMax = buildCertContainer(9_007_199_254_740_991L)
        assertNotNull(BarnardB005EnvelopeV2.verify(atMax, 6_000_000, recoverer), "2^53-1 must be accepted")
        val overMax = buildCertContainer(9_007_199_254_740_992L)
        assertNull(BarnardB005EnvelopeV2.verify(overMax, 6_000_000, recoverer), "2^53 must be rejected")
    }

    // Builds a structurally-valid authority-direct-mode container with `keyCount` synthetic
    // authority keys, no delegation certificate, and a caller-supplied raw signature, so tests
    // can drive signatureMatches/recoverMember with arbitrary r/s/v without real ECDSA math.
    private fun buildSyntheticContainer(keyCount: Int, signature: ByteArray): ByteArray {
        var envelope = byteArrayOf(1) + ByteArray(20) + ByteArray(20) + ByteArray(32) + byteArrayOf(keyCount.toByte())
        for (i in 0 until keyCount) envelope += ByteArray(33) { (i + 1).toByte() }
        envelope += byteArrayOf(1) // joinMode = gated
        envelope += byteArrayOf(0x01, 0x2c) // eninSeconds = 300
        envelope += byteArrayOf(0, 0, 0x03, 0xe8.toByte()) // validFrom = 1000
        envelope += byteArrayOf(0, 0, 0x03, 0xe9.toByte()) // validThrough = 1001
        envelope += byteArrayOf(0, 0, 0x03, 0xe9.toByte()) // relayExpiresAtEnin = 1001
        envelope += byteArrayOf(2) // fixed marker byte
        envelope += ByteArray(8) // eventCodeHash (unchecked under gated mode)
        envelope += byteArrayOf(1) // nameLength
        envelope += "X".encodeToByteArray()
        envelope += byteArrayOf(0) // certLength = 0
        envelope += signature
        return BarnardB005EnvelopeV2.encodeContainer(0, envelope) ?: error("container build failed")
    }

    @Test fun authorityDirectVerificationRecoversExactlyOnce() {
        val recoverer = CountingNonMemberRecoverer()
        val signature = ByteArray(31) + byteArrayOf(1) + ByteArray(31) + byteArrayOf(1) + byteArrayOf(0) // r=1, s=1, v=0
        val container = buildSyntheticContainer(8, signature)
        assertNull(BarnardB005EnvelopeV2.verify(container, 1000, recoverer), "recovered key is never a set member")
        assertEquals(1, recoverer.count, "authority-direct mode must recover exactly once regardless of key-set size")
    }

    @Test fun highSSignatureRejectedEvenWithAnAcceptingRecoverer() {
        // s = N - 1 (maximal, definitely > N/2): a fake recoverer that never checks S itself
        // would happily "match" this, so the rejection MUST come from signatureMatches's own
        // low-S gate.
        val highS = byteArrayOf(
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xfe.toByte(),
            0xba.toByte(), 0xae.toByte(), 0xdc.toByte(), 0xe6.toByte(), 0xaf.toByte(), 0x48, 0xa0.toByte(), 0x3b,
            0xbf.toByte(), 0xd2.toByte(), 0x5e, 0x8c.toByte(), 0xd0.toByte(), 0x36, 0x41, 0x40,
        )
        val r = ByteArray(31) + byteArrayOf(1)
        val acceptingKey = ByteArray(33) { 7 }
        val signature = r + highS + byteArrayOf(0)
        val container = buildSyntheticContainer(1, signature)
        assertNull(BarnardB005EnvelopeV2.verify(container, 1000, AlwaysAcceptingRecoverer(acceptingKey)))
    }

    @Test fun highSCertificateSignatureRejectedEvenWithAnAcceptingRecoverer() {
        // Same claim as above but for the certificate's own COSE signature path
        // (recoveryByte = false, the two-attempt branch), a separate code path from the
        // envelope signature.
        val envelopeHex = v("v2_envelope")
        val oldCert = v("v2_delegation_cert")
        val idx = envelopeHex.indexOf(oldCert)
        check(idx >= 0)
        val envelope = hex(envelopeHex)
        val certByteOffset = idx / 2
        val certEnd = certByteOffset + oldCert.length / 2
        val highS = byteArrayOf(
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
            0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xfe.toByte(),
            0xba.toByte(), 0xae.toByte(), 0xdc.toByte(), 0xe6.toByte(), 0xaf.toByte(), 0x48, 0xa0.toByte(), 0x3b,
            0xbf.toByte(), 0xd2.toByte(), 0x5e, 0x8c.toByte(), 0xd0.toByte(), 0x36, 0x41, 0x40,
        )
        // Certificate signature is the last 64 bytes of the cert byte range (COSE_Sign1 bstr .size 64).
        val sigStart = certEnd - 64
        val r = ByteArray(31) + byteArrayOf(1)
        r.copyInto(envelope, sigStart)
        highS.copyInto(envelope, sigStart + 32)
        val container = BarnardB005EnvelopeV2.encodeContainer(1, envelope) ?: error("container build failed")
        assertNull(BarnardB005EnvelopeV2.verify(container, 6_000_000, AlwaysAcceptingRecoverer(ByteArray(33) { 7 })))
    }

    // --- CBOR builder overflow (P2) ---

    @Test fun buildSigStructureHandlesFieldsAtAndBeyond256Bytes() {
        val protected300 = ByteArray(300) { 0x11 }
        val payload10 = ByteArray(10) { 0x22 }
        val structure = BarnardB005EnvelopeV2.buildSigStructure(protected300, payload10) ?: error("300-byte field must not truncate or fail")
        val headerEnd = 2 + 10
        assertContentEquals(byteArrayOf(0x59, 0x01, 0x2c), structure.copyOfRange(headerEnd, headerEnd + 3), "canonical 2-byte length for 300")
        assertEquals(2 + 10 + 3 + 300 + 1 + 1 + 10, structure.size)
        assertContentEquals(protected300, structure.copyOfRange(headerEnd + 3, headerEnd + 3 + 300))
    }

    @Test fun buildSigStructureRejectsOversizedField() {
        val tooLarge = ByteArray(65536)
        assertNull(BarnardB005EnvelopeV2.buildSigStructure(tooLarge, ByteArray(0)))
    }

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun findRepoRoot(): File { var f = File(System.getProperty("user.dir")); repeat(20) { if (File(f, "test-vectors/b005-envelope-v2.txt").isFile) return f; f = f.parentFile }; error("repo root") }
    private fun parseVectors(file: File) = file.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.associate { val i = it.indexOf('='); it.substring(0, i) to it.substring(i + 1) }
}
