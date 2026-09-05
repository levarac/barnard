package org.levarac.barnard

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

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

    // --- Registry-tier confirmation (P1: cannot be forged from a bare bool) ---

    @Test fun confirmAgainstRegistryRequiresFullAgreement() {
        val container = hex(v("v1_container"))
        val verified = BarnardB005EnvelopeV2.verify(container, 6_000_000) ?: error("expected RADIO_SELF_VERIFIED baseline")
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, verified.receiverState)
        fun agreeing() = BarnardEventDefinitionV1(
            verified.eventId, verified.keySetDigest, verified.joinMode, verified.eventCodeHash,
            verified.validFromEnin * verified.eninSeconds, verified.validThroughEnin * verified.eninSeconds,
        )
        assertEquals(BarnardB005ReceiverState.REGISTRY_VERIFIED, BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, agreeing()).receiverState)

        val wrongEventId = agreeing().eventId.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, agreeing().copy(eventId = wrongEventId)).receiverState, "eventId mismatch")

        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, agreeing().copy(joinMode = if (verified.joinMode == 0) 1 else 0)).receiverState, "joinMode mismatch")

        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, agreeing().copy(validFromUnixSeconds = (verified.validThroughEnin + 1) * verified.eninSeconds)).receiverState, "window mismatch")

        val wrongKeySetDigest = verified.keySetDigest.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertEquals(BarnardB005ReceiverState.RADIO_SELF_VERIFIED, BarnardB005EnvelopeV2.confirmAgainstRegistry(verified, agreeing().copy(keySetDigest = wrongKeySetDigest)).receiverState, "signer-authority (keySetDigest) mismatch")
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
