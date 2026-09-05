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

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun findRepoRoot(): File { var f = File(System.getProperty("user.dir")); repeat(20) { if (File(f, "test-vectors/b005-envelope-v2.txt").isFile) return f; f = f.parentFile }; error("repo root") }
    private fun parseVectors(file: File) = file.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.associate { val i = it.indexOf('='); it.substring(0, i) to it.substring(i + 1) }
}
