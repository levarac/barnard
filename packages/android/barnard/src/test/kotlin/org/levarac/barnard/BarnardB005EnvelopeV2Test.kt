package org.levarac.barnard

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class BarnardB005EnvelopeV2Test {
    private val vectors by lazy { parseVectors(File(findRepoRoot(), "test-vectors/b005-envelope-v2.txt")) }
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
    }
    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun findRepoRoot(): File { var f = File(System.getProperty("user.dir")); repeat(20) { if (File(f, "test-vectors/b005-envelope-v2.txt").isFile) return f; f = f.parentFile }; error("repo root") }
    private fun parseVectors(file: File) = file.readLines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.associate { val i = it.indexOf('='); it.substring(0, i) to it.substring(i + 1) }
}
