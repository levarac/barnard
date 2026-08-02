package org.levarac.barnard

import org.levarac.barnard.BarnardCrypto.toHex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class BarnardEventInfoTest {
    @Test
    fun goldenVectorsSerializeAndParseByteForByte() {
        val vectors = listOf(
            arrayOf("CORE-SPLIT-80", "Barnard Core Split", "0b9f14789f13968f", "010100124261726e61726420436f72652053706c69740200080b9f14789f13968f"),
            arrayOf("東京-2026", "東京 2026", "34dc60f26d21cb94", "0101000be69db1e4baac203230323602000834dc60f26d21cb94"),
        )
        for ((eventCode, displayName, expectedHash, expectedPayload) in vectors) {
            val b004 = BarnardCrypto.computeEventCodeHash(eventCode)
            assertEquals(expectedHash, b004.toHex())
            val payload = BarnardEventInfoCodec.serialize(eventCode, displayName, b004)
            assertEquals(expectedPayload, payload.toHex())
            val parsed = BarnardEventInfoCodec.parse(payload)
            assertEquals(displayName, parsed.eventDisplayName)
            assertArrayEquals(b004, parsed.eventCodeHash)
        }
    }

    @Test
    fun parserSkipsWellFormedUnknownTlvButRejectsMalformedCorpus() {
        val validWithUnknown = "010100124261726e61726420436f72652053706c69740200080b9f14789f13968f100001ff".hexBytes()
        assertEquals("Barnard Core Split", BarnardEventInfoCodec.parse(validWithUnknown).eventDisplayName)

        val malformed = listOf(
            "",
            "020100124261726e61726420436f72652053706c69740200080b9f14789f13968f",
            "010100124261726e61726420436f72652053706c69740200080b9f14789f1396",
            "010200080b9f14789f13968f0100124261726e61726420436f72652053706c6974",
            "01010001410200080b9f14789f13968f020000",
            "01010001ff0200080b9f14789f13968f",
            "0101000241010200080b9f14789f13968f",
            "0101000341cc8a0200080b9f14789f13968f",
        )
        malformed.forEach { hex ->
            assertThrows("expected malformed B005 to fail: $hex", IllegalArgumentException::class.java) {
                BarnardEventInfoCodec.parse(hex.hexBytes())
            }
        }
    }

    @Test
    fun serializerRejectsB004MismatchAndDisabledPolicy() {
        val b004 = BarnardCrypto.computeEventCodeHash("CORE-SPLIT-80")
        assertThrows(IllegalArgumentException::class.java) {
            BarnardEventInfoCodec.serialize("CORE-SPLIT-80", "Barnard Core Split", ByteArray(8))
        }
        assertNull(BarnardEventInfoCodec.payloadIfServing(
            BarnardEventInfoServePolicy(),
            "CORE-SPLIT-80",
            "Barnard Core Split",
            b004,
        ))
    }

    @Test
    fun discoveryRetentionCapsNamesHashesAndResetsAtFiveMinutes() {
        val session = BarnardEventInfoDiscoverySession(0L)
        repeat(32) { index ->
            session.observe(BarnardEventInfo("Event $index", ByteArray(8) { index.toByte() }), 1L)
        }
        assertEquals(32, session.retainedHashCount)
        assertEquals(true, session.observe(BarnardEventInfo("Overflow", ByteArray(8) { 0xff.toByte() }), 2L).additionalEventsOmitted)

        val names = BarnardEventInfoDiscoverySession(0L)
        val hash = ByteArray(8) { 0x42 }
        repeat(4) { index -> names.observe(BarnardEventInfo("Name $index", hash), 1L) }
        assertEquals(true, names.observe(BarnardEventInfo("Name 4", hash), 2L).additionalNamesOmitted)
        names.observe(BarnardEventInfo("Fresh", hash), 300_000L)
        assertEquals(1, names.retainedHashCount)
    }

    @Test
    fun retryBudgetAllowsOnlyTwoTransportAttemptsWithThirtySecondBackoff() {
        val retries = BarnardEventInfoRetryBudget()
        val peer = "AA:BB"
        assertEquals(true, retries.canStart(peer, 0L))
        assertEquals(30_000L, retries.recordRecoverableFailure(peer, 0L))
        assertEquals(false, retries.canStart(peer, 29_999L))
        assertEquals(true, retries.canStart(peer, 30_000L))
        assertEquals(null, retries.recordRecoverableFailure(peer, 30_000L))
        assertEquals(false, retries.canStart(peer, 60_000L))
        retries.recordSemanticUnavailable(peer)
        assertEquals(false, retries.canStart(peer, 999_000L))
    }
}

private fun String.hexBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
