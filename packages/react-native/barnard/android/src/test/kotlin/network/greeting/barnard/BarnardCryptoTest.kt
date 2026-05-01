package network.greeting.barnard

import network.greeting.barnard.BarnardCrypto.toHex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BarnardCryptoTest {

    @Test
    fun deriveTekForEvent_isDeterministic_andDifferentFromAnonymous() {
        val deviceSecret = ByteArray(32) { it.toByte() }

        val eventTekA = BarnardCrypto.deriveTekForEvent(deviceSecret, "ethglobal")
        val eventTekB = BarnardCrypto.deriveTekForEvent(deviceSecret, "ethglobal")
        val anonymousTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret)

        assertEquals(16, eventTekA.size)
        assertArrayEquals(eventTekA, eventTekB)
        assertFalse(eventTekA.contentEquals(anonymousTek))
    }

    @Test
    fun computeEventCodeHash_isDeterministic_and8Bytes() {
        val hashA1 = BarnardCrypto.computeEventCodeHash("event-a")
        val hashA2 = BarnardCrypto.computeEventCodeHash("event-a")
        val hashB = BarnardCrypto.computeEventCodeHash("event-b")

        assertEquals(8, hashA1.size)
        assertArrayEquals(hashA1, hashA2)
        assertFalse(hashA1.contentEquals(hashB))
    }

    @Test
    fun displayId4_isSha256FirstFourBytes() {
        val tek = ByteArray(16) // all zeros
        // Known answer: SHA-256(16 zero bytes)[0:4] = 37 47 08 ff
        val displayId = BarnardCrypto.displayId4(tek)
        assertEquals(4, displayId.size)
        assertEquals("374708ff", displayId.toHex())
    }

    @Test
    fun displayIdString_is8LowercaseHexChars() {
        val tek = ByteArray(16) { (it + 1).toByte() } // 0x01..0x10
        val displayId = BarnardCrypto.displayIdString(tek)
        assertEquals(8, displayId.length)
        assertTrue(displayId.matches(Regex("^[0-9a-f]{8}$")))
        // Known answer: SHA-256(0x01..0x10)[0:4] = 5d fb ab ee
        assertEquals("5dfbabee", displayId)
    }

    @Test
    fun displayIdString_isDeterministic_andDistinctForDistinctTeks() {
        val tek1 = ByteArray(16) { it.toByte() }
        val tek2 = ByteArray(16) { (it + 1).toByte() }

        assertEquals(BarnardCrypto.displayIdString(tek1), BarnardCrypto.displayIdString(tek1))
        assertFalse(
            BarnardCrypto.displayIdString(tek1) == BarnardCrypto.displayIdString(tek2)
        )
    }
}
