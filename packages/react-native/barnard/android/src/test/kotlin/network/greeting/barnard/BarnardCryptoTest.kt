package network.greeting.barnard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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
    fun resolveRpi_returnsMatchingTek_whenRpiIsKnown() {
        val tekA = ByteArray(16) { (it + 1).toByte() }
        val tekB = ByteArray(16) { (it + 33).toByte() }
        val currentEnin = BarnardCrypto.calculateEnin()

        val rpik = BarnardCrypto.deriveRpik(tekB)
        val rpi = BarnardCrypto.generateRpi(rpik, currentEnin)

        val resolved = BarnardCrypto.resolveRpi(rpi, listOf(tekA, tekB), currentEnin)

        assertNotNull(resolved)
        assertArrayEquals(tekB, resolved)
    }

    @Test
    fun resolveRpi_returnsNull_whenNoTekMatches() {
        val tekA = ByteArray(16) { (it + 5).toByte() }
        val tekB = ByteArray(16) { (it + 85).toByte() }
        val enin = 12345u

        val rpi = BarnardCrypto.generateRpi(BarnardCrypto.deriveRpik(tekA), enin)

        val resolved = BarnardCrypto.resolveRpi(rpi, listOf(tekB), enin)

        assertNull(resolved)
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
    fun displayId_usesFirstThreeBytesAsLowercaseHex() {
        val tek = byteArrayOf(
            0xAB.toByte(),
            0xCD.toByte(),
            0xEF.toByte(),
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0A,
            0x0B,
            0x0C,
            0x0D
        )

        assertEquals("abcdef", BarnardCrypto.displayId(tek))
    }
}
