// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BarnardCryptoTest {
    @Test
    fun deriveTekForEventIsDeterministic() {
        val deviceSecret = ByteArray(32) { 0xAB.toByte() }
        val tek1 = BarnardCrypto.deriveTekForEvent(deviceSecret, "EVT1")
        val tek2 = BarnardCrypto.deriveTekForEvent(deviceSecret, "EVT1")
        assertArrayEquals(tek1, tek2)
        assertEquals(16, tek1.size)
    }

    @Test
    fun deriveTekForEventDependsOnEventCode() {
        val deviceSecret = ByteArray(32) { 0xAB.toByte() }
        val tekA = BarnardCrypto.deriveTekForEvent(deviceSecret, "EVT-A")
        val tekB = BarnardCrypto.deriveTekForEvent(deviceSecret, "EVT-B")
        assertFalse(tekA.contentEquals(tekB))
    }

    @Test
    fun deriveTekForAnonymousDiffersFromEventMode() {
        val deviceSecret = ByteArray(32) { 0xCD.toByte() }
        val anonymousTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret)
        val eventTek = BarnardCrypto.deriveTekForEvent(deviceSecret, "EVT1")
        assertEquals(16, anonymousTek.size)
        assertFalse(anonymousTek.contentEquals(eventTek))
    }

    @Test
    fun deriveRpikRequires16ByteTek() {
        val shortTek = ByteArray(8) { 0x01 }
        assertArrayEquals(ByteArray(16), BarnardCrypto.deriveRpik(shortTek))

        val tek = ByteArray(16) { 0x02 }
        val rpik = BarnardCrypto.deriveRpik(tek)
        assertEquals(16, rpik.size)
    }

    @Test
    fun generateRpiIsDeterministicForSameEnin() {
        val rpik = ByteArray(16) { 0x03 }
        val rpi1 = BarnardCrypto.generateRpi(rpik, 42u)
        val rpi2 = BarnardCrypto.generateRpi(rpik, 42u)
        assertArrayEquals(rpi1, rpi2)
        assertEquals(16, rpi1.size)
    }

    @Test
    fun generateRpiChangesWithEnin() {
        val rpik = ByteArray(16) { 0x03 }
        val rpiA = BarnardCrypto.generateRpi(rpik, 1u)
        val rpiB = BarnardCrypto.generateRpi(rpik, 2u)
        assertFalse(rpiA.contentEquals(rpiB))
    }

    @Test
    fun calculateEninFixedLengthFloorsToWindow() {
        // 300s window: unix seconds 900...1199 all map to ENIN 3.
        val enin = BarnardCrypto.calculateEnin(1000L * 1000, BarnardCrypto.EninMode.FIXED_LENGTH, 300L)
        assertEquals(3u, enin)
    }

    @Test
    fun calculateEninFixedLengthClampsSeconds() {
        val timestampMs = 1_000_000L * 1000
        val eninTooSmall = BarnardCrypto.calculateEnin(timestampMs, BarnardCrypto.EninMode.FIXED_LENGTH, 1L)
        val eninAt12 = BarnardCrypto.calculateEnin(timestampMs, BarnardCrypto.EninMode.FIXED_LENGTH, 12L)
        assertEquals(eninAt12, eninTooSmall)

        val eninTooLarge = BarnardCrypto.calculateEnin(timestampMs, BarnardCrypto.EninMode.FIXED_LENGTH, 999_999L)
        val eninAt3600 = BarnardCrypto.calculateEnin(timestampMs, BarnardCrypto.EninMode.FIXED_LENGTH, 3600L)
        assertEquals(eninAt3600, eninTooLarge)
    }

    @Test
    fun calculateEninBeaconSlotBeforeGenesisIsZero() {
        val chain = BarnardCrypto.BeaconChainConfig(chainId = "test", genesisUnixSeconds = 1_000_000L, slotSeconds = 12L)
        val beforeGenesisMs = 500_000L * 1000
        assertEquals(0u, BarnardCrypto.calculateEnin(beforeGenesisMs, BarnardCrypto.EninMode.BEACON_SLOT, beaconChain = chain))
    }

    @Test
    fun calculateEninBeaconSlotAfterGenesis() {
        val chain = BarnardCrypto.BeaconChainConfig(chainId = "test", genesisUnixSeconds = 1_000_000L, slotSeconds = 12L)
        val timestampMs = (1_000_000L + 36) * 1000
        assertEquals(3u, BarnardCrypto.calculateEnin(timestampMs, BarnardCrypto.EninMode.BEACON_SLOT, beaconChain = chain))
    }

    @Test
    fun stableReadEninReturnsNullAcrossBoundary() {
        val startedAtMs = 899L * 1000
        val completedAtMs = 901L * 1000
        assertEquals(
            null,
            BarnardCrypto.stableReadEnin(startedAtMs, completedAtMs, eninSeconds = 300L)
        )
    }

    @Test
    fun stableReadEninReturnsEninWithinSameWindow() {
        val startedAtMs = 905L * 1000
        val completedAtMs = 907L * 1000
        assertEquals(
            3u,
            BarnardCrypto.stableReadEnin(startedAtMs, completedAtMs, eninSeconds = 300L)
        )
    }

    @Test
    fun computeEventCodeHashIs8BytesAndDeterministic() {
        val hash1 = BarnardCrypto.computeEventCodeHash("EVT1")
        val hash2 = BarnardCrypto.computeEventCodeHash("EVT1")
        assertArrayEquals(hash1, hash2)
        assertEquals(8, hash1.size)

        val otherHash = BarnardCrypto.computeEventCodeHash("EVT2")
        assertFalse(hash1.contentEquals(otherHash))
    }

    @Test
    fun displayId4Is4BytesAndDeterministic() {
        val tek = ByteArray(16) { 0x09 }
        val id1 = BarnardCrypto.displayId4(tek)
        val id2 = BarnardCrypto.displayId4(tek)
        assertArrayEquals(id1, id2)
        assertEquals(4, id1.size)
    }

    @Test
    fun displayIdStringIs8LowercaseHexChars() {
        val tek = ByteArray(16) { 0x0A }
        val str = BarnardCrypto.displayIdString(tek)
        assertEquals(8, str.length)
        assertEquals(str, str.lowercase())
        assertNotNull(str.toLong(16))
    }

    @Test
    fun generateRandomBytesProducesRequestedLengthAndVaries() {
        val a = BarnardCrypto.generateRandomBytes(32)
        val b = BarnardCrypto.generateRandomBytes(32)
        assertEquals(32, a.size)
        assertEquals(32, b.size)
        // Astronomically unlikely to collide; guards against a broken/stubbed RNG.
        assertFalse(a.contentEquals(b))
    }

    // MARK: - On-wire invariant

    /**
     * Barnard's core privacy invariant (AGENTS.md, issue #56): no
     * device-unique persistent identifier may appear on the wire. RPI must
     * rotate every ENIN window instead of staying fixed per device.
     */
    @Test
    fun rpiRotatesAcrossEninWindowsForSameDevice() {
        val deviceSecret = ByteArray(32) { 0x11 }
        val tek = BarnardCrypto.deriveTekForEvent(deviceSecret, "EVT1")
        val rpik = BarnardCrypto.deriveRpik(tek)

        val rpiWindow1 = BarnardCrypto.generateRpi(rpik, 100u)
        val rpiWindow2 = BarnardCrypto.generateRpi(rpik, 101u)
        assertNotEquals(rpiWindow1.toList(), rpiWindow2.toList())
        assertTrue(!rpiWindow1.contentEquals(rpiWindow2))
    }
}
