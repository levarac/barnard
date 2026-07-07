// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

private fun deviceSecret(seed: Int): ByteArray = ByteArray(32) { ((it * 7 + seed) and 0xff).toByte() }

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

class BarnardSigningTest {

    @Test
    fun sameDeviceSameEvent_producesIdenticalSigningKey() {
        val secret = deviceSecret(1)
        val a = BarnardSigning.deriveSigningKeyPair(secret, "event-A")
        val b = BarnardSigning.deriveSigningKeyPair(secret, "event-A")

        assertArrayEquals(a.publicKeyCompressed, b.publicKeyCompressed)
        assertEquals(a.privateKey, b.privateKey)
    }

    @Test
    fun sameDeviceDifferentEvent_producesDifferentSigningKey() {
        val secret = deviceSecret(1)
        val a = BarnardSigning.deriveSigningKeyPair(secret, "event-A")
        val b = BarnardSigning.deriveSigningKeyPair(secret, "event-B")

        assertFalse(a.publicKeyCompressed.contentEquals(b.publicKeyCompressed))
    }

    @Test
    fun noCrossEventStableKey_manyEventsNeverCollide() {
        val secret = deviceSecret(42)
        val seen = HashSet<String>()
        for (i in 0 until 50) {
            val pub = BarnardSigning.deriveSigningKeyPair(secret, "event-$i").publicKeyCompressed
            val hex = pub.joinToString("") { "%02x".format(it) }
            assertTrue("event-$i collided with a prior event's key", seen.add(hex))
        }
    }

    @Test
    fun reDerivableOffline_reproducesSameKeyFromDeviceSecretAlone() {
        val secret = deviceSecret(7)
        val first = BarnardSigning.deriveSigningKeyPair(secret, "reunion-2026")
        val second = BarnardSigning.deriveSigningKeyPair(secret.copyOf(), "reunion-2026")

        assertArrayEquals(first.publicKeyCompressed, second.publicKeyCompressed)
    }

    @Test
    fun differentDevices_produceDifferentKeysForSameEvent() {
        val a = BarnardSigning.deriveSigningKeyPair(deviceSecret(1), "shared-event")
        val b = BarnardSigning.deriveSigningKeyPair(deviceSecret(2), "shared-event")

        assertFalse(a.publicKeyCompressed.contentEquals(b.publicKeyCompressed))
    }

    @Test
    fun domainSeparatedFromTekRpik() {
        val secret = deviceSecret(3)
        val eventCode = "domain-sep-event"

        val signingPub = BarnardSigning.deriveSigningKeyPair(secret, eventCode).publicKeyCompressed
        val tek = BarnardCrypto.deriveTekForEvent(secret, eventCode)
        val rpik = BarnardCrypto.deriveRpik(tek)

        assertFalse(signingPub.contentEquals(tek))
        assertFalse(signingPub.contentEquals(rpik))
        assertFalse(tek.contentEquals(rpik))
    }

    @Test
    fun signatureRecoversExactSigningPublicKey() {
        val secret = deviceSecret(5)
        val eventCode = "ecrecover-event"
        val keyPair = BarnardSigning.deriveSigningKeyPair(secret, eventCode)
        val message = "hello barnard".toByteArray(Charsets.UTF_8)
        val messageHash = sha256(message)

        val sig = BarnardSigning.signRecoverable(keyPair.privateKey, messageHash)
        val recovered = BarnardSigning.recoverPublicKey(
            sig.v,
            java.math.BigInteger(1, sig.r),
            java.math.BigInteger(1, sig.s),
            messageHash,
        )

        assertNotNull(recovered)
        assertArrayEquals(keyPair.publicKeyCompressed, recovered)
    }

    @Test
    fun recoveryFailsAgainstTamperedMessage() {
        val secret = deviceSecret(6)
        val eventCode = "tamper-event"
        val keyPair = BarnardSigning.deriveSigningKeyPair(secret, eventCode)
        val original = "original".toByteArray(Charsets.UTF_8)
        val tampered = "tampered!".toByteArray(Charsets.UTF_8)

        val sig = BarnardSigning.signRecoverable(keyPair.privateKey, sha256(original))
        val recovered = BarnardSigning.recoverPublicKey(
            sig.v,
            java.math.BigInteger(1, sig.r),
            java.math.BigInteger(1, sig.s),
            sha256(tampered),
        )

        assertFalse(keyPair.publicKeyCompressed.contentEquals(recovered ?: ByteArray(0)))
    }

    @Test
    fun signatureShape_is32ByteRs_withRecoveryIdInRange() {
        val keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret(8), "shape-event")
        val sig = BarnardSigning.signRecoverable(keyPair.privateKey, sha256(byteArrayOf(1, 2, 3)))

        assertEquals(32, sig.r.size)
        assertEquals(32, sig.s.size)
        assertTrue(sig.v == 0 || sig.v == 1)
    }
}
