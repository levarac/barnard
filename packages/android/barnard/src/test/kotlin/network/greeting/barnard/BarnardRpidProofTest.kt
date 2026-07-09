// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import java.math.BigInteger
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

private fun deviceSecret(seed: Int): ByteArray = ByteArray(32) { ((it * 7 + seed) and 0xff).toByte() }

private fun eventIdHash(seed: Int): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(ByteArray(40) { ((it + seed) and 0xff).toByte() })

class BarnardRpidProofTest {

    @Test
    fun proofMatchesIndependentlyComputedRpi_andRecoversToSigningPublicKey() {
        val secret = deviceSecret(11)
        val eventCode = "rpid-proof-event"
        val idHash = eventIdHash(1)

        val proof = BarnardSigning.proveRpidOwnership(secret, eventCode, idHash, 2948599L, null)

        val tek = BarnardCrypto.deriveTekForEvent(secret, eventCode)
        val rpik = BarnardCrypto.deriveRpik(tek)
        val expectedRpi = BarnardCrypto.generateRpi(rpik, 2948599u)
        assertArrayEquals(expectedRpi, proof.rpi)

        val message = BarnardSigning.buildRpidProofMessage(idHash, proof.enin, proof.rpi, null)
        val recovered = BarnardSigning.recoverPublicKey(
            proof.sig.v,
            java.math.BigInteger(1, proof.sig.r),
            java.math.BigInteger(1, proof.sig.s),
            MessageDigest.getInstance("SHA-256").digest(message),
        )
        assertNotNull(recovered)
        assertArrayEquals(proof.signingPublicKey, recovered)
    }

    @Test
    fun discloseNoTekOrRpik() {
        val secret = deviceSecret(12)
        val eventCode = "no-tek-leak-event"
        val tek = BarnardCrypto.deriveTekForEvent(secret, eventCode)
        val rpik = BarnardCrypto.deriveRpik(tek)

        val proof = BarnardSigning.proveRpidOwnership(secret, eventCode, eventIdHash(2), 100L, null)

        assertFalse(proof.rpi.contentEquals(tek))
        assertFalse(proof.rpi.contentEquals(rpik))
    }

    @Test
    fun notReplayableToAnotherEvent() {
        val secret = deviceSecret(14)
        val eventCode = "replay-event"

        val proofA = BarnardSigning.proveRpidOwnership(secret, eventCode, eventIdHash(4), 5L, null)
        val proofB = BarnardSigning.proveRpidOwnership(secret, eventCode, eventIdHash(5), 5L, null)

        assertArrayEquals(proofA.rpi, proofB.rpi)
        assertFalse(proofA.sig.r.contentEquals(proofB.sig.r))

        val messageForB = BarnardSigning.buildRpidProofMessage(proofB.eventIdHash, proofA.enin, proofA.rpi, null)
        val recoveredWrong = BarnardSigning.recoverPublicKey(
            proofA.sig.v,
            BigInteger(1, proofA.sig.r),
            BigInteger(1, proofA.sig.s),
            MessageDigest.getInstance("SHA-256").digest(messageForB),
        )
        assertFalse(proofA.signingPublicKey.contentEquals(recoveredWrong ?: ByteArray(0)))
    }

    @Test
    fun notReplayableToAnotherEnin() {
        val secret = deviceSecret(15)
        val eventCode = "replay-enin-event"
        val idHash = eventIdHash(6)

        val proofEnin5 = BarnardSigning.proveRpidOwnership(secret, eventCode, idHash, 5L, null)

        val messageForEnin6 = BarnardSigning.buildRpidProofMessage(idHash, 6L, proofEnin5.rpi, null)
        val recoveredWrong = BarnardSigning.recoverPublicKey(
            proofEnin5.sig.v,
            BigInteger(1, proofEnin5.sig.r),
            BigInteger(1, proofEnin5.sig.s),
            MessageDigest.getInstance("SHA-256").digest(messageForEnin6),
        )
        assertFalse(proofEnin5.signingPublicKey.contentEquals(recoveredWrong ?: ByteArray(0)))
    }

    @Test
    fun challengeChangesSignedMessage() {
        val secret = deviceSecret(16)
        val eventCode = "challenge-event"
        val idHash = eventIdHash(7)

        val proofNoChallenge = BarnardSigning.proveRpidOwnership(secret, eventCode, idHash, 9L, null)
        val proofWithChallenge = BarnardSigning.proveRpidOwnership(secret, eventCode, idHash, 9L, byteArrayOf(1, 2, 3, 4))

        assertFalse(proofNoChallenge.sig.r.contentEquals(proofWithChallenge.sig.r))
    }

    @Test
    fun keyBindingRecoversToSigningPublicKey() {
        val secret = deviceSecret(20)
        val eventCode = "binding-event"

        val tek = BarnardCrypto.deriveTekForEvent(secret, eventCode)
        val displayId = BarnardCrypto.displayId4(tek)
        val eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)

        val sig = BarnardSigning.signKeyBinding(secret, eventCode, eventCodeHash, displayId)

        val message = BarnardSigning.buildKeyBindingMessage(eventCodeHash, displayId)
        val recovered = BarnardSigning.recoverPublicKey(
            sig.v,
            BigInteger(1, sig.r),
            BigInteger(1, sig.s),
            MessageDigest.getInstance("SHA-256").digest(message),
        )

        val keyPair = BarnardSigning.deriveSigningKeyPair(secret, eventCode)
        assertArrayEquals(keyPair.publicKeyCompressed, recovered)
    }
}
