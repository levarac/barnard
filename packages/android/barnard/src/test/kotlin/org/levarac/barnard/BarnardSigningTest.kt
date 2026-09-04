// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

private fun deviceSecret(seed: Int): ByteArray = ByteArray(32) { ((it * 7 + seed) and 0xff).toByte() }

private fun accountSecret(seed: Int): ByteArray = ByteArray(32) { ((it * 11 + seed) and 0xff).toByte() }

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
    fun deriveSigningKeyPairForAdoptionCredentialThrowsOnMalformedCredentialIdLength() {
        val secret = deviceSecret(1)

        for (malformedLength in listOf(31, 33)) {
            val malformedCredentialId = ByteArray(malformedLength) { 0xEF.toByte() }
            assertThrows(BarnardCryptoInputException::class.java) {
                BarnardSigning.deriveSigningKeyPairForAdoptionCredential(secret, malformedCredentialId)
            }
        }

        val validCredentialId = ByteArray(32) { 0xCD.toByte() }
        val keyPair = BarnardSigning.deriveSigningKeyPairForAdoptionCredential(secret, validCredentialId)
        assertEquals(33, keyPair.publicKeyCompressed.size)
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
            sig.r,
            sig.s,
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
            sig.r,
            sig.s,
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

    // MARK: - Owner key derivation (barnard#133 / barnard#92)

    @Test
    fun ownerKeyDerivation_isDeterministic() {
        val secret = accountSecret(1)
        val a = BarnardSigning.deriveOwnerKeyPair(secret)
        val b = BarnardSigning.deriveOwnerKeyPair(secret.copyOf())

        assertArrayEquals(a.publicKeyCompressed, b.publicKeyCompressed)
        assertEquals(a.privateKey, b.privateKey)
    }

    @Test
    fun ownerKeyDerivation_domainSeparatedFromSigningKey() {
        val secret = accountSecret(2)
        val ownerPub = BarnardSigning.deriveOwnerKeyPair(secret).publicKeyCompressed
        val signingPub = BarnardSigning.deriveSigningKeyPair(secret, "some-event").publicKeyCompressed

        assertFalse(ownerPub.contentEquals(signingPub))
    }

    @Test(expected = IllegalArgumentException::class)
    fun ownerKeyDerivation_rejectsWrongLengthSecret() {
        BarnardSigning.deriveOwnerKeyPair(ByteArray(31))
    }

    // MARK: - Account binding text (barnard#133 / barnard#92)

    @Test
    fun accountBindingText_matchesCanonicalTemplate() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(3))
        val walletAddress = ByteArray(20) { it.toByte() }
        val nonce = ByteArray(16) { (it + 1).toByte() }

        val text = BarnardSigning.buildAccountBindingText(
            domain = "example.com",
            walletAddress = walletAddress,
            ownerPublicKey = owner.publicKeyCompressed,
            chainId = 1uL,
            nonce = nonce,
            issuedAt = "2026-08-27T12:00:00Z",
        )

        assertNotNull(text)
        val expected = listOf(
            "example.com wants to bind this wallet to a Levarac owner key.",
            "",
            "This signature authorizes no transaction and moves no assets.",
            "",
            "Domain-Tag: barnard-account-binding:v1",
            "Wallet: 0x" + walletAddress.joinToString("") { "%02x".format(it) },
            "Owner-Key: 0x" + owner.publicKeyCompressed.joinToString("") { "%02x".format(it) },
            "Chain-ID: eip155:1",
            "Scope: global",
            "Nonce: 0x" + nonce.joinToString("") { "%02x".format(it) },
            "Issued-At: 2026-08-27T12:00:00Z",
        ).joinToString("\n")
        assertEquals(expected, text)
        assertFalse(text!!.endsWith("\n"))
    }

    @Test
    fun accountBindingText_acceptsMaxChainId() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(4))
        val text = BarnardSigning.buildAccountBindingText(
            domain = "example.com",
            walletAddress = ByteArray(20),
            ownerPublicKey = owner.publicKeyCompressed,
            chainId = ULong.MAX_VALUE,
            nonce = ByteArray(16),
            issuedAt = "2026-08-27T12:00:00Z",
        )

        assertNotNull(text)
        assertTrue(text!!.contains("Chain-ID: eip155:18446744073709551615"))
    }

    @Test
    fun accountBindingText_nullOnGuardFailures() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(5))
        val validWallet = ByteArray(20)
        val validNonce = ByteArray(16)
        val validIssuedAt = "2026-08-27T12:00:00Z"

        assertNull(
            BarnardSigning.buildAccountBindingText("Example.com", validWallet, owner.publicKeyCompressed, 1uL, validNonce, validIssuedAt),
        )
        assertNull(
            BarnardSigning.buildAccountBindingText("example.com", ByteArray(19), owner.publicKeyCompressed, 1uL, validNonce, validIssuedAt),
        )
        assertNull(
            BarnardSigning.buildAccountBindingText("example.com", validWallet, ByteArray(33), 1uL, validNonce, validIssuedAt),
        )
        assertNull(
            BarnardSigning.buildAccountBindingText("example.com", validWallet, owner.publicKeyCompressed, 1uL, ByteArray(15), validIssuedAt),
        )
        assertNull(
            BarnardSigning.buildAccountBindingText("example.com", validWallet, owner.publicKeyCompressed, 1uL, validNonce, "not-a-timestamp"),
        )
    }

    // MARK: - Self-proof (barnard#133 / barnard#92)

    @Test
    fun selfProofMessage_hasExpectedLayoutAndLength() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(6))
        val eventKeyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret(1), "self-proof-event")
        val eventIdHash = sha256("event".toByteArray(Charsets.UTF_8))

        val message = BarnardSigning.buildSelfProofMessage(
            eventIdHash = eventIdHash,
            eventSigningPublicKey = eventKeyPair.publicKeyCompressed,
            eninStart = 10uL,
            eninEnd = 20uL,
            ownerPublicKey = owner.publicKeyCompressed,
        )

        assertNotNull(message)
        assertEquals(135, message!!.size)

        val domainTagBytes = "barnard-self-proof:v1".toByteArray(Charsets.UTF_8)
        assertArrayEquals(domainTagBytes, message.copyOfRange(0, domainTagBytes.size))
        var offset = domainTagBytes.size
        assertArrayEquals(eventIdHash, message.copyOfRange(offset, offset + 32))
        offset += 32
        assertArrayEquals(eventKeyPair.publicKeyCompressed, message.copyOfRange(offset, offset + 33))
        offset += 33
        assertEquals(10L, java.nio.ByteBuffer.wrap(message.copyOfRange(offset, offset + 8)).long)
        offset += 8
        assertEquals(20L, java.nio.ByteBuffer.wrap(message.copyOfRange(offset, offset + 8)).long)
        offset += 8
        assertArrayEquals(owner.publicKeyCompressed, message.copyOfRange(offset, offset + 33))
    }

    @Test
    fun selfProofMessage_nullWhenEninStartAfterEninEnd() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(7))
        val eventKeyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret(2), "self-proof-event-2")

        val message = BarnardSigning.buildSelfProofMessage(
            eventIdHash = sha256("event2".toByteArray(Charsets.UTF_8)),
            eventSigningPublicKey = eventKeyPair.publicKeyCompressed,
            eninStart = 20uL,
            eninEnd = 10uL,
            ownerPublicKey = owner.publicKeyCompressed,
        )

        assertNull(message)
    }

    @Test
    fun selfProofMessage_nullOnInvalidPublicKeysOrHashLength() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(8))
        val eventKeyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret(3), "self-proof-event-3")
        val eventIdHash = sha256("event3".toByteArray(Charsets.UTF_8))

        assertNull(
            BarnardSigning.buildSelfProofMessage(ByteArray(31), eventKeyPair.publicKeyCompressed, 1uL, 2uL, owner.publicKeyCompressed),
        )
        assertNull(
            BarnardSigning.buildSelfProofMessage(eventIdHash, ByteArray(33), 1uL, 2uL, owner.publicKeyCompressed),
        )
        assertNull(
            BarnardSigning.buildSelfProofMessage(eventIdHash, eventKeyPair.publicKeyCompressed, 1uL, 2uL, ByteArray(33)),
        )
    }

    @Test
    fun signSelfProof_recoversToOwnerPublicKey() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(9))
        val eventKeyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret(4), "self-proof-event-4")
        val eventIdHash = sha256("event4".toByteArray(Charsets.UTF_8))

        val sig = BarnardSigning.signSelfProof(
            ownerPrivateKey = owner.privateKey,
            eventIdHash = eventIdHash,
            eventSigningPublicKey = eventKeyPair.publicKeyCompressed,
            eninStart = 100uL,
            eninEnd = 200uL,
            ownerPublicKey = owner.publicKeyCompressed,
        )
        assertNotNull(sig)

        val message = BarnardSigning.buildSelfProofMessage(
            eventIdHash, eventKeyPair.publicKeyCompressed, 100uL, 200uL, owner.publicKeyCompressed,
        )!!
        val recovered = BarnardSigning.recoverPublicKey(
            sig!!.v,
            sig.r,
            sig.s,
            sha256(message),
        )
        assertArrayEquals(owner.publicKeyCompressed, recovered)
    }

    @Test
    fun signSelfProof_nullOnZeroPrivateKey() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(13))
        val eventKeyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret(6), "self-proof-event-zero")

        val sig = BarnardSigning.signSelfProof(
            ownerPrivateKey = java.math.BigInteger.ZERO,
            eventIdHash = sha256("event-zero".toByteArray(Charsets.UTF_8)),
            eventSigningPublicKey = eventKeyPair.publicKeyCompressed,
            eninStart = 1uL,
            eninEnd = 2uL,
            ownerPublicKey = owner.publicKeyCompressed,
        )

        assertNull(sig)
    }

    @Test
    fun signSelfProof_nullWhenPrivateKeyDoesNotMatchOwnerPublicKey() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(10))
        val otherOwner = BarnardSigning.deriveOwnerKeyPair(accountSecret(11))
        val eventKeyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret(5), "self-proof-event-5")

        val sig = BarnardSigning.signSelfProof(
            ownerPrivateKey = otherOwner.privateKey,
            eventIdHash = sha256("event5".toByteArray(Charsets.UTF_8)),
            eventSigningPublicKey = eventKeyPair.publicKeyCompressed,
            eninStart = 1uL,
            eninEnd = 2uL,
            ownerPublicKey = owner.publicKeyCompressed,
        )

        assertNull(sig)
    }

    // MARK: - Wallet acknowledgement (barnard#133 / barnard#92)

    @Test
    fun walletAcknowledgementMessage_hasExpectedLayoutAndLength() {
        val walletAddress = ByteArray(20) { (it + 5).toByte() }
        val walletSignature = ByteArray(65) { (it + 9).toByte() }

        val message = BarnardSigning.buildWalletAcknowledgementMessage(walletAddress, walletSignature)

        assertNotNull(message)
        assertEquals(73, message!!.size)

        val domainTagBytes = "barnard-wallet-ack:v1".toByteArray(Charsets.UTF_8)
        assertArrayEquals(domainTagBytes, message.copyOfRange(0, domainTagBytes.size))
        var offset = domainTagBytes.size
        assertArrayEquals(walletAddress, message.copyOfRange(offset, offset + 20))
        offset += 20
        assertArrayEquals(sha256(walletSignature), message.copyOfRange(offset, offset + 32))
    }

    @Test
    fun walletAcknowledgementMessage_nullOnGuardFailures() {
        assertNull(BarnardSigning.buildWalletAcknowledgementMessage(ByteArray(19), byteArrayOf(1)))
        assertNull(BarnardSigning.buildWalletAcknowledgementMessage(ByteArray(20), ByteArray(0)))
    }

    @Test
    fun signWalletAcknowledgement_recoversToOwnerPublicKey() {
        val owner = BarnardSigning.deriveOwnerKeyPair(accountSecret(12))
        val walletAddress = ByteArray(20) { (it + 1).toByte() }
        val walletSignature = ByteArray(65) { (it + 2).toByte() }

        val sig = BarnardSigning.signWalletAcknowledgement(owner.privateKey, walletAddress, walletSignature)
        assertNotNull(sig)

        val message = BarnardSigning.buildWalletAcknowledgementMessage(walletAddress, walletSignature)!!
        val recovered = BarnardSigning.recoverPublicKey(
            sig!!.v,
            sig.r,
            sig.s,
            sha256(message),
        )
        assertArrayEquals(owner.publicKeyCompressed, recovered)
    }

    @Test
    fun signWalletAcknowledgement_nullOnZeroPrivateKey() {
        val sig = BarnardSigning.signWalletAcknowledgement(
            java.math.BigInteger.ZERO,
            ByteArray(20),
            byteArrayOf(1),
        )
        assertNull(sig)
    }
}
