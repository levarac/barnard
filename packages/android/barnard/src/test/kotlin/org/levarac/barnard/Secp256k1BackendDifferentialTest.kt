// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.io.File
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Proves the production backend remains byte-identical to the removed main-source implementation. */
class Secp256k1BackendDifferentialTest {
    private val production: Secp256k1Backend = BouncyCastleSecp256k1Backend
    private val legacy: Secp256k1Backend = HandRolledSecp256k1Backend

    @Test
    fun vectorsAndTwoHundredSeededPairs_areByteIdentical() {
        val owner = vectors("owner-key-v1.txt")
        for (prefix in listOf("owner_zero", "owner_seq")) {
            comparePublic(BigInteger(owner.getValue("${prefix}_private_key"), 16))
        }
        compareSignature(
            BigInteger(owner.getValue("selfproof_owner_private_key"), 16),
            sha256(hex(owner.getValue("selfproof_expected_message"))),
        )
        compareSignature(
            BigInteger(owner.getValue("walletack_owner_private_key"), 16),
            sha256(hex(owner.getValue("walletack_expected_message"))),
        )

        val profile = vectors("secp256k1-ecdsa-v1.txt")
        val d = BigInteger(profile.getValue("private_key_valid"), 16)
        val hash = hex(profile.getValue("message_hash"))
        comparePublic(d)
        compareSignature(d, hash)
        for (key in listOf("private_key_zero", "private_key_n", "private_key_n_plus_one")) {
            assertEquals(null, production.normalizePrivateKey(BigInteger(profile.getValue(key), 16)))
            assertEquals(null, legacy.normalizePrivateKey(BigInteger(profile.getValue(key), 16)))
        }
        for ((rKey, sKey) in listOf(
            "malformed_r_short" to "expected_s", "malformed_r_long" to "expected_s",
            "expected_r" to "malformed_s_short", "expected_r" to "malformed_s_long",
            "expected_r" to "high_s",
        )) {
            val r = hex(profile.getValue(rKey))
            val s = hex(profile.getValue(sKey))
            assertNull(production.recoverPublicKey(profile.getValue("expected_v").toInt(), r, s, hash))
            assertNull(legacy.recoverPublicKey(profile.getValue("expected_v").toInt(), r, s, hash))
        }
        assertNull(production.recoverPublicKey(2, hex(profile.getValue("expected_r")), hex(profile.getValue("expected_s")), hash))
        assertNull(legacy.recoverPublicKey(2, hex(profile.getValue("expected_r")), hex(profile.getValue("expected_s")), hash))

        val random = SecureRandom.getInstance("SHA1PRNG").apply { setSeed(byteArrayOf(0x16, 0x00, 0x13, 0x07)) }
        repeat(200) {
            val keyBytes = ByteArray(32)
            var key: BigInteger
            do {
                random.nextBytes(keyBytes)
                key = BigInteger(1, keyBytes)
            } while (production.normalizePrivateKey(key) == null)
            val randomHash = ByteArray(32).also(random::nextBytes)
            comparePublic(key)
            compareSignature(key, randomHash)
        }
    }

    private fun comparePublic(key: BigInteger) =
        assertArrayEquals(legacy.compressedPublicKey(key), production.compressedPublicKey(key))

    private fun compareSignature(key: BigInteger, hash: ByteArray) {
        val expected = legacy.signRecoverable(key, hash)
        val actual = production.signRecoverable(key, hash)
        assertArrayEquals(expected.r, actual.r)
        assertArrayEquals(expected.s, actual.s)
        assertEquals(expected.v, actual.v)
        assertArrayEquals(
            legacy.recoverPublicKey(expected.v, expected.r, expected.s, hash),
            production.recoverPublicKey(actual.v, actual.r, actual.s, hash),
        )
    }

    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    private fun hex(value: String) = ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun vectors(name: String): Map<String, String> {
        var directory: File? = File(System.getProperty("user.dir")).absoluteFile
        repeat(20) {
            val file = directory?.resolve("test-vectors/$name")
            if (file?.isFile == true) return file.readLines().filter { it.isNotBlank() && !it.startsWith("#") }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
            directory = directory?.parentFile
        }
        error("could not locate test-vectors/$name")
    }
}
