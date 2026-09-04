// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.io.File
import java.math.BigInteger
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * Cross-language conformance test (barnard#133 / barnard#92): loads the
 * vectors pinned by the Swift `BarnardCore` reference implementation from
 * `test-vectors/owner-key-v1.txt` and asserts this Kotlin implementation
 * produces byte-identical output. See `test-vectors/README.md` for the file
 * format this parser implements.
 */
class BarnardOwnerKeyConformanceVectorTest {

    private val vectors: Map<String, String> by lazy { parseVectors(File(findRepoRoot(), "test-vectors/owner-key-v1.txt")) }
    private val ecdsaVectors: Map<String, String> by lazy {
        parseVectors(File(findRepoRoot(), "test-vectors/secp256k1-ecdsa-v1.txt"))
    }

    private fun v(key: String): String = vectors[key] ?: error("missing vector key: $key")
    private fun ev(key: String): String = ecdsaVectors[key] ?: error("missing ECDSA vector key: $key")

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0) { "odd-length hex value: $value" }
        return ByteArray(value.length / 2) { i -> value.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    /**
     * Walk upward from the Gradle unit-test working directory (not
     * guaranteed identical across invocations) looking for a sibling
     * `test-vectors/owner-key-v1.txt`. Bounded so a missing/moved directory
     * fails the test instead of looping forever.
     */
    private fun findRepoRoot(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        var levels = 0
        while (dir != null && levels < 20) {
            if (File(dir, "test-vectors/owner-key-v1.txt").isFile) return dir
            dir = dir.parentFile
            levels++
        }
        fail(
            "Could not locate repo root containing test-vectors/owner-key-v1.txt by walking up " +
                "from ${System.getProperty("user.dir")} (searched $levels levels)",
        )
        error("unreachable")
    }

    /** Decodes the two escapes defined by test-vectors/README.md: `\n` -> newline, `\\` -> backslash. */
    private fun decodeEscapes(raw: String): String {
        val out = StringBuilder(raw.length)
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            if (c == '\\') {
                require(i + 1 < raw.length) { "trailing backslash in vector value: $raw" }
                when (raw[i + 1]) {
                    'n' -> out.append('\n')
                    '\\' -> out.append('\\')
                    else -> error("malformed escape \\${raw[i + 1]} in vector value: $raw")
                }
                i += 2
            } else {
                out.append(c)
                i += 1
            }
        }
        return out.toString()
    }

    private fun parseVectors(file: File): Map<String, String> {
        val keyPattern = Regex("[A-Za-z0-9_]+")
        val result = LinkedHashMap<String, String>()
        for (line in file.readLines(Charsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) continue
            val eq = line.indexOf('=')
            require(eq > 0) { "malformed vector line (no '=' or empty key): $line" }
            val key = line.substring(0, eq)
            require(keyPattern.matches(key)) { "malformed vector key: $key" }
            result[key] = decodeEscapes(line.substring(eq + 1))
        }
        return result
    }

    @Test
    fun deriveOwnerKeyPair_matchesVectors() {
        for (prefix in listOf("owner_zero", "owner_seq")) {
            val accountSecret = hex(v("${prefix}_account_secret"))
            val expectedPrivateKey = BigInteger(v("${prefix}_private_key"), 16)
            val expectedPublicKey = hex(v("${prefix}_public_key"))

            val keyPair = BarnardSigning.deriveOwnerKeyPair(accountSecret)

            assertEquals(expectedPrivateKey, keyPair.privateKey)
            assertArrayEquals(expectedPublicKey, keyPair.publicKeyCompressed)
        }
    }

    @Test
    fun buildAccountBindingText_matchesVector() {
        val text = BarnardSigning.buildAccountBindingText(
            domain = v("binding_domain"),
            walletAddress = hex(v("binding_wallet_address")),
            ownerPublicKey = hex(v("binding_owner_public_key")),
            chainId = v("binding_chain_id").toULong(),
            nonce = hex(v("binding_nonce")),
            issuedAt = v("binding_issued_at"),
        )

        assertNotNull(text)
        assertEquals(v("binding_expected_text"), text)
    }

    @Test
    fun selfProof_matchesVectors() {
        val eventIdHash = hex(v("selfproof_event_id_hash"))
        val eventSigningPublicKey = hex(v("selfproof_event_signing_public_key"))
        val eninStart = v("selfproof_enin_start").toULong()
        val eninEnd = v("selfproof_enin_end").toULong()
        val ownerPrivateKey = BigInteger(v("selfproof_owner_private_key"), 16)
        val ownerPublicKey = hex(v("selfproof_owner_public_key"))

        val message = BarnardSigning.buildSelfProofMessage(eventIdHash, eventSigningPublicKey, eninStart, eninEnd, ownerPublicKey)
        assertNotNull(message)
        assertArrayEquals(hex(v("selfproof_expected_message")), message)

        val sig = BarnardSigning.signSelfProof(ownerPrivateKey, eventIdHash, eventSigningPublicKey, eninStart, eninEnd, ownerPublicKey)
        assertNotNull(sig)
        assertArrayEquals(hex(v("selfproof_expected_sig_r")), sig!!.r)
        assertArrayEquals(hex(v("selfproof_expected_sig_s")), sig.s)
        assertEquals(v("selfproof_expected_sig_v").toInt(), sig.v)
    }

    @Test
    fun walletAcknowledgement_matchesVectors() {
        val walletAddress = hex(v("walletack_wallet_address"))
        val walletSignature = hex(v("walletack_wallet_signature"))
        val ownerPrivateKey = BigInteger(v("walletack_owner_private_key"), 16)
        val ownerPublicKey = hex(v("walletack_owner_public_key"))

        val message = BarnardSigning.buildWalletAcknowledgementMessage(walletAddress, walletSignature)
        assertNotNull(message)
        assertArrayEquals(hex(v("walletack_expected_message")), message)

        val sig = BarnardSigning.signWalletAcknowledgement(ownerPrivateKey, walletAddress, walletSignature)
        assertNotNull(sig)
        assertArrayEquals(hex(v("walletack_expected_sig_r")), sig!!.r)
        assertArrayEquals(hex(v("walletack_expected_sig_s")), sig.s)
        assertEquals(v("walletack_expected_sig_v").toInt(), sig.v)

        val recovered = BarnardSigning.recoverPublicKey(
            sig.v,
            BigInteger(1, sig.r),
            BigInteger(1, sig.s),
            MessageDigest.getInstance("SHA-256").digest(message!!),
        )
        assertArrayEquals(ownerPublicKey, recovered)
    }

    @Test
    fun ecdsaProfile_positiveVector() {
        val signature = BarnardSigning.signRecoverable(BigInteger(ev("private_key_valid"), 16), hex(ev("message_hash")))
        assertArrayEquals(hex(ev("expected_r")), signature.r)
        assertArrayEquals(hex(ev("expected_s")), signature.s)
        assertEquals(ev("expected_v").toInt(), signature.v)
        assertArrayEquals(
            hex(ev("public_key_compressed")),
            BarnardSigning.recoverPublicKey(
                signature.v,
                BigInteger(1, signature.r),
                BigInteger(1, signature.s),
                hex(ev("message_hash")),
            ),
        )
    }

    @Test
    fun ecdsaProfile_rejectsPrivateKeyBoundariesAndOffCurveKey() {
        for (key in listOf("private_key_zero", "private_key_n", "private_key_n_plus_one")) {
            assertNull(
                key,
                BarnardSigning.signWalletAcknowledgement(
                    BigInteger(ev(key), 16), ByteArray(20), byteArrayOf(1),
                ),
            )
        }
        assertNull(
            BarnardSigning.buildSelfProofMessage(
                ByteArray(32), hex(ev("off_curve_public_key")), 0u, 0u,
                hex(ev("public_key_compressed")),
            ),
        )
    }

    private fun assertMalformedComponentRejected(rKey: String = "expected_r", sKey: String = "expected_s") {
        val hash = hex(ev("message_hash"))
        assertNull(
            "$rKey/$sKey",
            BarnardSigning.recoverPublicKey(
                ev("expected_v").toInt(), BigInteger(1, hex(ev(rKey))),
                BigInteger(1, hex(ev(sKey))), hash,
            ),
        )
    }

    @Test
    fun ecdsaProfile_rejectsShortR() = assertMalformedComponentRejected(rKey = "malformed_r_short")

    @Test
    fun ecdsaProfile_rejectsLongR() = assertMalformedComponentRejected(rKey = "malformed_r_long")

    @Test
    fun ecdsaProfile_rejectsShortS() = assertMalformedComponentRejected(sKey = "malformed_s_short")

    @Test
    fun ecdsaProfile_rejectsLongS() = assertMalformedComponentRejected(sKey = "malformed_s_long")

    @Test
    fun ecdsaProfile_rejectsHighS() {
        val hash = hex(ev("message_hash"))
        val r = BigInteger(ev("expected_r"), 16)
        assertNull(
            BarnardSigning.recoverPublicKey(
                ev("high_s_recovery_v").toInt(), r, BigInteger(ev("high_s"), 16), hash,
            ),
        )
    }

    @Test
    fun ecdsaProfile_rejectsOutOfRangeRecoveryId() {
        assertNull(
            BarnardSigning.recoverPublicKey(
                ev("out_of_range_recovery_id").toInt(), BigInteger(ev("expected_r"), 16),
                BigInteger(ev("expected_s"), 16), hex(ev("message_hash")),
            ),
        )
    }
}
