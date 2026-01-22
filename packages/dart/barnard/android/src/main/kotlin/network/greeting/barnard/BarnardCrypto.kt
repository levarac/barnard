// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * GAEN v1.2-compatible cryptographic utilities for Resolvable ID.
 *
 * Key derivation chain:
 * ```
 * DeviceSecret (32 bytes)
 *      |
 *      +-- Anonymous Mode: TEK = random 16 bytes
 *      |
 *      +-- Event Mode: TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)
 *                           |
 *                           v
 *                      RPIK = HKDF(TEK, "EN-RPIK", 16)
 *                           |
 *                           v
 *                      RPI = AES128-ECB(RPIK, PaddedData)
 * ```
 */
object BarnardCrypto {

    // MARK: - TEK Derivation

    /**
     * Derive TEK for Event Mode from DeviceSecret and EventCode.
     *
     * `TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)`
     */
    fun deriveTekForEvent(deviceSecret: ByteArray, eventCode: String): ByteArray {
        val eventCodeBytes = eventCode.toByteArray(Charsets.UTF_8)
        val combined = deviceSecret + eventCodeBytes
        return hkdfSha256(combined, "barnard-tek".toByteArray(Charsets.UTF_8), 16)
    }

    /**
     * Generate a random TEK for Anonymous Mode.
     */
    fun generateRandomTek(): ByteArray = generateRandomBytes(16)

    // MARK: - RPIK Derivation

    /**
     * Derive RPIK (Rolling Proximity Identifier Key) from TEK.
     *
     * `RPIK = HKDF(TEK, "EN-RPIK", 16)`
     */
    fun deriveRpik(tek: ByteArray): ByteArray {
        if (tek.size != 16) return ByteArray(16)
        return hkdfSha256(tek, "EN-RPIK".toByteArray(Charsets.UTF_8), 16)
    }

    // MARK: - RPI Generation

    /**
     * Generate RPI from RPIK and ENIN.
     *
     * `RPI = AES128-ECB(RPIK, PaddedData)`
     *
     * Where PaddedData = "EN-RPI" (6 bytes) + 0x000000000000 (6 bytes) + ENIN (4 bytes big-endian)
     */
    fun generateRpi(rpik: ByteArray, enin: UInt): ByteArray {
        if (rpik.size != 16) return ByteArray(16)

        // Build PaddedData: "EN-RPI" + 6 zero bytes + ENIN (4 bytes big-endian)
        val paddedData = ByteArray(16)

        // "EN-RPI" (6 bytes)
        val prefix = "EN-RPI".toByteArray(Charsets.UTF_8)
        System.arraycopy(prefix, 0, paddedData, 0, 6)

        // 6 zero bytes (already initialized to 0)

        // ENIN as 4 bytes big-endian at offset 12
        val eninBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(enin.toInt()).array()
        System.arraycopy(eninBytes, 0, paddedData, 12, 4)

        // AES-128-ECB encryption
        return aes128EcbEncrypt(rpik, paddedData)
    }

    /**
     * AES-128-ECB encryption of a single 16-byte block.
     */
    private fun aes128EcbEncrypt(key: ByteArray, plaintext: ByteArray): ByteArray {
        if (key.size != 16 || plaintext.size != 16) return ByteArray(16)

        return try {
            val cipher = Cipher.getInstance("AES/ECB/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
            cipher.doFinal(plaintext)
        } catch (e: Exception) {
            ByteArray(16)
        }
    }

    // MARK: - ENIN Calculation

    /**
     * Calculate ENIN (EN Interval Number) for a given timestamp.
     *
     * `ENIN = floor(unix_timestamp_seconds / 600)`
     *
     * Each ENIN represents a 10-minute interval.
     */
    fun calculateEnin(timestampMs: Long = System.currentTimeMillis()): UInt {
        return ((timestampMs / 1000) / 600).toUInt()
    }

    // MARK: - EventCodeHash

    /**
     * Calculate EventCodeHash from EventCode.
     *
     * `EventCodeHash = SHA256(EventCode)[0:8]`
     */
    fun computeEventCodeHash(eventCode: String): ByteArray {
        val eventCodeBytes = eventCode.toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(eventCodeBytes)
        return hash.copyOfRange(0, 8)
    }

    // MARK: - RPI Resolution

    /**
     * Attempt to resolve an RPI to a known TEK.
     *
     * Searches within a time window around the current ENIN (±6 past + 1 future).
     *
     * @param rpi The 16-byte RPI to resolve
     * @param knownTeks List of known TEKs to search
     * @param currentEnin Current ENIN (defaults to now)
     * @return The matching TEK if found, null otherwise
     */
    fun resolveRpi(rpi: ByteArray, knownTeks: List<ByteArray>, currentEnin: UInt? = null): ByteArray? {
        if (rpi.size != 16) return null

        val enin = currentEnin ?: calculateEnin()

        for (tek in knownTeks) {
            if (tek.size != 16) continue

            val rpik = deriveRpik(tek)

            // Search window: 6 intervals past + current + 1 future
            for (offset in -6..1) {
                val testEnin = (enin.toInt() + offset).toUInt()
                val candidate = generateRpi(rpik, testEnin)

                if (candidate.contentEquals(rpi)) {
                    return tek
                }
            }
        }

        return null
    }

    // MARK: - Display ID

    /**
     * Get displayId from TEK (first 3 bytes as uppercase hex).
     */
    fun displayId(tek: ByteArray): String {
        return tek.take(3).joinToString("") { "%02X".format(it) }
    }

    // MARK: - HKDF

    /**
     * HKDF-SHA256 key derivation (simplified: no salt, extract-then-expand).
     */
    private fun hkdfSha256(ikm: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        // Extract: PRK = HMAC-SHA256(salt=zeros, IKM)
        val salt = ByteArray(32) // All zeros
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        // Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info)
        mac.update(0x01.toByte())
        val okm = mac.doFinal()

        return okm.copyOfRange(0, outputLength)
    }

    // MARK: - Random Bytes

    /**
     * Generate cryptographically secure random bytes.
     */
    fun generateRandomBytes(count: Int): ByteArray {
        val bytes = ByteArray(count)
        SecureRandom().nextBytes(bytes)
        return bytes
    }
}
