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
 * GAEN v1.2-compatible cryptographic utilities for Resolvable ID (v2).
 *
 * Key derivation chain:
 * ```
 * DeviceSecret (32 bytes)
 *      |
 *      +-- Anonymous Mode: TEK = HKDF(DeviceSecret, "barnard-tek-anonymous", 16)
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
    enum class EninMode { FIXED_LENGTH, BEACON_SLOT }

    const val rpidBoundaryRetryDelayMs: Long = 250L

    data class BeaconChainConfig(
        val chainId: String = "mainnet",
        val genesisUnixSeconds: Long = 1606824023L,
        val slotSeconds: Long = 12L,
    ) {
        val effectiveGenesisUnixSeconds: Long
            get() = genesisUnixSeconds.coerceAtLeast(0L)
        val effectiveSlotSeconds: Long
            get() = slotSeconds.coerceAtLeast(1L)
    }

    fun deriveTekForEvent(deviceSecret: ByteArray, eventCode: String): ByteArray {
        val eventCodeBytes = eventCode.toByteArray(Charsets.UTF_8)
        val combined = deviceSecret + eventCodeBytes
        return hkdfSha256(combined, "barnard-tek".toByteArray(Charsets.UTF_8), 16)
    }

    fun deriveTekForAnonymous(deviceSecret: ByteArray): ByteArray {
        return hkdfSha256(deviceSecret, "barnard-tek-anonymous".toByteArray(Charsets.UTF_8), 16)
    }

    fun deriveRpik(tek: ByteArray): ByteArray {
        if (tek.size != 16) return ByteArray(16)
        return hkdfSha256(tek, "EN-RPIK".toByteArray(Charsets.UTF_8), 16)
    }

    fun generateRpi(rpik: ByteArray, enin: UInt): ByteArray {
        if (rpik.size != 16) return ByteArray(16)

        val paddedData = ByteArray(16)
        val prefix = "EN-RPI".toByteArray(Charsets.UTF_8)
        System.arraycopy(prefix, 0, paddedData, 0, 6)

        val eninBytes = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(enin.toInt()).array()
        System.arraycopy(eninBytes, 0, paddedData, 12, 4)

        return aes128EcbEncrypt(rpik, paddedData)
    }

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

    fun calculateEnin(
        timestampMs: Long = System.currentTimeMillis(),
        mode: EninMode = EninMode.FIXED_LENGTH,
        eninSeconds: Long = 300L,
        beaconChain: BeaconChainConfig = BeaconChainConfig(),
    ): UInt {
        val unixSeconds = timestampMs / 1000
        return when (mode) {
            EninMode.FIXED_LENGTH -> {
                val effectiveSeconds = eninSeconds.coerceIn(12L, 3600L)
                (unixSeconds / effectiveSeconds).toUInt()
            }
            EninMode.BEACON_SLOT -> {
                val elapsed = unixSeconds - beaconChain.effectiveGenesisUnixSeconds
                if (elapsed <= 0L) 0U else (elapsed / beaconChain.effectiveSlotSeconds).toUInt()
            }
        }
    }

    fun stableReadEnin(
        startedAtMs: Long,
        completedAtMs: Long,
        mode: EninMode = EninMode.FIXED_LENGTH,
        eninSeconds: Long = 300L,
        beaconChain: BeaconChainConfig = BeaconChainConfig(),
    ): UInt? {
        val startedEnin = calculateEnin(startedAtMs, mode, eninSeconds, beaconChain)
        val completedEnin = calculateEnin(completedAtMs, mode, eninSeconds, beaconChain)
        return if (startedEnin == completedEnin) completedEnin else null
    }

    fun computeEventCodeHash(eventCode: String): ByteArray {
        val eventCodeBytes = eventCode.toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(eventCodeBytes)
        return hash.copyOfRange(0, 8)
    }

    // MARK: - v2 displayId

    /** v2 displayId bytes: SHA256(TEK)[0:4] = 4 bytes. */
    fun displayId4(tek: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(tek)
        return hash.copyOfRange(0, 4)
    }

    /** v2 displayId string: 8 lowercase hex chars, SHA256(TEK)[0:4]. */
    fun displayIdString(tek: ByteArray): String {
        return displayId4(tek).toHex()
    }

    /** Lowercase-hex encoder for the RN bridge boundary. */
    fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    internal fun hkdfSha256(ikm: ByteArray, info: ByteArray, outputLength: Int): ByteArray {
        val salt = ByteArray(32)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(info)
        mac.update(0x01.toByte())
        val okm = mac.doFinal()

        return okm.copyOfRange(0, outputLength)
    }

    fun generateRandomBytes(count: Int): ByteArray {
        val bytes = ByteArray(count)
        SecureRandom().nextBytes(bytes)
        return bytes
    }
}
