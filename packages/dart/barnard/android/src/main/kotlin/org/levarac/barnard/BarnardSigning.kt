// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.math.BigInteger

/**
 * Per-event device signing identity (barnard#65).
 *
 * Key derivation chain:
 * ```
 * DeviceSecret (32 bytes)
 *      |
 *      +-- signSeed = HKDF(DeviceSecret || EventCode, "barnard-sign", 32)
 *                          |
 *                          v
 *                     secp256k1 keypair (signSeed reduced mod curve order)
 * ```
 *
 * Mirrors the TEK event-mode derivation shape
 * (`TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)`) but uses a
 * distinct HKDF `info` string ("barnard-sign" vs "barnard-tek" / "EN-RPIK")
 * so the signing key and the TEK/RPIK chain are not cross-computable.
 *
 * Delegates secp256k1 operations to a narrow, independently testable backend.
 */
internal object BarnardSigning {
    const val signingKeyInfo = "barnard-sign"
    const val ownerKeyInfo = "barnard-owner"

    /** Domain-separation tag for [buildRpidProofMessage] (barnard#63). */
    const val rpidProofDomainTag = "barnard-rpid-proof:v1"

    /** Domain-separation tag for [buildKeyBindingMessage] (barnard#63). */
    const val keyBindingDomainTag = "barnard-key-binding:v1"

    /** Domain-separation tag for [buildSelfProofMessage] (barnard#133 / barnard#92). */
    const val selfProofDomainTag = "barnard-self-proof:v1"

    /** Domain-separation tag for [buildWalletAcknowledgementMessage] (barnard#133 / barnard#92). */
    const val walletAcknowledgementDomainTag = "barnard-wallet-ack:v1"

    /** Domain-separation tag for [buildAccountBindingText] (barnard#133 / barnard#92). */
    const val accountBindingDomainTag = "barnard-account-binding:v1"

    private val secp256k1: Secp256k1Backend = BouncyCastleSecp256k1Backend

    // MARK: - Key derivation

    data class SigningKeyPair(val privateKey: BigInteger, val publicKeyCompressed: ByteArray)

    /**
     * Derive the per-event signing keypair from [deviceSecret] and [eventCode].
     */
    fun deriveSigningKeyPair(deviceSecret: ByteArray, eventCode: String): SigningKeyPair {
        val combined = deviceSecret + eventCode.toByteArray(Charsets.UTF_8)
        var seed = BarnardCrypto.hkdfSha256(combined, signingKeyInfo.toByteArray(Charsets.UTF_8), 32)
        var d = BigInteger(1, seed).mod(SECP256K1_N)
        while (d.signum() == 0) {
            seed = sha256(seed)
            d = BigInteger(1, seed).mod(SECP256K1_N)
        }
        return SigningKeyPair(d, checkNotNull(secp256k1.compressedPublicKey(d)))
    }

    /**
     * Derive the long-lived owner keypair from a 32-byte AccountSecret
     * (barnard#133 / barnard#92). Same convention as [deriveSigningKeyPair]:
     * HKDF-SHA256(IKM=accountSecret, info="barnard-owner", 32 bytes) ->
     * reduce mod curve order -> re-hash the seed with SHA-256 and retry if
     * the reduced scalar is zero. Unlike [deriveSigningKeyPair], the IKM is
     * the account secret alone (no event-code concatenation).
     */
    fun deriveOwnerKeyPair(accountSecret: ByteArray): SigningKeyPair {
        require(accountSecret.size == 32) { "accountSecret must be 32 bytes" }
        var seed = BarnardCrypto.hkdfSha256(accountSecret, ownerKeyInfo.toByteArray(Charsets.UTF_8), 32)
        var d = BigInteger(1, seed).mod(SECP256K1_N)
        while (d.signum() == 0) {
            seed = sha256(seed)
            d = BigInteger(1, seed).mod(SECP256K1_N)
        }
        return SigningKeyPair(d, checkNotNull(secp256k1.compressedPublicKey(d)))
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)

    // MARK: - RPID ownership proof / key binding (barnard#63)

    /**
     * Canonical, fixed-order/length-prefixed encoding of an RPID ownership
     * proof claim:
     * `"barnard-rpid-proof:v1" ‖ eventIdHash(32) ‖ enin(8, BE) ‖ rpi(16) ‖ len(challenge) as u16 BE ‖ challenge`.
     */
    fun buildRpidProofMessage(eventIdHash: ByteArray, enin: Long, rpi: ByteArray, challenge: ByteArray?): ByteArray {
        require(eventIdHash.size == 32) { "eventIdHash must be 32 bytes" }
        require(rpi.size == 16) { "rpi must be 16 bytes" }
        val challengeBytes = challenge ?: ByteArray(0)
        require(challengeBytes.size <= 0xffff) { "challenge too long" }

        val eninBytes = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(enin).array()
        val lenBytes = java.nio.ByteBuffer.allocate(2).order(java.nio.ByteOrder.BIG_ENDIAN)
            .putShort(challengeBytes.size.toShort()).array()

        return rpidProofDomainTag.toByteArray(Charsets.UTF_8) + eventIdHash + eninBytes + rpi + lenBytes + challengeBytes
    }

    /** Canonical encoding of a signing-key-to-device-identity binding claim. */
    fun buildKeyBindingMessage(eventCodeHash: ByteArray, displayId: ByteArray): ByteArray {
        return keyBindingDomainTag.toByteArray(Charsets.UTF_8) + eventCodeHash + displayId
    }

    data class RpidOwnershipProof(
        val rpi: ByteArray,
        val enin: Long,
        val eventIdHash: ByteArray,
        val signingPublicKey: ByteArray,
        val sig: RecoverableSignature,
    )

    /**
     * Compute the RPID ownership proof for [enin] within [eventCode], per
     * barnard#63. Derives the TEK/RPIK/RPI internally from [deviceSecret]
     * (via [BarnardCrypto]) — only the resulting `rpi` (not the TEK/RPIK)
     * appears in the output.
     */
    fun proveRpidOwnership(
        deviceSecret: ByteArray,
        eventCode: String,
        eventIdHash: ByteArray,
        enin: Long,
        challenge: ByteArray?,
    ): RpidOwnershipProof {
        val tek = BarnardCrypto.deriveTekForEvent(deviceSecret, eventCode)
        val rpik = BarnardCrypto.deriveRpik(tek)
        val rpi = BarnardCrypto.generateRpi(rpik, enin.toUInt())

        val message = buildRpidProofMessage(eventIdHash, enin, rpi, challenge)
        val keyPair = deriveSigningKeyPair(deviceSecret, eventCode)
        val sig = signRecoverable(keyPair.privateKey, sha256(message))

        return RpidOwnershipProof(rpi, enin, eventIdHash, keyPair.publicKeyCompressed, sig)
    }

    /** Sign the key-binding claim per barnard#63 acceptance criterion 3. */
    fun signKeyBinding(deviceSecret: ByteArray, eventCode: String, eventCodeHash: ByteArray, displayId: ByteArray): RecoverableSignature {
        val message = buildKeyBindingMessage(eventCodeHash, displayId)
        val keyPair = deriveSigningKeyPair(deviceSecret, eventCode)
        return signRecoverable(keyPair.privateKey, sha256(message))
    }

    // MARK: - Owner key: account binding, self-proof, wallet acknowledgement (barnard#133 / barnard#92)

    /** 33-byte SEC1-compressed encoding whose point is on secp256k1. */
    private fun isValidCompressedPublicKey(publicKey: ByteArray): Boolean =
        secp256k1.isValidCompressedPublicKey(publicKey)

    private fun lowercaseHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun isLowercaseAsciiLetterOrDigit(byte: Byte): Boolean {
        val value = byte.toInt()
        return value in 0x61..0x7a || value in 0x30..0x39
    }

    /** Lowercase hostname, optionally `:port` (1-65535, no leading zero) — RFC 3986 `reg-name` subset used by [buildAccountBindingText]. */
    private fun isCanonicalDomain(domain: String): Boolean {
        val bytes = domain.toByteArray(Charsets.UTF_8)
        if (bytes.isEmpty() || !isLowercaseAsciiLetterOrDigit(bytes[0])) return false

        var colonIndex: Int? = null
        for (index in bytes.indices) {
            val byte = bytes[index]
            if (colonIndex != null) {
                if (byte.toInt() !in 0x30..0x39) return false
                continue
            }
            when {
                byte.toInt() in 0x61..0x7a || byte.toInt() in 0x30..0x39 || byte == 0x2d.toByte() || byte == 0x2e.toByte() -> {}
                byte == 0x3a.toByte() -> {
                    if (index == 0) return false
                    colonIndex = index
                }
                else -> return false
            }
        }

        val hostEnd = colonIndex ?: bytes.size
        if (hostEnd <= 0 || !isLowercaseAsciiLetterOrDigit(bytes[hostEnd - 1])) return false
        val ci = colonIndex ?: return true

        val portBytes = bytes.copyOfRange(ci + 1, bytes.size)
        if (portBytes.isEmpty() || portBytes.size > 5) return false
        if (!portBytes.all { it.toInt() in 0x30..0x39 }) return false
        if (portBytes.size != 1 && portBytes[0] == 0x30.toByte()) return false
        val port = String(portBytes, Charsets.UTF_8).toLongOrNull() ?: return false
        return port <= 65535
    }

    /** `YYYY-MM-DDTHH:MM:SSZ`, calendar-valid — the fixed-width ISO-8601 UTC shape used by [buildAccountBindingText]. */
    private fun isCanonicalIssuedAt(value: String): Boolean {
        val bytes = value.toByteArray(Charsets.UTF_8)
        if (bytes.size != 20) return false
        if (bytes[4] != 0x2d.toByte() || bytes[7] != 0x2d.toByte() || bytes[10] != 0x54.toByte() ||
            bytes[13] != 0x3a.toByte() || bytes[16] != 0x3a.toByte() || bytes[19] != 0x5a.toByte()
        ) {
            return false
        }

        val digitPositions = intArrayOf(0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18)
        if (!digitPositions.all { bytes[it].toInt() in 0x30..0x39 }) return false

        fun digit(index: Int): Int = bytes[index].toInt() - 0x30
        fun decimal(first: Int, second: Int): Int = digit(first) * 10 + digit(second)

        val year = decimal(0, 1) * 100 + decimal(2, 3)
        val month = decimal(5, 6)
        val day = decimal(8, 9)
        val hour = decimal(11, 12)
        val minute = decimal(14, 15)
        val second = decimal(17, 18)
        if (month !in 1..12 || hour !in 0..23 || minute !in 0..59 || second !in 0..59) return false

        val daysInMonth = intArrayOf(31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
        val isLeapYear = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        if (isLeapYear) daysInMonth[1] = 29
        return day in 1..daysInMonth[month - 1]
    }

    /**
     * Canonical, EIP-4361-shaped human-readable text a host hands to a
     * wallet's `personal_sign` to bind [walletAddress] to [ownerPublicKey]
     * (barnard#133 / barnard#92). Returns `null` on any guard failure
     * (invalid input is data, not a programmer error, per the spec).
     */
    fun buildAccountBindingText(
        domain: String,
        walletAddress: ByteArray,
        ownerPublicKey: ByteArray,
        chainId: ULong,
        nonce: ByteArray,
        issuedAt: String,
    ): String? {
        if (!isCanonicalDomain(domain) ||
            walletAddress.size != 20 ||
            !isValidCompressedPublicKey(ownerPublicKey) ||
            nonce.size != 16 ||
            !isCanonicalIssuedAt(issuedAt)
        ) {
            return null
        }

        return listOf(
            "$domain wants to bind this wallet to a Levarac owner key.",
            "",
            "This signature authorizes no transaction and moves no assets.",
            "",
            "Domain-Tag: $accountBindingDomainTag",
            "Wallet: 0x${lowercaseHex(walletAddress)}",
            "Owner-Key: 0x${lowercaseHex(ownerPublicKey)}",
            "Chain-ID: eip155:$chainId",
            "Scope: global",
            "Nonce: 0x${lowercaseHex(nonce)}",
            "Issued-At: $issuedAt",
        ).joinToString("\n")
    }

    /**
     * Canonical, fixed-order/length encoding of a self-proof claim binding
     * [eventSigningPublicKey] to [ownerPublicKey] for the ENIN range
     * `[eninStart, eninEnd]` (barnard#133 / barnard#92):
     * `"barnard-self-proof:v1" ‖ eventIdHash(32) ‖ eventSigningPublicKey(33) ‖ eninStart(8, BE) ‖ eninEnd(8, BE) ‖ ownerPublicKey(33)`
     * (135 bytes total). Returns `null` on any guard failure.
     */
    fun buildSelfProofMessage(
        eventIdHash: ByteArray,
        eventSigningPublicKey: ByteArray,
        eninStart: ULong,
        eninEnd: ULong,
        ownerPublicKey: ByteArray,
    ): ByteArray? {
        if (eventIdHash.size != 32 ||
            !isValidCompressedPublicKey(eventSigningPublicKey) ||
            eninStart > eninEnd ||
            !isValidCompressedPublicKey(ownerPublicKey)
        ) {
            return null
        }

        val eninStartBytes = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.BIG_ENDIAN)
            .putLong(eninStart.toLong()).array()
        val eninEndBytes = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.BIG_ENDIAN)
            .putLong(eninEnd.toLong()).array()

        return selfProofDomainTag.toByteArray(Charsets.UTF_8) +
            eventIdHash +
            eventSigningPublicKey +
            eninStartBytes +
            eninEndBytes +
            ownerPublicKey
    }

    /** Nonzero scalar strictly less than the curve order — the guard every raw private-key input must pass before any EC math touches it. */
    private fun isValidPrivateKeyScalar(k: BigInteger): Boolean = secp256k1.normalizePrivateKey(k) != null

    /**
     * Sign the self-proof claim per [buildSelfProofMessage] with
     * [ownerPrivateKey], after confirming it actually derives
     * [ownerPublicKey]. Returns `null` on any guard failure.
     */
    fun signSelfProof(
        ownerPrivateKey: BigInteger,
        eventIdHash: ByteArray,
        eventSigningPublicKey: ByteArray,
        eninStart: ULong,
        eninEnd: ULong,
        ownerPublicKey: ByteArray,
    ): RecoverableSignature? {
        if (!isValidPrivateKeyScalar(ownerPrivateKey)) return null
        if (secp256k1.compressedPublicKey(ownerPrivateKey)?.contentEquals(ownerPublicKey) != true) return null
        val message = buildSelfProofMessage(eventIdHash, eventSigningPublicKey, eninStart, eninEnd, ownerPublicKey)
            ?: return null
        return signRecoverable(ownerPrivateKey, sha256(message))
    }

    /**
     * Canonical encoding of a wallet-acknowledgement claim counter-signing
     * one exact wallet endorsement (barnard#133 / barnard#92):
     * `"barnard-wallet-ack:v1" ‖ walletAddress(20) ‖ sha256(walletSignature)(32)`
     * (73 bytes total). Returns `null` on any guard failure.
     */
    fun buildWalletAcknowledgementMessage(walletAddress: ByteArray, walletSignature: ByteArray): ByteArray? {
        if (walletAddress.size != 20 || walletSignature.isEmpty()) return null
        return walletAcknowledgementDomainTag.toByteArray(Charsets.UTF_8) + walletAddress + sha256(walletSignature)
    }

    /**
     * Sign the wallet-acknowledgement claim per
     * [buildWalletAcknowledgementMessage] with [ownerPrivateKey]. Unlike
     * [signSelfProof], there is no public-key-match requirement — only that
     * [ownerPrivateKey] is a valid nonzero scalar `< N`. Returns `null` on
     * any guard failure.
     */
    fun signWalletAcknowledgement(
        ownerPrivateKey: BigInteger,
        walletAddress: ByteArray,
        walletSignature: ByteArray,
    ): RecoverableSignature? {
        if (!isValidPrivateKeyScalar(ownerPrivateKey)) return null
        val message = buildWalletAcknowledgementMessage(walletAddress, walletSignature) ?: return null
        return signRecoverable(ownerPrivateKey, sha256(message))
    }

    // MARK: - Recoverable ECDSA

    data class RecoverableSignature(val r: ByteArray, val s: ByteArray, val v: Int)

    fun signRecoverable(privateKey: BigInteger, messageHash32: ByteArray): RecoverableSignature {
        val signature = secp256k1.signRecoverable(privateKey, messageHash32)
        return RecoverableSignature(signature.r, signature.s, signature.v)
    }

    fun recoverPublicKey(recId: Int, r: ByteArray, s: ByteArray, messageHash32: ByteArray): ByteArray? =
        secp256k1.recoverPublicKey(recId, r, s, messageHash32)

    private val SECP256K1_N = BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
}
