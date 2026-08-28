// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.math.BigInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

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
 * Implements secp256k1 EC math directly on [BigInteger] (no third-party
 * crypto dependency): field/point arithmetic, RFC 6979 deterministic
 * ECDSA, and recovery-id computation for ecrecover-compatible signatures.
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

    // MARK: - secp256k1 curve parameters

    private val P = BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    private val N = BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    private val GX = BigInteger(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    private val GY = BigInteger(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    private val G = ECPoint(GX, GY)

    /** An affine point on secp256k1. `null` coordinates represent infinity. */
    data class ECPoint(val x: BigInteger?, val y: BigInteger?) {
        val isInfinity: Boolean get() = x == null || y == null
    }

    private val INFINITY = ECPoint(null, null)

    private fun mod(a: BigInteger): BigInteger = a.mod(P)

    private fun pointDouble(p: ECPoint): ECPoint {
        if (p.isInfinity || p.y == BigInteger.ZERO) return INFINITY
        val x = p.x!!
        val y = p.y!!
        // slope = (3x^2) / (2y) mod P  (a = 0 for secp256k1)
        val num = mod(BigInteger.valueOf(3) * x * x)
        val den = mod(BigInteger.valueOf(2) * y).modInverse(P)
        val slope = mod(num * den)
        val x3 = mod(slope * slope - x - x)
        val y3 = mod(slope * (x - x3) - y)
        return ECPoint(x3, y3)
    }

    private fun pointAdd(p1: ECPoint, p2: ECPoint): ECPoint {
        if (p1.isInfinity) return p2
        if (p2.isInfinity) return p1
        if (p1.x == p2.x) {
            return if (mod(p1.y!! + p2.y!!) == BigInteger.ZERO) INFINITY else pointDouble(p1)
        }
        val slope = mod((p2.y!! - p1.y!!) * (p2.x!! - p1.x!!).modInverse(P))
        val x3 = mod(slope * slope - p1.x - p2.x)
        val y3 = mod(slope * (p1.x - x3) - p1.y)
        return ECPoint(x3, y3)
    }

    private fun scalarMult(k: BigInteger, point: ECPoint): ECPoint {
        var result = INFINITY
        var addend = point
        var scalar = k
        while (scalar.signum() > 0) {
            if (scalar.testBit(0)) {
                result = pointAdd(result, addend)
            }
            addend = pointDouble(addend)
            scalar = scalar.shiftRight(1)
        }
        return result
    }

    /** SEC1-compressed encoding (33 bytes: 0x02/0x03 prefix + 32-byte X). */
    private fun compress(point: ECPoint): ByteArray {
        val x = point.x!!
        val y = point.y!!
        val prefix: Byte = if (y.testBit(0)) 0x03 else 0x02
        return byteArrayOf(prefix) + toFixedBytes(x, 32)
    }

    /** Decompress a point from its X coordinate and Y parity bit. Returns null if X is not on the curve. */
    private fun decompress(x: BigInteger, yIsOdd: Boolean): ECPoint? {
        // y^2 = x^3 + 7 mod P
        val rhs = mod(x.modPow(BigInteger.valueOf(3), P) + BigInteger.valueOf(7))
        // secp256k1's P is congruent to 3 mod 4, so sqrt(a) = a^((P+1)/4) mod P.
        val sqrtExp = (P + BigInteger.ONE).shiftRight(2)
        var y = rhs.modPow(sqrtExp, P)
        if (mod(y * y) != rhs) return null
        if (y.testBit(0) != yIsOdd) {
            y = P - y
        }
        return ECPoint(x, y)
    }

    private fun toFixedBytes(value: BigInteger, length: Int): ByteArray {
        val raw = value.toByteArray()
        val trimmed = if (raw.size > length && raw[0] == 0.toByte()) raw.copyOfRange(raw.size - length, raw.size) else raw
        return when {
            trimmed.size == length -> trimmed
            trimmed.size < length -> ByteArray(length - trimmed.size) + trimmed
            else -> trimmed.copyOfRange(trimmed.size - length, trimmed.size)
        }
    }

    private fun bytesToBigInt(bytes: ByteArray): BigInteger = BigInteger(1, bytes)

    // MARK: - Key derivation

    data class SigningKeyPair(val privateKey: BigInteger, val publicKeyCompressed: ByteArray)

    /**
     * Derive the per-event signing keypair from [deviceSecret] and [eventCode].
     */
    fun deriveSigningKeyPair(deviceSecret: ByteArray, eventCode: String): SigningKeyPair {
        val combined = deviceSecret + eventCode.toByteArray(Charsets.UTF_8)
        var seed = BarnardCrypto.hkdfSha256(combined, signingKeyInfo.toByteArray(Charsets.UTF_8), 32)
        var d = bytesToBigInt(seed).mod(N)
        while (d.signum() == 0) {
            seed = sha256(seed)
            d = bytesToBigInt(seed).mod(N)
        }
        val q = scalarMult(d, G)
        return SigningKeyPair(d, compress(q))
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
        var d = bytesToBigInt(seed).mod(N)
        while (d.signum() == 0) {
            seed = sha256(seed)
            d = bytesToBigInt(seed).mod(N)
        }
        val q = scalarMult(d, G)
        return SigningKeyPair(d, compress(q))
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

    /** 33-byte SEC1-compressed encoding whose X coordinate is on the curve and matches its Y-parity prefix. */
    private fun isValidCompressedPublicKey(publicKey: ByteArray): Boolean {
        if (publicKey.size != 33) return false
        if (publicKey[0] != 0x02.toByte() && publicKey[0] != 0x03.toByte()) return false
        val x = bytesToBigInt(publicKey.copyOfRange(1, 33))
        if (x >= P) return false
        return decompress(x, publicKey[0] == 0x03.toByte()) != null
    }

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
    private fun isValidPrivateKeyScalar(k: BigInteger): Boolean = k.signum() > 0 && k < N

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
        if (!compress(scalarMult(ownerPrivateKey, G)).contentEquals(ownerPublicKey)) return null
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

    // MARK: - Recoverable ECDSA (RFC 6979 deterministic k)

    data class RecoverableSignature(val r: ByteArray, val s: ByteArray, val v: Int)

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 6979 deterministic `k` (HMAC-SHA256, qlen == hlen == 32 bytes for secp256k1/SHA-256). */
    private fun deterministicK(privateKey: BigInteger, messageHash32: ByteArray): BigInteger {
        val x = toFixedBytes(privateKey, 32)
        val h1 = toFixedBytes(bytesToBigInt(messageHash32).mod(N), 32)

        var v = ByteArray(32) { 0x01 }
        var k = ByteArray(32) { 0x00 }

        k = hmacSha256(k, v + byteArrayOf(0x00) + x + h1)
        v = hmacSha256(k, v)
        k = hmacSha256(k, v + byteArrayOf(0x01) + x + h1)
        v = hmacSha256(k, v)

        while (true) {
            v = hmacSha256(k, v)
            val kCandidate = bytesToBigInt(v)
            if (kCandidate.signum() > 0 && kCandidate < N) {
                return kCandidate
            }
            k = hmacSha256(k, v + byteArrayOf(0x00))
            v = hmacSha256(k, v)
        }
    }

    /**
     * Sign a 32-byte message hash with [privateKey], returning a recoverable
     * signature `(r, s, v)`. Normalizes `s` to the lower half of the curve
     * order (canonical / "low-S" form) and searches for the recovery id
     * (`0` or `1`) that recovers the caller's own public key — i.e. after
     * low-S normalization, not before.
     */
    fun signRecoverable(privateKey: BigInteger, messageHash32: ByteArray): RecoverableSignature {
        require(messageHash32.size == 32) { "messageHash must be 32 bytes" }

        val e = bytesToBigInt(messageHash32).mod(N)
        val expectedPub = compress(scalarMult(privateKey, G))

        var r: BigInteger
        var s: BigInteger
        var k: BigInteger
        while (true) {
            k = deterministicK(privateKey, messageHash32)
            val rPoint = scalarMult(k, G)
            r = rPoint.x!!.mod(N)
            if (r.signum() == 0) continue
            s = (k.modInverse(N) * (e + privateKey * r)).mod(N)
            if (s.signum() == 0) continue
            break
        }

        val halfOrder = N.shiftRight(1)
        if (s > halfOrder) {
            s = N - s
        }

        var recoveryId = -1
        for (id in 0..3) {
            val candidate = recoverPublicKey(id, r, s, messageHash32)
            if (candidate != null && candidate.contentEquals(expectedPub)) {
                recoveryId = id
                break
            }
        }
        check(recoveryId != -1) { "signRecoverable: could not determine recovery id" }

        return RecoverableSignature(toFixedBytes(r, 32), toFixedBytes(s, 32), recoveryId)
    }

    /** Recover the SEC1-compressed public key from `(recId, r, s)` and the signed message hash. */
    fun recoverPublicKey(recId: Int, r: BigInteger, s: BigInteger, messageHash32: ByteArray): ByteArray? {
        val i = BigInteger.valueOf((recId / 2).toLong())
        val x = r + i * N
        if (x >= P) return null

        val rPoint = decompress(x, (recId and 1) == 1) ?: return null

        val nTimesR = scalarMult(N, rPoint)
        if (!nTimesR.isInfinity) return null

        val e = bytesToBigInt(messageHash32).mod(N)
        val eNeg = N - e.mod(N)
        val rInv = r.modInverse(N)
        val srInv = (rInv * s).mod(N)
        val eInvrInv = (rInv * eNeg).mod(N)

        val term1 = scalarMult(eInvrInv, G)
        val term2 = scalarMult(srInv, rPoint)
        val point = pointAdd(term1, term2)
        if (point.isInfinity) return null
        return compress(point)
    }
}
