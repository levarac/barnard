// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

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

    private fun sha256(bytes: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)

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
