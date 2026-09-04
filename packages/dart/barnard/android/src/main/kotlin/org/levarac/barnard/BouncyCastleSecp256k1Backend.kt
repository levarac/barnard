// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.math.BigInteger
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.ECAlgorithms
import org.bouncycastle.math.ec.ECPoint

/** secp256k1 implementation backed by Bouncy Castle's low-level, provider-independent API. */
internal object BouncyCastleSecp256k1Backend : Secp256k1Backend {
    private val curve = SECNamedCurves.getByName("secp256k1")
    private val domain = ECDomainParameters(curve.curve, curve.g, curve.n, curve.h)
    private val n: BigInteger = curve.n
    private val halfN: BigInteger = n.shiftRight(1)

    override fun normalizePrivateKey(privateKey: BigInteger): BigInteger? =
        privateKey.takeIf { it.signum() > 0 && it < n }

    override fun compressedPublicKey(privateKey: BigInteger): ByteArray? =
        normalizePrivateKey(privateKey)?.let { curve.g.multiply(it).normalize().getEncoded(true) }

    override fun isValidCompressedPublicKey(publicKey: ByteArray): Boolean {
        if (publicKey.size != 33 || publicKey[0] !in byteArrayOf(0x02, 0x03)) return false
        return try {
            val point = curve.curve.decodePoint(publicKey)
            !point.isInfinity && point.isValid
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    override fun signRecoverable(privateKey: BigInteger, messageHash32: ByteArray): Secp256k1Signature {
        require(messageHash32.size == 32) { "messageHash must be 32 bytes" }
        val d = requireNotNull(normalizePrivateKey(privateKey)) { "privateKey must satisfy 1 <= d < N" }
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(d, domain))
        val components = signer.generateSignature(messageHash32)
        val r = components[0]
        val s = if (components[1] > halfN) n - components[1] else components[1]
        val expected = compressedPublicKey(d)!!
        val rBytes = fixed32(r)
        val sBytes = fixed32(s)
        val recoveryId = (0..1).firstOrNull {
            recoverPublicKey(it, rBytes, sBytes, messageHash32)?.contentEquals(expected) == true
        } ?: error("signRecoverable: could not determine profile recovery id")
        return Secp256k1Signature(rBytes, sBytes, recoveryId)
    }

    override fun recoverPublicKey(
        recoveryId: Int,
        r: ByteArray,
        s: ByteArray,
        messageHash32: ByteArray,
    ): ByteArray? {
        if (recoveryId !in 0..1 || r.size != 32 || s.size != 32 || messageHash32.size != 32) return null
        val rValue = BigInteger(1, r)
        val sValue = BigInteger(1, s)
        if (rValue.signum() == 0 || rValue >= n || sValue.signum() == 0 || sValue > halfN) return null

        val encoded = byteArrayOf((if (recoveryId == 0) 0x02 else 0x03).toByte()) + r
        val ephemeral = try {
            curve.curve.decodePoint(encoded)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (!ephemeral.multiply(n).isInfinity) return null

        val e = BigInteger(1, messageHash32).mod(n)
        val rInverse = rValue.modInverse(n)
        val q: ECPoint = ECAlgorithms.sumOfTwoMultiplies(
            curve.g,
            e.negate().mod(n).multiply(rInverse).mod(n),
            ephemeral,
            sValue.multiply(rInverse).mod(n),
        ).normalize()
        return if (q.isInfinity || !q.isValid) null else q.getEncoded(true)
    }

    private fun fixed32(value: BigInteger): ByteArray {
        val unsigned = value.toByteArray().let { if (it.size == 33 && it[0] == 0.toByte()) it.copyOfRange(1, 33) else it }
        require(unsigned.size <= 32)
        return ByteArray(32 - unsigned.size) + unsigned
    }
}
