// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.math.BigInteger

/** Pre-migration implementation, retained only as a differential-test oracle. */
internal object HandRolledSecp256k1Backend : Secp256k1Backend {
    private val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    override fun normalizePrivateKey(privateKey: BigInteger): BigInteger? =
        privateKey.takeIf { it.signum() > 0 && it < n }

    override fun compressedPublicKey(privateKey: BigInteger): ByteArray? =
        LegacyBarnardSigning.backendCompressedPublicKey(privateKey)

    override fun isValidCompressedPublicKey(publicKey: ByteArray): Boolean =
        throw UnsupportedOperationException("not part of differential coverage")

    override fun signRecoverable(privateKey: BigInteger, messageHash32: ByteArray): Secp256k1Signature {
        val signature = LegacyBarnardSigning.signRecoverable(privateKey, messageHash32)
        return Secp256k1Signature(signature.r, signature.s, signature.v)
    }

    override fun recoverPublicKey(recoveryId: Int, r: ByteArray, s: ByteArray, messageHash32: ByteArray): ByteArray? {
        if (recoveryId !in 0..1 || r.size != 32 || s.size != 32 || messageHash32.size != 32) return null
        val sValue = BigInteger(1, s)
        if (sValue > n.shiftRight(1)) return null
        return LegacyBarnardSigning.recoverPublicKey(recoveryId, BigInteger(1, r), sValue, messageHash32)
    }
}
