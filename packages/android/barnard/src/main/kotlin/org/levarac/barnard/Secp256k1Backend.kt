// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.math.BigInteger

/** The deliberately small cryptographic boundary used by Barnard's signing profile. */
internal interface Secp256k1Backend {
    fun normalizePrivateKey(privateKey: BigInteger): BigInteger?
    fun compressedPublicKey(privateKey: BigInteger): ByteArray?
    fun isValidCompressedPublicKey(publicKey: ByteArray): Boolean
    fun signRecoverable(privateKey: BigInteger, messageHash32: ByteArray): Secp256k1Signature
    fun recoverPublicKey(recoveryId: Int, r: ByteArray, s: ByteArray, messageHash32: ByteArray): ByteArray?
}

internal data class Secp256k1Signature(val r: ByteArray, val s: ByteArray, val v: Int)
