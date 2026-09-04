// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.security.MessageDigest

/** Identity-scoped, single-entry cache for the deterministic per-event signing key derivation. */
internal class BarnardSigningKeyCache {
    private var fingerprint: ByteArray? = null
    private var keyPair: BarnardSigning.SigningKeyPair? = null

    /** Synchronizing the cold derivation guarantees that concurrent callers derive an entry once. */
    @Synchronized
    fun keyPair(
        deviceSecret: ByteArray,
        eventCode: String,
        derive: (ByteArray, String) -> BarnardSigning.SigningKeyPair,
    ): BarnardSigning.SigningKeyPair {
        val wanted = fingerprint(deviceSecret, eventCode)
        if (fingerprint?.contentEquals(wanted) == true) return checkNotNull(keyPair)

        return derive(deviceSecret, eventCode).also {
            fingerprint = wanted
            keyPair = it
        }
    }

    /** Hash both length-delimited inputs so the cache does not retain the DeviceSecret itself. */
    private fun fingerprint(deviceSecret: ByteArray, eventCode: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("barnard-signing-key-cache:v1".toByteArray(Charsets.UTF_8))
        digest.update(
            byteArrayOf(
                (deviceSecret.size ushr 24).toByte(),
                (deviceSecret.size ushr 16).toByte(),
                (deviceSecret.size ushr 8).toByte(),
                deviceSecret.size.toByte(),
            ),
        )
        digest.update(deviceSecret)
        return digest.digest(eventCode.toByteArray(Charsets.UTF_8))
    }
}
