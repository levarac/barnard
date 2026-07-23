// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.levarac.barnard.BarnardCrypto.toHex
import java.security.MessageDigest

/** Recoverable secp256k1 signature `(r, s, v)`, Kotlin-first mirror of [BarnardSigning.RecoverableSignature]. */
public data class BarnardRecoverableSignature(
    val r: String,
    val s: String,
    val v: Int,
)

/** Result of [BarnardIdentity.proveRpidOwnership]. */
public data class BarnardRpidOwnershipProof(
    val rpi: String,
    val signingPublicKey: String,
    val signature: BarnardRecoverableSignature,
)

/**
 * Barnard per-event device signing identity (barnard#65), Flutter-free
 * port of `BarnardIdentityController`.
 *
 * A module separate from [BarnardEngine] (the sensing client) — it shares
 * the same on-device `DeviceSecret` storage (`SharedPreferences` key
 * `rpidSeed` in the `barnard` prefs file) as `BarnardEngine` so the
 * signing identity is rooted in the same secret as the sensing client's
 * TEK, but the private signing key it derives never leaves this type —
 * only the public key and signatures do.
 */
public class BarnardIdentity(private val appContext: Context) {
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences("barnard", Context.MODE_PRIVATE)

    public fun signingPublicKey(eventCode: String): String {
        val keyPair = BarnardSigning.deriveSigningKeyPair(getOrCreateDeviceSecret(), eventCode)
        return keyPair.publicKeyCompressed.toHex()
    }

    /** Signs `SHA256(bytes)` with the per-event signing key derived from [eventCode]. */
    public fun sign(eventCode: String, bytes: ByteArray): BarnardRecoverableSignature {
        val keyPair = BarnardSigning.deriveSigningKeyPair(getOrCreateDeviceSecret(), eventCode)
        val messageHash = MessageDigest.getInstance("SHA-256").digest(bytes)
        val sig = BarnardSigning.signRecoverable(keyPair.privateKey, messageHash)
        return BarnardRecoverableSignature(r = sig.r.toHex(), s = sig.s.toHex(), v = sig.v)
    }

    public fun proveRpidOwnership(
        eventCode: String,
        enin: Long,
        eventIdHash: ByteArray,
        challenge: ByteArray? = null,
    ): BarnardRpidOwnershipProof {
        val proof = BarnardSigning.proveRpidOwnership(
            getOrCreateDeviceSecret(),
            eventCode,
            eventIdHash,
            enin,
            challenge,
        )
        return BarnardRpidOwnershipProof(
            rpi = proof.rpi.toHex(),
            signingPublicKey = proof.signingPublicKey.toHex(),
            signature = BarnardRecoverableSignature(
                r = proof.sig.r.toHex(),
                s = proof.sig.s.toHex(),
                v = proof.sig.v,
            ),
        )
    }

    public fun proveKeyBinding(eventCode: String, displayId: ByteArray): BarnardRecoverableSignature {
        val eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
        val sig = BarnardSigning.signKeyBinding(
            getOrCreateDeviceSecret(),
            eventCode,
            eventCodeHash,
            displayId,
        )
        return BarnardRecoverableSignature(r = sig.r.toHex(), s = sig.s.toHex(), v = sig.v)
    }

    // MARK: - DeviceSecret Management
    //
    // Same storage key as BarnardEngine.getOrCreateDeviceSecret — the
    // signing identity and the sensing client are rooted in the same
    // DeviceSecret, but this type never exposes it (unlike
    // BarnardEngine.exportCurrentTek, which is the TEK, not the raw secret).

    private fun getOrCreateDeviceSecret(): ByteArray {
        val key = "rpidSeed"
        val existing = prefs.getString(key, null)
        if (existing != null) {
            val bytes = Base64.decode(existing, Base64.DEFAULT)
            if (bytes.size >= 32) return bytes
        }
        val bytes = BarnardCrypto.generateRandomBytes(32)
        prefs.edit().putString(key, Base64.encodeToString(bytes, Base64.NO_WRAP)).apply()
        return bytes
    }
}
