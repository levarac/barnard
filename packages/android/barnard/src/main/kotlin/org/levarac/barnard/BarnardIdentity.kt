// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.levarac.barnard.BarnardCrypto.toHex
import java.math.BigInteger
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

/** The long-lived owner keypair (barnard#133 / barnard#92), Kotlin-first mirror of [BarnardSigning.SigningKeyPair]. */
public data class BarnardOwnerKeyPair(
    val privateKey: String,
    val publicKeyCompressed: String,
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

    // MARK: - Owner key: account binding, self-proof, wallet acknowledgement (barnard#133 / barnard#92)
    //
    // Unlike signingPublicKey/sign/proveRpidOwnership/proveKeyBinding above,
    // these six do not use appContext or the device secret — the owner key
    // is rooted in an externally supplied account secret, not the device.
    // They live on this same public wrapper anyway: Android's BarnardSigning
    // is a single internal object (not split into a public "Core" + a
    // public "Identity" layer like Swift's BarnardCore/BarnardIdentity), so
    // this is the pragmatic Android equivalent of Swift's surface.

    /**
     * Derives the long-lived owner keypair from a 32-byte [accountSecret]
     * (barnard#133 / barnard#92). See [BarnardSigning.deriveOwnerKeyPair].
     */
    public fun deriveOwnerKeyPair(accountSecret: ByteArray): BarnardOwnerKeyPair {
        val keyPair = BarnardSigning.deriveOwnerKeyPair(accountSecret)
        return BarnardOwnerKeyPair(
            privateKey = fixedHex32(keyPair.privateKey),
            publicKeyCompressed = keyPair.publicKeyCompressed.toHex(),
        )
    }

    /**
     * Canonical, EIP-4361-shaped text for an external wallet SDK to sign
     * with `personal_sign`, binding [walletAddress] to [ownerPublicKey]
     * (barnard#133 / barnard#92). Returns `null` on any guard failure. See
     * [BarnardSigning.buildAccountBindingText].
     */
    public fun buildAccountBindingText(
        domain: String,
        walletAddress: ByteArray,
        ownerPublicKey: ByteArray,
        chainId: ULong,
        nonce: ByteArray,
        issuedAt: String,
    ): String? {
        return BarnardSigning.buildAccountBindingText(domain, walletAddress, ownerPublicKey, chainId, nonce, issuedAt)
    }

    /**
     * Canonical self-proof claim message binding [eventSigningPublicKey] to
     * [ownerPublicKey] for the ENIN range `[eninStart, eninEnd]`
     * (barnard#133 / barnard#92). Returns `null` on any guard failure. See
     * [BarnardSigning.buildSelfProofMessage].
     */
    public fun buildSelfProofMessage(
        eventIdHash: ByteArray,
        eventSigningPublicKey: ByteArray,
        eninStart: ULong,
        eninEnd: ULong,
        ownerPublicKey: ByteArray,
    ): ByteArray? {
        return BarnardSigning.buildSelfProofMessage(eventIdHash, eventSigningPublicKey, eninStart, eninEnd, ownerPublicKey)
    }

    /**
     * Signs the self-proof claim per [buildSelfProofMessage] with
     * [ownerPrivateKey] (lowercase hex), after confirming it actually
     * derives [ownerPublicKey] (barnard#133 / barnard#92). Returns `null` on
     * any guard failure. See [BarnardSigning.signSelfProof].
     */
    public fun signSelfProof(
        ownerPrivateKey: String,
        eventIdHash: ByteArray,
        eventSigningPublicKey: ByteArray,
        eninStart: ULong,
        eninEnd: ULong,
        ownerPublicKey: ByteArray,
    ): BarnardRecoverableSignature? {
        val sig = BarnardSigning.signSelfProof(
            parseOwnerPrivateKey(ownerPrivateKey) ?: return null,
            eventIdHash,
            eventSigningPublicKey,
            eninStart,
            eninEnd,
            ownerPublicKey,
        ) ?: return null
        return BarnardRecoverableSignature(r = sig.r.toHex(), s = sig.s.toHex(), v = sig.v)
    }

    /**
     * Canonical wallet-acknowledgement claim message counter-signing one
     * exact [walletSignature] over [walletAddress] (barnard#133 /
     * barnard#92). Returns `null` on any guard failure. See
     * [BarnardSigning.buildWalletAcknowledgementMessage].
     */
    public fun buildWalletAcknowledgementMessage(walletAddress: ByteArray, walletSignature: ByteArray): ByteArray? {
        return BarnardSigning.buildWalletAcknowledgementMessage(walletAddress, walletSignature)
    }

    /**
     * Signs the wallet-acknowledgement claim per
     * [buildWalletAcknowledgementMessage] with [ownerPrivateKey] (lowercase
     * hex, barnard#133 / barnard#92). Returns `null` on any guard failure.
     * See [BarnardSigning.signWalletAcknowledgement].
     */
    public fun signWalletAcknowledgement(
        ownerPrivateKey: String,
        walletAddress: ByteArray,
        walletSignature: ByteArray,
    ): BarnardRecoverableSignature? {
        val sig = BarnardSigning.signWalletAcknowledgement(
            parseOwnerPrivateKey(ownerPrivateKey) ?: return null,
            walletAddress,
            walletSignature,
        )
            ?: return null
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

    // MARK: - Owner-key hex <-> BigInteger conversion (barnard#133 / barnard#92)
    //
    // BarnardSigning keeps private keys as BigInteger internally and its own
    // fixed-width encoder (toFixedBytes(value, 32)) is private to that file
    // by design. These are a small local duplicate scoped to the hex string
    // boundary this public wrapper needs, so BarnardSigning.kt does not need
    // any visibility change.

    /** Fixed-width 32-byte big-endian lowercase hex, matching the convention `BarnardSigning`'s own `toFixedBytes(value, 32)` uses internally. */
    private fun fixedHex32(value: BigInteger): String {
        val raw = value.toByteArray()
        val trimmed = if (raw.size > 32 && raw[0] == 0.toByte()) raw.copyOfRange(raw.size - 32, raw.size) else raw
        val fixed = when {
            trimmed.size == 32 -> trimmed
            trimmed.size < 32 -> ByteArray(32 - trimmed.size) + trimmed
            else -> trimmed.copyOfRange(trimmed.size - 32, trimmed.size)
        }
        return fixed.toHex()
    }

    private fun parseOwnerPrivateKey(hex: String): BigInteger? {
        if (!Regex("[0-9a-f]{64}").matches(hex)) return null
        return BigInteger(hex, 16)
    }
}
