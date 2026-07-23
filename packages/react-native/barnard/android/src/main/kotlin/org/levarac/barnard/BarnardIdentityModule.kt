package org.levarac.barnard

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.WritableMap
import org.levarac.barnard.BarnardCrypto.toHex
import java.security.MessageDigest

/**
 * Barnard per-event device signing identity (barnard#65).
 *
 * A **module separate from the sensing client** (`BarnardModule`) — its own
 * RN native module, not part of `BarnardModule`. It shares the same
 * on-device `DeviceSecret` storage (SharedPreferences key `rpidSeed` in the
 * `barnard` prefs file) as `BarnardController`, so the signing identity is
 * rooted in the same secret as the sensing client's TEK, but the private
 * signing key it derives never crosses the RN bridge — only the public key
 * and signatures do.
 */
class BarnardIdentityModule(reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private val prefs: SharedPreferences =
        reactContext.applicationContext.getSharedPreferences("barnard", Context.MODE_PRIVATE)

    override fun getName(): String = "BarnardIdentity"

    @ReactMethod
    fun signingPublicKey(eventCode: String, promise: Promise) {
        try {
            val keyPair = BarnardSigning.deriveSigningKeyPair(getOrCreateDeviceSecret(), eventCode)
            promise.resolve(keyPair.publicKeyCompressed.toHex())
        } catch (e: Exception) {
            promise.reject("E_SIGNING_PUBLIC_KEY", e.message, e)
        }
    }

    @ReactMethod
    fun sign(eventCode: String, bytesHex: String, promise: Promise) {
        try {
            val keyPair = BarnardSigning.deriveSigningKeyPair(getOrCreateDeviceSecret(), eventCode)
            val messageHash = MessageDigest.getInstance("SHA-256").digest(hexToBytes(bytesHex))
            val sig = BarnardSigning.signRecoverable(keyPair.privateKey, messageHash)

            val map: WritableMap = com.facebook.react.bridge.Arguments.createMap()
            map.putString("r", sig.r.toHex())
            map.putString("s", sig.s.toHex())
            map.putInt("v", sig.v)
            promise.resolve(map)
        } catch (e: Exception) {
            promise.reject("E_SIGN", e.message, e)
        }
    }

    @ReactMethod
    fun proveRpidOwnership(
        eventCode: String,
        enin: Double,
        eventIdHashHex: String,
        challengeHex: String?,
        promise: Promise,
    ) {
        try {
            val proof = BarnardSigning.proveRpidOwnership(
                getOrCreateDeviceSecret(),
                eventCode,
                hexToBytes(eventIdHashHex),
                enin.toLong(),
                challengeHex?.let { hexToBytes(it) },
            )

            val map: WritableMap = com.facebook.react.bridge.Arguments.createMap()
            map.putString("rpi", proof.rpi.toHex())
            map.putString("signingPublicKey", proof.signingPublicKey.toHex())
            map.putString("r", proof.sig.r.toHex())
            map.putString("s", proof.sig.s.toHex())
            map.putInt("v", proof.sig.v)
            promise.resolve(map)
        } catch (e: Exception) {
            promise.reject("E_PROVE_RPID_OWNERSHIP", e.message, e)
        }
    }

    @ReactMethod
    fun proveKeyBinding(eventCode: String, displayIdHex: String, promise: Promise) {
        try {
            val eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
            val sig = BarnardSigning.signKeyBinding(
                getOrCreateDeviceSecret(),
                eventCode,
                eventCodeHash,
                hexToBytes(displayIdHex),
            )

            val map: WritableMap = com.facebook.react.bridge.Arguments.createMap()
            map.putString("r", sig.r.toHex())
            map.putString("s", sig.s.toHex())
            map.putInt("v", sig.v)
            promise.resolve(map)
        } catch (e: Exception) {
            promise.reject("E_PROVE_KEY_BINDING", e.message, e)
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = if (hex.length % 2 == 0) hex else "0$hex"
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    // Same storage key as BarnardController.getOrCreateDeviceSecret — see
    // that class for the rationale (shared DeviceSecret, never exposed).
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
