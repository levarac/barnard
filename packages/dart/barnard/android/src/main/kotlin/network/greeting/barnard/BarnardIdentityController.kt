// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import network.greeting.barnard.BarnardCrypto.toHex

/**
 * Barnard per-event device signing identity (barnard#65).
 *
 * A **module separate from the sensing client** — its own `barnard/identity`
 * method channel, not `barnard/methods` (owned by [BarnardController]). It
 * shares the same on-device `DeviceSecret` storage (SharedPreferences key
 * `rpidSeed` in the `barnard` prefs file) so the signing identity is rooted
 * in the same secret as the sensing client's TEK, but the private signing
 * key it derives never crosses the method channel — only the public key
 * and signatures do.
 */
internal class BarnardIdentityController(
    private val appContext: Context,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler {
    private val methods = MethodChannel(messenger, "barnard/identity")

    private val prefs: SharedPreferences =
        appContext.getSharedPreferences("barnard", Context.MODE_PRIVATE)

    init {
        methods.setMethodCallHandler(this)
    }

    fun dispose() {
        methods.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "signingPublicKey" -> {
                val eventCode = (call.arguments as? Map<*, *>)?.get("eventCode") as? String
                if (eventCode == null) {
                    result.error("E_ARGS", "eventCode is required", null)
                    return
                }
                val keyPair = BarnardSigning.deriveSigningKeyPair(getOrCreateDeviceSecret(), eventCode)
                result.success(keyPair.publicKeyCompressed.toHex())
            }

            "sign" -> {
                val args = call.arguments as? Map<*, *>
                val eventCode = args?.get("eventCode") as? String
                val bytesHex = args?.get("bytes") as? String
                if (eventCode == null || bytesHex == null) {
                    result.error("E_ARGS", "eventCode and bytes are required", null)
                    return
                }
                val keyPair = BarnardSigning.deriveSigningKeyPair(getOrCreateDeviceSecret(), eventCode)
                val messageHash = java.security.MessageDigest.getInstance("SHA-256").digest(hexToBytes(bytesHex))
                val sig = BarnardSigning.signRecoverable(keyPair.privateKey, messageHash)
                result.success(
                    mapOf(
                        "r" to sig.r.toHex(),
                        "s" to sig.s.toHex(),
                        "v" to sig.v,
                    )
                )
            }

            "proveRpidOwnership" -> {
                val args = call.arguments as? Map<*, *>
                val eventCode = args?.get("eventCode") as? String
                val enin = (args?.get("enin") as? Number)?.toLong()
                val eventIdHashHex = args?.get("eventIdHash") as? String
                val challengeHex = args?.get("challenge") as? String
                if (eventCode == null || enin == null || eventIdHashHex == null) {
                    result.error("E_ARGS", "eventCode, enin and eventIdHash are required", null)
                    return
                }
                val proof = BarnardSigning.proveRpidOwnership(
                    getOrCreateDeviceSecret(),
                    eventCode,
                    hexToBytes(eventIdHashHex),
                    enin,
                    challengeHex?.let { hexToBytes(it) },
                )
                result.success(
                    mapOf(
                        "rpi" to proof.rpi.toHex(),
                        "signingPublicKey" to proof.signingPublicKey.toHex(),
                        "r" to proof.sig.r.toHex(),
                        "s" to proof.sig.s.toHex(),
                        "v" to proof.sig.v,
                    )
                )
            }

            "proveKeyBinding" -> {
                val args = call.arguments as? Map<*, *>
                val eventCode = args?.get("eventCode") as? String
                val displayIdHex = args?.get("displayId") as? String
                if (eventCode == null || displayIdHex == null) {
                    result.error("E_ARGS", "eventCode and displayId are required", null)
                    return
                }
                val eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
                val sig = BarnardSigning.signKeyBinding(
                    getOrCreateDeviceSecret(),
                    eventCode,
                    eventCodeHash,
                    hexToBytes(displayIdHex),
                )
                result.success(
                    mapOf(
                        "r" to sig.r.toHex(),
                        "s" to sig.s.toHex(),
                        "v" to sig.v,
                    )
                )
            }

            else -> result.notImplemented()
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = if (hex.length % 2 == 0) hex else "0$hex"
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    // MARK: - DeviceSecret Management
    //
    // Same storage key as BarnardController.getOrCreateDeviceSecret — the
    // signing identity and the sensing client are rooted in the same
    // DeviceSecret, but this module never exposes it (unlike
    // BarnardClient.exportCurrentTek, which is the TEK, not the raw secret).

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
