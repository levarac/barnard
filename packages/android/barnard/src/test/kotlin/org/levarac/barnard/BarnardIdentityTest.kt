// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.content.Context
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * [BarnardIdentity] shares the same on-device `DeviceSecret` storage as
 * [BarnardEngine] (SharedPreferences key `rpidSeed` in the `barnard` prefs
 * file), so joining the same event on both must yield a `displayId` and a
 * signing key that are consistent with each other (barnard#65).
 */
@RunWith(RobolectricTestRunner::class)
class BarnardIdentityTest {
    private fun newContext(): Context = ApplicationProvider.getApplicationContext()

    private fun storeDeviceSecret(context: Context, secret: ByteArray) {
        context.getSharedPreferences("barnard", Context.MODE_PRIVATE).edit()
            .putString("rpidSeed", Base64.encodeToString(secret, Base64.NO_WRAP))
            .commit()
    }

    @Test
    fun signCachesDerivationAndInvalidatesForChangedInputs() {
        val context = newContext()
        val firstSecret = ByteArray(32) { 0x31 }
        storeDeviceSecret(context, firstSecret)
        var derivations = 0
        val identity = BarnardIdentity(context) { secret, eventCode ->
            derivations += 1
            BarnardSigning.deriveSigningKeyPair(secret, eventCode)
        }

        repeat(5) { identity.sign("CACHE-EVT-A", "message-$it".toByteArray()) }
        assertEquals("same DeviceSecret/eventCode must derive once", 1, derivations)

        identity.sign("CACHE-EVT-B", "message".toByteArray())
        assertEquals("a changed eventCode must re-derive", 2, derivations)

        storeDeviceSecret(context, ByteArray(32) { 0x32 })
        identity.sign("CACHE-EVT-B", "message".toByteArray())
        assertEquals("a rotated DeviceSecret must re-derive", 3, derivations)
    }

    @Test
    fun cachedIdentitySignatureMatchesPreCacheGoldenVector() {
        val context = newContext()
        storeDeviceSecret(context, ByteArray(32) { it.toByte() })
        val identity = BarnardIdentity(context)

        val signature = identity.sign("CORE-SPLIT-80", "issue-80-signing".toByteArray())

        assertEquals("e7df5948c76c2c0c3397dcdbf72fed1cf87e5d2379cb0831e4d2f1f2b3f262f5", signature.r)
        assertEquals("51760b12ac9be31472f61ca68574e7d1c950ca68504d7dd37bff1bba97e3e7d8", signature.s)
        assertEquals(0, signature.v)
    }

    @Test
    fun signingPublicKeyIsDeterministicForSameEvent() {
        val identity = BarnardIdentity(newContext())
        val a = identity.signingPublicKey("EVT1")
        val b = identity.signingPublicKey("EVT1")
        assertEquals(a, b)
    }

    @Test
    fun signingPublicKeyDiffersAcrossEvents() {
        val identity = BarnardIdentity(newContext())
        val a = identity.signingPublicKey("EVT-A")
        val b = identity.signingPublicKey("EVT-B")
        assertNotEquals(a, b)
    }

    @Test
    fun signingKeySharesDeviceSecretWithEngine() {
        val context = newContext()
        val engine = BarnardEngine(context)
        val identity = BarnardIdentity(context)

        engine.joinEvent("SHARED-EVT")
        val displayId = engine.getMyDisplayId()

        // proveKeyBinding must succeed deterministically from the same
        // DeviceSecret-rooted signing key the engine derives.
        val sigA = identity.proveKeyBinding("SHARED-EVT", hexToBytes(displayId))
        val sigB = identity.proveKeyBinding("SHARED-EVT", hexToBytes(displayId))
        assertEquals(sigA, sigB)
    }

    @Test
    fun proveRpidOwnershipMatchesEngineCurrentRpi() {
        val context = newContext()
        val engine = BarnardEngine(context)
        val identity = BarnardIdentity(context)

        engine.joinEvent("RPID-PROOF-EVT")
        val enin = engine.getCurrentEnin()
        val expectedRpi = engine.getCurrentRpi()

        val eventIdHash = ByteArray(32) { it.toByte() }
        val proof = identity.proveRpidOwnership("RPID-PROOF-EVT", enin, eventIdHash)

        assertEquals(expectedRpi, proof.rpi)
    }

    @Test
    fun signProducesStableRAndSLengthSignature() {
        val identity = BarnardIdentity(newContext())
        val sig = identity.sign("SIGN-EVT", "hello barnard".toByteArray(Charsets.UTF_8))
        assertEquals(64, sig.r.length)
        assertEquals(64, sig.s.length)
        assertEquals(true, sig.v == 0 || sig.v == 1)
    }

    private fun hexToBytes(hex: String): ByteArray {
        val clean = if (hex.length % 2 == 0) hex else "0$hex"
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
