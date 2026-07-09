// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import android.content.Context
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
