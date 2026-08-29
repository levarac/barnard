// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.levarac.barnard.BarnardIdentity
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Reachability proof for the owner-key wrappers added to [BarnardIdentity]
 * (barnard#133 follow-up). This module consumes `packages/android/barnard`
 * as an external Gradle module dependency (see
 * `examples/android-native/settings.gradle.kts`), a genuine build boundary
 * where Kotlin's `internal` visibility is actually enforced — unlike a
 * same-module test, which the Kotlin Gradle plugin wires as a friend-path
 * of `src/main/kotlin`. This test would fail to *compile* if these six
 * operations were reachable only via `internal object BarnardSigning`.
 *
 * Byte-exact conformance for these primitives is proven separately by
 * `BarnardOwnerKeyConformanceVectorTest` in `packages/android/barnard`,
 * against `test-vectors/owner-key-v1.txt`. This test reuses a few of those
 * same fixed vector values, but only to keep inputs realistic — it is not a
 * substitute for that conformance suite.
 *
 * `@Config(sdk = [34])`: this app module's `defaultConfig.targetSdk = 36`
 * (pre-existing, unrelated to this task) exceeds Robolectric 4.11.1's max
 * supported SDK (34, per `DefaultSdkPicker`); pin the simulated framework
 * SDK for just this test class rather than touch shared module config.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BarnardIdentityOwnerKeyPublicApiTest {
    private fun newContext(): Context = ApplicationProvider.getApplicationContext()

    private fun hex(value: String): ByteArray =
        ByteArray(value.length / 2) { i -> value.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    // test-vectors/owner-key-v1.txt: owner_zero_*
    private val accountSecret = hex("0000000000000000000000000000000000000000000000000000000000000000")
    private val expectedOwnerZeroPrivateKey = "46cbfd04992339fab4937354a6f24c115a238f4bd133a8c43b18162ab986bf27"
    private val expectedOwnerZeroPublicKey = "03351e5165d083f53425fc4a51e7228d53e88eb2899bcb6a83368a8aafaa1de5f4"

    // test-vectors/owner-key-v1.txt: binding_*
    private val bindingDomain = "beid.levarac.org"
    private val bindingWalletAddress = hex("14791697260e4c9a71f18484c9f997b308e59325")
    private val bindingOwnerPublicKey = hex("03879beac8b548009124867a99a358aeb34ff42f957f868bbc83339568b16d9c67")
    private val bindingChainId = 1uL
    private val bindingNonce = hex("000102030405060708090a0b0c0d0e0f")
    private val bindingIssuedAt = "2026-07-30T09:00:00Z"

    // test-vectors/owner-key-v1.txt: selfproof_*
    private val selfProofEventIdHash = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val selfProofEventSigningPublicKey = hex("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    private val selfProofEninStart = 12uL
    private val selfProofEninEnd = 34uL
    private val selfProofOwnerPrivateKey = "0000000000000000000000000000000000000000000000000000000000000001"
    private val selfProofOwnerPublicKey = hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

    // test-vectors/owner-key-v1.txt: walletack_*
    private val walletAckWalletAddress = hex("202122232425262728292a2b2c2d2e2f30313233")
    private val walletAckWalletSignature = hex(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80",
    )
    private val walletAckOwnerPrivateKey = "0000000000000000000000000000000000000000000000000000000000000001"

    @Test
    fun deriveOwnerKeyPairIsReachableAndMatchesVector() {
        val identity = BarnardIdentity(newContext())
        val keyPair = identity.deriveOwnerKeyPair(accountSecret)
        assertEquals(expectedOwnerZeroPrivateKey, keyPair.privateKey)
        assertEquals(expectedOwnerZeroPublicKey, keyPair.publicKeyCompressed)
    }

    @Test
    fun buildAccountBindingTextIsReachable() {
        val identity = BarnardIdentity(newContext())
        val text = identity.buildAccountBindingText(
            domain = bindingDomain,
            walletAddress = bindingWalletAddress,
            ownerPublicKey = bindingOwnerPublicKey,
            chainId = bindingChainId,
            nonce = bindingNonce,
            issuedAt = bindingIssuedAt,
        )
        assertNotNull(text)
    }

    @Test
    fun buildSelfProofMessageIsReachable() {
        val identity = BarnardIdentity(newContext())
        val message = identity.buildSelfProofMessage(
            eventIdHash = selfProofEventIdHash,
            eventSigningPublicKey = selfProofEventSigningPublicKey,
            eninStart = selfProofEninStart,
            eninEnd = selfProofEninEnd,
            ownerPublicKey = selfProofOwnerPublicKey,
        )
        assertNotNull(message)
    }

    @Test
    fun signSelfProofIsReachable() {
        val identity = BarnardIdentity(newContext())
        val sig = identity.signSelfProof(
            ownerPrivateKey = selfProofOwnerPrivateKey,
            eventIdHash = selfProofEventIdHash,
            eventSigningPublicKey = selfProofEventSigningPublicKey,
            eninStart = selfProofEninStart,
            eninEnd = selfProofEninEnd,
            ownerPublicKey = selfProofOwnerPublicKey,
        )
        assertNotNull(sig)
    }

    @Test
    fun buildWalletAcknowledgementMessageIsReachable() {
        val identity = BarnardIdentity(newContext())
        val message = identity.buildWalletAcknowledgementMessage(
            walletAddress = walletAckWalletAddress,
            walletSignature = walletAckWalletSignature,
        )
        assertNotNull(message)
    }

    @Test
    fun signWalletAcknowledgementIsReachable() {
        val identity = BarnardIdentity(newContext())
        val sig = identity.signWalletAcknowledgement(
            ownerPrivateKey = walletAckOwnerPrivateKey,
            walletAddress = walletAckWalletAddress,
            walletSignature = walletAckWalletSignature,
        )
        assertNotNull(sig)
    }
}
