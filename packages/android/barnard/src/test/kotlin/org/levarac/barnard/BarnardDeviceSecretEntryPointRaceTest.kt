// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BarnardDeviceSecretEntryPointRaceTest {
    @Test
    fun identityConcurrentColdFirstUseReturnsStoredRoot() {
        val storage = DeviceSecretRendezvous()
        val first = BarnardIdentity(storage.context)
        val second = BarnardIdentity(storage.context)
        storage.race({ readDeviceSecret(first) }, { readDeviceSecret(second) })
    }

    @Test
    fun coldEngineAndIdentityShareStoredRoot() {
        val storage = DeviceSecretRendezvous()
        var signingRoot: ByteArray? = null
        val identity = BarnardIdentity(storage.context) { secret, eventCode ->
            signingRoot = secret.copyOf()
            BarnardSigning.deriveSigningKeyPair(secret, eventCode)
        }
        storage.race({
            val engine = BarnardEngine(storage.context)
            storage.assertAnonymousTek(engine)
            storage.callerRoot()
        }, {
            identity.signingPublicKey("cold-first-use")
            checkNotNull(signingRoot)
        })
    }
}
