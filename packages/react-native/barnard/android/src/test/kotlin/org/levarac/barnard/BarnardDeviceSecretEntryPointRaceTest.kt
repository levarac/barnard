// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

import com.facebook.react.bridge.ReactApplicationContext

@RunWith(RobolectricTestRunner::class)
class BarnardDeviceSecretEntryPointRaceTest {
    @Test
    fun controllerConcurrentColdFirstUseReturnsStoredRoot() {
        val storage = DeviceSecretRendezvous()
        val initialize = {
            val controller = BarnardController(storage.context)
            storage.assertAnonymousTek(controller)
            storage.callerRoot()
        }
        storage.race(initialize, initialize)
    }

    @Test
    fun identityConcurrentColdFirstUseReturnsStoredRoot() {
        val storage = DeviceSecretRendezvous()
        val first = BarnardIdentityModule(ReactApplicationContext(storage.context))
        val second = BarnardIdentityModule(ReactApplicationContext(storage.context))
        storage.race({ readDeviceSecret(first) }, { readDeviceSecret(second) })
    }

    @Test
    fun coldControllerAndIdentityShareStoredRoot() {
        val storage = DeviceSecretRendezvous()
        val identity = BarnardIdentityModule(ReactApplicationContext(storage.context))
        storage.race({
            val controller = BarnardController(storage.context)
            storage.assertAnonymousTek(controller)
            storage.callerRoot()
        }, { readDeviceSecret(identity) })
    }
}
