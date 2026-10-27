// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

import io.flutter.plugin.common.BinaryMessenger
import java.nio.ByteBuffer

@RunWith(RobolectricTestRunner::class)
class BarnardDeviceSecretEntryPointRaceTest {
    @Test
    fun controllerConcurrentColdFirstUseReturnsStoredRoot() {
        val storage = DeviceSecretRendezvous()
        val initialize = {
            val controller = BarnardController(storage.context, SilentBinaryMessenger())
            storage.assertAnonymousTek(controller)
            storage.callerRoot()
        }
        storage.race(initialize, initialize)
    }

    @Test
    fun identityConcurrentColdFirstUseReturnsStoredRoot() {
        val storage = DeviceSecretRendezvous()
        val first = BarnardIdentityController(storage.context, SilentBinaryMessenger())
        val second = BarnardIdentityController(storage.context, SilentBinaryMessenger())
        storage.race({ readDeviceSecret(first) }, { readDeviceSecret(second) })
    }

    @Test
    fun coldControllerAndIdentityShareStoredRoot() {
        val storage = DeviceSecretRendezvous()
        val identity = BarnardIdentityController(storage.context, SilentBinaryMessenger())
        storage.race({
            val controller = BarnardController(storage.context, SilentBinaryMessenger())
            storage.assertAnonymousTek(controller)
            storage.callerRoot()
        }, { readDeviceSecret(identity) })
    }
}

private class SilentBinaryMessenger : BinaryMessenger {
    override fun send(channel: String, message: ByteBuffer?) = Unit
    override fun send(channel: String, message: ByteBuffer?, callback: BinaryMessenger.BinaryReply?) = Unit
    override fun setMessageHandler(channel: String, handler: BinaryMessenger.BinaryMessageHandler?) = Unit
}
