package network.greeting.barnard

import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.nio.ByteBuffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
internal class BarnardPluginTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        context.getSharedPreferences("barnard", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test
    fun onMethodCall_getCapabilities_returnsMap() {
        val messenger = RecordingBinaryMessenger()
        val result = RecordingResult()

        val controller = BarnardController(context, messenger)
        val call = MethodCall("getCapabilities", null)
        controller.onMethodCall(call, result)

        assertTrue(result.value is Map<*, *>)
    }

    @Test
    fun onMethodCall_configure_appliesEventCode() {
        val messenger = RecordingBinaryMessenger()
        val configureResult = RecordingResult()
        val eventCodeResult = RecordingResult()

        val controller = BarnardController(context, messenger)
        controller.onMethodCall(
            MethodCall("configure", mapOf("eventCode" to "CONF-2026")),
            configureResult
        )
        controller.onMethodCall(MethodCall("getCurrentEventCode", null), eventCodeResult)

        assertEquals("CONF-2026", eventCodeResult.value)
    }

    @Test
    @Config(sdk = [31])
    fun onMethodCall_getPermissionStatus_returnsStableShape() {
        val messenger = RecordingBinaryMessenger()
        val result = RecordingResult()

        val controller = BarnardController(context, messenger)
        val call = MethodCall("getPermissionStatus", null)
        controller.onMethodCall(call, result)

        val value = result.value as Map<*, *>
        assertTrue(value["platform"] == "android")
        assertTrue(value["permissions"] is Map<*, *>)
        assertTrue(value["requiredPermissions"] is List<*>)
        assertTrue(value["missingPermissions"] is List<*>)
        assertTrue(value["requestablePermissions"] is List<*>)
        assertTrue(value["blockedPermissions"] is List<*>)
        assertTrue(value["canScan"] is Boolean)
        assertTrue(value["canAdvertise"] is Boolean)
    }

    @Test
    @Config(sdk = [31])
    fun onMethodCall_getPermissionStatus_reportsNoBleCapabilityWithoutHardware() {
        // Android Emulator and BLE-less devices do not advertise the
        // FEATURE_BLUETOOTH_LE system feature. Capability flags must reflect
        // that gap independently of permission grants so host apps can hide
        // BLE-only UI on these devices. See issue #57.
        Shadows.shadowOf(context.packageManager)
            .setSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE, false)

        val messenger = RecordingBinaryMessenger()
        val result = RecordingResult()

        val controller = BarnardController(context, messenger)
        val call = MethodCall("getPermissionStatus", null)
        controller.onMethodCall(call, result)

        val value = result.value as Map<*, *>
        assertEquals(false, value["canScan"])
        assertEquals(false, value["canAdvertise"])
    }

    private class RecordingBinaryMessenger : BinaryMessenger {
        private val handlers: MutableMap<String, BinaryMessenger.BinaryMessageHandler?> = mutableMapOf()

        override fun send(channel: String, message: ByteBuffer?) = Unit

        override fun send(
            channel: String,
            message: ByteBuffer?,
            callback: BinaryMessenger.BinaryReply?
        ) = Unit

        override fun setMessageHandler(
            channel: String,
            handler: BinaryMessenger.BinaryMessageHandler?
        ) {
            handlers[channel] = handler
        }
    }

    private class RecordingResult : MethodChannel.Result {
        var value: Any? = null

        override fun success(result: Any?) {
            value = result
        }

        override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
            throw AssertionError("Unexpected error: $errorCode $errorMessage")
        }

        override fun notImplemented() {
            throw AssertionError("Unexpected notImplemented")
        }
    }
}
