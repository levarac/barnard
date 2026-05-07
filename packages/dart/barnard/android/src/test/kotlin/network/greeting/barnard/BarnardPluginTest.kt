package network.greeting.barnard

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.nio.ByteBuffer
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
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
        assertTrue(value["canScan"] is Boolean)
        assertTrue(value["canAdvertise"] is Boolean)
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
