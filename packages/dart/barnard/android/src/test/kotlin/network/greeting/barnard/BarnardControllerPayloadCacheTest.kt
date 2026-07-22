package network.greeting.barnard

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.flutter.plugin.common.BinaryMessenger
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
internal class BarnardControllerPayloadCacheTest {
    private lateinit var context: Context
    private lateinit var computePayload: Method

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        context.getSharedPreferences("barnard", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        computePayload = BarnardController::class.java
            .getDeclaredMethod("computePayload", Long::class.javaPrimitiveType)
            .apply { isAccessible = true }
    }

    @Test
    fun computePayload_reusesExactByteArrayWithinSameEninAndTek() {
        val controller = BarnardController(context, RecordingBinaryMessenger())

        val first = controller.computePayloadAt(1_000L)
        val second = controller.computePayloadAt(2_000L)

        assertSame(first, second)
    }

    @Test
    fun computePayload_recomputesAcrossEninBoundary() {
        val controller = BarnardController(context, RecordingBinaryMessenger())

        val beforeBoundary = controller.computePayloadAt(299_999L)
        val afterBoundary = controller.computePayloadAt(300_000L)

        assertNotSame(beforeBoundary, afterBoundary)
        assertFalse(beforeBoundary.contentEquals(afterBoundary))
    }

    @Test
    fun computePayload_recomputesWhenTekChangesWithinSameEnin() {
        val controller = BarnardController(context, RecordingBinaryMessenger())
        val anonymous = controller.computePayloadAt(1_000L)

        controller.joinEventForTest("payload-cache-test")
        val joined = controller.computePayloadAt(1_000L)
        controller.leaveEventForTest()
        val left = controller.computePayloadAt(1_000L)

        assertNotSame(anonymous, joined)
        assertFalse(anonymous.contentEquals(joined))
        assertNotSame(joined, left)
        assertFalse(joined.contentEquals(left))
        assertNotSame(anonymous, left)
        assertTrue(anonymous.contentEquals(left))
    }

    @Test
    fun computePayload_serializesCacheAccessAcrossThreads() {
        assertTrue(Modifier.isSynchronized(computePayload.modifiers))
    }

    @Test
    fun currentTek_publishesChangesAcrossThreads() {
        val field = BarnardController::class.java.getDeclaredField("currentTek")

        assertTrue(Modifier.isVolatile(field.modifiers))
    }

    private fun BarnardController.computePayloadAt(nowMs: Long): ByteArray {
        return computePayload.invoke(this, nowMs) as ByteArray
    }

    private fun BarnardController.joinEventForTest(code: String) {
        BarnardController::class.java.getDeclaredMethod("joinEvent", String::class.java)
            .apply { isAccessible = true }
            .invoke(this, code)
    }

    private fun BarnardController.leaveEventForTest() {
        BarnardController::class.java.getDeclaredMethod("leaveEvent")
            .apply { isAccessible = true }
            .invoke(this)
    }

    private class RecordingBinaryMessenger : BinaryMessenger {
        override fun send(channel: String, message: ByteBuffer?) = Unit

        override fun send(
            channel: String,
            message: ByteBuffer?,
            callback: BinaryMessenger.BinaryReply?
        ) = Unit

        override fun setMessageHandler(
            channel: String,
            handler: BinaryMessenger.BinaryMessageHandler?
        ) = Unit
    }
}
