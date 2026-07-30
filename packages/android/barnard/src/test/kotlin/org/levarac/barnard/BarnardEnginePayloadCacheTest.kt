// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BarnardEnginePayloadCacheTest {
    private lateinit var context: Context
    private lateinit var computePayload: Method

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        context.getSharedPreferences("barnard", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        computePayload = BarnardEngine::class.java
            .getDeclaredMethod("computePayload", Long::class.javaPrimitiveType)
            .apply { isAccessible = true }
    }

    @Test
    fun computePayloadReusesExactByteArrayWithinSameEninAndTek() {
        val engine = BarnardEngine(context)

        val first = engine.computePayloadAt(1_000L)
        val second = engine.computePayloadAt(2_000L)

        assertSame(first, second)
    }

    @Test
    fun computePayloadRecomputesAcrossEninBoundary() {
        val engine = BarnardEngine(context)

        val beforeBoundary = engine.computePayloadAt(299_999L)
        val afterBoundary = engine.computePayloadAt(300_000L)

        assertNotSame(beforeBoundary, afterBoundary)
        assertFalse(beforeBoundary.contentEquals(afterBoundary))
    }

    @Test
    fun computePayloadRecomputesWhenTekChangesAndReturnsAfterLeave() {
        val engine = BarnardEngine(context)
        val anonymous = engine.computePayloadAt(1_000L)

        engine.joinEvent("payload-cache-test")
        val joined = engine.computePayloadAt(1_000L)
        engine.leaveEvent()
        val left = engine.computePayloadAt(1_000L)

        assertNotSame(anonymous, joined)
        assertFalse(anonymous.contentEquals(joined))
        assertNotSame(joined, left)
        assertFalse(joined.contentEquals(left))
        assertNotSame(anonymous, left)
        assertTrue(anonymous.contentEquals(left))
    }

    @Test
    fun computePayloadSerializesCacheAccessAcrossThreads() {
        assertTrue(Modifier.isSynchronized(computePayload.modifiers))
    }

    @Test
    fun currentTekPublishesChangesAcrossThreads() {
        val field = BarnardEngine::class.java.getDeclaredField("currentTek")

        assertTrue(Modifier.isVolatile(field.modifiers))
    }

    private fun BarnardEngine.computePayloadAt(nowMs: Long): ByteArray =
        computePayload.invoke(this, nowMs) as ByteArray
}
