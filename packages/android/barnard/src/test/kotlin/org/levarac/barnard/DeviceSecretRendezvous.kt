// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

/** Uses the Context storage seam so the real entry points, including constructors, run unchanged. */
internal class DeviceSecretRendezvous {
    private val base: Context = ApplicationProvider.getApplicationContext()
    private val preferences = base.getSharedPreferences("barnard", Context.MODE_PRIVATE)
    private val bothRead = CountDownLatch(2)
    private val releaseReads = CountDownLatch(1)
    private val roots = ConcurrentHashMap<Thread, ByteArray>()
    private val commits = AtomicInteger()
    private val applies = AtomicInteger()

    val context: Context = object : ContextWrapper(base) {
        override fun getApplicationContext(): Context = this
        override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
            if (name == "barnard") intercepted else super.getSharedPreferences(name, mode)
    }

    private val intercepted = object : SharedPreferences by preferences {
        override fun getString(key: String, defValue: String?): String? {
            val snapshot = preferences.getString(key, defValue)
            if (key == "rpidSeed") {
                if (snapshot == null) {
                    // Take the snapshot before waiting: two unlocked callers must both see absent.
                    bothRead.countDown()
                    check(releaseReads.await(10, TimeUnit.SECONDS)) { "storage rendezvous timed out" }
                } else {
                    roots[Thread.currentThread()] = Base64.decode(snapshot, Base64.DEFAULT)
                }
            }
            return snapshot
        }

        override fun edit(): SharedPreferences.Editor {
            val editor = preferences.edit()
            return object : SharedPreferences.Editor by editor {
                override fun putString(key: String, value: String?): SharedPreferences.Editor {
                    if (key == "rpidSeed" && value != null) {
                        roots[Thread.currentThread()] = Base64.decode(value, Base64.DEFAULT)
                    }
                    editor.putString(key, value)
                    return this
                }

                override fun commit(): Boolean {
                    commits.incrementAndGet()
                    return editor.commit()
                }

                override fun apply() {
                    applies.incrementAndGet()
                    editor.apply()
                }
            }
        }
    }

    init {
        check(preferences.edit().clear().commit())
    }

    fun callerRoot(): ByteArray = checkNotNull(roots[Thread.currentThread()])

    fun assertAnonymousTek(instance: Any) {
        val tek = instance.javaClass.getDeclaredField("currentTek").apply { isAccessible = true }
            .get(instance) as ByteArray
        assertTrue("cached TEK must use the caller's root", tek.contentEquals(
            BarnardCrypto.deriveTekForAnonymous(callerRoot()),
        ))
    }

    fun race(first: () -> ByteArray, second: () -> ByteArray) {
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val results = arrayOfNulls<ByteArray>(2)
        val failures = arrayOfNulls<Throwable>(2)
        val workers = listOf(first, second).mapIndexed { index, action ->
            Thread({
                try {
                    ready.countDown()
                    check(start.await(10, TimeUnit.SECONDS)) { "start barrier timed out" }
                    results[index] = action()
                } catch (failure: Throwable) {
                    failures[index] = failure
                }
            }, "device-secret-entry-$index")
        }
        workers.forEach(Thread::start)
        try {
            assertTrue("both callers must start", ready.await(5, TimeUnit.SECONDS))
            start.countDown()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            // RED: open only after both absent snapshots. GREEN: the shared monitor prevents
            // the second read, so release once it is demonstrably blocked in the helper.
            while (bothRead.count > 0 && System.nanoTime() < deadline) {
                if (bothRead.count == 1L && workers.any { worker ->
                    worker.state == Thread.State.BLOCKED && worker.stackTrace.any {
                        it.className == "org.levarac.barnard.BarnardDeviceSecretStorage" &&
                            it.methodName == "getOrCreate"
                    }
                }) break
                Thread.sleep(1)
            }
            assertTrue("both absent reads or a serialized second caller must be observed",
                bothRead.count == 0L || workers.any { worker ->
                    worker.state == Thread.State.BLOCKED && worker.stackTrace.any {
                        it.className == "org.levarac.barnard.BarnardDeviceSecretStorage"
                    }
                })
        } finally {
            start.countDown()
            releaseReads.countDown()
            workers.forEach { it.join(10_000) }
        }
        assertFalse("callers must finish", workers.any(Thread::isAlive))
        failures.firstOrNull { it != null }?.let { throw AssertionError("caller failed", it) }
        val stored = Base64.decode(checkNotNull(preferences.getString("rpidSeed", null)), Base64.DEFAULT)
        assertTrue("both callers must return the same root", results[0]!!.contentEquals(results[1]!!))
        results.forEach { assertTrue("returned root must equal storage", it!!.contentEquals(stored)) }
        assertEquals("exactly one synchronous write", 1, commits.get())
        assertEquals("no asynchronous secret writes", 0, applies.get())
    }
}

internal fun readDeviceSecret(instance: Any): ByteArray = instance.javaClass
    .getDeclaredMethod("getOrCreateDeviceSecret").apply { isAccessible = true }.invoke(instance) as ByteArray
