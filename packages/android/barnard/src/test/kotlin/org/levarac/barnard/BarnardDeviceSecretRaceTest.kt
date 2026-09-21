// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BarnardDeviceSecretRaceTest {
    @Test
    fun concurrentColdInitializationSerializesReadCreatePersist() {
        val storage = InMemoryProtectedStringStorage()
        val bothCallersReady = CountDownLatch(2)
        val releaseCallers = CountDownLatch(1)
        val firstGeneratorEntered = CountDownLatch(1)
        val releaseFirstGenerator = CountDownLatch(1)
        val generationCount = AtomicInteger()
        val results = arrayOfNulls<ByteArray>(2)
        val failures = arrayOfNulls<Throwable>(2)
        val workers = List(2) { index ->
            Thread(
                {
                    try {
                        bothCallersReady.countDown()
                        check(releaseCallers.await(5, TimeUnit.SECONDS)) {
                            "caller start barrier timed out"
                        }
                        results[index] = BarnardDeviceSecretStorage.getOrCreate(storage) { size ->
                            val generation = generationCount.incrementAndGet()
                            if (generation == 1) {
                                firstGeneratorEntered.countDown()
                                check(releaseFirstGenerator.await(5, TimeUnit.SECONDS)) {
                                    "first generator release timed out"
                                }
                            }
                            ByteArray(size) { generation.toByte() }
                        }
                    } catch (failure: Throwable) {
                        failures[index] = failure
                    }
                },
                "barnard-device-secret-reader-$index",
            )
        }

        workers.forEach(Thread::start)
        val callersWereReady = bothCallersReady.await(5, TimeUnit.SECONDS)
        releaseCallers.countDown()
        val generatorWasEntered = firstGeneratorEntered.await(5, TimeUnit.SECONDS)
        val serializedCallerObserved = generatorWasEntered && waitForBlockedWorker(workers)
        releaseFirstGenerator.countDown()
        workers.forEach { it.join(5_000) }

        assertTrue("both callers must reach the start barrier", callersWereReady)
        assertTrue("one caller must enter cold generation", generatorWasEntered)
        assertTrue(
            "the second caller must block on process-local serialization while the first initializes",
            serializedCallerObserved,
        )
        assertFalse("workers must complete after releasing the first generator", workers.any(Thread::isAlive))
        failures.firstOrNull { it != null }?.let { throw AssertionError("worker failed", it) }

        assertEquals(1, generationCount.get())
        assertEquals(1, storage.synchronousWrites.get())
        assertArrayEquals(results[0], results[1])
        val persisted = BarnardDeviceSecretStorage.getOrCreate(storage) {
            error("persisted initialization must not generate a second secret")
        }
        assertArrayEquals(results[0], persisted)
    }

    private fun waitForBlockedWorker(workers: List<Thread>): Boolean {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (System.nanoTime() < deadline) {
            if (workers.any { it.state == Thread.State.BLOCKED }) {
                return true
            }
            Thread.sleep(1)
        }
        return false
    }

    private class InMemoryProtectedStringStorage : BarnardProtectedStringStorage {
        private val values = ConcurrentHashMap<String, String>()
        val synchronousWrites = AtomicInteger()

        override fun getString(key: String): String? = values[key]

        override fun putStringSynchronously(key: String, value: String): Boolean {
            synchronousWrites.incrementAndGet()
            values[key] = value
            return true
        }
    }
}
