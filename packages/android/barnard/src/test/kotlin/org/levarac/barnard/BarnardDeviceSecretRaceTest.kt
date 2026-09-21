// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BarnardDeviceSecretRaceTest {
    @Test
    fun concurrentColdInitializationReturnsThePersistedSecret() {
        val baseContext = ApplicationProvider.getApplicationContext<Context>()
        baseContext.getSharedPreferences("barnard", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        val preferences = ColdReadBarrierPreferences(
            baseContext.getSharedPreferences("barnard", Context.MODE_PRIVATE),
        )
        val context = object : ContextWrapper(baseContext) {
            override fun getSharedPreferences(name: String, mode: Int): SharedPreferences = preferences
        }
        val executor = Executors.newFixedThreadPool(2)
        Thread {
            Thread.sleep(1_000)
            preferences.releaseReaders.countDown()
        }.apply {
            isDaemon = true
            start()
        }
        val calls = List(2) { executor.submit<BarnardEngine> { BarnardEngine(context) } }

        try {
            val first = calls[0].get(5, TimeUnit.SECONDS)
            val second = calls[1].get(5, TimeUnit.SECONDS)
            val persisted = preferences.delegate.getString("rpidSeed", null)
                ?: fail("cold initialization did not persist a device secret")
            val persistedEngine = BarnardEngine(context)

            assertEquals(currentTek(first), currentTek(second))
            assertEquals(currentTek(first), currentTek(persistedEngine))
            first.dispose()
            second.dispose()
            persistedEngine.dispose()
        } finally {
            preferences.releaseReaders.countDown()
            executor.shutdownNow()
        }
    }

    private class ColdReadBarrierPreferences(
        val delegate: SharedPreferences,
    ) : SharedPreferences {
        val bothReadersReady = CountDownLatch(2)
        val releaseReaders = CountDownLatch(1)
        override fun getString(key: String, defValue: String?): String? {
            if (key == "rpidSeed" && delegate.getString(key, null) == null) {
                bothReadersReady.countDown()
                check(releaseReaders.await(5, TimeUnit.SECONDS)) { "cold-read barrier timed out" }
            }
            return delegate.getString(key, defValue)
        }

        override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor by delegate.edit() {
            private val editor = delegate.edit()

            override fun putString(key: String, value: String?): SharedPreferences.Editor {
                editor.putString(key, value)
                return this
            }

            override fun apply() {
                editor.commit()
            }

            override fun commit(): Boolean = editor.commit()
        }

        override fun getAll(): Map<String, *> = delegate.all
        override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? = delegate.getStringSet(key, defValues)
        override fun getInt(key: String, defValue: Int): Int = delegate.getInt(key, defValue)
        override fun getLong(key: String, defValue: Long): Long = delegate.getLong(key, defValue)
        override fun getFloat(key: String, defValue: Float): Float = delegate.getFloat(key, defValue)
        override fun getBoolean(key: String, defValue: Boolean): Boolean = delegate.getBoolean(key, defValue)
        override fun contains(key: String): Boolean = delegate.contains(key)
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) = delegate.registerOnSharedPreferenceChangeListener(listener)
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) = delegate.unregisterOnSharedPreferenceChangeListener(listener)
    }

    private fun currentTek(engine: BarnardEngine): List<Byte> {
        val field = BarnardEngine::class.java.getDeclaredField("currentTek")
            .apply { isAccessible = true }
        return (field.get(engine) as ByteArray).toList()
    }
}
