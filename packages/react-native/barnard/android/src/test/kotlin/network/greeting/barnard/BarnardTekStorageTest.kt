package network.greeting.barnard

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BarnardTekStorageTest {

    private lateinit var context: Context

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        context.getSharedPreferences("barnard_tek_storage", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test
    fun store_andGetEntries_returnsStoredTek() {
        val storage = BarnardTekStorage(context)
        val now = System.currentTimeMillis()
        val eventCodeHash = BarnardCrypto.computeEventCodeHash("event-a")
        val entry = TekEntry(
            tek = tek(1),
            eventCodeHash = eventCodeHash,
            exchangedAt = now,
            lastSeenAt = now
        )

        storage.store(entry)

        val entries = storage.getEntries(eventCodeHash)
        assertEquals(1, entries.size)
        assertArrayEquals(entry.tek, entries[0].tek)
        assertEquals(entry.displayId, entries[0].displayId)
    }

    @Test
    fun store_sameTek_updatesLastSeen_withoutDuplicate() {
        val storage = BarnardTekStorage(context)
        val eventCodeHash = BarnardCrypto.computeEventCodeHash("event-a")
        val exchangedAt = System.currentTimeMillis() - 10_000
        val firstSeenAt = exchangedAt
        val secondSeenAt = exchangedAt + 5_000

        storage.store(
            TekEntry(
                tek = tek(7),
                eventCodeHash = eventCodeHash,
                exchangedAt = exchangedAt,
                lastSeenAt = firstSeenAt
            )
        )

        storage.store(
            TekEntry(
                tek = tek(7),
                eventCodeHash = eventCodeHash,
                exchangedAt = exchangedAt,
                lastSeenAt = secondSeenAt
            )
        )

        val entries = storage.getEntries(eventCodeHash)
        assertEquals(1, entries.size)
        assertEquals(secondSeenAt, entries[0].lastSeenAt)
        assertEquals(exchangedAt, entries[0].exchangedAt)
    }

    @Test
    fun clear_removesOnlyTargetEvent() {
        val storage = BarnardTekStorage(context)
        val hashA = BarnardCrypto.computeEventCodeHash("event-a")
        val hashB = BarnardCrypto.computeEventCodeHash("event-b")
        val now = System.currentTimeMillis()

        storage.store(TekEntry(tek(1), hashA, now, now))
        storage.store(TekEntry(tek(2), hashB, now, now))

        val removed = storage.clear(hashA)

        assertEquals(1, removed)
        assertEquals(0, storage.getEntries(hashA).size)
        assertEquals(1, storage.getEntries(hashB).size)
    }

    @Test
    fun clearAll_removesEntriesAcrossAllEvents() {
        val storage = BarnardTekStorage(context)
        val hashA = BarnardCrypto.computeEventCodeHash("event-a")
        val hashB = BarnardCrypto.computeEventCodeHash("event-b")
        val now = System.currentTimeMillis()

        storage.store(TekEntry(tek(1), hashA, now, now))
        storage.store(TekEntry(tek(2), hashA, now, now))
        storage.store(TekEntry(tek(3), hashB, now, now))

        val removed = storage.clearAll()

        assertEquals(3, removed)
        assertEquals(0, storage.getEntries(hashA).size)
        assertEquals(0, storage.getEntries(hashB).size)
    }

    @Test
    fun store_evictsExpiredEntries_byTtl() {
        val storage = BarnardTekStorage(
            context,
            TekStorageConfig(ttlMs = 1, maxEntries = 100)
        )
        val hashA = BarnardCrypto.computeEventCodeHash("event-a")
        val now = System.currentTimeMillis()

        storage.store(
            TekEntry(
                tek = tek(1),
                eventCodeHash = hashA,
                exchangedAt = now - 10_000,
                lastSeenAt = now - 10_000
            )
        )

        assertEquals(0, storage.getEntries(hashA).size)
    }

    @Test
    fun store_evictsLeastRecentlySeen_whenOverCapacity() {
        val storage = BarnardTekStorage(
            context,
            TekStorageConfig(ttlMs = 86_400_000L, maxEntries = 2)
        )
        val hashA = BarnardCrypto.computeEventCodeHash("event-a")
        val base = System.currentTimeMillis()

        val oldTek = tek(11)
        val midTek = tek(22)
        val newTek = tek(33)

        storage.store(TekEntry(oldTek, hashA, base, base))
        storage.store(TekEntry(midTek, hashA, base + 1, base + 1))
        storage.store(TekEntry(newTek, hashA, base + 2, base + 2))

        val stored = storage.getEntries(hashA)

        assertEquals(2, stored.size)
        assertFalse(stored.any { it.tek.contentEquals(oldTek) })
        assertEquals(1, stored.count { it.tek.contentEquals(midTek) })
        assertEquals(1, stored.count { it.tek.contentEquals(newTek) })
    }

    private fun tek(seed: Int): ByteArray {
        return ByteArray(16) { idx -> (seed + idx).toByte() }
    }
}
