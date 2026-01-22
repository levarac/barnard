// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/**
 * A stored TEK entry from GATT exchange.
 */
data class TekEntry(
    /** The 16-byte TEK. */
    val tek: ByteArray,
    /** The 8-byte EventCodeHash (SHA256(EventCode)[0:8]). */
    val eventCodeHash: ByteArray,
    /** When the TEK was first exchanged (epoch millis). */
    val exchangedAt: Long,
    /** When the TEK holder was last seen (epoch millis). */
    var lastSeenAt: Long
) {
    /** Display ID: first 3 bytes of TEK as uppercase hex. */
    val displayId: String
        get() = BarnardCrypto.displayId(tek)

    /** Convert to JSON for storage. */
    fun toJson(): JSONObject = JSONObject().apply {
        put("tek", Base64.encodeToString(tek, Base64.NO_WRAP))
        put("eventCodeHash", Base64.encodeToString(eventCodeHash, Base64.NO_WRAP))
        put("exchangedAt", exchangedAt)
        put("lastSeenAt", lastSeenAt)
    }

    /** Convert to platform channel map. */
    fun toMap(): Map<String, Any?> = mapOf(
        "tek" to Base64.encodeToString(tek, Base64.NO_WRAP),
        "eventCodeHash" to Base64.encodeToString(eventCodeHash, Base64.NO_WRAP),
        "exchangedAt" to BarnardIso8601.fromMs(exchangedAt),
        "lastSeenAt" to BarnardIso8601.fromMs(lastSeenAt),
        "displayId" to displayId
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TekEntry) return false
        return tek.contentEquals(other.tek)
    }

    override fun hashCode(): Int = tek.contentHashCode()

    companion object {
        /** Create from JSON. */
        fun fromJson(json: JSONObject): TekEntry? {
            return try {
                TekEntry(
                    tek = Base64.decode(json.getString("tek"), Base64.DEFAULT),
                    eventCodeHash = Base64.decode(json.getString("eventCodeHash"), Base64.DEFAULT),
                    exchangedAt = json.getLong("exchangedAt"),
                    lastSeenAt = json.getLong("lastSeenAt")
                )
            } catch (e: Exception) {
                null
            }
        }
    }
}

/**
 * TEK storage configuration.
 */
data class TekStorageConfig(
    /** TTL in milliseconds (default 24 hours). */
    val ttlMs: Long = 86400_000L,
    /** Maximum number of stored entries (default 1000). */
    val maxEntries: Int = 1000
)

/**
 * Persistent storage for exchanged TEKs.
 *
 * Storage is organized by EventCodeHash (base64), with bounded size and TTL.
 */
class BarnardTekStorage(
    private val context: Context,
    private val config: TekStorageConfig = TekStorageConfig()
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("barnard_tek_storage", Context.MODE_PRIVATE)

    private val keyPrefix = "teks_"

    // MARK: - Public API

    /**
     * Store a TEK entry for a given event code hash.
     */
    fun store(entry: TekEntry) {
        val key = storageKey(entry.eventCodeHash)
        val entries = loadEntries(key).toMutableList()

        // Check if we already have this TEK
        val existingIndex = entries.indexOfFirst { it.tek.contentEquals(entry.tek) }
        if (existingIndex >= 0) {
            // Update lastSeenAt
            entries[existingIndex].lastSeenAt = entry.lastSeenAt
        } else {
            entries.add(entry)
        }

        // Evict expired entries
        val now = System.currentTimeMillis()
        val validEntries = entries.filter { now - it.exchangedAt < config.ttlMs }.toMutableList()

        // LRU eviction if over capacity
        if (validEntries.size > config.maxEntries) {
            validEntries.sortBy { it.lastSeenAt }
            validEntries.subList(0, validEntries.size - config.maxEntries).clear()
        }

        saveEntries(validEntries, key)
    }

    /**
     * Get all TEK entries for a given event code hash.
     */
    fun getEntries(eventCodeHash: ByteArray): List<TekEntry> {
        val key = storageKey(eventCodeHash)
        val entries = loadEntries(key)

        // Filter expired entries
        val now = System.currentTimeMillis()
        val validEntries = entries.filter { now - it.exchangedAt < config.ttlMs }

        // Save back if we filtered any
        if (validEntries.size != entries.size) {
            saveEntries(validEntries, key)
        }

        return validEntries
    }

    /**
     * Get all TEKs (as ByteArray) for a given event code hash.
     */
    fun getTeks(eventCodeHash: ByteArray): List<ByteArray> {
        return getEntries(eventCodeHash).map { it.tek }
    }

    /**
     * Clear all TEKs for a given event code hash.
     * @return The number of entries removed.
     */
    fun clear(eventCodeHash: ByteArray): Int {
        val key = storageKey(eventCodeHash)
        val entries = loadEntries(key)
        val count = entries.size
        prefs.edit().remove(key).apply()
        return count
    }

    /**
     * Clear all stored TEKs across all events.
     * @return The total number of entries removed.
     */
    fun clearAll(): Int {
        var total = 0

        val allKeys = prefs.all.keys.filter { it.startsWith(keyPrefix) }
        val editor = prefs.edit()

        for (key in allKeys) {
            val entries = loadEntries(key)
            total += entries.size
            editor.remove(key)
        }

        editor.apply()
        return total
    }

    /**
     * Update lastSeenAt for a TEK if it exists.
     */
    fun updateLastSeen(tek: ByteArray, eventCodeHash: ByteArray, at: Long = System.currentTimeMillis()) {
        val key = storageKey(eventCodeHash)
        val entries = loadEntries(key).toMutableList()

        val index = entries.indexOfFirst { it.tek.contentEquals(tek) }
        if (index >= 0) {
            entries[index].lastSeenAt = at
            saveEntries(entries, key)
        }
    }

    // MARK: - Private

    private fun storageKey(eventCodeHash: ByteArray): String {
        return keyPrefix + Base64.encodeToString(eventCodeHash, Base64.NO_WRAP)
    }

    private fun loadEntries(key: String): List<TekEntry> {
        val jsonString = prefs.getString(key, null) ?: return emptyList()

        return try {
            val array = JSONArray(jsonString)
            (0 until array.length()).mapNotNull { i ->
                TekEntry.fromJson(array.getJSONObject(i))
            }
        } catch (e: Exception) {
            // Corrupted data, clear it
            prefs.edit().remove(key).apply()
            emptyList()
        }
    }

    private fun saveEntries(entries: List<TekEntry>, key: String) {
        if (entries.isEmpty()) {
            prefs.edit().remove(key).apply()
            return
        }

        val array = JSONArray()
        for (entry in entries) {
            array.put(entry.toJson())
        }
        prefs.edit().putString(key, array.toString()).apply()
    }
}
