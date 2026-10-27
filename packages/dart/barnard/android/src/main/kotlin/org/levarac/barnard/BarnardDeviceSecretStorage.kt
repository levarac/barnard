// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.content.SharedPreferences
import android.util.Base64

internal interface BarnardProtectedStringStorage {
    fun getString(key: String): String?
    fun putStringSynchronously(key: String, value: String): Boolean
}

private class SharedPreferencesProtectedStringStorage(
    private val preferences: SharedPreferences,
) : BarnardProtectedStringStorage {
    override fun getString(key: String): String? = preferences.getString(key, null)

    override fun putStringSynchronously(key: String, value: String): Boolean =
        preferences.edit().putString(key, value).commit()
}

/** In-process serialization for the read-create-persist transaction. */
internal object BarnardDeviceSecretStorage {
    private const val KEY = "rpidSeed"
    private const val SECRET_SIZE = 32
    private val initializationLock = Any()

    fun getOrCreate(
        preferences: SharedPreferences,
        generate: (Int) -> ByteArray = BarnardCrypto::generateRandomBytes,
    ): ByteArray = getOrCreate(SharedPreferencesProtectedStringStorage(preferences), generate)

    internal fun getOrCreate(
        storage: BarnardProtectedStringStorage,
        generate: (Int) -> ByteArray,
    ): ByteArray = synchronized(initializationLock) {
        storage.getString(KEY)?.let { encoded ->
            Base64.decode(encoded, Base64.DEFAULT).takeIf { it.size >= SECRET_SIZE }?.let { return it }
        }

        val secret = generate(SECRET_SIZE)
        val encoded = Base64.encodeToString(secret, Base64.NO_WRAP)
        check(storage.putStringSynchronously(KEY, encoded)) {
            "Unable to persist the Barnard device secret"
        }
        secret
    }
}
