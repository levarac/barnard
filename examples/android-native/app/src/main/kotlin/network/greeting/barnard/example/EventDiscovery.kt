// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard.example

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * Spike (barnard-eventcode-discovery, not production): wire format for the
 * organizer -> participant BLE announcement that lets a participant derive
 * an event's EventCode without typing it.
 *
 * Design note: docs/spike-eventcode-discovery.md ("Payload format" /
 * "GATT-characteristic announcement" design).
 *
 * The announcement rides a GATT characteristic read (ATT MTU budget), not
 * the legacy 31-byte advertisement payload -- the advertisement only says
 * "an announcement is readable here" via a fixed discovery service UUID.
 */
object EventDiscovery {
    /** Fixed, not per-event -- same rationale as barnard's B001 service UUID. */
    val DISCOVERY_SERVICE_UUID: UUID = UUID.fromString("0000b101-0000-1000-8000-00805f9b34fb")

    /** Read-only characteristic carrying the serialized [Announcement]. */
    val ANNOUNCEMENT_CHARACTERISTIC_UUID: UUID = UUID.fromString("0000b102-0000-1000-8000-00805f9b34fb")

    private const val VERSION: Byte = 1

    data class Announcement(
        val eventId: String,
        val eventCode: String,
        val expiresAtEpochSec: Long,
    ) {
        val isExpired: Boolean
            get() = System.currentTimeMillis() / 1000L >= expiresAtEpochSec
    }

    /**
     * version(1) | eventIdLen(1) | eventId(utf8) | eventCodeLen(1) | eventCode(utf8) | expiresAtEpochSec(8, BE)
     *
     * No device-unique bytes anywhere in this payload -- eventId is
     * organizer-chosen, eventCode is the existing event-scoped secret,
     * expiresAtEpochSec is a timestamp.
     */
    fun encode(announcement: Announcement): ByteArray {
        val eventIdBytes = announcement.eventId.toByteArray(StandardCharsets.UTF_8)
        val eventCodeBytes = announcement.eventCode.toByteArray(StandardCharsets.UTF_8)
        require(eventIdBytes.size <= 255) { "eventId too long for spike wire format" }
        require(eventCodeBytes.size <= 255) { "eventCode too long for spike wire format" }

        val buffer = ByteBuffer.allocate(1 + 1 + eventIdBytes.size + 1 + eventCodeBytes.size + 8)
            .order(ByteOrder.BIG_ENDIAN)
        buffer.put(VERSION)
        buffer.put(eventIdBytes.size.toByte())
        buffer.put(eventIdBytes)
        buffer.put(eventCodeBytes.size.toByte())
        buffer.put(eventCodeBytes)
        buffer.putLong(announcement.expiresAtEpochSec)
        return buffer.array()
    }

    /** Returns null on any malformed/unsupported-version payload (fail closed). */
    fun decode(bytes: ByteArray): Announcement? {
        return try {
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val version = buffer.get()
            if (version != VERSION) return null

            val eventIdLen = buffer.get().toInt() and 0xFF
            val eventIdBytes = ByteArray(eventIdLen)
            buffer.get(eventIdBytes)

            val eventCodeLen = buffer.get().toInt() and 0xFF
            val eventCodeBytes = ByteArray(eventCodeLen)
            buffer.get(eventCodeBytes)

            val expiresAtEpochSec = buffer.long

            Announcement(
                eventId = String(eventIdBytes, StandardCharsets.UTF_8),
                eventCode = String(eventCodeBytes, StandardCharsets.UTF_8),
                expiresAtEpochSec = expiresAtEpochSec,
            )
        } catch (e: Exception) {
            null
        }
    }
}
