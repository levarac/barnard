package org.levarac.barnard

import org.levarac.barnard.BarnardCrypto.toHex

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.text.Normalizer

/** B005's unauthenticated, event-scoped discovery hint. */
public class BarnardEventInfo(
    public val eventDisplayName: String,
    eventCodeHash: ByteArray,
) {
    public val eventCodeHash: ByteArray = eventCodeHash.copyOf()
}

/** Local serving state only; neither flag is present in B005 bytes. */
public data class BarnardEventInfoServePolicy(
    val organizerDesignated: Boolean = false,
    val eventActiveForDiscovery: Boolean = false,
) {
    internal val mayServe: Boolean get() = organizerDesignated && eventActiveForDiscovery
}

/** Pure B005 serializer/parser. Hash computation is delegated to B004's function. */
public object BarnardEventInfoCodec {
    public const val FORMAT_VERSION: Int = 1
    public const val MAXIMUM_PAYLOAD_BYTES: Int = 512
    public const val MAXIMUM_DISPLAY_NAME_BYTES: Int = 64

    @JvmStatic
    public fun payloadIfServing(
        policy: BarnardEventInfoServePolicy,
        eventCode: String?,
        eventDisplayName: String?,
        b004EventCodeHash: ByteArray,
    ): ByteArray? {
        if (!policy.mayServe || eventCode.isNullOrEmpty() || eventDisplayName == null) return null
        return serialize(eventCode, eventDisplayName, b004EventCodeHash)
    }

    @JvmStatic
    public fun validateEventDisplayName(eventDisplayName: String) {
        canonicalDisplayNameBytes(eventDisplayName)
    }

    @JvmStatic
    public fun serialize(eventCode: String, eventDisplayName: String, b004EventCodeHash: ByteArray): ByteArray {
        val displayNameBytes = canonicalDisplayNameBytes(eventDisplayName)
        val eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
        require(eventCodeHash.size == 8 && eventCodeHash.contentEquals(b004EventCodeHash)) {
            "B005 EventCodeHash must equal B004"
        }
        val payload = ByteBuffer.allocate(1 + 3 + displayNameBytes.size + 3 + eventCodeHash.size)
            .put(FORMAT_VERSION.toByte())
            .put(0x01)
            .putShort(displayNameBytes.size.toShort())
            .put(displayNameBytes)
            .put(0x02)
            .putShort(eventCodeHash.size.toShort())
            .put(eventCodeHash)
            .array()
        require(payload.size in 16..MAXIMUM_PAYLOAD_BYTES) { "B005 payload length is invalid" }
        return payload
    }

    @JvmStatic
    public fun parse(payload: ByteArray): BarnardEventInfo {
        require(payload.size in 16..MAXIMUM_PAYLOAD_BYTES) { "B005 payload length is invalid" }
        require((payload[0].toInt() and 0xff) == FORMAT_VERSION) { "Unsupported B005 format version" }
        var offset = 1
        var previousType = 0
        var displayName: String? = null
        var eventCodeHash: ByteArray? = null
        while (offset < payload.size) {
            require(offset + 3 <= payload.size) { "Truncated B005 TLV header" }
            val type = payload[offset].toInt() and 0xff
            val length = ((payload[offset + 1].toInt() and 0xff) shl 8) or (payload[offset + 2].toInt() and 0xff)
            offset += 3
            require(type != 0) { "B005 TLV type zero is invalid" }
            require(type > previousType) { "B005 TLV types must be strictly ordered" }
            previousType = type
            require(length <= payload.size - offset) { "Truncated B005 TLV value" }
            val value = payload.copyOfRange(offset, offset + length)
            offset += length
            when (type) {
                0x01 -> {
                    require(displayName == null) { "Duplicate B005 display name" }
                    displayName = validatedDisplayName(value)
                }
                0x02 -> {
                    require(eventCodeHash == null && value.size == 8) { "Invalid B005 EventCodeHash" }
                    eventCodeHash = value
                }
            }
        }
        require(displayName != null) { "B005 display name is required" }
        require(eventCodeHash != null) { "B005 EventCodeHash is required" }
        return BarnardEventInfo(displayName, eventCodeHash)
    }

    private fun canonicalDisplayNameBytes(displayName: String): ByteArray {
        require(Normalizer.normalize(displayName, Normalizer.Form.NFC) == displayName) { "B005 display name must be NFC" }
        val bytes = displayName.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size in 1..MAXIMUM_DISPLAY_NAME_BYTES) { "B005 display name length is invalid" }
        require(displayName.codePoints().allMatch { it > 0x1f && it != 0x7f }) { "B005 display name contains a control" }
        return bytes
    }

    private fun validatedDisplayName(bytes: ByteArray): String {
        val displayName = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } catch (_: Exception) {
            throw IllegalArgumentException("B005 display name is not valid UTF-8")
        }
        canonicalDisplayNameBytes(displayName)
        return displayName
    }
}

public data class BarnardEventInfoDiscoveryObservation(
    val additionalNamesOmitted: Boolean,
    val additionalEventsOmitted: Boolean,
)

/** Bounded, observer-local state for one five-minute B005 discovery session. */
public class BarnardEventInfoDiscoverySession(startedAtMs: Long) {
    private var startedAtMs = startedAtMs
    private val namesByHash = mutableMapOf<String, MutableSet<String>>()
    public var additionalNamesOmitted: Boolean = false
        private set
    public var additionalEventsOmitted: Boolean = false
        private set
    public val retainedHashCount: Int get() = namesByHash.size

    public fun observe(info: BarnardEventInfo, nowMs: Long): BarnardEventInfoDiscoveryObservation {
        if (nowMs - startedAtMs >= 300_000L) {
            startedAtMs = nowMs
            namesByHash.clear()
            additionalNamesOmitted = false
            additionalEventsOmitted = false
        }
        val hash = info.eventCodeHash.toHex()
        val name = info.eventDisplayName
        val names = namesByHash[hash]
        when {
            names != null && name !in names && names.size >= 4 -> additionalNamesOmitted = true
            names != null -> names += name
            namesByHash.size >= 32 -> additionalEventsOmitted = true
            else -> namesByHash[hash] = mutableSetOf(name)
        }
        return BarnardEventInfoDiscoveryObservation(additionalNamesOmitted, additionalEventsOmitted)
    }
}

/** Two B005 transport attempts per peer/session, with a fixed 30-second retry delay. */
public class BarnardEventInfoRetryBudget {
    private val attempts = mutableMapOf<String, Int>()
    private val retryAfterMs = mutableMapOf<String, Long>()
    private val semanticUnavailable = mutableSetOf<String>()

    public fun canStart(peer: String, nowMs: Long): Boolean =
        peer !in semanticUnavailable && (attempts[peer] ?: 0) < 2 && nowMs >= (retryAfterMs[peer] ?: 0L)

    public fun recordRecoverableFailure(peer: String, nowMs: Long): Long? {
        val count = (attempts[peer] ?: 0) + 1
        attempts[peer] = count
        if (count >= 2) return null
        return (nowMs + 30_000L).also { retryAfterMs[peer] = it }
    }

    public fun recordSemanticUnavailable(peer: String) { semanticUnavailable += peer }

    public fun clear(peer: String) {
        attempts.remove(peer)
        retryAfterMs.remove(peer)
        semanticUnavailable.remove(peer)
    }

    public fun clearAll() {
        attempts.clear()
        retryAfterMs.clear()
        semanticUnavailable.clear()
    }
}
