package org.levarac.barnard

import org.levarac.barnard.BarnardCrypto.toHex

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.text.Normalizer

/** B005's unauthenticated, event-scoped discovery hint. */
public class BarnardEventInfo(
    public val eventDisplayName: String,
    eventCodeHash: ByteArray,
    census: ByteArray? = null,
) {
    private val eventCodeHashBytes: ByteArray = eventCodeHash.copyOf()
    private val censusBytes: ByteArray? = census?.copyOf()

    /** Returns a defensive copy; mutating it cannot affect equality or hashing. */
    public val eventCodeHash: ByteArray
        get() = eventCodeHashBytes.copyOf()

    /** Reserved for the optional 0x10 census extension. v1 leaves it absent. Returns a defensive copy. */
    public val census: ByteArray?
        get() = censusBytes?.copyOf()

    override fun equals(other: Any?): Boolean =
        other is BarnardEventInfo &&
            eventDisplayName == other.eventDisplayName &&
            eventCodeHashBytes.contentEquals(other.eventCodeHashBytes) &&
            censusBytes.contentEquals(other.censusBytes)

    override fun hashCode(): Int =
        31 * (31 * eventDisplayName.hashCode() + eventCodeHashBytes.contentHashCode()) + censusBytes.contentHashCode()
}

/** Kotlin mirror of Swift's [BarnardEventInfoError] reasons. */
public enum class BarnardEventInfoError {
    INVALID_PAYLOAD_LENGTH,
    UNSUPPORTED_FORMAT_VERSION,
    TRUNCATED_TLV,
    ZERO_TLV_TYPE,
    UNORDERED_TLV_TYPES,
    MISSING_DISPLAY_NAME,
    MISSING_EVENT_CODE_HASH,
    INVALID_DISPLAY_NAME,
    INVALID_EVENT_CODE_HASH,
    EVENT_CODE_HASH_MISMATCH,
}

public class BarnardEventInfoException(
    public val reason: BarnardEventInfoError,
) : IllegalArgumentException(reason.name)

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
        requireEventInfo(eventCodeHash.size == 8 && eventCodeHash.contentEquals(b004EventCodeHash), BarnardEventInfoError.EVENT_CODE_HASH_MISMATCH)
        val payload = ByteBuffer.allocate(1 + 3 + displayNameBytes.size + 3 + eventCodeHash.size)
            .put(FORMAT_VERSION.toByte())
            .put(0x01)
            .putShort(displayNameBytes.size.toShort())
            .put(displayNameBytes)
            .put(0x02)
            .putShort(eventCodeHash.size.toShort())
            .put(eventCodeHash)
            .array()
        requireEventInfo(payload.size in 16..MAXIMUM_PAYLOAD_BYTES, BarnardEventInfoError.INVALID_PAYLOAD_LENGTH)
        return payload
    }

    @JvmStatic
    public fun parse(payload: ByteArray): BarnardEventInfo {
        requireEventInfo(payload.size in 16..MAXIMUM_PAYLOAD_BYTES, BarnardEventInfoError.INVALID_PAYLOAD_LENGTH)
        requireEventInfo((payload[0].toInt() and 0xff) == FORMAT_VERSION, BarnardEventInfoError.UNSUPPORTED_FORMAT_VERSION)
        var offset = 1
        var previousType = 0
        var displayName: String? = null
        var eventCodeHash: ByteArray? = null
        while (offset < payload.size) {
            requireEventInfo(offset + 3 <= payload.size, BarnardEventInfoError.TRUNCATED_TLV)
            val type = payload[offset].toInt() and 0xff
            val length = ((payload[offset + 1].toInt() and 0xff) shl 8) or (payload[offset + 2].toInt() and 0xff)
            offset += 3
            requireEventInfo(type != 0, BarnardEventInfoError.ZERO_TLV_TYPE)
            requireEventInfo(type > previousType, BarnardEventInfoError.UNORDERED_TLV_TYPES)
            previousType = type
            requireEventInfo(length <= payload.size - offset, BarnardEventInfoError.TRUNCATED_TLV)
            val value = payload.copyOfRange(offset, offset + length)
            offset += length
            when (type) {
                0x01 -> {
                    requireEventInfo(displayName == null, BarnardEventInfoError.UNORDERED_TLV_TYPES)
                    displayName = validatedDisplayName(value)
                }
                0x02 -> {
                    requireEventInfo(eventCodeHash == null && value.size == 8, BarnardEventInfoError.INVALID_EVENT_CODE_HASH)
                    eventCodeHash = value
                }
            }
        }
        val resolvedDisplayName = displayName ?: throw BarnardEventInfoException(BarnardEventInfoError.MISSING_DISPLAY_NAME)
        val resolvedEventCodeHash = eventCodeHash ?: throw BarnardEventInfoException(BarnardEventInfoError.MISSING_EVENT_CODE_HASH)
        return BarnardEventInfo(resolvedDisplayName, resolvedEventCodeHash)
    }

    @JvmStatic
    public fun matchesB004(info: BarnardEventInfo, b004EventCodeHash: ByteArray): Boolean =
        b004EventCodeHash.isNotEmpty() && info.eventCodeHash.contentEquals(b004EventCodeHash)

    private fun canonicalDisplayNameBytes(displayName: String): ByteArray {
        requireEventInfo(Normalizer.normalize(displayName, Normalizer.Form.NFC) == displayName, BarnardEventInfoError.INVALID_DISPLAY_NAME)
        val bytes = try {
            val encoded = StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(displayName))
            ByteArray(encoded.remaining()).also(encoded::get)
        } catch (_: Exception) {
            throw BarnardEventInfoException(BarnardEventInfoError.INVALID_DISPLAY_NAME)
        }
        requireEventInfo(bytes.size in 1..MAXIMUM_DISPLAY_NAME_BYTES, BarnardEventInfoError.INVALID_DISPLAY_NAME)
        requireEventInfo(displayName.codePoints().allMatch { it > 0x1f && it != 0x7f }, BarnardEventInfoError.INVALID_DISPLAY_NAME)
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
            throw BarnardEventInfoException(BarnardEventInfoError.INVALID_DISPLAY_NAME)
        }
        canonicalDisplayNameBytes(displayName)
        return displayName
    }

    private fun requireEventInfo(condition: Boolean, reason: BarnardEventInfoError) {
        if (!condition) throw BarnardEventInfoException(reason)
    }
}

public data class BarnardEventInfoDiscoveryObservation(
    val additionalNamesOmitted: Boolean,
    val additionalEventsOmitted: Boolean,
    val shouldEmitGenericHint: Boolean,
)

/** Replaces an overflowed B005 hint with a marker that has no parsed data. */
internal fun eventInfoForDiscoveryHint(
    eventInfo: BarnardEventInfo,
    shouldEmitGenericHint: Boolean,
): BarnardEventInfo = if (shouldEmitGenericHint) BarnardEventInfo("", ByteArray(0)) else eventInfo

/** Bounded, observer-local state for one five-minute B005 discovery session. */
public class BarnardEventInfoDiscoverySession(startedAtMs: Long) {
    private var startedAtMs = startedAtMs
    private val namesByHash = mutableMapOf<String, MutableSet<String>>()
    public var additionalNamesOmitted: Boolean = false
        private set
    public var additionalEventsOmitted: Boolean = false
        private set
    public val retainedHashCount: Int get() = synchronized(this) { namesByHash.size }

    @Synchronized
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
        var overflowedThisObservation = false
        when {
            names != null && name !in names && names.size >= 4 -> additionalNamesOmitted = true
            names != null -> names += name
            namesByHash.size >= 32 -> {
                additionalEventsOmitted = true
                overflowedThisObservation = true
            }
            else -> namesByHash[hash] = mutableSetOf(name)
        }
        return BarnardEventInfoDiscoveryObservation(
            additionalNamesOmitted,
            additionalEventsOmitted,
            overflowedThisObservation,
        )
    }
}

/** Two B005 transport attempts per peer/session, with a fixed 30-second retry delay. */
public class BarnardEventInfoRetryBudget {
    private val attempts = mutableMapOf<String, Int>()
    private val retryAfterMs = mutableMapOf<String, Long>()
    private val semanticUnavailable = mutableSetOf<String>()
    private val lastSeenMs = mutableMapOf<String, Long>()

    @Synchronized
    public fun canStart(peer: String, nowMs: Long): Boolean {
        prune(nowMs)
        lastSeenMs[peer] = nowMs
        return peer !in semanticUnavailable && (attempts[peer] ?: 0) < 2 && nowMs >= (retryAfterMs[peer] ?: 0L)
    }

    @Synchronized
    public fun recordRecoverableFailure(peer: String, nowMs: Long): Long? {
        prune(nowMs)
        lastSeenMs[peer] = nowMs
        val count = (attempts[peer] ?: 0) + 1
        attempts[peer] = count
        if (count >= 2) return null
        return (nowMs + 30_000L).also { retryAfterMs[peer] = it }
    }

    /** A successful B005 read still consumes one of the two session attempts. */
    @Synchronized
    public fun recordSuccessfulAttempt(peer: String, nowMs: Long) {
        prune(nowMs)
        lastSeenMs[peer] = nowMs
        attempts[peer] = (attempts[peer] ?: 0) + 1
        retryAfterMs.remove(peer)
    }

    @Synchronized
    public fun recordSemanticUnavailable(peer: String, nowMs: Long = System.currentTimeMillis()) {
        prune(nowMs)
        lastSeenMs[peer] = nowMs
        semanticUnavailable += peer
    }

    @Synchronized
    public fun clear(peer: String) {
        attempts.remove(peer)
        retryAfterMs.remove(peer)
        semanticUnavailable.remove(peer)
        lastSeenMs.remove(peer)
    }

    @Synchronized
    public fun clearAll() {
        attempts.clear()
        retryAfterMs.clear()
        semanticUnavailable.clear()
        lastSeenMs.clear()
    }

    private fun prune(nowMs: Long) {
        val stalePeers = lastSeenMs.filterValues { seenAt -> nowMs >= seenAt && nowMs - seenAt >= 300_000L }.keys
        stalePeers.forEach(::clear)
    }
}
