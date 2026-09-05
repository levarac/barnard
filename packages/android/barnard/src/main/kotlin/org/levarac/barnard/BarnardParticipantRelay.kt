// Use of this source code is governed by a BSD-style license.
package org.levarac.barnard

import java.security.MessageDigest

public fun interface BarnardRelayMonotonicClock { public fun nowMilliseconds(): Long }
public fun interface BarnardRelayEninSource { public fun currentEnin(): Long? }
public fun interface BarnardRelayVerifier { public fun verify(envelope: ByteArray, currentEnin: Long): BarnardRelayVerification }
public interface BarnardRelayOutputSink { public fun start(container: ByteArray); public fun stop() }
public fun interface BarnardRelayJoinedEventProvider { public fun joinedEventId(): ByteArray? }
public sealed class BarnardRelayVerification {
    public data object Rejected : BarnardRelayVerification()
    public data object RadioSelfVerified : BarnardRelayVerification()
    public data class RegistryVerified(val eventId: ByteArray, val validFromEnin: Long, val validThroughEnin: Long, val relayExpiresAtEnin: Long) : BarnardRelayVerification()
}
public enum class BarnardRelayObservationResult { ACCEPTED, DUPLICATE, SATURATED, REJECTED }

private val ENIN_RANGE = 0L..0xFFFF_FFFFL

/** Pure relay policy. Sensitive election and neighborhood inputs have no accessor. */
public class BarnardParticipantRelay(
    private val clock: BarnardRelayMonotonicClock, private val eninSource: BarnardRelayEninSource,
    private val verifier: BarnardRelayVerifier, private val sink: BarnardRelayOutputSink,
    private val joinedEventProvider: BarnardRelayJoinedEventProvider,
    randomnessSeedMaterial: ByteArray,
) {
    private data class Candidate(val digest: ByteArray, val envelope: ByteArray, var hop: Int, val eventId: ByteArray, val verifiedAt: Long, val validFrom: Long, val validThrough: Long, val expires: Long)
    private val electionKey = randomnessSeedMaterial.copyOf()
    private val candidates = linkedMapOf<String, Candidate>()
    private var selected: String? = null; private var pinUntil = 0L
    private val handles = linkedMapOf<String, Long>()
    private var overflowSeenAt: Long? = null
    private var activeUntil: Long? = null; private var contentionUntil: Long? = null; private var lastDecisionEpoch: Long? = null; private var stopped = false

    private fun withinRelayWindow(c: Candidate, current: Long): Boolean = current in c.validFrom until c.expires

    public fun observe(container: ByteArray, peerHandle: ByteArray): BarnardRelayObservationResult {
        if (stopped || container.size !in 5..512 || container[0].toInt() != 3 || (container[1].toInt() and 255) > 2) return BarnardRelayObservationResult.REJECTED
        val n = ((container[2].toInt() and 255) shl 8) or (container[3].toInt() and 255)
        val current = eninSource.currentEnin() ?: return BarnardRelayObservationResult.REJECTED
        if (current !in ENIN_RANGE) return BarnardRelayObservationResult.REJECTED
        if (n !in 1..508 || n + 4 != container.size) return BarnardRelayObservationResult.REJECTED
        val envelope = container.copyOfRange(4, container.size); val digest = MessageDigest.getInstance("SHA-256").digest(envelope); val key = digest.hex()
        candidates[key]?.let { old ->
            if (!withinRelayWindow(old, current)) {
                candidates.remove(key)
                if (selected == key) deselect()
                return BarnardRelayObservationResult.REJECTED
            }
            old.hop = minOf(old.hop, container[1].toInt() and 255)
            if (selected == key && (container[1].toInt() and 255) > 0) retain(peerHandle, clock.nowMilliseconds())
            return BarnardRelayObservationResult.DUPLICATE
        }
        if (candidates.size == 32) return BarnardRelayObservationResult.SATURATED
        val verified = verifier.verify(envelope.copyOf(), current) as? BarnardRelayVerification.RegistryVerified ?: return BarnardRelayObservationResult.REJECTED
        if (verified.validFromEnin !in ENIN_RANGE || verified.validThroughEnin !in ENIN_RANGE || verified.relayExpiresAtEnin !in ENIN_RANGE) return BarnardRelayObservationResult.REJECTED
        if (current < verified.validFromEnin || current >= verified.relayExpiresAtEnin || verified.relayExpiresAtEnin > verified.validThroughEnin || verified.relayExpiresAtEnin - verified.validFromEnin !in 0..12) return BarnardRelayObservationResult.REJECTED
        candidates[key] = Candidate(digest, envelope, container[1].toInt() and 255, verified.eventId.copyOf(), clock.nowMilliseconds(), verified.validFromEnin, verified.validThroughEnin, verified.relayExpiresAtEnin)
        selectIfNeeded(selected == null); if (selected == key && (container[1].toInt() and 255) > 0) retain(peerHandle, clock.nowMilliseconds())
        return BarnardRelayObservationResult.ACCEPTED
    }
    public fun advance() {
        if (stopped) return; val now = clock.nowMilliseconds(); val current = eninSource.currentEnin() ?: run { teardown(); return }
        candidates.entries.removeIf { !withinRelayWindow(it.value, current) }; if (selected != null && !candidates.containsKey(selected)) deselect(); selectIfNeeded(selected == null || now >= pinUntil)
        handles.entries.removeIf { now - it.value >= 30_000 }
        var wasActive = false; activeUntil?.let { if (now >= it) { wasActive = true; stopLease() } }
        contentionUntil?.let { if (now >= it) { contentionUntil = null; if (relayCount(now) < 3) startLease(now) } }
        if (contentionUntil != null || activeUntil != null) return; val candidate = selected?.let { candidates[it] } ?: return; if (candidate.hop >= 2) return
        // Spec: decision runs once per 30s wall-clock epoch, not re-evaluated every time r changes within it.
        val epoch = now / 30_000; if (lastDecisionEpoch == epoch) return; lastDecisionEpoch = epoch; val r = relayCount(now); val threshold = if (wasActive) minOf(1.0, 3.0 / (r + 1)) else ((3 - r).toDouble() / 3.0).coerceIn(0.0, 1.0)
        if (randomUnit(candidate.digest, epoch, 0) < threshold) contentionUntil = now + (randomUnit(candidate.digest, epoch, 1) * 15_001.0).toLong()
    }
    public fun invalidateDefinition() = teardown(); public fun signatureFailed() = teardown()
    public fun hostStop() { stopped = true; teardown() }; public val isServing: Boolean get() = activeUntil != null
    private fun selectIfNeeded(force: Boolean) {
        if (!force) return; val old = selected; val joined = joinedEventProvider.joinedEventId()
        selected = candidates.entries.sortedWith(
            compareBy(
                { !(joined != null && it.value.eventId.contentEquals(joined)) },
                { it.value.hop },
                { it.value.verifiedAt },
                { it.key },
            ),
        ).firstOrNull()?.key
        pinUntil = clock.nowMilliseconds() + 300_000
        if (old != selected) { stopLease(); handles.clear(); overflowSeenAt = null; lastDecisionEpoch = null }
    }
    private fun retain(handle: ByteArray, now: Long) {
        // Prune before checking the 32-handle cap so a handle observed T ago no longer holds a slot.
        // Spec line 231: "further handles saturate r >= k without being retained" -- a new handle
        // arriving while 32 are already retained is neither retained nor allowed to evict an
        // existing one; it only marks overflowSeenAt so r reads as saturated until that overflow
        // itself ages out of the window.
        handles.entries.removeIf { now - it.value >= 30_000 }
        val key = handle.hex()
        if (key in handles) { handles[key] = now; return }
        if (handles.size >= 32) { overflowSeenAt = now; return }
        handles[key] = now
    }
    private fun relayCount(now: Long): Int {
        val live = handles.values.count { now - it < 30_000 }
        val overflow = overflowSeenAt
        return if (overflow != null && now - overflow < 30_000) maxOf(live, 3) else live
    }
    private fun startLease(now: Long) { val c = selected?.let { candidates[it] } ?: return; if (c.hop >= 2) return; val n = c.envelope.size; sink.start(byteArrayOf(3, (c.hop + 1).toByte(), (n shr 8).toByte(), n.toByte()) + c.envelope); activeUntil = now + 30_000 }
    private fun stopLease() { if (activeUntil != null) sink.stop(); activeUntil = null; contentionUntil = null }
    private fun deselect() { stopLease(); selected = null; handles.clear(); overflowSeenAt = null; lastDecisionEpoch = null }
    private fun teardown() { deselect(); candidates.clear() }
    private fun randomUnit(digest: ByteArray, epoch: Long, purpose: Int): Double { val bytes = electionKey + digest + ByteArray(8) { (epoch ushr (56 - it * 8)).toByte() } + purpose.toByte(); val hash = MessageDigest.getInstance("SHA-256").digest(bytes); var value = 0L; repeat(8) { value = (value shl 8) or (hash[it].toLong() and 255) }; return (value ushr 11).toDouble() / 9_007_199_254_740_992.0 }
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
}
