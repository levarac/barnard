package org.levarac.barnard

import kotlin.test.*
import org.junit.Test
import java.io.File

class BarnardParticipantRelayTest {
    private class Clock(var now: Long = 0) : BarnardRelayMonotonicClock { override fun nowMilliseconds() = now }
    private class Enin(var value: Long? = 10) : BarnardRelayEninSource { override fun currentEnin() = value }
    private class Verify(var result: BarnardRelayVerification = BarnardRelayVerification.RegistryVerified(byteArrayOf(1),10,22,22)) : BarnardRelayVerifier { override fun verify(envelope: ByteArray, currentEnin: Long) = result }
    private class Sink : BarnardRelayOutputSink { val served = mutableListOf<ByteArray>(); var stops=0; override fun start(container: ByteArray) { served += container }; override fun stop() { stops++ } }
    private class Joined(var eventId: ByteArray? = null) : BarnardRelayJoinedEventProvider { override fun joinedEventId() = eventId }
    private data class F(val relay: BarnardParticipantRelay,val clock:Clock,val enin:Enin,val verify:Verify,val sink:Sink,val joined:Joined)
    private fun fixture(): F { val c=Clock(); val e=Enin(); val v=Verify(); val s=Sink(); val j=Joined(); return F(BarnardParticipantRelay(c,e,v,s,j,byteArrayOf(7,8,9)),c,e,v,s,j) }
    private fun container(hop:Int, vararg envelope:Int):ByteArray { val e=envelope.map(Int::toByte).toByteArray(); return byteArrayOf(3,hop.toByte(),0,e.size.toByte())+e }
    private fun finish(f:F) { f.relay.advance(); f.clock.now += 15_001; f.relay.advance(); if(!f.relay.isServing){f.clock.now=(f.clock.now/30_000+1)*30_000;f.relay.advance();f.clock.now+=15_001;f.relay.advance()} }
    @Test fun hopDedupAndByteExactCopy() { val f=fixture(); assertEquals(BarnardRelayObservationResult.ACCEPTED,f.relay.observe(container(1,1,2,3,4),byteArrayOf(1))); assertEquals(BarnardRelayObservationResult.DUPLICATE,f.relay.observe(container(0,1,2,3,4),byteArrayOf(2))); finish(f); assertContentEquals(container(1,1,2,3,4),f.sink.served.last()) }
    @Test fun hopTwoAndRegistryGate() { val f=fixture(); assertEquals(BarnardRelayObservationResult.ACCEPTED,f.relay.observe(container(2,1),byteArrayOf(1))); finish(f); assertTrue(f.sink.served.isEmpty()); f.verify.result=BarnardRelayVerification.RadioSelfVerified; assertEquals(BarnardRelayObservationResult.REJECTED,f.relay.observe(container(0,2),byteArrayOf(2))) }
    @Test fun selectionPinExpires() { val f=fixture(); f.relay.observe(container(1,1),byteArrayOf(1)); f.relay.observe(container(0,2),byteArrayOf(2)); finish(f); assertEquals(2,f.sink.served.last()[1].toInt()); f.clock.now=300_001; f.relay.advance(); f.clock.now+=15_001; f.relay.advance(); assertEquals(1,f.sink.served.last()[1].toInt()) }
    @Test fun halfOpenEninBoundaries() { for ((n,ok) in listOf(21L to true,22L to false,23L to false)) { val f=fixture(); f.enin.value=n; assertEquals(ok,f.relay.observe(container(0,n.toInt()),byteArrayOf(1))==BarnardRelayObservationResult.ACCEPTED) } }
    @Test fun thirtyThreeHandlesSaturate() { val f=fixture(); val c=container(1,4); f.relay.observe(c,byteArrayOf(0)); for(i in 1..32) assertEquals(BarnardRelayObservationResult.DUPLICATE,f.relay.observe(c,byteArrayOf(i.toByte()))); f.relay.advance(); f.clock.now += 15_001; f.relay.advance(); assertTrue(f.sink.served.isEmpty()) }

    // P1: a saturated handle set (33rd handle) must expire after T=30s so an
    // inactive candidate can be re-elected once local density is stale.
    @Test fun saturationExpiresAfterDensityWindow() {
        val f = fixture(); val c = container(1, 4)
        f.relay.observe(c, byteArrayOf(0)); for (i in 1..32) assertEquals(BarnardRelayObservationResult.DUPLICATE, f.relay.observe(c, byteArrayOf(i.toByte())))
        f.relay.advance(); f.clock.now += 15_001; f.relay.advance(); assertTrue(f.sink.served.isEmpty())
        f.clock.now += 30_000; f.relay.advance()
        finish(f)
        assertFalse(f.sink.served.isEmpty())
    }

    // P1: r must track the exact set of handles seen within the trailing T=30s
    // window, not a sticky "ever saturated" flag. 32 handles observed at t=0
    // followed by a 33rd at t=29s must yield r=1 (not 3) at t=30s, because the
    // original 32 have aged out of the window by then.
    @Test fun saturatedHandlesExpireIndividuallyNotAsAStickyFlag() {
        val f = fixture(); val c = container(1, 9)
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(c, byteArrayOf(0)))
        for (i in 1..32) assertEquals(BarnardRelayObservationResult.DUPLICATE, f.relay.observe(c, byteArrayOf(i.toByte())))
        f.clock.now = 29_000
        assertEquals(BarnardRelayObservationResult.DUPLICATE, f.relay.observe(c, byteArrayOf(33)))
        // At t=30s the 32 handles seen at t=0 are exactly at the 30s boundary
        // (age == window, not < window) and must no longer count; only the
        // handle refreshed at t=29s (age=1s) is still live, so r=1 lets a
        // fresh candidate enter contention instead of staying suppressed at r=3.
        f.clock.now = 30_000
        finish(f)
        assertFalse(f.sink.served.isEmpty(), "r=1 (or lower, once further aged) after the saturation window must allow relay to start")
    }

    // P1: selection rule 1 -- the joined event's verified envelope wins over a
    // lower-hop, earlier-verified competitor once a reselection actually runs
    // (the five-minute pin holds the original choice until then, per spec).
    @Test fun selectionPrefersJoinedEventOverLowerHop() {
        val f = fixture()
        f.verify.result = BarnardRelayVerification.RegistryVerified(byteArrayOf(9), 10, 600, 22)
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(0, 1), byteArrayOf(1)))
        f.joined.eventId = byteArrayOf(42)
        f.verify.result = BarnardRelayVerification.RegistryVerified(byteArrayOf(42), 10, 600, 22)
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(1, 2), byteArrayOf(2)))
        f.clock.now = 300_001
        f.relay.advance() // pin expired: reselection now compares both candidates
        finish(f)
        assertContentEquals(byteArrayOf(2), f.sink.served.last().copyOfRange(4, f.sink.served.last().size))
    }

    // P1: lastDecisionEpoch must not survive a selection switch -- a newly
    // selected candidate must still get a decision within the same wall-clock
    // epoch that its predecessor was decided in.
    @Test fun decisionEpochResetsOnSelectionSwitch() {
        val f = fixture()
        f.verify.result = BarnardRelayVerification.RegistryVerified(byteArrayOf(1), 10, 22, 11)
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(0, 1), byteArrayOf(1)))
        f.relay.advance() // epoch 0 decision for candidate A (r=0, guaranteed contention entry)
        f.enin.value = 11 // candidate A falls out of [validFrom, expires)
        f.verify.result = BarnardRelayVerification.RegistryVerified(byteArrayOf(2), 10, 22, 22)
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(0, 2), byteArrayOf(2)))
        f.relay.advance() // still epoch 0: must expire A, reset the epoch, and decide for B
        f.clock.now += 15_001
        f.relay.advance() // B's contention window (<=15s) must have completed by now
        assertTrue(f.relay.isServing)
        assertContentEquals(byteArrayOf(2), f.sink.served.last().copyOfRange(4, f.sink.served.last().size))
    }

    // P1: a cached candidate must be re-checked against the full half-open
    // window, both on duplicate short-circuit and in advance().
    @Test fun cachedCandidateRechecksFullWindowOnDuplicateAndAdvance() {
        val f = fixture(); f.enin.value = 15
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(0, 1), byteArrayOf(1)))
        finish(f); assertTrue(f.relay.isServing)
        f.enin.value = 5
        f.relay.advance()
        assertFalse(f.relay.isServing)
        f.enin.value = 15
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(0, 1), byteArrayOf(1)))
        f.enin.value = 5
        assertEquals(BarnardRelayObservationResult.REJECTED, f.relay.observe(container(0, 1), byteArrayOf(2)))
    }

    // P1: Kotlin must constrain every ENIN to the unsigned 32-bit range, matching Swift's UInt32.
    @Test fun negativeEninRejected() {
        val f = fixture(); f.enin.value = -1
        assertEquals(BarnardRelayObservationResult.REJECTED, f.relay.observe(container(0, 1), byteArrayOf(1)))
        val g = fixture()
        g.verify.result = BarnardRelayVerification.RegistryVerified(byteArrayOf(1), -2, 10, 0)
        assertEquals(BarnardRelayObservationResult.REJECTED, g.relay.observe(container(0, 1), byteArrayOf(1)))
    }

    // P1: the verifier's eventId array must be copied on ingest, not aliased --
    // a verifier that reuses its parse buffer must not be able to mutate a
    // stored candidate's event identity after the fact. Candidate A is hop=1
    // and the joined event; candidate B is hop=0 but not joined. Joined-match
    // outranks hop in the selection comparator, so A must still win at
    // reselection even though B has the lower hop -- unless A's stored eventId
    // was corrupted by the post-accept mutation of the verifier's buffer.
    @Test fun eventIdIsCopiedNotAliasedFromVerifier() {
        val f = fixture()
        val mutableEventId = byteArrayOf(1, 2, 3)
        f.verify.result = BarnardRelayVerification.RegistryVerified(mutableEventId, 10, 600, 22)
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(1, 1), byteArrayOf(1)))
        mutableEventId[0] = 99 // simulate the verifier reusing/mutating its parse buffer
        f.joined.eventId = byteArrayOf(1, 2, 3) // A's original, unmutated identity
        f.verify.result = BarnardRelayVerification.RegistryVerified(byteArrayOf(9), 10, 600, 22)
        assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(container(0, 2), byteArrayOf(2)))
        f.clock.now = 300_001
        f.relay.advance() // pin expired: reselection compares both candidates
        finish(f)
        assertContentEquals(byteArrayOf(1), f.sink.served.last().copyOfRange(4, f.sink.served.last().size))
    }

    @Test fun leaseRenewalAndExpiryTeardown() { val f=fixture(); f.relay.observe(container(0,5),byteArrayOf(1)); finish(f); assertTrue(f.relay.isServing); f.clock.now+=30_000; f.relay.advance(); f.clock.now+=15_001; f.relay.advance(); assertTrue(f.sink.served.size>=2); f.enin.value=22; f.relay.advance(); assertFalse(f.relay.isServing); assertTrue(f.sink.stops>0) }
    @Test fun contentionCancellationAndSensitiveInputsNotExposed() { val f=fixture(); f.relay.observe(container(0,6),byteArrayOf(99)); f.relay.advance(); repeat(3){f.relay.observe(container(1,6),byteArrayOf(it.toByte()))}; f.clock.now+=15_001; f.relay.advance(); assertTrue(f.sink.served.isEmpty()); val publicNames=BarnardParticipantRelay::class.java.methods.map{it.name}; assertFalse(publicNames.any{it.contains("handle",true)||it.contains("secret",true)||it=="getR"}) }

    private fun load(name: String): Map<String, String> {
        val file = sequenceOf(File("../../../test-vectors/$name.txt"), File("test-vectors/$name.txt")).first { it.isFile }
        return file.readLines().filter { !it.startsWith("#") && it.contains('=') }
            .associate { it.substringBefore('=') to it.substringAfter('=') }
    }
    private fun hexBytes(hex: String): ByteArray = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    @Test fun sharedRelayHopAndDensityVectors() {
        val hop = load("relay-hop-dedup"); val density = load("density-decisions")
        assertEquals("0301000401020304", hop["served_from_zero"]); assertEquals("32", hop["handle_cap"])
        assertEquals("03", hop["format_version"]); assertEquals("12", hop["relay_lifetime_enins"]); assertEquals("3", density["k"])
        for (r in 0..4) assertEquals(maxOf(0, 3 - r), density["r${r}_enter_numerator"]!!.toInt())
        assertEquals("30000", density["window_ms"]); assertEquals("15000", density["contention_max_ms"])

        val envelope = hexBytes(hop["envelope"]!!)
        val zeroContainer = hexBytes(hop["hop_zero_container"]!!)
        val oneContainer = hexBytes(hop["hop_one_container"]!!)
        val twoContainer = hexBytes(hop["hop_two_container"]!!)
        assertContentEquals(byteArrayOf(3, 0, 0, envelope.size.toByte()) + envelope, zeroContainer)
        assertContentEquals(byteArrayOf(3, 1, 0, envelope.size.toByte()) + envelope, oneContainer)
        assertContentEquals(byteArrayOf(3, 2, 0, envelope.size.toByte()) + envelope, twoContainer)

        run {
            val f = fixture(); assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(zeroContainer, byteArrayOf(1))); finish(f)
            assertContentEquals(hexBytes(hop["served_from_zero"]!!), f.sink.served.last())
        }
        run {
            val f = fixture(); assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(oneContainer, byteArrayOf(1))); finish(f)
            assertContentEquals(hexBytes(hop["served_from_one"]!!), f.sink.served.last())
        }
        run {
            val f = fixture(); assertEquals(BarnardRelayObservationResult.ACCEPTED, f.relay.observe(twoContainer, byteArrayOf(1))); finish(f)
            assertTrue(f.sink.served.isEmpty())
        }

        val windowMs = density["window_ms"]!!.toLong(); val contentionMax = density["contention_max_ms"]!!.toLong(); val k = density["k"]!!.toInt()
        for (r in 0..4) {
            val enterNumerator = density["r${r}_enter_numerator"]!!.toInt()
            val f = fixture()
            // Establish the candidate at hop 0 (direct source) so accepting it does not
            // itself retain a handle -- only hop-positive relay sources count toward r.
            f.relay.observe(container(0, r), byteArrayOf(1))
            for (i in 0 until r) f.relay.observe(container(1, r), byteArrayOf((100 + i).toByte()))
            f.relay.advance(); f.clock.now += contentionMax + 1; f.relay.advance()
            assertEquals(enterNumerator > 0, f.relay.isServing, "r=$r enter decision mismatch")
        }

        // Keep-phase: entry only ever happens at r < k (see the enter-phase
        // loop above), so r=3,4 can never be reached by driving entry with a
        // live r. Instead force a guaranteed entry at r=0 (r0_enter_numerator
        // makes pEnter=1) and then, independently, populate r handles just
        // before the lease boundary so they are still inside the 30s window
        // at the exact instant the keep decision runs -- this is what lets
        // r=3,4 actually reach the keep formula instead of being pruned to
        // r=0 by a full-window advance before the check (round-2 P2).
        for (r in 0..k + 1) {
            val f = fixture()
            f.relay.observe(container(0, 210 + r), byteArrayOf(1))
            f.relay.advance(); f.clock.now += contentionMax + 1; f.relay.advance()
            assertTrue(f.relay.isServing, "keep-phase entry at r=0 must be guaranteed")
            f.clock.now += windowMs - 1
            for (i in 0 until r) f.relay.observe(container(1, 210 + r), byteArrayOf((150 + i).toByte()))
            f.clock.now += 1 // now == activeUntil: triggers the keep decision at this exact r
            f.relay.advance(); f.clock.now += contentionMax + 1; f.relay.advance()
            // pKeep = min(1, k/(r+1)) picks a keep candidate whenever r*_keep_numerator > 0,
            // but Advertise only actually restarts if r < k at the end of the contention
            // delay (advance()'s shared `relayCount(now) < 3` gate) -- both must hold.
            val keepNumerator = density["r${r}_keep_numerator"]?.toInt() ?: k
            val expectKeep = keepNumerator > 0 && r < k
            assertEquals(expectKeep, f.relay.isServing, "r=$r keep decision mismatch")
        }
    }
}
