package org.levarac.barnard

import kotlin.test.*
import org.junit.Test
import java.io.File

class BarnardParticipantRelayTest {
    private class Clock(var now: Long = 0) : BarnardRelayMonotonicClock { override fun nowMilliseconds() = now }
    private class Enin(var value: Long? = 10) : BarnardRelayEninSource { override fun currentEnin() = value }
    private class Verify(var result: BarnardRelayVerification = BarnardRelayVerification.RegistryVerified(10,22,22)) : BarnardRelayVerifier { override fun verify(envelope: ByteArray, currentEnin: Long) = result }
    private class Sink : BarnardRelayOutputSink { val served = mutableListOf<ByteArray>(); var stops=0; override fun start(container: ByteArray) { served += container }; override fun stop() { stops++ } }
    private data class F(val relay: BarnardParticipantRelay,val clock:Clock,val enin:Enin,val verify:Verify,val sink:Sink)
    private fun fixture(): F { val c=Clock(); val e=Enin(); val v=Verify(); val s=Sink(); return F(BarnardParticipantRelay(c,e,v,s,byteArrayOf(7,8,9)),c,e,v,s) }
    private fun container(hop:Int, vararg envelope:Int):ByteArray { val e=envelope.map(Int::toByte).toByteArray(); return byteArrayOf(3,hop.toByte(),0,e.size.toByte())+e }
    private fun finish(f:F) { f.relay.advance(); f.clock.now += 15_001; f.relay.advance(); if(!f.relay.isServing){f.clock.now=(f.clock.now/30_000+1)*30_000;f.relay.advance();f.clock.now+=15_001;f.relay.advance()} }
    @Test fun hopDedupAndByteExactCopy() { val f=fixture(); assertEquals(BarnardRelayObservationResult.ACCEPTED,f.relay.observe(container(1,1,2,3,4),byteArrayOf(1))); assertEquals(BarnardRelayObservationResult.DUPLICATE,f.relay.observe(container(0,1,2,3,4),byteArrayOf(2))); finish(f); assertContentEquals(container(1,1,2,3,4),f.sink.served.last()) }
    @Test fun hopTwoAndRegistryGate() { val f=fixture(); assertEquals(BarnardRelayObservationResult.ACCEPTED,f.relay.observe(container(2,1),byteArrayOf(1))); finish(f); assertTrue(f.sink.served.isEmpty()); f.verify.result=BarnardRelayVerification.RadioSelfVerified; assertEquals(BarnardRelayObservationResult.REJECTED,f.relay.observe(container(0,2),byteArrayOf(2))) }
    @Test fun selectionPinExpires() { val f=fixture(); f.relay.observe(container(1,1),byteArrayOf(1)); f.relay.observe(container(0,2),byteArrayOf(2)); finish(f); assertEquals(2,f.sink.served.last()[1].toInt()); f.clock.now=300_001; f.relay.advance(); f.clock.now+=15_001; f.relay.advance(); assertEquals(1,f.sink.served.last()[1].toInt()) }
    @Test fun halfOpenEninBoundaries() { for ((n,ok) in listOf(21L to true,22L to false,23L to false)) { val f=fixture(); f.enin.value=n; assertEquals(ok,f.relay.observe(container(0,n.toInt()),byteArrayOf(1))==BarnardRelayObservationResult.ACCEPTED) } }
    @Test fun thirtyThreeHandlesSaturate() { val f=fixture(); val c=container(1,4); f.relay.observe(c,byteArrayOf(0)); for(i in 1..32) assertEquals(BarnardRelayObservationResult.DUPLICATE,f.relay.observe(c,byteArrayOf(i.toByte()))); finish(f); assertTrue(f.sink.served.isEmpty()) }
    @Test fun leaseRenewalAndExpiryTeardown() { val f=fixture(); f.relay.observe(container(0,5),byteArrayOf(1)); finish(f); assertTrue(f.relay.isServing); f.clock.now+=30_000; f.relay.advance(); f.clock.now+=15_001; f.relay.advance(); assertTrue(f.sink.served.size>=2); f.enin.value=22; f.relay.advance(); assertFalse(f.relay.isServing); assertTrue(f.sink.stops>0) }
    @Test fun contentionCancellationAndSensitiveInputsNotExposed() { val f=fixture(); f.relay.observe(container(0,6),byteArrayOf(99)); f.relay.advance(); repeat(3){f.relay.observe(container(1,6),byteArrayOf(it.toByte()))}; f.clock.now+=15_001; f.relay.advance(); assertTrue(f.sink.served.isEmpty()); val publicNames=BarnardParticipantRelay::class.java.methods.map{it.name}; assertFalse(publicNames.any{it.contains("handle",true)||it.contains("secret",true)||it=="getR"}) }
    @Test fun sharedRelayHopAndDensityVectors() {
        fun load(name: String): Map<String, String> {
            val file = sequenceOf(File("../../../test-vectors/$name.txt"), File("test-vectors/$name.txt")).first { it.isFile }
            return file.readLines().filter { !it.startsWith("#") && it.contains('=') }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
        }
        val hop = load("relay-hop-dedup"); val density = load("density-decisions")
        assertEquals("0301000401020304", hop["served_from_zero"]); assertEquals("32", hop["handle_cap"])
        for (r in 0..4) assertEquals(maxOf(0, 3 - r), density["r${r}_enter_numerator"]!!.toInt())
        assertEquals("30000", density["window_ms"]); assertEquals("15000", density["contention_max_ms"])
    }
}
