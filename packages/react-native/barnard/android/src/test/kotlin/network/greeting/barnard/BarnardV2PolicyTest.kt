package network.greeting.barnard

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

internal class BarnardV2PolicyTest {
    @Test
    fun shouldServeGattDisplayId_onlyWhenJoinedToEvent() {
        assertFalse(BarnardV2Policy.shouldServeGattDisplayId(null))
        assertFalse(BarnardV2Policy.shouldServeGattDisplayId(""))
        assertTrue(BarnardV2Policy.shouldServeGattDisplayId("CONF-2026"))
    }

    @Test
    fun knownPeerRpidIsReusableOnlyWithinSameEnin() {
        val peer = BarnardV2Policy.KnownPeerWindow(enin = 1234)

        assertTrue(peer.matches(1234))
        assertFalse(peer.matches(1235))
    }

    @Test
    fun shouldEmitRssiUpdate_rejectsCachedPeerAfterEninRotation() {
        assertTrue(BarnardV2Policy.shouldEmitRssiUpdate(cachedPeerEnin = 1234, currentEnin = 1234))
        assertFalse(BarnardV2Policy.shouldEmitRssiUpdate(cachedPeerEnin = 1234, currentEnin = 1235))
    }
}
