package network.greeting.barnard

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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
}
