package network.greeting.barnard

internal object BarnardV2Policy {
    fun shouldServeGattDisplayId(eventCode: String?): Boolean {
        return !eventCode.isNullOrEmpty()
    }

    data class KnownPeerWindow(val enin: Long) {
        fun matches(currentEnin: Long): Boolean = enin == currentEnin
    }

    fun shouldEmitRssiUpdate(cachedPeerEnin: Long, currentEnin: Long): Boolean {
        return KnownPeerWindow(cachedPeerEnin).matches(currentEnin)
    }
}
