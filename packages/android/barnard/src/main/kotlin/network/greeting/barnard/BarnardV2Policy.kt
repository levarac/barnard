package network.greeting.barnard

internal object BarnardV2Policy {
    fun shouldServeGattDisplayId(eventCode: String?): Boolean {
        return !eventCode.isNullOrEmpty()
    }

    data class KnownPeerWindow(val enin: Long) {
        fun matches(currentEnin: Long): Boolean = enin == currentEnin
    }

    data class BoundaryRetryBudget(
        val maxRetries: Int = 3,
        private val counts: MutableMap<String, Int> = mutableMapOf()
    ) {
        fun consume(address: String): Boolean {
            if (address.isEmpty()) return false
            val next = (counts[address] ?: 0) + 1
            counts[address] = next
            return next <= maxRetries
        }

        fun clear(address: String) {
            counts.remove(address)
        }

        fun clearAll() {
            counts.clear()
        }
    }

    fun shouldEmitRssiUpdate(cachedPeerEnin: Long, currentEnin: Long): Boolean {
        return KnownPeerWindow(cachedPeerEnin).matches(currentEnin)
    }
}
