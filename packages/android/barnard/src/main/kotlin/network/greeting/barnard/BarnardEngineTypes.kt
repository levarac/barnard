// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

/**
 * Flutter-free, Kotlin-first public event/value types for [BarnardEngine].
 *
 * These mirror the shapes emitted on the Flutter `barnard/events` and
 * `barnard/debugEvents` channels (see
 * `packages/dart/barnard/android/src/main/kotlin/network/greeting/barnard/BarnardController.kt`)
 * but are expressed as typed Kotlin classes instead of untyped
 * `Map<String, Any?>` payloads.
 */
public data class BarnardBeaconChain(
    val chainId: String,
    val genesisUnixSeconds: Long,
    val slotSeconds: Long,
) {
    public companion object {
        public val ethereumMainnet: BarnardBeaconChain = BarnardBeaconChain(
            chainId = "mainnet",
            genesisUnixSeconds = 1_606_824_023L,
            slotSeconds = 12L,
        )
    }

    internal fun toInternal(): BarnardCrypto.BeaconChainConfig = BarnardCrypto.BeaconChainConfig(
        chainId = chainId,
        genesisUnixSeconds = genesisUnixSeconds,
        slotSeconds = slotSeconds,
    )
}

public enum class BarnardEninMode {
    FIXED_LENGTH,
    BEACON_SLOT,
    ;

    internal fun toInternal(): BarnardCrypto.EninMode = when (this) {
        FIXED_LENGTH -> BarnardCrypto.EninMode.FIXED_LENGTH
        BEACON_SLOT -> BarnardCrypto.EninMode.BEACON_SLOT
    }

    internal companion object {
        fun fromInternal(mode: BarnardCrypto.EninMode): BarnardEninMode = when (mode) {
            BarnardCrypto.EninMode.FIXED_LENGTH -> FIXED_LENGTH
            BarnardCrypto.EninMode.BEACON_SLOT -> BEACON_SLOT
        }
    }
}

public data class BarnardCapabilities(
    val supportedTransports: List<String>,
    val supportsConnectionlessRpid: Boolean,
    val supportsGattFallback: Boolean,
    val supportsBackground: Boolean,
    val supportsHighRateRssi: Boolean,
    val eninMode: BarnardEninMode,
    val eninSeconds: Long,
    val beaconChain: BarnardBeaconChain,
)

public data class BarnardState(
    val isScanning: Boolean,
    val isAdvertising: Boolean,
    val eventCode: String?,
    val eninMode: BarnardEninMode,
    val eninSeconds: Long,
    val beaconChain: BarnardBeaconChain,
    val reasonCode: String?,
)

public data class BarnardPermissionStatus(
    val platform: String,
    val permissions: Map<String, String>,
    val requiredPermissions: List<String>,
    val missingPermissions: List<String>,
    val requestablePermissions: List<String>,
    val blockedPermissions: List<String>,
    val canScan: Boolean,
    val canAdvertise: Boolean,
)

/**
 * Error accompanying a [BarnardPermissionResult.Failed], mirroring the
 * Flutter plugin's `MethodChannel.Result.error` codes for
 * `requestPermissions` (`E_DISPOSED`, `E_NO_ACTIVITY`,
 * `E_PERMISSION_REQUEST_IN_PROGRESS`). [status] carries the
 * last-known [BarnardPermissionStatus] as details, same as the original's
 * error `details` argument — `null` for `E_DISPOSED`, matching the
 * original passing `null` there too.
 */
public data class BarnardPermissionError(
    val code: String,
    val message: String,
    val status: BarnardPermissionStatus?,
)

/**
 * Outcome of [BarnardEngine.requestPermissions]. Callers MUST branch on
 * this instead of assuming every callback invocation means the request
 * actually completed — [Failed] signals a request that never happened
 * (no attached `Activity`, one already in flight) or was abandoned
 * ([BarnardEngine.dispose] called before the platform replied).
 */
public sealed class BarnardPermissionResult {
    public data class Granted(val status: BarnardPermissionStatus) : BarnardPermissionResult()
    public data class Failed(val error: BarnardPermissionError) : BarnardPermissionResult()
}

public data class BarnardDetectionEvent(
    /** Unix epoch milliseconds. */
    val timestampMs: Long,
    val rssi: Int,
    val formatVersion: Int,
    /** Lowercase hex, 17 bytes. */
    val rpid: String,
    /** Lowercase hex, this device's own current RPID at [timestampMs]. */
    val reporterRpid: String,
    val detectedDisplayId: String?,
    val enin: Long,
    val debugLocalName: String?,
)

public data class BarnardRssiUpdateEvent(
    val timestampMs: Long,
    val rssi: Int,
    val rpid: String,
    val reporterRpid: String,
    val enin: Long,
    val detectedDisplayId: String?,
    val debugLocalName: String?,
)

public data class BarnardErrorEvent(
    val code: String,
    val message: String,
    val recoverable: Boolean?,
)

public data class BarnardConstraintEvent(
    val code: String,
    val message: String?,
    val requiredAction: String?,
)

public sealed class BarnardEvent {
    public data class State(val state: BarnardState) : BarnardEvent()
    public data class Constraint(val constraint: BarnardConstraintEvent) : BarnardEvent()
    public data class Error(val error: BarnardErrorEvent) : BarnardEvent()
    public data class Detection(val detection: BarnardDetectionEvent) : BarnardEvent()
    public data class RssiUpdate(val update: BarnardRssiUpdateEvent) : BarnardEvent()
}

public data class BarnardDebugEvent(
    val timestampMs: Long,
    val level: String,
    val name: String,
    val data: Map<String, Any?>?,
)

public data class BarnardAutoStartResult(
    val scanningStarted: Boolean,
    val advertisingStarted: Boolean,
)
