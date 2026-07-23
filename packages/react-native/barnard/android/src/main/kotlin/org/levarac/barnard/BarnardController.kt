// Use of this source code is governed by a BSD-style license.

package org.levarac.barnard

import android.Manifest
import android.app.Activity
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.provider.Settings
import android.util.Base64
import android.util.Log
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import org.levarac.barnard.BarnardCrypto.toHex
import java.util.UUID

private const val TAG = "BarnardBLE"

internal fun isRuntimePermissionRequestBlocked(
    sdkInt: Int,
    hasPermission: Boolean,
    wasRequestedBefore: Boolean,
    shouldShowRequestPermissionRationale: Boolean
): Boolean {
    if (sdkInt < 23 || hasPermission) return false
    if (!wasRequestedBefore) return false
    return !shouldShowRequestPermissionRationale
}

/**
 * Barnard v2 BLE controller (React Native bridge variant).
 *
 * Mirrors the Flutter v2 controller but emits events via WritableMap
 * callbacks (onEvent / onDebugEvent) instead of a method channel.
 *
 * - B002 RPID (Read, 17 bytes)
 * - B003 displayId (Read, 4 bytes when joined to an event) — SHA256(TEK)[0:4]
 * - B004 EventCodeHash (Read, 0 or 8 bytes)
 *
 * TEK is never transmitted over BLE in v2.
 */
internal class BarnardController(
    private val appContext: Context
) {
    private companion object {
        const val permissionRequestedKeyPrefix = "permission_requested:"
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    var onEvent: ((String, WritableMap) -> Unit)? = null
    var onDebugEvent: ((String, WritableMap) -> Unit)? = null

    // MARK: - UUIDs

    private val serviceUuid: UUID = UUID.fromString("0000B001-0000-1000-8000-00805F9B34FB")
    private val rpidCharUuid: UUID = UUID.fromString("0000B002-0000-1000-8000-00805F9B34FB")
    private val displayIdCharUuid: UUID = UUID.fromString("0000B003-0000-1000-8000-00805F9B34FB")
    private val eventCodeHashCharUuid: UUID = UUID.fromString("0000B004-0000-1000-8000-00805F9B34FB")

    // MARK: - Bluetooth

    private val bluetoothManager: BluetoothManager? =
        appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager?.adapter

    private var gattServer: BluetoothGattServer? = null

    // MARK: - State

    private var isScanning: Boolean = false
    private var isAdvertising: Boolean = false
    private var allowDuplicates: Boolean = true
    private var formatVersion: Int = 1
    private var debugOriginalName: String? = null
    private val unavailableRssi: Int = 127
    private var eninMode: BarnardCrypto.EninMode = BarnardCrypto.EninMode.FIXED_LENGTH
    private var eninSeconds: Long = 300L
    private var beaconChain: BarnardCrypto.BeaconChainConfig = BarnardCrypto.BeaconChainConfig()

    // MARK: - Event Mode

    private var eventCode: String? = null
    @Volatile
    private var currentTek: ByteArray = ByteArray(16)

    private data class CachedReporterPayload(
        val enin: UInt,
        val tekHash: Int,
        val payload: ByteArray,
    )

    private var cachedReporterPayload: CachedReporterPayload? = null

    // MARK: - Discovery State

    private val discoveredRssi: MutableMap<String, Int> = mutableMapOf()
    private val discoveredAt: MutableMap<String, Long> = mutableMapOf()
    private val lastDiscoveryNameById: MutableMap<String, String> = mutableMapOf()

    // MARK: - Connection Queue

    private val connectQueue: ArrayDeque<BluetoothDevice> = ArrayDeque()
    private val lastConnectAttemptAtMs: MutableMap<String, Long> = mutableMapOf()
    private val resolutionBackoffUntilMs: MutableMap<String, Long> = mutableMapOf()
    private val pendingBoundaryRetryDevices: MutableMap<String, BluetoothDevice> = mutableMapOf()
    private val boundaryRetryBudget = BarnardV2Policy.BoundaryRetryBudget()
    private var activeGatt: BluetoothGatt? = null

    private val maxConnectQueue: Int = 20
    private val cooldownPerPeerMs: Long = 10_000
    private val resolutionFailureBackoffMs: Long = 30_000
    private val resolutionRejectedBackoffMs: Long = 5 * 60_000

    // See Flutter Android variant: prevent `activeGatt` from pinning the
    // queue forever when `connectGatt` never receives a callback.
    private val connectTimeoutMs: Long = 8_000
    private var connectWatchdog: Runnable? = null

    // MARK: - Central GATT State (v2)

    private data class GattReadValues(
        var eventCodeHash: ByteArray? = null,
        var rpid: ByteArray? = null,
        var rpidReadStartedAtMs: Long? = null,
        var rpidReadCompletedAtMs: Long? = null,
        var detectedDisplayId: ByteArray? = null
    )

    private val peripheralReadValues: MutableMap<String, GattReadValues> = mutableMapOf()

    // MARK: - Known Peers

    private data class KnownPeer(
        val rpid: ByteArray,
        val enin: Long,
        val detectedDisplayId: String?
    )

    private val knownPeers: MutableMap<String, KnownPeer> = mutableMapOf()

    // MARK: - Storage

    private val prefs: SharedPreferences =
        appContext.getSharedPreferences("barnard", Context.MODE_PRIVATE)

    init {
        initializeTek()
    }

    private fun isDebugBuild(): Boolean {
        return BuildConfig.BUILD_TYPE != "release"
    }

    private fun initializeTek() {
        eventCode = prefs.getString("eventCode", null)

        val deviceSecret = getOrCreateDeviceSecret()
        currentTek = if (eventCode != null) {
            BarnardCrypto.deriveTekForEvent(deviceSecret, eventCode!!)
        } else {
            BarnardCrypto.deriveTekForAnonymous(deviceSecret)
        }
    }

    fun dispose() {
        stopScanInternal()
        stopAdvertiseInternal()
        onEvent = null
        onDebugEvent = null
    }

    // MARK: - Public API

    fun getCapabilities(): WritableMap {
        val transports = Arguments.createArray().apply { pushString("ble") }
        return Arguments.createMap().apply {
            putArray("supportedTransports", transports)
            putBoolean("supportsConnectionlessRpid", false)
            putBoolean("supportsGattFallback", true)
            putBoolean("supportsBackground", false)
            putBoolean("supportsHighRateRssi", false)
            putString("eninMode", eninModeName())
            putInt("eninSeconds", eninSeconds.toInt())
            putMap("beaconChain", toWritableMap(beaconChainMap()))
        }
    }

    fun getState(): WritableMap {
        return Arguments.createMap().apply {
            putBoolean("isScanning", isScanning)
            putBoolean("isAdvertising", isAdvertising)
            if (eventCode != null) {
                putString("eventCode", eventCode)
            } else {
                putNull("eventCode")
            }
            putString("eninMode", eninModeName())
            putInt("eninSeconds", eninSeconds.toInt())
            putMap("beaconChain", toWritableMap(beaconChainMap()))
        }
    }

    fun getPermissionStatus(activity: Activity? = null): WritableMap {
        return toWritableMap(permissionStatusPayload(activity))
    }

    /** v2 API: current event code (or null). */
    fun getCurrentEventCode(): String? = eventCode

    /** v2 API: 8-char lowercase hex `SHA256(TEK)[0:4]`. */
    fun getMyDisplayId(): String = BarnardCrypto.displayIdString(currentTek)

    /** v2 API: 32-char lowercase hex for the inner 16-byte RPI. */
    fun getCurrentRpi(): String {
        val rpik = BarnardCrypto.deriveRpik(currentTek)
        val rpi = BarnardCrypto.generateRpi(rpik, currentEnin())
        return rpi.toHex()
    }

    /** v2 API: current ENIN as Long. */
    fun getCurrentEnin(): Long = currentEnin().toLong()

    fun configure(
        eninMode: BarnardCrypto.EninMode,
        eninSeconds: Long,
        beaconChain: BarnardCrypto.BeaconChainConfig,
        eventCode: String?
    ) {
        this.eninMode = eninMode
        this.eninSeconds = eninSeconds.coerceIn(12L, 3600L)
        this.beaconChain = beaconChain

        if (!eventCode.isNullOrEmpty() && eventCode != this.eventCode) {
            joinEvent(eventCode)
        }

        knownPeers.clear()
        boundaryRetryBudget.clearAll()
        emitDebug("info", "configure", mapOf(
            "eninMode" to eninModeName(),
            "eninSeconds" to this.eninSeconds,
            "beaconChain" to beaconChainMap(),
        ))
    }

    /**
     * v2 API: raw TEK as 32-char lowercase hex. Explicit privacy egress;
     * the SDK never transmits TEK over BLE.
     */
    fun exportCurrentTek(): String = currentTek.toHex()

    fun startScan(allowDuplicates: Boolean) {
        this.allowDuplicates = allowDuplicates
        startScanInternal()
    }

    fun stopScan() {
        stopScanInternal()
    }

    fun startAdvertise(formatVersion: Int) {
        this.formatVersion = acceptFormatVersion(formatVersion)
        startAdvertiseInternal()
    }

    fun stopAdvertise() {
        stopAdvertiseInternal()
    }

    fun joinEvent(code: String) {
        resetPeerDiscoveryState("join_event")
        eventCode = code
        prefs.edit().putString("eventCode", code).apply()

        val deviceSecret = getOrCreateDeviceSecret()
        currentTek = BarnardCrypto.deriveTekForEvent(deviceSecret, code)

        rebuildGattServerIfNeeded()

        emitState("join_event")
        emitDebug(
            "info",
            "join_event",
            mapOf(
                "eventCode" to code,
                "myDisplayId" to BarnardCrypto.displayIdString(currentTek)
            )
        )
    }

    fun leaveEvent() {
        resetPeerDiscoveryState("leave_event")
        eventCode = null
        prefs.edit().remove("eventCode").apply()

        val deviceSecret = getOrCreateDeviceSecret()
        currentTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret)

        rebuildGattServerIfNeeded()

        emitState("leave_event")
        emitDebug("info", "leave_event", null)
    }

    private val isEventMode: Boolean
        get() = eventCode != null

    private fun getEventCodeHash(): ByteArray {
        val code = eventCode ?: return ByteArray(0)
        return BarnardCrypto.computeEventCodeHash(code)
    }

    private fun eventCodeHashMatches(peerHash: ByteArray): Boolean {
        return peerHash.contentEquals(getEventCodeHash())
    }

    private fun getOrCreateDeviceSecret(): ByteArray {
        val key = "rpidSeed"
        val existing = prefs.getString(key, null)
        if (existing != null) {
            val bytes = Base64.decode(existing, Base64.DEFAULT)
            if (bytes.size >= 32) return bytes
        }
        val bytes = BarnardCrypto.generateRandomBytes(32)
        prefs.edit().putString(key, Base64.encodeToString(bytes, Base64.NO_WRAP)).apply()
        return bytes
    }

    // MARK: - Scan Control

    private fun startScanInternal() {
        val a = adapter ?: run {
            emitConstraint("bluetooth_unavailable", "BluetoothAdapter is null")
            return
        }
        if (!a.isEnabled) {
            emitConstraint("bluetooth_off", "Bluetooth is disabled")
            return
        }
        if (!hasScanPermission()) {
            emitConstraint(
                "permission_denied",
                "Missing ${requiredScanPermission()} permission",
                requiredAction = "grant_permission"
            )
            return
        }
        val scanner = adapter?.bluetoothLeScanner ?: run {
            emitError("scan_failed", "BluetoothLeScanner is null", recoverable = true)
            return
        }
        if (isScanning) return

        scanCallback?.let { cb ->
            try {
                scanner.stopScan(cb)
            } catch (e: Exception) {
                Log.w(TAG, "stopScan before start failed: ${e.message}")
            }
        }

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setReportDelay(0)
            .build()

        val cb = createScanCallback()
        scanCallback = cb

        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(serviceUuid))
            .build()

        scanner.startScan(listOf(filter), settings, cb)
        isScanning = true
        scanner.flushPendingScanResults(cb)
        emitState("scan_start")
        emitDebug("info", "scan_start", mapOf("allowDuplicates" to allowDuplicates))
    }

    private fun stopScanInternal() {
        if (!isScanning) return
        scanCallback?.let { cb ->
            if (hasScanPermission()) {
                adapter?.bluetoothLeScanner?.stopScan(cb)
            }
        }
        scanCallback = null
        isScanning = false
        cancelConnectWatchdog()
        resetPeerDiscoveryState("scan_stop")

        emitState("scan_stop")
        emitDebug("info", "scan_stop", null)
    }

    private fun resetPeerDiscoveryState(reason: String) {
        connectQueue.clear()
        activeGatt?.close()
        activeGatt = null

        discoveredRssi.clear()
        discoveredAt.clear()
        lastDiscoveryNameById.clear()
        lastConnectAttemptAtMs.clear()
        resolutionBackoffUntilMs.clear()
        pendingBoundaryRetryDevices.clear()
        boundaryRetryBudget.clearAll()
        peripheralReadValues.clear()
        knownPeers.clear()

        emitDebug("info", "peer_cache_reset", mapOf("reason" to reason))
    }

    // MARK: - Advertise Control

    private fun startAdvertiseInternal() {
        val a = adapter ?: run {
            emitConstraint("bluetooth_unavailable", "BluetoothAdapter is null")
            return
        }
        if (!a.isEnabled) {
            emitConstraint("bluetooth_off", "Bluetooth is disabled")
            return
        }
        if (!hasAdvertisePermission()) {
            emitConstraint(
                "permission_denied",
                "Missing BLUETOOTH_ADVERTISE permission",
                requiredAction = "grant_permission"
            )
            return
        }
        if (!a.isMultipleAdvertisementSupported) {
            emitConstraint("advertise_unsupported", "Multiple advertisement not supported")
            return
        }
        if (!hasConnectPermission()) {
            emitConstraint(
                "permission_denied",
                "Missing BLUETOOTH_CONNECT permission",
                requiredAction = "grant_permission"
            )
            return
        }
        val adv = a.bluetoothLeAdvertiser ?: run {
            emitError("advertise_failed", "BluetoothLeAdvertiser is null", recoverable = true)
            return
        }
        if (isAdvertising) return

        ensureGattServer()

        val localName = if (isDebugBuild()) {
            val deviceSecret = getOrCreateDeviceSecret()
            val tail = if (deviceSecret.size >= 2) {
                deviceSecret.copyOfRange(deviceSecret.size - 2, deviceSecret.size)
            } else {
                deviceSecret
            }
            val suffix = tail.joinToString("") { "%02x".format(it) }.uppercase()
            val debugName = "BND-" + if (suffix.isEmpty()) "DEAD" else suffix
            if (debugOriginalName == null && !a.name.isNullOrEmpty()) {
                debugOriginalName = a.name
            }
            if (a.name != debugName) {
                a.name = debugName
            }
            debugName
        } else {
            "BNRD"
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(serviceUuid))
            .setIncludeDeviceName(isDebugBuild())
            .build()
        adv.startAdvertising(settings, data, advertiseCallback)
        isAdvertising = true
        emitState("advertise_start")
        emitDebug(
            "info",
            "advertise_start",
            mapOf(
                "formatVersion" to formatVersion,
                "serviceUuid" to serviceUuid.toString(),
                "localName" to localName,
            )
        )
    }

    private fun stopAdvertiseInternal() {
        if (!isAdvertising) return
        if (hasAdvertisePermission()) {
            adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        }
        if (BuildConfig.DEBUG) {
            val original = debugOriginalName
            if (original != null && adapter?.name != original) {
                adapter?.name = original
            }
            debugOriginalName = null
        }
        isAdvertising = false
        gattServer?.close()
        gattServer = null
        emitState("advertise_stop")
        emitDebug("info", "advertise_stop", null)
    }

    // MARK: - GATT Server (v2)

    @SuppressLint("MissingPermission")
    private fun ensureGattServer() {
        if (gattServer != null) return
        buildAndAddGattServer()
    }

    @SuppressLint("MissingPermission")
    private fun rebuildGattServerIfNeeded() {
        if (!hasConnectPermission()) return
        gattServer?.close()
        gattServer = null
        if (isAdvertising) {
            buildAndAddGattServer()
        }
    }

    @SuppressLint("MissingPermission")
    private fun buildAndAddGattServer() {
        if (!hasConnectPermission()) {
            emitConstraint("permission_denied", "Missing BLUETOOTH_CONNECT permission", requiredAction = "grant_permission")
            return
        }
        val manager = bluetoothManager ?: return
        val server = manager.openGattServer(appContext, gattServerCallback)

        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        service.addCharacteristic(BluetoothGattCharacteristic(
            rpidCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        ))

        // v2: B003 = 4-byte displayId, Read only.
        service.addCharacteristic(BluetoothGattCharacteristic(
            displayIdCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        ))

        service.addCharacteristic(BluetoothGattCharacteristic(
            eventCodeHashCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        ))

        server.addService(service)
        gattServer = server
        emitDebug("info", "gatt_server_started", mapOf(
            "characteristics" to listOf("RPID", "displayId", "EventCodeHash")
        ))
    }

    // MARK: - RPID Payload Generation

    @Synchronized
    private fun computePayload(nowMs: Long): ByteArray {
        val enin = currentEnin(nowMs)
        val tek = currentTek
        val tekHash = tek.contentHashCode()
        val cached = cachedReporterPayload
        if (cached != null && cached.enin == enin && cached.tekHash == tekHash) {
            return cached.payload
        }

        val rpik = BarnardCrypto.deriveRpik(tek)
        val rpi = BarnardCrypto.generateRpi(rpik, enin)

        val payload = ByteArray(17)
        payload[0] = (formatVersion and 0xFF).toByte()
        System.arraycopy(rpi, 0, payload, 1, 16)
        cachedReporterPayload = CachedReporterPayload(enin, tekHash, payload)
        return payload
    }

    // MARK: - Event Emission (v2 payload via WritableMap)

    private fun emitState(reasonCode: String?) {
        val state = Arguments.createMap().apply {
            putBoolean("isScanning", isScanning)
            putBoolean("isAdvertising", isAdvertising)
            if (eventCode != null) putString("eventCode", eventCode) else putNull("eventCode")
        }
        val payload = Arguments.createMap().apply {
            putString("type", "state")
            putString("timestamp", BarnardIso8601.now())
            putMap("state", state)
            if (reasonCode != null) putString("reasonCode", reasonCode) else putNull("reasonCode")
        }
        mainHandler.post { onEvent?.invoke("BarnardState", payload) }
    }

    private fun emitConstraint(code: String, message: String?, requiredAction: String? = null) {
        val payload = Arguments.createMap().apply {
            putString("type", "constraint")
            putString("timestamp", BarnardIso8601.now())
            putString("code", code)
            if (message != null) putString("message", message) else putNull("message")
            if (requiredAction != null) putString("requiredAction", requiredAction) else putNull("requiredAction")
        }
        mainHandler.post { onEvent?.invoke("BarnardConstraint", payload) }
    }

    private fun emitError(code: String, message: String, recoverable: Boolean? = null) {
        val payload = Arguments.createMap().apply {
            putString("type", "error")
            putString("timestamp", BarnardIso8601.now())
            putString("code", code)
            putString("message", message)
            if (recoverable != null) putBoolean("recoverable", recoverable) else putNull("recoverable")
        }
        mainHandler.post { onEvent?.invoke("BarnardError", payload) }
    }

    private fun emitDetection(
        timestampMs: Long,
        rssi: Int,
        payloadBytes: ByteArray,
        detectedDisplayIdHex: String?,
        debugLocalName: String? = null
    ) {
        if (payloadBytes.size != 17) {
            emitDebug("warn", "payload_invalid_length", mapOf("length" to payloadBytes.size))
            return
        }
        val version = payloadBytes[0].toInt() and 0xFF
        if (version != 1) {
            emitDebug("warn", "payload_unsupported_version", mapOf("formatVersion" to version))
            return
        }

        val reporterPayload = computePayload(timestampMs)
        // ENIN fits comfortably in Int32 for the next ~40 000 years, so
        // prefer `putInt` to match the schema's `type: integer` contract
        // and the wire shape of the Flutter-native bridge.
        val enin = currentEnin(timestampMs).toInt()

        val payload = Arguments.createMap().apply {
            putString("type", "detection")
            putString("timestamp", BarnardIso8601.fromMs(timestampMs))
            putString("transport", "ble")
            putInt("formatVersion", version)
            putString("rpid", payloadBytes.toHex())
            putString("reporterRpid", reporterPayload.toHex())
            if (detectedDisplayIdHex != null) putString("detectedDisplayId", detectedDisplayIdHex) else putNull("detectedDisplayId")
            putInt("enin", enin)
            putInt("rssi", rssi)
            putNull("rssiSummary")
            putString("payloadRaw", payloadBytes.toHex())
            if (isDebugBuild() && debugLocalName != null) putString("debugLocalName", debugLocalName)
        }
        mainHandler.post { onEvent?.invoke("BarnardDetection", payload) }
    }

    private fun emitRssiUpdate(address: String, rssi: Int, timestampMs: Long) {
        if (!isUsableRssi(rssi)) return
        val peer = knownPeers[address] ?: return
        // Atomic reporter snapshot (same contract as DetectionEvent).
        val reporterPayload = computePayload(timestampMs)
        val enin = currentEnin(timestampMs).toInt()
        // Parity with RN iOS + Flutter iOS + Flutter Android: omit
        // detectedDisplayId when it is null, rather than emitting an
        // explicit null field. TS type accepts either, but wire parity
        // across bridges is required for consumer fixtures.
        val payload = Arguments.createMap().apply {
            putString("type", "rssi_update")
            putString("timestamp", BarnardIso8601.fromMs(timestampMs))
            putString("rpid", peer.rpid.toHex())
            putString("reporterRpid", reporterPayload.toHex())
            putInt("enin", enin)
            putInt("rssi", rssi)
            if (peer.detectedDisplayId != null) {
                putString("detectedDisplayId", peer.detectedDisplayId)
            }
        }
        mainHandler.post { onEvent?.invoke("BarnardRssiUpdate", payload) }
    }

    private fun isUsableRssi(rssi: Int): Boolean {
        return rssi != unavailableRssi
    }

    private fun emitDebug(level: String, name: String, data: Map<String, Any?>?) {
        val payload = Arguments.createMap().apply {
            putString("type", "debug")
            putString("timestamp", BarnardIso8601.now())
            putString("level", level)
            putString("name", name)
            if (data != null) putMap("data", toWritableMap(data)) else putNull("data")
        }
        mainHandler.post { onDebugEvent?.invoke("BarnardDebug", payload) }
    }

    /**
     * Accept a caller-provided formatVersion. v2 only ships format 1, so
     * clamp to 1 and emit a debug warning otherwise.
     */
    private fun acceptFormatVersion(raw: Int): Int {
        if (raw == 1) return 1
        emitDebug("warn", "format_version_clamped", mapOf("requested" to raw, "applied" to 1))
        return 1
    }

    private fun currentEnin(timestampMs: Long = System.currentTimeMillis()): UInt {
        return BarnardCrypto.calculateEnin(
            timestampMs = timestampMs,
            mode = eninMode,
            eninSeconds = eninSeconds,
            beaconChain = beaconChain,
        )
    }

    private fun eninModeName(): String {
        return when (eninMode) {
            BarnardCrypto.EninMode.BEACON_SLOT -> "beaconSlot"
            BarnardCrypto.EninMode.FIXED_LENGTH -> "fixedLength"
        }
    }

    private fun beaconChainMap(): Map<String, Any> = mapOf(
        "chainId" to beaconChain.chainId,
        "genesisUnixSeconds" to beaconChain.effectiveGenesisUnixSeconds,
        "slotSeconds" to beaconChain.effectiveSlotSeconds,
    )

    private fun toWritableMap(src: Map<String, Any?>): WritableMap {
        val map = Arguments.createMap()
        for ((k, v) in src) {
            when (v) {
                null -> map.putNull(k)
                is Boolean -> map.putBoolean(k, v)
                is Int -> map.putInt(k, v)
                is Long -> map.putDouble(k, v.toDouble())
                is Double -> map.putDouble(k, v)
                is String -> map.putString(k, v)
                is List<*> -> {
                    val arr = Arguments.createArray()
                    for (item in v) {
                        when (item) {
                            null -> arr.pushNull()
                            is Boolean -> arr.pushBoolean(item)
                            is Int -> arr.pushInt(item)
                            is Long -> arr.pushDouble(item.toDouble())
                            is Double -> arr.pushDouble(item)
                            is String -> arr.pushString(item)
                            else -> arr.pushString(item.toString())
                        }
                    }
                    map.putArray(k, arr)
                }
                is Map<*, *> -> {
                    @Suppress("UNCHECKED_CAST")
                    map.putMap(k, toWritableMap(v as Map<String, Any?>))
                }
                else -> map.putString(k, v.toString())
            }
        }
        return map
    }

    // MARK: - Permissions

    fun requiredRuntimePermissions(): List<String> {
        return when {
            Build.VERSION.SDK_INT >= 31 -> listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_CONNECT,
            )
            Build.VERSION.SDK_INT >= 23 -> listOf(Manifest.permission.ACCESS_FINE_LOCATION)
            else -> emptyList()
        }
    }

    fun hasPermission(permission: String): Boolean {
        if (Build.VERSION.SDK_INT < 23) return true
        return appContext.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    }

    fun isPermissionRequestBlocked(permission: String, activity: Activity?): Boolean {
        if (Build.VERSION.SDK_INT < 23 || hasPermission(permission)) return false
        val currentActivity = activity ?: return false
        return isRuntimePermissionRequestBlocked(
            sdkInt = Build.VERSION.SDK_INT,
            hasPermission = false,
            wasRequestedBefore = wasPermissionRequested(permission),
            shouldShowRequestPermissionRationale =
                currentActivity.shouldShowRequestPermissionRationale(permission)
        )
    }

    fun markPermissionsRequested(permissions: List<String>) {
        if (permissions.isEmpty()) return
        prefs.edit().apply {
            for (permission in permissions) {
                putBoolean(permissionRequestedKey(permission), true)
            }
        }.apply()
    }

    private fun wasPermissionRequested(permission: String): Boolean {
        return prefs.getBoolean(permissionRequestedKey(permission), false)
    }

    private fun permissionRequestedKey(permission: String): String {
        return "$permissionRequestedKeyPrefix$permission"
    }

    private fun permissionStatusPayload(activity: Activity?): Map<String, Any> {
        val required = requiredRuntimePermissions()
        val missing = required.filter { !hasPermission(it) }
        val blocked = missing.filter { isPermissionRequestBlocked(it, activity) }
        val requestable = missing.filterNot { blocked.contains(it) }
        val permissions = required.associateWith { permission ->
            if (hasPermission(permission)) "granted" else "denied"
        }
        // BLE capability requires both runtime permission AND hardware support.
        // Android Emulator and BLE-less devices report permission grants but
        // cannot actually scan or advertise — host apps would otherwise enable
        // BLE-only UI based on permission state alone. See issue #57.
        val hasBleHardware = appContext.packageManager
            .hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)
        val a = adapter
        val hasAdvertiseHardware = hasBleHardware &&
            a != null &&
            a.bluetoothLeAdvertiser != null &&
            a.isMultipleAdvertisementSupported
        return mapOf(
            "platform" to "android",
            "permissions" to permissions,
            "requiredPermissions" to required,
            "missingPermissions" to missing,
            "requestablePermissions" to requestable,
            "blockedPermissions" to blocked,
            "canScan" to (hasScanPermission() && hasBleHardware),
            "canAdvertise" to (
                hasAdvertisePermission() && hasConnectPermission() && hasAdvertiseHardware
            ),
        )
    }

    fun openAppSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", appContext.packageName, null)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        appContext.startActivity(intent)
    }

    private fun hasScanPermission(): Boolean {
        return when {
            Build.VERSION.SDK_INT >= 31 -> hasPermission(Manifest.permission.BLUETOOTH_SCAN)
            Build.VERSION.SDK_INT >= 23 -> hasPermission(Manifest.permission.ACCESS_FINE_LOCATION)
            else -> true
        }
    }

    private fun requiredScanPermission(): String {
        return if (Build.VERSION.SDK_INT >= 31) {
            Manifest.permission.BLUETOOTH_SCAN
        } else {
            Manifest.permission.ACCESS_FINE_LOCATION
        }
    }

    private fun hasAdvertisePermission(): Boolean {
        if (Build.VERSION.SDK_INT < 31) return true
        return hasPermission(Manifest.permission.BLUETOOTH_ADVERTISE)
    }

    private fun hasConnectPermission(): Boolean {
        if (Build.VERSION.SDK_INT < 31) return true
        return hasPermission(Manifest.permission.BLUETOOTH_CONNECT)
    }

    // MARK: - Advertise Callback

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            emitError("advertise_failed", "errorCode=$errorCode", recoverable = true)
            isAdvertising = false
            emitState("advertise_failed")
        }

        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            emitDebug("info", "advertise_started", null)
        }
    }

    // MARK: - Scan Callback

    private var scanCallback: ScanCallback? = null

    private fun createScanCallback(): ScanCallback {
        return object : ScanCallback() {
            override fun onScanFailed(errorCode: Int) {
                Log.e(TAG, "onScanFailed: errorCode=$errorCode")
                emitError("scan_failed", "errorCode=$errorCode", recoverable = true)
                isScanning = false
                emitState("scan_failed")
            }

            override fun onScanResult(callbackType: Int, result: ScanResult) {
                handleScanResult(result)
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                for (r in results) handleScanResult(r)
            }
        }
    }

    private fun handleScanResult(result: ScanResult) {
        val device = result.device ?: return
        val address = device.address ?: return
        if (!isBarnardScanResult(result)) {
            emitDebug(
                "trace",
                "scan_ignored",
                mapOf(
                    "address" to address,
                    "name" to result.scanRecord?.deviceName,
                    "hasService" to (result.scanRecord?.serviceUuids?.any { it.uuid == serviceUuid } == true),
                    "isConnectable" to isConnectableResult(result),
                )
            )
            return
        }
        val nowMs = System.currentTimeMillis()
        if (!isUsableRssi(result.rssi)) {
            emitDebug("trace", "ble_discovery_rssi_unavailable", mapOf(
                "id" to address,
                "rssi" to result.rssi,
                "name" to result.scanRecord?.deviceName
            ))
            return
        }
        if (!allowDuplicates) {
            val last = discoveredAt[address]
            if (last != null && nowMs - last < 2_000) return
        }
        discoveredRssi[address] = result.rssi
        discoveredAt[address] = nowMs
        if (isDebugBuild()) {
            result.scanRecord?.deviceName?.let { name ->
                if (name.isNotEmpty()) lastDiscoveryNameById[address] = name
            }
        }

        emitDebug("trace", "ble_discovery_result", mapOf(
            "id" to address,
            "rssi" to result.rssi,
            "name" to result.scanRecord?.deviceName
        ))

        val knownPeer = knownPeers[address]
        if (knownPeer != null) {
            val nowEnin = currentEnin(nowMs).toLong()
            if (BarnardV2Policy.shouldEmitRssiUpdate(knownPeer.enin, nowEnin)) {
                emitRssiUpdate(address, result.rssi, nowMs)
            } else {
                knownPeers.remove(address)
                emitDebug("trace", "known_peer_rpid_expired", mapOf(
                    "address" to address,
                    "cachedEnin" to knownPeer.enin,
                    "currentEnin" to nowEnin,
                ))
                // Force a fresh resolution. enqueueConnect dedups against in-flight /
                // queued connects, so following advertisements on the same address
                // remain safe.
                enqueueConnect(device)
            }
        } else if (isResolutionBackedOff(address, nowMs)) {
            emitResolutionBackoff(address, nowMs)
        } else {
            enqueueConnect(device)
        }
    }

    private fun isBarnardScanResult(result: ScanResult): Boolean {
        val record = result.scanRecord ?: return false
        val uuids = record.serviceUuids
        val hasService = uuids?.any { it.uuid == serviceUuid } == true
        val name = record.deviceName
        val isBnrd = name == "BNRD" || (isDebugBuild() && name?.startsWith("BND-") == true)
        if (hasService) return true
        if (isBnrd) return true
        return false
    }

    private fun isConnectableResult(result: ScanResult): Boolean {
        return if (Build.VERSION.SDK_INT >= 26) {
            result.isConnectable
        } else {
            true
        }
    }

    // MARK: - Connection Queue

    private fun enqueueConnect(device: BluetoothDevice) {
        val address = device.address ?: return
        val nowMs = System.currentTimeMillis()
        if (isResolutionBackedOff(address, nowMs)) {
            emitResolutionBackoff(address, nowMs)
            return
        }
        if (connectQueue.any { it.address == address }) return
        if (activeGatt?.device?.address == address) return

        if (connectQueue.size >= maxConnectQueue) {
            emitDebug("warn", "connect_queue_full", mapOf("max" to maxConnectQueue))
            return
        }
        connectQueue.add(device)
        pumpConnectQueue()
    }

    @SuppressLint("MissingPermission")
    private fun pumpConnectQueue() {
        if (activeGatt != null) return
        val device = connectQueue.removeFirstOrNull() ?: return
        val nowMs = System.currentTimeMillis()
        val key = device.address ?: ""
        val last = lastConnectAttemptAtMs[key]
        if (last != null && nowMs - last < cooldownPerPeerMs) {
            connectQueue.add(device)
            val remainingMs = cooldownPerPeerMs - (nowMs - last)
            mainHandler.postDelayed({ pumpConnectQueue() }, remainingMs + 50)
            return
        }
        if (!hasConnectPermission()) {
            emitConstraint("permission_denied", "Missing BLUETOOTH_CONNECT permission", requiredAction = "grant_permission")
            return
        }
        lastConnectAttemptAtMs[key] = nowMs
        peripheralReadValues[key] = GattReadValues()

        activeGatt =
            if (Build.VERSION.SDK_INT >= 23) {
                device.connectGatt(appContext, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
            } else {
                @Suppress("DEPRECATION")
                device.connectGatt(appContext, false, gattCallback)
            }
        emitDebug("trace", "connect_attempt", mapOf("address" to device.address))
        armConnectWatchdog(device.address ?: "")
    }

    @SuppressLint("MissingPermission")
    private fun armConnectWatchdog(address: String) {
        connectWatchdog?.let { mainHandler.removeCallbacks(it) }
        val task = Runnable {
            val current = activeGatt?.device?.address
            if (current != address) return@Runnable
            emitDebug(
                "warn",
                "connect_timeout",
                mapOf("address" to address, "ms" to connectTimeoutMs)
            )
            markGattResolutionFailed(
                address = address,
                reason = "connect_timeout",
                recoverable = true,
                extra = mapOf("ms" to connectTimeoutMs)
            )
            activeGatt?.close()
            activeGatt = null
            peripheralReadValues.remove(address)
            lastDiscoveryNameById.remove(address)
            pumpConnectQueue()
        }
        connectWatchdog = task
        mainHandler.postDelayed(task, connectTimeoutMs)
    }

    private fun cancelConnectWatchdog() {
        connectWatchdog?.let { mainHandler.removeCallbacks(it) }
        connectWatchdog = null
    }

    private fun isResolutionBackedOff(address: String, nowMs: Long): Boolean {
        val until = resolutionBackoffUntilMs[address] ?: return false
        if (nowMs < until) return true
        resolutionBackoffUntilMs.remove(address)
        return false
    }

    private fun emitResolutionBackoff(address: String, nowMs: Long) {
        val until = resolutionBackoffUntilMs[address] ?: return
        emitDebug(
            "trace",
            "gatt_resolution_backoff",
            mapOf(
                "address" to address,
                "remainingMs" to (until - nowMs).coerceAtLeast(0),
            )
        )
    }

    private fun markGattResolutionFailed(
        address: String,
        reason: String,
        recoverable: Boolean,
        extra: Map<String, Any?> = emptyMap()
    ) {
        if (address.isEmpty()) return
        val backoffMs = if (recoverable) resolutionFailureBackoffMs else resolutionRejectedBackoffMs
        resolutionBackoffUntilMs[address] = System.currentTimeMillis() + backoffMs
        emitDebug(
            if (recoverable) "warn" else "info",
            "gatt_resolution_failed",
            mapOf(
                "address" to address,
                "reason" to reason,
                "recoverable" to recoverable,
                "backoffMs" to backoffMs,
            ) + extra
        )
    }

    @SuppressLint("MissingPermission")
    private fun retryAfterRpidBoundaryCrossing(gatt: BluetoothGatt, address: String) {
        if (!boundaryRetryBudget.consume(address)) {
            markGattResolutionFailed(
                address = address,
                reason = "rpid_boundary_retry_exhausted",
                recoverable = true,
                extra = mapOf("maxRetries" to boundaryRetryBudget.maxRetries)
            )
            finishConnection(gatt)
            return
        }
        val device = gatt.device
        lastConnectAttemptAtMs.remove(address)
        if (device != null) {
            pendingBoundaryRetryDevices[address] = device
        }
        finishConnection(gatt)
    }

    private fun schedulePendingBoundaryRetry(address: String) {
        val device = pendingBoundaryRetryDevices.remove(address) ?: return
        mainHandler.postDelayed(
            {
                if (isScanning) enqueueConnect(device)
            },
            BarnardCrypto.rpidBoundaryRetryDelayMs
        )
    }

    // MARK: - GATT Client (v2)

    @SuppressLint("MissingPermission")
    private fun finishConnection(gatt: BluetoothGatt) {
        val address = gatt.device?.address ?: ""
        peripheralReadValues.remove(address)
        lastDiscoveryNameById.remove(address)
        gatt.disconnect()
    }

    private val gattCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (activeGatt !== gatt) {
                emitDebug("trace", "stale_connection_callback_ignored", mapOf(
                    "address" to (gatt.device?.address ?: ""),
                    "status" to status,
                    "newState" to newState,
                ))
                return
            }
            if (status != BluetoothGatt.GATT_SUCCESS) {
                cancelConnectWatchdog()
                emitError("connect_failed", "status=$status", recoverable = true)
                val address = gatt.device?.address ?: ""
                markGattResolutionFailed(
                    address = address,
                    reason = "connect_failed",
                    recoverable = true,
                    extra = mapOf("status" to status)
                )
                gatt.close()
                peripheralReadValues.remove(address)
                lastDiscoveryNameById.remove(address)
                activeGatt = null
                pumpConnectQueue()
                return
            }
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                cancelConnectWatchdog()
                emitDebug("trace", "connected", mapOf("address" to gatt.device.address))
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                cancelConnectWatchdog()
                val address = gatt.device?.address ?: ""
                peripheralReadValues.remove(address)
                lastDiscoveryNameById.remove(address)
                gatt.close()
                activeGatt = null
                schedulePendingBoundaryRetry(address)
                pumpConnectQueue()
            }
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                markGattResolutionFailed(
                    address = gatt.device?.address ?: "",
                    reason = "service_discovery_failed",
                    recoverable = true,
                    extra = mapOf("status" to status)
                )
                emitError("service_discovery_failed", "status=$status", recoverable = true)
                finishConnection(gatt)
                return
            }
            val svc = gatt.getService(serviceUuid)
            if (svc == null) {
                markGattResolutionFailed(
                    address = gatt.device?.address ?: "",
                    reason = "service_not_found",
                    recoverable = true
                )
                emitError("service_not_found", "Barnard service not found", recoverable = true)
                finishConnection(gatt)
                return
            }

            val eventCodeHashCh = svc.getCharacteristic(eventCodeHashCharUuid)
            if (eventCodeHashCh != null && hasConnectPermission()) {
                gatt.readCharacteristic(eventCodeHashCh)
            } else {
                val address = gatt.device?.address ?: ""
                markGattResolutionFailed(
                    address = address,
                    reason = "b004_missing",
                    recoverable = true
                )
                emitDebug("warn", "gatt_b004_missing", mapOf("address" to address))
                finishConnection(gatt)
            }
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            val value = characteristic.value ?: ByteArray(0)
            handleCharacteristicRead(gatt, characteristic.uuid, status, value)
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int
        ) {
            handleCharacteristicRead(gatt, characteristic.uuid, status, value)
        }

        @SuppressLint("MissingPermission")
        private fun handleCharacteristicRead(gatt: BluetoothGatt, uuid: UUID, status: Int, value: ByteArray) {
            val address = gatt.device?.address ?: ""
            val svc = gatt.getService(serviceUuid) ?: run {
                finishConnection(gatt)
                return
            }

            if (status != BluetoothGatt.GATT_SUCCESS) {
                if (uuid == displayIdCharUuid) {
                    emitDebug("warn", "gatt_b003_read_failed", mapOf(
                        "address" to address,
                        "status" to status,
                    ))
                    peripheralReadValues[address]?.detectedDisplayId = null
                    completeGattExchange(gatt)
                    return
                }
                markGattResolutionFailed(
                    address = address,
                    reason = "read_failed",
                    recoverable = true,
                    extra = mapOf(
                        "status" to status,
                        "characteristic" to uuid.toString(),
                    )
                )
                emitError("read_failed", "status=$status uuid=$uuid", recoverable = true)
                finishConnection(gatt)
                return
            }

            when (uuid) {
                eventCodeHashCharUuid -> {
                    peripheralReadValues[address]?.eventCodeHash = value
                    val matches = eventCodeHashMatches(value)
                    emitDebug("trace", "gatt_read_event_code_hash", mapOf(
                        "address" to address,
                        "bytes" to value.size,
                        "isEmpty" to value.isEmpty(),
                        "matches" to matches,
                    ))
                    if (!matches) {
                        markGattResolutionFailed(
                            address = address,
                            reason = "b004_mismatch",
                            recoverable = false,
                            extra = mapOf("bytes" to value.size)
                        )
                        emitDebug("info", "gatt_b004_mismatch", mapOf(
                            "address" to address,
                            "bytes" to value.size,
                        ))
                        finishConnection(gatt)
                        return
                    }
                    val rpidCh = svc.getCharacteristic(rpidCharUuid)
                    if (rpidCh != null && hasConnectPermission()) {
                        peripheralReadValues[address]?.rpidReadStartedAtMs = System.currentTimeMillis()
                        gatt.readCharacteristic(rpidCh)
                    } else {
                        markGattResolutionFailed(
                            address = address,
                            reason = "b002_missing",
                            recoverable = true
                        )
                        finishConnection(gatt)
                    }
                }

                rpidCharUuid -> {
                    peripheralReadValues[address]?.rpid = value
                    peripheralReadValues[address]?.rpidReadCompletedAtMs = System.currentTimeMillis()
                    emitDebug("trace", "gatt_read_rpid", mapOf(
                        "address" to address,
                        "bytes" to value.size
                    ))
                    val displayIdCh = svc.getCharacteristic(displayIdCharUuid)
                    if (displayIdCh != null && hasConnectPermission()) {
                        gatt.readCharacteristic(displayIdCh)
                    } else {
                        emitDebug("warn", "gatt_b003_missing", mapOf("address" to address))
                        completeGattExchange(gatt)
                    }
                }

                displayIdCharUuid -> {
                    if (value.size == 4) {
                        peripheralReadValues[address]?.detectedDisplayId = value
                        emitDebug("trace", "gatt_read_display_id", mapOf(
                            "address" to address,
                            "displayId" to value.toHex(),
                        ))
                    } else {
                        emitDebug("warn", "gatt_b003_invalid_length", mapOf(
                            "address" to address,
                            "length" to value.size,
                        ))
                        peripheralReadValues[address]?.detectedDisplayId = null
                    }
                    completeGattExchange(gatt)
                }
            }
        }

        private fun completeGattExchange(gatt: BluetoothGatt) {
            val address = gatt.device?.address ?: ""
            val values = peripheralReadValues[address]

            val rpidData = values?.rpid
            if (rpidData != null) {
                val rssi = discoveredRssi[address] ?: 0
                val completedAtMs = values.rpidReadCompletedAtMs ?: System.currentTimeMillis()
                val stablePeerEnin = BarnardCrypto.stableReadEnin(
                    startedAtMs = values.rpidReadStartedAtMs ?: completedAtMs,
                    completedAtMs = completedAtMs,
                    mode = eninMode,
                    eninSeconds = eninSeconds,
                    beaconChain = beaconChain,
                )
                if (stablePeerEnin == null) {
                    emitDebug("warn", "gatt_rpid_read_crossed_enin_boundary", mapOf(
                        "address" to address,
                        "startedAtMs" to values.rpidReadStartedAtMs,
                        "completedAtMs" to completedAtMs,
                    ))
                    retryAfterRpidBoundaryCrossing(gatt, address)
                    return
                }
                val detectedDisplayIdHex = values.detectedDisplayId?.toHex()
                emitDetection(completedAtMs, rssi, rpidData, detectedDisplayIdHex, lastDiscoveryNameById[address])
                resolutionBackoffUntilMs.remove(address)
                boundaryRetryBudget.clear(address)

                if (rpidData.size == 17) {
                    knownPeers[address] = KnownPeer(rpidData, stablePeerEnin.toLong(), detectedDisplayIdHex)
                }
            }

            finishConnection(gatt)
            schedulePendingBoundaryRetry(address)
        }
    }

    // MARK: - GATT Server Callback (v2)

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            val server = gattServer ?: return

            when (characteristic.uuid) {
                rpidCharUuid -> {
                    val payload = computePayload(System.currentTimeMillis())
                    val slice =
                        if (offset <= 0) payload
                        else if (offset >= payload.size) ByteArray(0)
                        else payload.copyOfRange(offset, payload.size)
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                    emitDebug(
                        "trace",
                        "gatt_respond_rpid",
                        mapOf(
                            "bytes" to payload.size,
                            "formatVersion" to (payload[0].toInt() and 0xFF),
                        )
                    )
                }

                displayIdCharUuid -> {
                    if (!BarnardV2Policy.shouldServeGattDisplayId(eventCode)) {
                        server.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, offset, null)
                        emitDebug("trace", "gatt_reject_display_id_read", mapOf(
                            "reason" to "not_joined_to_event"
                        ))
                        return
                    }

                    val displayId = BarnardCrypto.displayId4(currentTek)
                    val slice =
                        if (offset <= 0) displayId
                        else if (offset >= displayId.size) ByteArray(0)
                        else displayId.copyOfRange(offset, displayId.size)
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                    emitDebug("trace", "gatt_respond_display_id", mapOf(
                        "bytes" to displayId.size
                    ))
                }

                eventCodeHashCharUuid -> {
                    val hash = getEventCodeHash()
                    val slice =
                        if (offset <= 0) hash
                        else if (offset >= hash.size) ByteArray(0)
                        else hash.copyOfRange(offset, hash.size)
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                    emitDebug("trace", "gatt_respond_event_code_hash", mapOf(
                        "bytes" to hash.size,
                        "isEmpty" to hash.isEmpty()
                    ))
                }

                else -> {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, offset, null)
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            val server = gattServer ?: return
            if (responseNeeded) {
                server.sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED, offset, null)
            }
            emitDebug("warn", "gatt_write_rejected", mapOf(
                "uuid" to characteristic.uuid.toString(),
            ))
        }
    }
}
