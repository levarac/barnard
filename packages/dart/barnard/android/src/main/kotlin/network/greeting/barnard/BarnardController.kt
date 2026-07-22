// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

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
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.PluginRegistry
import network.greeting.barnard.BarnardCrypto.toHex
import network.greeting.barnard.BuildConfig
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
 * Barnard v2 BLE controller.
 *
 * GATT service (fixed UUID):
 * - B002 RPID (Read, 17 bytes)
 * - B003 displayId (Read, 4 bytes when joined to an event) — SHA256(TEK)[0:4]
 * - B004 EventCodeHash (Read, 0 or 8 bytes)
 *
 * TEK is never transmitted over BLE in v2.
 */
internal class BarnardController(
    private val appContext: Context,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler, PluginRegistry.RequestPermissionsResultListener {
    private companion object {
        const val permissionRequestCode = 0xB4D
        const val permissionRequestedKeyPrefix = "permission_requested:"
    }

    private val mainHandler = Handler(Looper.getMainLooper())

    private val methods = MethodChannel(messenger, "barnard/methods")
    private val events = EventChannel(messenger, "barnard/events")
    private val debugEvents = EventChannel(messenger, "barnard/debugEvents")

    private var eventSink: EventChannel.EventSink? = null
    private var debugEventSink: EventChannel.EventSink? = null
    private var activity: Activity? = null
    private var pendingPermissionResult: MethodChannel.Result? = null

    // MARK: - UUIDs

    private val serviceUuid: UUID = UUID.fromString("0000B001-0000-1000-8000-00805F9B34FB")
    private val rpidCharUuid: UUID = UUID.fromString("0000B002-0000-1000-8000-00805F9B34FB")
    private val displayIdCharUuid: UUID = UUID.fromString("0000B003-0000-1000-8000-00805F9B34FB")
    private val eventCodeHashCharUuid: UUID = UUID.fromString("0000B004-0000-1000-8000-00805F9B34FB")

    // MARK: - Bluetooth

    private val bluetoothManager: BluetoothManager? =
        appContext.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
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

    private fun isDebugBuild(): Boolean {
        return BuildConfig.BUILD_TYPE != "release"
    }

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

    // `connectGatt` has no built-in deadline; a hung connection to a peer
    // whose BLE MAC has since rotated pins `activeGatt` forever, starving
    // every subsequently-discovered peripheral as "scan only, awaiting
    // GATT". Arm a manual watchdog that closes the GATT and releases the
    // pin if no connection progress is made.
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

    // MARK: - Known Peers (for high-rate RSSI updates)

    private data class KnownPeer(
        val rpid: ByteArray,
        val enin: Long,
        val detectedDisplayId: String?,
        val debugLocalName: String?
    )

    private val knownPeers: MutableMap<String, KnownPeer> = mutableMapOf()

    // MARK: - Storage

    private val prefs: SharedPreferences =
        appContext.getSharedPreferences("barnard", Context.MODE_PRIVATE)

    init {
        methods.setMethodCallHandler(this)

        events.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
                eventSink = sink
            }

            override fun onCancel(arguments: Any?) {
                eventSink = null
            }
        })

        debugEvents.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, sink: EventChannel.EventSink) {
                debugEventSink = sink
            }

            override fun onCancel(arguments: Any?) {
                debugEventSink = null
            }
        })

        initializeTek()
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

    fun setActivity(activity: Activity?) {
        this.activity = activity
    }

    fun dispose() {
        methods.setMethodCallHandler(null)
        stopScan()
        stopAdvertise()
        pendingPermissionResult?.error("E_DISPOSED", "BarnardController disposed before permission result", null)
        pendingPermissionResult = null
        activity = null
        eventSink = null
        debugEventSink = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "getCapabilities" -> result.success(
                mapOf(
                    "supportedTransports" to listOf("ble"),
                    "supportsConnectionlessRpid" to false,
                    "supportsGattFallback" to true,
                    "supportsBackground" to false,
                    "supportsHighRateRssi" to false,
                    "eninMode" to eninModeName(),
                    "eninSeconds" to eninSeconds,
                    "beaconChain" to beaconChainMap(),
                )
            )

            "getState" -> result.success(
                mapOf(
                    "isScanning" to isScanning,
                    "isAdvertising" to isAdvertising,
                    "eventCode" to eventCode,
                    "eninMode" to eninModeName(),
                    "eninSeconds" to eninSeconds,
                    "beaconChain" to beaconChainMap(),
                )
            )

            "configure" -> {
                val args = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
                configure(args)
                result.success(null)
            }

            "getCurrentEventCode" -> result.success(eventCode)

            "getMyDisplayId" -> result.success(BarnardCrypto.displayIdString(currentTek))

            "getCurrentRpi" -> {
                val rpik = BarnardCrypto.deriveRpik(currentTek)
                val rpi = BarnardCrypto.generateRpi(rpik, currentEnin())
                result.success(rpi.toHex())
            }

            "getCurrentEnin" -> result.success(currentEnin().toLong())

            "exportCurrentTek" -> {
                // Explicit privacy egress. SDK never transmits TEK over BLE.
                //
                // Deprecated (barnard#63): exposing the raw TEK lets anyone
                // derive every RPID and the displayId for it. Use
                // BarnardIdentityController's "proveRpidOwnership" instead.
                // Kept (not removed) for backward compatibility.
                result.success(currentTek.toHex())
            }

            "getPermissionStatus" -> result.success(getPermissionStatus())

            "requestPermissions" -> requestPermissions(result)

            "openAppSettings" -> {
                openAppSettings()
                result.success(null)
            }

            "startScan" -> {
                val args = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
                allowDuplicates = args["allowDuplicates"] as? Boolean ?: true
                startScan()
                result.success(null)
            }

            "stopScan" -> {
                stopScan()
                result.success(null)
            }

            "startAdvertise" -> {
                val args = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
                formatVersion = acceptFormatVersion(args["formatVersion"])
                startAdvertise()
                result.success(null)
            }

            "stopAdvertise" -> {
                stopAdvertise()
                result.success(null)
            }

            "startAuto" -> {
                val args = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
                val scan = args["scan"] as? Map<*, *>
                val adv = args["advertise"] as? Map<*, *>
                allowDuplicates = scan?.get("allowDuplicates") as? Boolean ?: true
                formatVersion = acceptFormatVersion(adv?.get("formatVersion"))

                val wasScanning = isScanning
                val wasAdvertising = isAdvertising
                startScan()
                startAdvertise()
                result.success(
                    mapOf(
                        "scanningStarted" to (!wasScanning && isScanning),
                        "advertisingStarted" to (!wasAdvertising && isAdvertising),
                        "issues" to emptyList<Any>(),
                    )
                )
            }

            "stopAuto" -> {
                stopScan()
                stopAdvertise()
                result.success(null)
            }

            "dispose" -> {
                dispose()
                result.success(null)
            }

            "joinEvent" -> {
                val args = call.arguments as? Map<*, *>
                val code = args?.get("eventCode") as? String
                if (code == null) {
                    result.error("INVALID_ARGUMENT", "eventCode required", null)
                    return
                }
                joinEvent(code)
                result.success(null)
            }

            "leaveEvent" -> {
                leaveEvent()
                result.success(null)
            }

            else -> result.notImplemented()
        }
    }

    // MARK: - Event Mode Control

    private fun joinEvent(code: String) {
        resetPeerDiscoveryState("join_event")
        eventCode = code
        prefs.edit().putString("eventCode", code).apply()

        val deviceSecret = getOrCreateDeviceSecret()
        currentTek = BarnardCrypto.deriveTekForEvent(deviceSecret, code)

        rebuildGattServerIfNeeded()

        emitState("join_event")
        emitDebug("info", "join_event", mapOf(
            "eventCode" to code,
            "myDisplayId" to BarnardCrypto.displayIdString(currentTek)
        ))
    }

    private fun leaveEvent() {
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

    private fun configure(args: Map<*, *>) {
        eninMode = when (args["eninMode"] as? String) {
            "beaconSlot" -> BarnardCrypto.EninMode.BEACON_SLOT
            else -> BarnardCrypto.EninMode.FIXED_LENGTH
        }
        eninSeconds = ((args["eninSeconds"] as? Number)?.toLong() ?: 300L).coerceIn(12L, 3600L)

        val chain = args["beaconChain"] as? Map<*, *>
        beaconChain = BarnardCrypto.BeaconChainConfig(
            chainId = chain?.get("chainId") as? String ?: "mainnet",
            genesisUnixSeconds = (chain?.get("genesisUnixSeconds") as? Number)?.toLong() ?: 1606824023L,
            slotSeconds = (chain?.get("slotSeconds") as? Number)?.toLong() ?: 12L,
        )

        (args["eventCode"] as? String)?.let { code ->
            if (code.isNotEmpty() && code != eventCode) joinEvent(code)
        }

        knownPeers.clear()
        emitDebug("info", "configure", mapOf(
            "eninMode" to eninModeName(),
            "eninSeconds" to eninSeconds,
            "beaconChain" to beaconChainMap(),
        ))
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

    private fun getEventCodeHash(): ByteArray {
        val code = eventCode ?: return ByteArray(0)
        return BarnardCrypto.computeEventCodeHash(code)
    }

    private fun eventCodeHashMatches(peerHash: ByteArray): Boolean {
        return peerHash.contentEquals(getEventCodeHash())
    }

    // MARK: - DeviceSecret Management

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

    private fun startScan() {
        val a = adapter ?: run {
            emitConstraint("bluetooth_unavailable", "BluetoothAdapter is null")
            return
        }
        if (!a.isEnabled) {
            emitConstraint("bluetooth_off", "Bluetooth is disabled")
            return
        }
        if (!hasScanPermission()) {
            emitConstraint("permission_denied", "Missing ${requiredScanPermission()} permission", requiredAction = "grant_permission")
            return
        }
        val s = adapter?.bluetoothLeScanner ?: run {
            emitError("scan_failed", "BluetoothLeScanner is null", recoverable = true)
            return
        }
        if (isScanning) return

        scanCallback?.let { cb ->
            try {
                s.stopScan(cb)
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

        Log.i(TAG, "Starting BLE scan with scanner: $s, callback: $cb, filter: $serviceUuid")
        s.startScan(listOf(filter), settings, cb)
        isScanning = true

        s.flushPendingScanResults(cb)
        Log.i(TAG, "BLE scan started (LOW_LATENCY, service UUID filter)")
        emitState("scan_start")
        emitDebug("info", "scan_start", mapOf("allowDuplicates" to allowDuplicates))
    }

    private fun stopScan() {
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

    private fun startAdvertise() {
        val a = adapter ?: run {
            emitConstraint("bluetooth_unavailable", "BluetoothAdapter is null")
            return
        }
        if (!a.isEnabled) {
            emitConstraint("bluetooth_off", "Bluetooth is disabled")
            return
        }
        if (!hasAdvertisePermission()) {
            emitConstraint("permission_denied", "Missing BLUETOOTH_ADVERTISE permission", requiredAction = "grant_permission")
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

    private fun stopAdvertise() {
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

        // B002 RPID (Read only)
        val rpidCh = BluetoothGattCharacteristic(
            rpidCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(rpidCh)

        // B003 displayId (Read only) — v2: was TEK (r/w), now event-scoped SHA256(TEK)[0:4]
        val displayIdCh = BluetoothGattCharacteristic(
            displayIdCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(displayIdCh)

        // B004 EventCodeHash (Read only)
        val eventCodeHashCh = BluetoothGattCharacteristic(
            eventCodeHashCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(eventCodeHashCh)

        server.addService(service)
        gattServer = server
        emitDebug("info", "gatt_server_started", mapOf(
            "characteristics" to listOf("RPID", "displayId", "EventCodeHash")
        ))
    }

    // MARK: - RPID Payload Generation

    /**
     * Build the 17-byte RPID wire form at [nowMs], atomically deriving ENIN
     * and RPI from the same timestamp.
     */
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

    // MARK: - Event Emission

    private fun emitState(reasonCode: String?) {
        val payload = mapOf(
            "type" to "state",
            "timestamp" to BarnardIso8601.now(),
            "state" to mapOf(
                "isScanning" to isScanning,
                "isAdvertising" to isAdvertising,
                "eventCode" to eventCode,
                "eninMode" to eninModeName(),
                "eninSeconds" to eninSeconds,
                "beaconChain" to beaconChainMap(),
            ),
            "reasonCode" to reasonCode,
        )
        mainHandler.post { eventSink?.success(payload) }
    }

    private fun emitConstraint(code: String, message: String?, requiredAction: String? = null) {
        val payload = mapOf(
            "type" to "constraint",
            "timestamp" to BarnardIso8601.now(),
            "code" to code,
            "message" to message,
            "requiredAction" to requiredAction,
        )
        mainHandler.post { eventSink?.success(payload) }
    }

    private fun emitError(code: String, message: String, recoverable: Boolean? = null) {
        val payload = mapOf(
            "type" to "error",
            "timestamp" to BarnardIso8601.now(),
            "code" to code,
            "message" to message,
            "recoverable" to recoverable,
        )
        mainHandler.post { eventSink?.success(payload) }
    }

    /**
     * Emit v2 detection event. Byte-valued fields are lowercase hex.
     */
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

        // Atomic reporter snapshot at the observation timestamp.
        val reporterPayload = computePayload(timestampMs)
        val enin = currentEnin(timestampMs).toLong()

        val payload = mutableMapOf<String, Any?>(
            "type" to "detection",
            "timestamp" to BarnardIso8601.fromMs(timestampMs),
            "transport" to "ble",
            "formatVersion" to version,
            "rpid" to payloadBytes.toHex(),
            "reporterRpid" to reporterPayload.toHex(),
            "detectedDisplayId" to detectedDisplayIdHex,
            "enin" to enin,
            "rssi" to rssi,
            "rssiSummary" to null,
            "payloadRaw" to payloadBytes.toHex(),
        )

        if (isDebugBuild() && debugLocalName != null) {
            payload["debugLocalName"] = debugLocalName
        }

        mainHandler.post { eventSink?.success(payload) }
    }

    private fun emitRssiUpdate(address: String, rssi: Int, timestampMs: Long) {
        if (!isUsableRssi(rssi)) return
        val peer = knownPeers[address] ?: return

        // Atomic reporter snapshot (same contract as DetectionEvent).
        val reporterPayload = computePayload(timestampMs)
        val enin = currentEnin(timestampMs).toLong()

        val payload = mutableMapOf<String, Any?>(
            "type" to "rssi_update",
            "timestamp" to BarnardIso8601.fromMs(timestampMs),
            "rpid" to peer.rpid.toHex(),
            "reporterRpid" to reporterPayload.toHex(),
            "enin" to enin,
            "rssi" to rssi,
        )

        if (peer.detectedDisplayId != null) {
            payload["detectedDisplayId"] = peer.detectedDisplayId
        }
        if (isDebugBuild() && peer.debugLocalName != null) {
            payload["debugLocalName"] = peer.debugLocalName
        }

        mainHandler.post { eventSink?.success(payload) }
    }

    private fun isUsableRssi(rssi: Int): Boolean {
        return rssi != unavailableRssi
    }

    private fun emitDebug(level: String, name: String, data: Map<String, Any?>?) {
        val payload = mapOf(
            "type" to "debug",
            "timestamp" to BarnardIso8601.now(),
            "level" to level,
            "name" to name,
            "data" to data,
        )
        mainHandler.post { debugEventSink?.success(payload) }
    }

    /**
     * Accept a caller-provided formatVersion. v2 only ships format 1, so
     * clamp to 1 and emit a debug warning otherwise. Advertising format 2+
     * would make the device silently undiscoverable to all v2 peers.
     */
    private fun acceptFormatVersion(raw: Any?): Int {
        val v = raw as? Int ?: return 1
        if (v == 1) return 1
        emitDebug("warn", "format_version_clamped", mapOf("requested" to v, "applied" to 1))
        return 1
    }

    // MARK: - Permissions

    fun getPermissionStatus(): Map<String, Any> {
        val required = requiredRuntimePermissions()
        val missing = required.filter { !hasPermission(it) }
        val blocked = missing.filter { isPermissionRequestBlocked(it) }
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

    private fun requestPermissions(result: MethodChannel.Result) {
        val missing = requiredRuntimePermissions().filter { !hasPermission(it) }
        if (missing.isEmpty()) {
            result.success(getPermissionStatus())
            return
        }
        val requestable = missing.filterNot { isPermissionRequestBlocked(it) }
        if (requestable.isEmpty()) {
            result.success(getPermissionStatus())
            return
        }

        val currentActivity = activity
        if (currentActivity == null) {
            result.error(
                "E_NO_ACTIVITY",
                "requestPermissions requires an attached Activity",
                getPermissionStatus()
            )
            return
        }

        if (pendingPermissionResult != null) {
            result.error(
                "E_PERMISSION_REQUEST_IN_PROGRESS",
                "A Barnard permission request is already in progress",
                getPermissionStatus()
            )
            return
        }

        pendingPermissionResult = result
        markPermissionsRequested(requestable)
        currentActivity.requestPermissions(requestable.toTypedArray(), permissionRequestCode)
    }

    private fun openAppSettings() {
        val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", appContext.packageName, null)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        (activity ?: appContext).startActivity(intent)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ): Boolean {
        if (requestCode != permissionRequestCode) return false
        val result = pendingPermissionResult ?: return false
        pendingPermissionResult = null
        result.success(getPermissionStatus())
        return true
    }

    private fun requiredRuntimePermissions(): List<String> {
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

    private fun hasPermission(permission: String): Boolean {
        if (Build.VERSION.SDK_INT < 23) return true
        return appContext.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun isPermissionRequestBlocked(permission: String): Boolean {
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

    private fun markPermissionsRequested(permissions: List<String>) {
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
                Log.d(TAG, "onScanResult: ${result.device?.address} name=${result.scanRecord?.deviceName} rssi=${result.rssi}")
                handleScanResult(result)
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                Log.d(TAG, "onBatchScanResults: ${results.size} results")
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
            val currentEnin = currentEnin(nowMs).toLong()
            if (BarnardV2Policy.shouldEmitRssiUpdate(knownPeer.enin, currentEnin)) {
                emitRssiUpdate(address, result.rssi, nowMs)
            } else {
                knownPeers.remove(address)
                emitDebug("trace", "known_peer_rpid_expired", mapOf(
                    "address" to address,
                    "cachedEnin" to knownPeer.enin,
                    "currentEnin" to currentEnin,
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
        Log.d(TAG, "isBarnardScanResult: addr=${result.device?.address} name=$name hasService=$hasService isBnrd=$isBnrd uuids=$uuids")
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

    // MARK: - GATT Exchange Logic (Central, v2 flow)

    @SuppressLint("MissingPermission")
    private fun finishConnection(gatt: BluetoothGatt) {
        val address = gatt.device?.address ?: ""
        peripheralReadValues.remove(address)
        lastDiscoveryNameById.remove(address)
        gatt.disconnect()
    }

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

            // v2 flow: B004 gates B002 -> B003
            val eventCodeHashCh = svc.getCharacteristic(eventCodeHashCharUuid)
            if (eventCodeHashCh != null && hasConnectPermission()) {
                gatt.readCharacteristic(eventCodeHashCh)
            } else {
                markGattResolutionFailed(
                    address = gatt.device?.address ?: "",
                    reason = "b004_missing",
                    recoverable = true
                )
                emitDebug("warn", "gatt_b004_missing", mapOf(
                    "address" to (gatt.device?.address ?: "")
                ))
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

            // v2 failure policy: B003 read failure keeps the detection flow alive
            // with detectedDisplayId=null. B002/B004 failures still drop.
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
                        "matches" to matches
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
                            "bytes" to value.size
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
                    // v2: always read B003 next.
                    val displayIdCh = svc.getCharacteristic(displayIdCharUuid)
                    if (displayIdCh != null && hasConnectPermission()) {
                        gatt.readCharacteristic(displayIdCh)
                    } else {
                        emitDebug("warn", "gatt_b003_missing", mapOf(
                            "address" to address,
                        ))
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
                    knownPeers[address] = KnownPeer(
                        rpidData,
                        stablePeerEnin.toLong(),
                        detectedDisplayIdHex,
                        lastDiscoveryNameById[address]
                    )
                }
            }

            finishConnection(gatt)
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

                    // v2: event-scoped 4-byte SHA256(TEK)[0:4].
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
            // v2 has no writable characteristics.
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
