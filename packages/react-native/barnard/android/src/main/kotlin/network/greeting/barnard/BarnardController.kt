// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard

import android.Manifest
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
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.util.Base64
import android.util.Log
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import network.greeting.barnard.BarnardCrypto.toHex
import java.util.UUID

private const val TAG = "BarnardBLE"

/**
 * Barnard v2 BLE controller (React Native bridge variant).
 *
 * Mirrors the Flutter v2 controller but emits events via WritableMap
 * callbacks (onEvent / onDebugEvent) instead of a method channel.
 *
 * - B002 RPID (Read, 17 bytes)
 * - B003 displayId (Read, 4 bytes) — SHA256(TEK)[0:4]
 * - B004 EventCodeHash (Read, 0 or 8 bytes)
 *
 * TEK is never transmitted over BLE in v2.
 */
internal class BarnardController(
    private val appContext: Context
) {
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

    // MARK: - Event Mode

    private var eventCode: String? = null
    private var currentTek: ByteArray = ByteArray(16)

    // MARK: - Discovery State

    private val discoveredRssi: MutableMap<String, Int> = mutableMapOf()
    private val discoveredAt: MutableMap<String, Long> = mutableMapOf()
    private val lastDiscoveryNameById: MutableMap<String, String> = mutableMapOf()

    // MARK: - Connection Queue

    private val connectQueue: ArrayDeque<BluetoothDevice> = ArrayDeque()
    private val lastConnectAttemptAtMs: MutableMap<String, Long> = mutableMapOf()
    private var activeGatt: BluetoothGatt? = null

    private val maxConnectQueue: Int = 20
    private val cooldownPerPeerMs: Long = 10_000

    // See Flutter Android variant: prevent `activeGatt` from pinning the
    // queue forever when `connectGatt` never receives a callback.
    private val connectTimeoutMs: Long = 8_000
    private var connectWatchdog: Runnable? = null

    // MARK: - Central GATT State (v2)

    private data class GattReadValues(
        var eventCodeHash: ByteArray? = null,
        var rpid: ByteArray? = null,
        var detectedDisplayId: ByteArray? = null
    )

    private val peripheralReadValues: MutableMap<String, GattReadValues> = mutableMapOf()

    // MARK: - Known Peers

    private data class KnownPeer(
        val rpid: ByteArray,
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
        }
    }

    /** v2 API: current event code (or null). */
    fun getCurrentEventCode(): String? = eventCode

    /** v2 API: 8-char lowercase hex `SHA256(TEK)[0:4]`. */
    fun getMyDisplayId(): String = BarnardCrypto.displayIdString(currentTek)

    /** v2 API: 32-char lowercase hex for the inner 16-byte RPI. */
    fun getCurrentRpi(): String {
        val rpik = BarnardCrypto.deriveRpik(currentTek)
        val rpi = BarnardCrypto.generateRpi(rpik, BarnardCrypto.calculateEnin())
        return rpi.toHex()
    }

    /** v2 API: current ENIN as Long. */
    fun getCurrentEnin(): Long = BarnardCrypto.calculateEnin().toLong()

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
                "Missing BLUETOOTH_SCAN permission",
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
        connectQueue.clear()
        activeGatt?.close()
        activeGatt = null

        discoveredRssi.clear()
        discoveredAt.clear()
        lastDiscoveryNameById.clear()
        lastConnectAttemptAtMs.clear()
        peripheralReadValues.clear()
        knownPeers.clear()

        emitState("scan_stop")
        emitDebug("info", "scan_stop", null)
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

    private fun computePayload(nowMs: Long): ByteArray {
        val enin = BarnardCrypto.calculateEnin(nowMs)
        val rpik = BarnardCrypto.deriveRpik(currentTek)
        val rpi = BarnardCrypto.generateRpi(rpik, enin)

        val payload = ByteArray(17)
        payload[0] = (formatVersion and 0xFF).toByte()
        System.arraycopy(rpi, 0, payload, 1, 16)
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
        val enin = BarnardCrypto.calculateEnin(timestampMs).toInt()

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
        val peer = knownPeers[address] ?: return
        // Parity with RN iOS + Flutter iOS + Flutter Android: omit
        // detectedDisplayId when it is null, rather than emitting an
        // explicit null field. TS type accepts either, but wire parity
        // across bridges is required for consumer fixtures.
        val payload = Arguments.createMap().apply {
            putString("type", "rssi_update")
            putString("timestamp", BarnardIso8601.fromMs(timestampMs))
            putString("rpid", peer.rpid.toHex())
            putInt("rssi", rssi)
            if (peer.detectedDisplayId != null) {
                putString("detectedDisplayId", peer.detectedDisplayId)
            }
        }
        mainHandler.post { onEvent?.invoke("BarnardRssiUpdate", payload) }
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

    private fun hasScanPermission(): Boolean {
        if (Build.VERSION.SDK_INT < 31) return true
        return appContext.checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
    }

    private fun hasAdvertisePermission(): Boolean {
        if (Build.VERSION.SDK_INT < 31) return true
        return appContext.checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED
    }

    private fun hasConnectPermission(): Boolean {
        if (Build.VERSION.SDK_INT < 31) return true
        return appContext.checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
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

        if (knownPeers.containsKey(address)) {
            emitRssiUpdate(address, result.rssi, nowMs)
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
            if (status != BluetoothGatt.GATT_SUCCESS) {
                cancelConnectWatchdog()
                emitError("connect_failed", "status=$status", recoverable = true)
                gatt.close()
                val address = gatt.device?.address ?: ""
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
                pumpConnectQueue()
            }
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emitError("service_discovery_failed", "status=$status", recoverable = true)
                finishConnection(gatt)
                return
            }
            val svc = gatt.getService(serviceUuid)
            if (svc == null) {
                emitError("service_not_found", "Barnard service not found", recoverable = true)
                finishConnection(gatt)
                return
            }

            val eventCodeHashCh = svc.getCharacteristic(eventCodeHashCharUuid)
            if (eventCodeHashCh != null && hasConnectPermission()) {
                gatt.readCharacteristic(eventCodeHashCh)
            } else {
                val rpidCh = svc.getCharacteristic(rpidCharUuid)
                if (rpidCh != null && hasConnectPermission()) {
                    gatt.readCharacteristic(rpidCh)
                } else {
                    finishConnection(gatt)
                }
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
                emitError("read_failed", "status=$status uuid=$uuid", recoverable = true)
                finishConnection(gatt)
                return
            }

            when (uuid) {
                eventCodeHashCharUuid -> {
                    peripheralReadValues[address]?.eventCodeHash = value
                    emitDebug("trace", "gatt_read_event_code_hash", mapOf(
                        "address" to address,
                        "bytes" to value.size,
                        "isEmpty" to value.isEmpty()
                    ))
                    val rpidCh = svc.getCharacteristic(rpidCharUuid)
                    if (rpidCh != null && hasConnectPermission()) {
                        gatt.readCharacteristic(rpidCh)
                    } else {
                        finishConnection(gatt)
                    }
                }

                rpidCharUuid -> {
                    peripheralReadValues[address]?.rpid = value
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
                val ts = discoveredAt[address] ?: System.currentTimeMillis()
                val detectedDisplayIdHex = values.detectedDisplayId?.toHex()
                emitDetection(ts, rssi, rpidData, detectedDisplayIdHex, lastDiscoveryNameById[address])

                if (rpidData.size == 17) {
                    knownPeers[address] = KnownPeer(rpidData, detectedDisplayIdHex)
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
