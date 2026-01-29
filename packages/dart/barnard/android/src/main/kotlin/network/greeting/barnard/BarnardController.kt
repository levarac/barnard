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
import network.greeting.barnard.BuildConfig
import android.util.Log
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.util.UUID

private const val TAG = "BarnardBLE"

internal class BarnardController(
    private val appContext: Context,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler {
    private val mainHandler = Handler(Looper.getMainLooper())

    private val methods = MethodChannel(messenger, "barnard/methods")
    private val events = EventChannel(messenger, "barnard/events")
    private val debugEvents = EventChannel(messenger, "barnard/debugEvents")

    private var eventSink: EventChannel.EventSink? = null
    private var debugEventSink: EventChannel.EventSink? = null

    // MARK: - UUIDs

    private val serviceUuid: UUID = UUID.fromString("0000B001-0000-1000-8000-00805F9B34FB")
    private val rpidCharUuid: UUID = UUID.fromString("0000B002-0000-1000-8000-00805F9B34FB")
    private val tekCharUuid: UUID = UUID.fromString("0000B003-0000-1000-8000-00805F9B34FB")
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

    // MARK: - Event Mode

    private var eventCode: String? = null
    private var currentTek: ByteArray = ByteArray(16)

    private val tekStorage: BarnardTekStorage by lazy { BarnardTekStorage(appContext) }

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
    private var activeGatt: BluetoothGatt? = null

    private val maxConnectQueue: Int = 20
    private val cooldownPerPeerMs: Long = 10_000

    // MARK: - Central GATT State

    private data class GattReadValues(
        var eventCodeHash: ByteArray? = null,
        var rpid: ByteArray? = null,
        var tek: ByteArray? = null
    )

    private val peripheralReadValues: MutableMap<String, GattReadValues> = mutableMapOf()

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

        // Initialize TEK
        initializeTek()
    }

    private fun initializeTek() {
        // Load persisted event code
        eventCode = prefs.getString("eventCode", null)

        if (eventCode != null) {
            // Event Mode: derive TEK from DeviceSecret + EventCode
            val deviceSecret = getOrCreateDeviceSecret()
            currentTek = BarnardCrypto.deriveTekForEvent(deviceSecret, eventCode!!)
        } else {
            // Anonymous Mode: derive TEK from DeviceSecret
            val deviceSecret = getOrCreateDeviceSecret()
            currentTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret)
        }
    }

    fun dispose() {
        methods.setMethodCallHandler(null)
        stopScan()
        stopAdvertise()
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
                )
            )

            "getState" -> result.success(
                mapOf(
                    "isScanning" to isScanning,
                    "isAdvertising" to isAdvertising,
                    "eventMode" to if (eventCode != null) "event" else "anonymous",
                    "eventCode" to eventCode
                )
            )

            "getEventMode" -> result.success(
                mapOf(
                    "mode" to if (eventCode != null) "event" else "anonymous",
                    "eventCode" to eventCode
                )
            )

            "getMyResolvedDisplayId" -> result.success(BarnardCrypto.displayId(currentTek))

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
                formatVersion = (args["formatVersion"] as? Int) ?: 1
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
                formatVersion = adv?.get("formatVersion") as? Int ?: 1

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

            // MARK: Event Mode APIs

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

            "getExchangedTeks" -> {
                val args = call.arguments as? Map<*, *>
                val code = args?.get("eventCode") as? String
                if (code == null) {
                    result.error("INVALID_ARGUMENT", "eventCode required", null)
                    return
                }
                val eventCodeHash = BarnardCrypto.computeEventCodeHash(code)
                val entries = tekStorage.getEntries(eventCodeHash)
                result.success(entries.map { it.toMap() })
            }

            "clearTeksForEvent" -> {
                val args = call.arguments as? Map<*, *>
                val code = args?.get("eventCode") as? String
                if (code == null) {
                    result.error("INVALID_ARGUMENT", "eventCode required", null)
                    return
                }
                val eventCodeHash = BarnardCrypto.computeEventCodeHash(code)
                val count = tekStorage.clear(eventCodeHash)
                emitDebug("info", "clear_teks_for_event", mapOf("eventCode" to code, "count" to count))
                result.success(count)
            }

            "clearAllTeks" -> {
                val count = tekStorage.clearAll()
                emitDebug("info", "clear_all_teks", mapOf("count" to count))
                result.success(count)
            }

            else -> result.notImplemented()
        }
    }

    // MARK: - Event Mode Control

    private fun joinEvent(code: String) {
        eventCode = code
        prefs.edit().putString("eventCode", code).apply()

        // Derive TEK from DeviceSecret + EventCode
        val deviceSecret = getOrCreateDeviceSecret()
        currentTek = BarnardCrypto.deriveTekForEvent(deviceSecret, code)

        // Rebuild GATT server
        rebuildGattServerIfNeeded()

        emitState("join_event")
        emitDebug("info", "join_event", mapOf(
            "eventCode" to code,
            "displayId" to BarnardCrypto.displayId(currentTek)
        ))
    }

    private fun leaveEvent() {
        eventCode = null
        prefs.edit().remove("eventCode").apply()

        // Derive TEK from DeviceSecret
        val deviceSecret = getOrCreateDeviceSecret()
        currentTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret)

        // Rebuild GATT server
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
            emitConstraint("permission_denied", "Missing BLUETOOTH_SCAN permission", requiredAction = "grant_permission")
            return
        }
        val s = adapter?.bluetoothLeScanner ?: run {
            emitError("scan_failed", "BluetoothLeScanner is null", recoverable = true)
            return
        }
        if (isScanning) return

        // Stop any previous scan first
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

        // Create fresh callback
        val cb = createScanCallback()
        scanCallback = cb

        // Filter by Barnard service UUID for efficiency
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(serviceUuid))
            .build()

        Log.i(TAG, "Starting BLE scan with scanner: $s, callback: $cb, filter: $serviceUuid")
        s.startScan(listOf(filter), settings, cb)
        isScanning = true

        // Flush any pending results
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
        connectQueue.clear()
        activeGatt?.close()
        activeGatt = null

        // Clear discovery state for clean restart
        discoveredRssi.clear()
        discoveredAt.clear()
        lastDiscoveryNameById.clear()
        lastConnectAttemptAtMs.clear()
        peripheralReadValues.clear()

        emitState("scan_stop")
        emitDebug("info", "scan_stop", null)
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
                "eventMode" to isEventMode,
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

    // MARK: - GATT Server

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

        // RPID characteristic (Read)
        val rpidCh = BluetoothGattCharacteristic(
            rpidCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(rpidCh)

        // TEK characteristic (Read/Write)
        val tekCh = BluetoothGattCharacteristic(
            tekCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        service.addCharacteristic(tekCh)

        // EventCodeHash characteristic (Read)
        val eventCodeHashCh = BluetoothGattCharacteristic(
            eventCodeHashCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(eventCodeHashCh)

        server.addService(service)
        gattServer = server
        emitDebug("info", "gatt_server_started", mapOf(
            "characteristics" to listOf("RPID", "TEK", "EventCodeHash")
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

    // MARK: - Event Emission

    private fun emitState(reasonCode: String?) {
        val payload = mapOf(
            "type" to "state",
            "timestamp" to BarnardIso8601.now(),
            "state" to mapOf(
                "isScanning" to isScanning,
                "isAdvertising" to isAdvertising,
                "eventMode" to if (isEventMode) "event" else "anonymous",
                "eventCode" to eventCode
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

    private fun emitDetection(
        timestampMs: Long,
        rssi: Int,
        payloadBytes: ByteArray,
        resolvedTek: ByteArray? = null,
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
        val rpid = payloadBytes.copyOfRange(1, 17)
        val displayId = rpid.copyOfRange(0, 4).joinToString("") { b -> "%02x".format(b) }

        // Try to resolve RPI if we have exchanged TEKs
        var resolvedTekToEmit = resolvedTek
        var resolvedDisplayId: String? = null

        if (resolvedTekToEmit == null && isEventMode) {
            // Try to resolve from stored TEKs
            val eventCodeHash = getEventCodeHash()
            val knownTeks = tekStorage.getTeks(eventCodeHash)

            resolvedTekToEmit = BarnardCrypto.resolveRpi(rpid, knownTeks)
            if (resolvedTekToEmit != null) {
                // Update lastSeenAt
                tekStorage.updateLastSeen(resolvedTekToEmit, eventCodeHash)
            }
        }

        if (resolvedTekToEmit != null) {
            resolvedDisplayId = BarnardCrypto.displayId(resolvedTekToEmit)
        }

        val payload = mutableMapOf<String, Any?>(
            "type" to "detection",
            "timestamp" to BarnardIso8601.fromMs(timestampMs),
            "transport" to "ble",
            "formatVersion" to version,
            "rpid" to Base64.encodeToString(rpid, Base64.NO_WRAP),
            "displayId" to displayId,
            "rssi" to rssi,
            "rssiSummary" to null,
            "payloadRaw" to Base64.encodeToString(payloadBytes, Base64.NO_WRAP),
        )

        if (resolvedTekToEmit != null) {
            payload["resolvedTek"] = Base64.encodeToString(resolvedTekToEmit, Base64.NO_WRAP)
        }
        if (resolvedDisplayId != null) {
            payload["resolvedDisplayId"] = resolvedDisplayId
        }
        if (isDebugBuild() && debugLocalName != null) {
            payload["debugLocalName"] = debugLocalName
        }

        mainHandler.post { eventSink?.success(payload) }
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

        enqueueConnect(device)
    }

    private fun isBarnardScanResult(result: ScanResult): Boolean {
        val record = result.scanRecord ?: return false
        val uuids = record.serviceUuids
        val hasService = uuids?.any { it.uuid == serviceUuid } == true
        val name = record.deviceName
        val isBnrd = name == "BNRD" || (isDebugBuild() && name?.startsWith("BND-") == true)
        Log.d(TAG, "isBarnardScanResult: addr=${result.device?.address} name=$name hasService=$hasService isBnrd=$isBnrd uuids=$uuids")
        // 1. Service UUID match (reliable for Android-to-Android).
        if (hasService) return true
        // 2. Local Name fallback for iOS foreground advertise.
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
        // Skip if already in queue or currently connecting.
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
    }

    // MARK: - GATT Exchange Logic

    private fun shouldExchangeTek(remoteEventCodeHash: ByteArray?): Boolean {
        // If we're in Anonymous Mode, don't exchange
        if (!isEventMode) return false

        // If remote is Anonymous (empty hash), don't exchange
        if (remoteEventCodeHash == null || remoteEventCodeHash.isEmpty()) return false

        // Check if hashes match
        val myHash = getEventCodeHash()
        return myHash.contentEquals(remoteEventCodeHash)
    }

    @SuppressLint("MissingPermission")
    private fun finishConnection(gatt: BluetoothGatt) {
        val address = gatt.device?.address ?: ""
        peripheralReadValues.remove(address)
        lastDiscoveryNameById.remove(address)
        gatt.disconnect()
    }

    // MARK: - GATT Client Callback

    private val gattCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
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
                emitDebug("trace", "connected", mapOf("address" to gatt.device.address))
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
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

            // Step 1: Read EventCodeHash first
            val eventCodeHashCh = svc.getCharacteristic(eventCodeHashCharUuid)
            if (eventCodeHashCh != null && hasConnectPermission()) {
                gatt.readCharacteristic(eventCodeHashCh)
            } else {
                // No EventCodeHash characteristic, read RPID directly
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
                    // Proceed to RPID read
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
                    // Check if we should exchange TEK
                    val remoteHash = peripheralReadValues[address]?.eventCodeHash
                    if (shouldExchangeTek(remoteHash)) {
                        val tekCh = svc.getCharacteristic(tekCharUuid)
                        if (tekCh != null && hasConnectPermission()) {
                            gatt.readCharacteristic(tekCh)
                        } else {
                            completeGattExchange(gatt)
                        }
                    } else {
                        completeGattExchange(gatt)
                    }
                }

                tekCharUuid -> {
                    peripheralReadValues[address]?.tek = value
                    emitDebug("trace", "gatt_read_tek", mapOf(
                        "address" to address,
                        "bytes" to value.size
                    ))
                    // Store received TEK
                    val remoteHash = peripheralReadValues[address]?.eventCodeHash
                    if (value.size == 16 && remoteHash != null && remoteHash.size == 8) {
                        val entry = TekEntry(
                            tek = value,
                            eventCodeHash = remoteHash,
                            exchangedAt = System.currentTimeMillis(),
                            lastSeenAt = System.currentTimeMillis()
                        )
                        tekStorage.store(entry)
                        emitDebug("info", "tek_received", mapOf(
                            "displayId" to BarnardCrypto.displayId(value)
                        ))
                    }
                    // Write our TEK to complete exchange
                    val tekCh = svc.getCharacteristic(tekCharUuid)
                    if (tekCh != null && hasConnectPermission()) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            gatt.writeCharacteristic(
                                tekCh,
                                currentTek,
                                BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                            )
                        } else {
                            tekCh.value = currentTek
                            gatt.writeCharacteristic(tekCh)
                        }
                    } else {
                        completeGattExchange(gatt)
                    }
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emitError("write_failed", "status=$status", recoverable = true)
            } else {
                emitDebug("trace", "gatt_write_tek", mapOf(
                    "address" to (gatt.device?.address ?: ""),
                    "displayId" to BarnardCrypto.displayId(currentTek)
                ))
            }
            completeGattExchange(gatt)
        }

        private fun completeGattExchange(gatt: BluetoothGatt) {
            val address = gatt.device?.address ?: ""
            val values = peripheralReadValues[address]

            // Emit detection
            val rpidData = values?.rpid
            if (rpidData != null) {
                val rssi = discoveredRssi[address] ?: 0
                val ts = discoveredAt[address] ?: System.currentTimeMillis()
                emitDetection(ts, rssi, rpidData, values?.tek, lastDiscoveryNameById[address])
            }

            finishConnection(gatt)
        }
    }

    // MARK: - GATT Server Callback

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
                        "gatt_read_rpid",
                        mapOf(
                            "bytes" to payload.size,
                            "formatVersion" to (payload[0].toInt() and 0xFF),
                            "displayId" to displayIdForPayload(payload),
                        )
                    )
                }

                tekCharUuid -> {
                    // Only return TEK in Event Mode
                    if (isEventMode) {
                        val slice =
                            if (offset <= 0) currentTek
                            else if (offset >= currentTek.size) ByteArray(0)
                            else currentTek.copyOfRange(offset, currentTek.size)
                        server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                        emitDebug("trace", "gatt_respond_tek_read", mapOf(
                            "displayId" to BarnardCrypto.displayId(currentTek)
                        ))
                    } else {
                        server.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, offset, null)
                        emitDebug("trace", "gatt_reject_tek_read", mapOf(
                            "reason" to "anonymous_mode"
                        ))
                    }
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

            if (characteristic.uuid != tekCharUuid) {
                if (responseNeeded) {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED, offset, null)
                }
                return
            }

            if (value == null || value.size != 16) {
                if (responseNeeded) {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH, offset, null)
                }
                return
            }

            // Only accept TEK writes in Event Mode
            if (!isEventMode) {
                if (responseNeeded) {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED, offset, null)
                }
                emitDebug("trace", "gatt_reject_tek_write", mapOf(
                    "reason" to "anonymous_mode"
                ))
                return
            }

            // Store the received TEK
            val eventCodeHash = getEventCodeHash()
            val entry = TekEntry(
                tek = value,
                eventCodeHash = eventCodeHash,
                exchangedAt = System.currentTimeMillis(),
                lastSeenAt = System.currentTimeMillis()
            )
            tekStorage.store(entry)

            if (responseNeeded) {
                server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, null)
            }
            emitDebug("info", "tek_received_via_write", mapOf(
                "displayId" to BarnardCrypto.displayId(value)
            ))
        }
    }

    private fun displayIdForPayload(payload: ByteArray): String {
        if (payload.size < 5) return ""
        return payload.copyOfRange(1, 5).joinToString("") { b -> "%02x".format(b) }
    }
}
