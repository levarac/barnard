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
import java.util.UUID

private const val TAG = "BarnardBLE"

internal class BarnardController(
    private val appContext: Context
) {
    private val mainHandler = Handler(Looper.getMainLooper())

    var onEvent: ((String, WritableMap) -> Unit)? = null
    var onDebugEvent: ((String, WritableMap) -> Unit)? = null

    // MARK: - UUIDs

    private val serviceUuid: UUID = UUID.fromString("0000B001-0000-1000-8000-00805F9B34FB")
    private val rpidCharUuid: UUID = UUID.fromString("0000B002-0000-1000-8000-00805F9B34FB")
    private val tekCharUuid: UUID = UUID.fromString("0000B003-0000-1000-8000-00805F9B34FB")
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

    private val tekStorage: BarnardTekStorage by lazy { BarnardTekStorage(appContext) }

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

    fun getCapabilities(): WritableMap {
        val transports = Arguments.createArray().apply {
            pushString("ble")
        }
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
            putString("eventMode", if (isEventMode) "event" else "anonymous")
            if (eventCode != null) {
                putString("eventCode", eventCode)
            } else {
                putNull("eventCode")
            }
        }
    }

    fun getEventMode(): WritableMap {
        return Arguments.createMap().apply {
            putString("mode", if (isEventMode) "event" else "anonymous")
            if (eventCode != null) {
                putString("eventCode", eventCode)
            } else {
                putNull("eventCode")
            }
        }
    }

    fun startScan(allowDuplicates: Boolean) {
        this.allowDuplicates = allowDuplicates
        startScanInternal()
    }

    fun stopScan() {
        stopScanInternal()
    }

    fun startAdvertise(formatVersion: Int) {
        this.formatVersion = formatVersion
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
                "displayId" to BarnardCrypto.displayId(currentTek)
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

    fun getExchangedTeks(eventCode: String): WritableArray {
        val eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
        val entries = tekStorage.getEntries(eventCodeHash)
        return Arguments.createArray().apply {
            entries.forEach { entry ->
                pushMap(toWritableMap(entry.toMap()))
            }
        }
    }

    fun clearTeksForEvent(eventCode: String): Int {
        val eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
        val count = tekStorage.clear(eventCodeHash)
        emitDebug(
            "info",
            "clear_teks_for_event",
            mapOf("eventCode" to eventCode, "count" to count)
        )
        return count
    }

    fun clearAllTeks(): Int {
        val count = tekStorage.clearAll()
        emitDebug("info", "clear_all_teks", mapOf("count" to count))
        return count
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

        Log.i(TAG, "Starting BLE scan with scanner: $scanner, callback: $cb, filter: $serviceUuid")
        scanner.startScan(listOf(filter), settings, cb)
        isScanning = true

        scanner.flushPendingScanResults(cb)
        Log.i(TAG, "BLE scan started (LOW_LATENCY, service UUID filter)")
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
        connectQueue.clear()
        activeGatt?.close()
        activeGatt = null

        discoveredRssi.clear()
        discoveredAt.clear()
        lastDiscoveryNameById.clear()
        lastConnectAttemptAtMs.clear()
        peripheralReadValues.clear()

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

        val advertiser = a.bluetoothLeAdvertiser ?: run {
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

        advertiser.startAdvertising(settings, data, advertiseCallback)
        isAdvertising = true
        emitState("advertise_start")
        emitDebug(
            "info",
            "advertise_start",
            mapOf(
                "formatVersion" to formatVersion,
                "serviceUuid" to serviceUuid.toString(),
                "localName" to localName,
                "eventMode" to isEventMode
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
            emitConstraint(
                "permission_denied",
                "Missing BLUETOOTH_CONNECT permission",
                requiredAction = "grant_permission"
            )
            return
        }
        val manager = bluetoothManager ?: return
        val server = manager.openGattServer(appContext, gattServerCallback)

        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        val rpidCh = BluetoothGattCharacteristic(
            rpidCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(rpidCh)

        val tekCh = BluetoothGattCharacteristic(
            tekCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        service.addCharacteristic(tekCh)

        val eventCodeHashCh = BluetoothGattCharacteristic(
            eventCodeHashCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(eventCodeHashCh)

        server.addService(service)
        gattServer = server
        emitDebug(
            "info",
            "gatt_server_started",
            mapOf("characteristics" to listOf("RPID", "TEK", "EventCodeHash"))
        )
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
        val payload = Arguments.createMap().apply {
            putString("type", "state")
            putString("timestamp", BarnardIso8601.now())
            putMap("state", getState())
            if (reasonCode != null) {
                putString("reasonCode", reasonCode)
            }
        }
        mainHandler.post { onEvent?.invoke("BarnardState", payload) }
    }

    private fun emitConstraint(code: String, message: String?, requiredAction: String? = null) {
        val payload = Arguments.createMap().apply {
            putString("type", "constraint")
            putString("timestamp", BarnardIso8601.now())
            putString("code", code)
            if (message != null) {
                putString("message", message)
            }
            if (requiredAction != null) {
                putString("requiredAction", requiredAction)
            }
        }
        mainHandler.post { onEvent?.invoke("BarnardConstraint", payload) }
    }

    private fun emitError(code: String, message: String, recoverable: Boolean? = null) {
        val payload = Arguments.createMap().apply {
            putString("type", "error")
            putString("timestamp", BarnardIso8601.now())
            putString("code", code)
            putString("message", message)
            if (recoverable != null) {
                putBoolean("recoverable", recoverable)
            }
        }
        mainHandler.post { onEvent?.invoke("BarnardError", payload) }
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

        var resolvedTekToEmit = resolvedTek
        var resolvedDisplayId: String? = null

        if (resolvedTekToEmit == null && isEventMode) {
            val eventCodeHash = getEventCodeHash()
            val knownTeks = tekStorage.getTeks(eventCodeHash)

            resolvedTekToEmit = BarnardCrypto.resolveRpi(rpid, knownTeks)
            if (resolvedTekToEmit != null) {
                tekStorage.updateLastSeen(resolvedTekToEmit, eventCodeHash)
            }
        }

        if (resolvedTekToEmit != null) {
            resolvedDisplayId = BarnardCrypto.displayId(resolvedTekToEmit)
        }

        val payload = Arguments.createMap().apply {
            putString("type", "detection")
            putString("timestamp", BarnardIso8601.fromMs(timestampMs))
            putString("transport", "ble")
            putInt("formatVersion", version)
            putString("rpid", Base64.encodeToString(rpid, Base64.NO_WRAP))
            putString("displayId", displayId)
            putInt("rssi", rssi)
            putNull("rssiSummary")
            putString("payloadRaw", Base64.encodeToString(payloadBytes, Base64.NO_WRAP))
            if (resolvedTekToEmit != null) {
                putString("resolvedTek", Base64.encodeToString(resolvedTekToEmit, Base64.NO_WRAP))
            }
            if (resolvedDisplayId != null) {
                putString("resolvedDisplayId", resolvedDisplayId)
            }
            if (isDebugBuild() && debugLocalName != null) {
                putString("debugLocalName", debugLocalName)
            }
        }

        mainHandler.post { onEvent?.invoke("BarnardDetection", payload) }
    }

    private fun emitDebug(level: String, name: String, data: Map<String, Any?>?) {
        val payload = Arguments.createMap().apply {
            putString("type", "debug")
            putString("timestamp", BarnardIso8601.now())
            putString("level", level)
            putString("name", name)
            if (data != null) {
                putMap("data", toWritableMap(data))
            }
        }
        mainHandler.post { onDebugEvent?.invoke("BarnardDebug", payload) }
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
                    "isConnectable" to isConnectableResult(result)
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

        emitDebug(
            "trace",
            "ble_discovery_result",
            mapOf(
                "id" to address,
                "rssi" to result.rssi,
                "name" to result.scanRecord?.deviceName
            )
        )

        enqueueConnect(device)
    }

    private fun isBarnardScanResult(result: ScanResult): Boolean {
        val record = result.scanRecord ?: return false
        val uuids = record.serviceUuids
        val hasService = uuids?.any { it.uuid == serviceUuid } == true
        val name = record.deviceName
        val isBnrd = name == "BNRD" || (isDebugBuild() && name?.startsWith("BND-") == true)
        Log.d(
            TAG,
            "isBarnardScanResult: addr=${result.device?.address} name=$name hasService=$hasService isBnrd=$isBnrd uuids=$uuids"
        )
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
            emitConstraint(
                "permission_denied",
                "Missing BLUETOOTH_CONNECT permission",
                requiredAction = "grant_permission"
            )
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
        if (!isEventMode) return false
        if (remoteEventCodeHash == null || remoteEventCodeHash.isEmpty()) return false

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

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
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
                    emitDebug(
                        "trace",
                        "gatt_read_event_code_hash",
                        mapOf(
                            "address" to address,
                            "bytes" to value.size,
                            "isEmpty" to value.isEmpty()
                        )
                    )
                    val rpidCh = svc.getCharacteristic(rpidCharUuid)
                    if (rpidCh != null && hasConnectPermission()) {
                        gatt.readCharacteristic(rpidCh)
                    } else {
                        finishConnection(gatt)
                    }
                }

                rpidCharUuid -> {
                    peripheralReadValues[address]?.rpid = value
                    emitDebug(
                        "trace",
                        "gatt_read_rpid",
                        mapOf(
                            "address" to address,
                            "bytes" to value.size
                        )
                    )
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
                    emitDebug(
                        "trace",
                        "gatt_read_tek",
                        mapOf(
                            "address" to address,
                            "bytes" to value.size
                        )
                    )
                    val remoteHash = peripheralReadValues[address]?.eventCodeHash
                    if (value.size == 16 && remoteHash != null && remoteHash.size == 8) {
                        val entry = TekEntry(
                            tek = value,
                            eventCodeHash = remoteHash,
                            exchangedAt = System.currentTimeMillis(),
                            lastSeenAt = System.currentTimeMillis()
                        )
                        tekStorage.store(entry)
                        emitDebug("info", "tek_received", mapOf("displayId" to BarnardCrypto.displayId(value)))
                    }
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
        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emitError("write_failed", "status=$status", recoverable = true)
            } else {
                emitDebug(
                    "trace",
                    "gatt_write_tek",
                    mapOf(
                        "address" to (gatt.device?.address ?: ""),
                        "displayId" to BarnardCrypto.displayId(currentTek)
                    )
                )
            }
            completeGattExchange(gatt)
        }

        private fun completeGattExchange(gatt: BluetoothGatt) {
            val address = gatt.device?.address ?: ""
            val values = peripheralReadValues[address]

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
                            "displayId" to displayIdForPayload(payload)
                        )
                    )
                }

                tekCharUuid -> {
                    if (isEventMode) {
                        val slice =
                            if (offset <= 0) currentTek
                            else if (offset >= currentTek.size) ByteArray(0)
                            else currentTek.copyOfRange(offset, currentTek.size)
                        server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                        emitDebug(
                            "trace",
                            "gatt_respond_tek_read",
                            mapOf("displayId" to BarnardCrypto.displayId(currentTek))
                        )
                    } else {
                        server.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, offset, null)
                        emitDebug(
                            "trace",
                            "gatt_reject_tek_read",
                            mapOf("reason" to "anonymous_mode")
                        )
                    }
                }

                eventCodeHashCharUuid -> {
                    val hash = getEventCodeHash()
                    val slice =
                        if (offset <= 0) hash
                        else if (offset >= hash.size) ByteArray(0)
                        else hash.copyOfRange(offset, hash.size)
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
                    emitDebug(
                        "trace",
                        "gatt_respond_event_code_hash",
                        mapOf(
                            "bytes" to hash.size,
                            "isEmpty" to hash.isEmpty()
                        )
                    )
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

            if (!isEventMode) {
                if (responseNeeded) {
                    server.sendResponse(device, requestId, BluetoothGatt.GATT_WRITE_NOT_PERMITTED, offset, null)
                }
                emitDebug("trace", "gatt_reject_tek_write", mapOf("reason" to "anonymous_mode"))
                return
            }

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
            emitDebug(
                "info",
                "tek_received_via_write",
                mapOf("displayId" to BarnardCrypto.displayId(value))
            )
        }
    }

    private fun displayIdForPayload(payload: ByteArray): String {
        if (payload.size < 5) return ""
        return payload.copyOfRange(1, 5).joinToString("") { b -> "%02x".format(b) }
    }

    private fun toWritableMap(map: Map<*, *>): WritableMap {
        val out = Arguments.createMap()
        map.forEach { (k, v) ->
            putDynamic(out, k?.toString() ?: return@forEach, v)
        }
        return out
    }

    private fun toWritableArray(list: List<*>): WritableArray {
        val out = Arguments.createArray()
        list.forEach { value ->
            when (value) {
                null -> out.pushNull()
                is String -> out.pushString(value)
                is Boolean -> out.pushBoolean(value)
                is Int -> out.pushInt(value)
                is Long -> {
                    if (value in Int.MIN_VALUE..Int.MAX_VALUE) {
                        out.pushInt(value.toInt())
                    } else {
                        out.pushDouble(value.toDouble())
                    }
                }
                is Float -> out.pushDouble(value.toDouble())
                is Double -> out.pushDouble(value)
                is Map<*, *> -> out.pushMap(toWritableMap(value))
                is List<*> -> out.pushArray(toWritableArray(value))
                else -> out.pushString(value.toString())
            }
        }
        return out
    }

    private fun putDynamic(map: WritableMap, key: String, value: Any?) {
        when (value) {
            null -> map.putNull(key)
            is String -> map.putString(key, value)
            is Boolean -> map.putBoolean(key, value)
            is Int -> map.putInt(key, value)
            is Long -> {
                if (value in Int.MIN_VALUE..Int.MAX_VALUE) {
                    map.putInt(key, value.toInt())
                } else {
                    map.putDouble(key, value.toDouble())
                }
            }
            is Float -> map.putDouble(key, value.toDouble())
            is Double -> map.putDouble(key, value)
            is Map<*, *> -> map.putMap(key, toWritableMap(value))
            is List<*> -> map.putArray(key, toWritableArray(value))
            else -> map.putString(key, value.toString())
        }
    }
}
