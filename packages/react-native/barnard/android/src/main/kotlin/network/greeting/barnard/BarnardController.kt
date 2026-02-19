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
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
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
import com.facebook.react.bridge.WritableMap
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val TAG = "BarnardBLE"

internal class BarnardController(
    private val appContext: Context
) {
    private val mainHandler = Handler(Looper.getMainLooper())

    var onEvent: ((String, WritableMap) -> Unit)? = null
    var onDebugEvent: ((String, WritableMap) -> Unit)? = null

    private val serviceUuid: UUID = UUID.fromString("0000B001-0000-1000-8000-00805F9B34FB")
    private val rpidCharUuid: UUID = UUID.fromString("0000B002-0000-1000-8000-00805F9B34FB")
    
    // RPID security parameters
    private val rotationSeconds = 600L
    private val seedSizeBytes = 32

    private val bluetoothManager: BluetoothManager? =
        appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager?.adapter

    private var gattServer: BluetoothGattServer? = null

    private var isScanning: Boolean = false
    private var isAdvertising: Boolean = false
    private var allowDuplicates: Boolean = true
    private var formatVersion: Int = 1
    private var eventCode: String? = null

    private val discoveredRssi: MutableMap<String, Int> = mutableMapOf()
    private val discoveredAt: MutableMap<String, Long> = mutableMapOf()

    private val connectQueue: ArrayDeque<BluetoothDevice> = ArrayDeque()
    private val lastConnectAttemptAtMs: MutableMap<String, Long> = mutableMapOf()
    private var activeGatt: BluetoothGatt? = null

    private val maxConnectQueue: Int = 20
    private val cooldownPerPeerMs: Long = 10_000

    private val prefs: SharedPreferences =
        appContext.getSharedPreferences("barnard", Context.MODE_PRIVATE)

    fun dispose() {
        stopScan()
        stopAdvertise()
        onEvent = null
        onDebugEvent = null
    }

    fun getCapabilities(): WritableMap {
        val map = Arguments.createMap()
        val transports = Arguments.createArray()
        transports.pushString("ble")
        map.putArray("supportedTransports", transports)
        map.putBoolean("supportsConnectionlessRpid", false)
        map.putBoolean("supportsGattFallback", true)
        map.putBoolean("supportsBackground", false)
        map.putBoolean("supportsHighRateRssi", false)
        return map
    }

    fun getState(): WritableMap {
        val map = Arguments.createMap()
        map.putBoolean("isScanning", isScanning)
        map.putBoolean("isAdvertising", isAdvertising)
        map.putString("eventMode", if (eventCode == null) "anonymous" else "event")
        if (eventCode != null) {
            map.putString("eventCode", eventCode)
        } else {
            map.putNull("eventCode")
        }
        return map
    }

    fun getEventMode(): WritableMap {
        val map = Arguments.createMap()
        map.putString("mode", if (eventCode == null) "anonymous" else "event")
        if (eventCode != null) {
            map.putString("eventCode", eventCode)
        } else {
            map.putNull("eventCode")
        }
        return map
    }

    fun joinEvent(code: String) {
        eventCode = code
        emitState("join_event")
        val debugData = Arguments.createMap()
        debugData.putString("eventCode", code)
        emitDebug("info", "join_event", debugData)
    }

    fun leaveEvent() {
        eventCode = null
        emitState("leave_event")
        emitDebug("info", "leave_event", null)
    }

    fun getExchangedTeks(eventCode: String): com.facebook.react.bridge.WritableArray {
        // Not yet implemented on Android in this branch; keep API parity with iOS.
        return Arguments.createArray()
    }

    fun clearTeksForEvent(eventCode: String): Int {
        // Not yet implemented on Android in this branch; keep API parity with iOS.
        return 0
    }

    fun clearAllTeks(): Int {
        // Not yet implemented on Android in this branch; keep API parity with iOS.
        return 0
    }

    fun startScan(allowDuplicates: Boolean) {
        this.allowDuplicates = allowDuplicates
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
        
        val debugData = Arguments.createMap()
        debugData.putBoolean("allowDuplicates", allowDuplicates)
        emitDebug("info", "scan_start", debugData)
    }

    fun stopScan() {
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
        emitState("scan_stop")
        emitDebug("info", "scan_stop", null)
    }

    fun startAdvertise(formatVersion: Int) {
        this.formatVersion = formatVersion
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
        val adv = a.bluetoothLeAdvertiser ?: run {
            emitError("advertise_failed", "BluetoothLeAdvertiser is null", recoverable = true)
            return
        }
        if (isAdvertising) return

        ensureGattServer()

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(serviceUuid))
            .setIncludeDeviceName(false)
            .build()
        adv.startAdvertising(settings, data, advertiseCallback)
        isAdvertising = true
        emitState("advertise_start")
        
        val debugData = Arguments.createMap()
        debugData.putInt("formatVersion", formatVersion)
        debugData.putString("serviceUuid", serviceUuid.toString())
        debugData.putString("localName", "BNRD")
        emitDebug("info", "advertise_start", debugData)
    }

    fun stopAdvertise() {
        if (!isAdvertising) return
        if (hasAdvertisePermission()) {
            adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        }
        isAdvertising = false
        gattServer?.close()
        gattServer = null
        emitState("advertise_stop")
        emitDebug("info", "advertise_stop", null)
    }

    @SuppressLint("MissingPermission")
    private fun ensureGattServer() {
        if (gattServer != null) return
        if (!hasConnectPermission()) {
            emitConstraint("permission_denied", "Missing BLUETOOTH_CONNECT permission", requiredAction = "grant_permission")
            return
        }
        val manager = bluetoothManager ?: return
        val server = manager.openGattServer(appContext, gattServerCallback)
        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        val ch = BluetoothGattCharacteristic(
            rpidCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(ch)
        server.addService(service)
        gattServer = server
        emitDebug("info", "gatt_server_started", null)
    }

    private fun computePayload(nowMs: Long): ByteArray {
        val window = (nowMs / 1000L) / rotationSeconds
        val seed = getOrCreateSeed()

        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(seed, "HmacSHA256"))
        val msg = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(window).array()
        val digest = mac.doFinal(msg)

        val out = ByteArray(17)
        out[0] = (formatVersion and 0xFF).toByte()
        System.arraycopy(digest, 0, out, 1, 16)
        return out
    }

    private fun getOrCreateSeed(): ByteArray {
        val key = "rpidSeed"
        val existing = prefs.getString(key, null)
        if (existing != null) {
            val bytes = Base64.decode(existing, Base64.DEFAULT)
            if (bytes.size >= seedSizeBytes) return bytes
        }
        val bytes = ByteArray(seedSizeBytes)
        java.security.SecureRandom().nextBytes(bytes)
        prefs.edit().putString(key, Base64.encodeToString(bytes, Base64.NO_WRAP)).apply()
        return bytes
    }

    private fun emitState(reasonCode: String?) {
        val payload = Arguments.createMap()
        payload.putString("type", "state")
        payload.putString("timestamp", BarnardIso8601.now())
        val state = Arguments.createMap()
        state.putBoolean("isScanning", isScanning)
        state.putBoolean("isAdvertising", isAdvertising)
        state.putString("eventMode", if (eventCode == null) "anonymous" else "event")
        if (eventCode != null) {
            state.putString("eventCode", eventCode)
        } else {
            state.putNull("eventCode")
        }
        payload.putMap("state", state)
        if (reasonCode != null) {
            payload.putString("reasonCode", reasonCode)
        }
        mainHandler.post { onEvent?.invoke("BarnardState", payload) }
    }

    private fun emitConstraint(code: String, message: String?, requiredAction: String? = null) {
        val payload = Arguments.createMap()
        payload.putString("type", "constraint")
        payload.putString("timestamp", BarnardIso8601.now())
        payload.putString("code", code)
        if (message != null) {
            payload.putString("message", message)
        }
        if (requiredAction != null) {
            payload.putString("requiredAction", requiredAction)
        }
        mainHandler.post { onEvent?.invoke("BarnardConstraint", payload) }
    }

    private fun emitError(code: String, message: String, recoverable: Boolean? = null) {
        val payload = Arguments.createMap()
        payload.putString("type", "error")
        payload.putString("timestamp", BarnardIso8601.now())
        payload.putString("code", code)
        payload.putString("message", message)
        if (recoverable != null) {
            payload.putBoolean("recoverable", recoverable)
        }
        mainHandler.post { onEvent?.invoke("BarnardError", payload) }
    }

    private fun emitDetection(timestampMs: Long, rssi: Int, payloadBytes: ByteArray) {
        if (payloadBytes.size != 17) {
            val debugData = Arguments.createMap()
            debugData.putInt("length", payloadBytes.size)
            emitDebug("warn", "payload_invalid_length", debugData)
            return
        }
        val version = payloadBytes[0].toInt() and 0xFF
        if (version != 1) {
            val debugData = Arguments.createMap()
            debugData.putInt("formatVersion", version)
            emitDebug("warn", "payload_unsupported_version", debugData)
            return
        }
        val rpid = payloadBytes.copyOfRange(1, 17)
        val displayId = rpid.copyOfRange(0, 4).joinToString("") { b -> "%02x".format(b) }
        
        val payload = Arguments.createMap()
        payload.putString("type", "detection")
        payload.putString("timestamp", BarnardIso8601.fromMs(timestampMs))
        payload.putString("transport", "ble")
        payload.putInt("formatVersion", version)
        payload.putString("rpid", Base64.encodeToString(rpid, Base64.NO_WRAP))
        payload.putString("displayId", displayId)
        payload.putInt("rssi", rssi)
        payload.putString("payloadRaw", Base64.encodeToString(payloadBytes, Base64.NO_WRAP))
        
        mainHandler.post { onEvent?.invoke("BarnardDetection", payload) }
    }

    private fun emitDebug(level: String, name: String, data: WritableMap?) {
        val payload = Arguments.createMap()
        payload.putString("type", "debug")
        payload.putString("timestamp", BarnardIso8601.now())
        payload.putString("level", level)
        payload.putString("name", name)
        if (data != null) {
            payload.putMap("data", data)
        }
        mainHandler.post { onDebugEvent?.invoke("BarnardDebug", payload) }
    }

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
            val debugData = Arguments.createMap()
            debugData.putString("address", address)
            result.scanRecord?.deviceName?.let { debugData.putString("name", it) }
            debugData.putBoolean("hasService", result.scanRecord?.serviceUuids?.any { it.uuid == serviceUuid } == true)
            debugData.putBoolean("isConnectable", isConnectableResult(result))
            emitDebug("trace", "scan_ignored", debugData)
            return
        }
        val nowMs = System.currentTimeMillis()
        if (!allowDuplicates) {
            val last = discoveredAt[address]
            if (last != null && nowMs - last < 2_000) return
        }
        discoveredRssi[address] = result.rssi
        discoveredAt[address] = nowMs

        val debugData = Arguments.createMap()
        debugData.putString("id", address)
        debugData.putInt("rssi", result.rssi)
        result.scanRecord?.deviceName?.let { debugData.putString("name", it) }
        emitDebug("trace", "ble_discovery_result", debugData)

        enqueueConnect(device)
    }

    private fun isBarnardScanResult(result: ScanResult): Boolean {
        val record = result.scanRecord ?: return false
        val uuids = record.serviceUuids
        val hasService = uuids?.any { it.uuid == serviceUuid } == true
        val name = record.deviceName
        val isBnrd = name == "BNRD"
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

    private fun enqueueConnect(device: BluetoothDevice) {
        val address = device.address ?: return
        // Skip if already in queue or currently connecting.
        if (connectQueue.any { it.address == address }) return
        if (activeGatt?.device?.address == address) return

        if (connectQueue.size >= maxConnectQueue) {
            val debugData = Arguments.createMap()
            debugData.putInt("max", maxConnectQueue)
            emitDebug("warn", "connect_queue_full", debugData)
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
        activeGatt =
            if (Build.VERSION.SDK_INT >= 23) {
                device.connectGatt(appContext, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
            } else {
                @Suppress("DEPRECATION")
                device.connectGatt(appContext, false, gattCallback)
            }
        val debugData = Arguments.createMap()
        debugData.putString("address", device.address)
        emitDebug("trace", "connect_attempt", debugData)
    }

    private val gattCallback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emitError("connect_failed", "status=$status", recoverable = true)
                gatt.close()
                activeGatt = null
                pumpConnectQueue()
                return
            }
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                val debugData = Arguments.createMap()
                debugData.putString("address", gatt.device.address)
                emitDebug("trace", "connected", debugData)
                gatt.discoverServices()
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                gatt.close()
                activeGatt = null
                pumpConnectQueue()
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emitError("service_discovery_failed", "status=$status", recoverable = true)
                gatt.disconnect()
                return
            }
            val svc = gatt.getService(serviceUuid)
            if (svc == null) {
                emitError("service_not_found", "Barnard service not found", recoverable = true)
                gatt.disconnect()
                return
            }
            val ch = svc.getCharacteristic(rpidCharUuid)
            if (ch == null) {
                emitError("characteristic_not_found", "RPID characteristic not found", recoverable = true)
                gatt.disconnect()
                return
            }
            if (!hasConnectPermission()) {
                emitConstraint("permission_denied", "Missing BLUETOOTH_CONNECT permission", requiredAction = "grant_permission")
                gatt.disconnect()
                return
            }
            @SuppressLint("MissingPermission")
            gatt.readCharacteristic(ch)
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            val value = characteristic.value ?: ByteArray(0)
            handleRead(gatt, status, value)
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int
        ) {
            handleRead(gatt, status, value)
        }

        private fun handleRead(gatt: BluetoothGatt, status: Int, value: ByteArray) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                emitError("read_failed", "status=$status", recoverable = true)
                gatt.disconnect()
                return
            }
            val address = gatt.device.address ?: ""
            val rssi = discoveredRssi[address] ?: 0
            val ts = discoveredAt[address] ?: System.currentTimeMillis()
            emitDetection(ts, rssi, value)
            gatt.disconnect()
        }
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            val server = gattServer ?: return
            val payload = computePayload(System.currentTimeMillis())
            val slice =
                if (offset <= 0) payload
                else if (offset >= payload.size) ByteArray(0)
                else payload.copyOfRange(offset, payload.size)
            server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, slice)
            
            val debugData = Arguments.createMap()
            debugData.putInt("bytes", payload.size)
            debugData.putInt("formatVersion", payload[0].toInt() and 0xFF)
            debugData.putString("displayId", displayIdForPayload(payload))
            emitDebug("trace", "gatt_read_rpid", debugData)
        }
    }

    private fun displayIdForPayload(payload: ByteArray): String {
        if (payload.size < 5) return ""
        return payload.copyOfRange(1, 5).joinToString("") { b -> "%02x".format(b) }
    }
}
