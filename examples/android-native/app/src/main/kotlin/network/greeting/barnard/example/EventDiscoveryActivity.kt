// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

package network.greeting.barnard.example

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
import android.os.Bundle
import android.os.ParcelUuid
import android.util.Log
import android.widget.Button
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import network.greeting.barnard.BarnardEngine
import network.greeting.barnard.BarnardEvent
import network.greeting.barnard.BarnardPermissionResult

private const val TAG = "EventDiscovery"
private const val MAX_LOG_LINES = 300
private const val ANNOUNCEMENT_TTL_SECONDS = 300L

/**
 * Spike (barnard-eventcode-discovery, not production): organizer advertises
 * an event announcement over BLE GATT; participant scans, reads it, and
 * auto-joins with zero manual EventCode entry.
 *
 * See docs/spike-eventcode-discovery.md for the design and security
 * trade-offs. This activity intentionally bypasses BarnardEngine's own
 * advertise/scan for the *discovery* step (BarnardEngine has no hook for a
 * custom characteristic) and only hands off to BarnardEngine.joinEvent()
 * once the EventCode has been recovered -- normal detection afterwards is
 * 100% stock BarnardEngine (startAuto()).
 */
class EventDiscoveryActivity : AppCompatActivity() {
    private val engine by lazy { BarnardEngine(applicationContext) }
    private val bluetoothManager by lazy {
        getSystemService(BluetoothManager::class.java)
    }

    private lateinit var statusText: TextView
    private lateinit var logText: TextView
    private lateinit var logScroll: ScrollView
    private val logLines = ArrayDeque<String>()

    private var gattServer: BluetoothGattServer? = null
    private var joined = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_event_discovery)

        statusText = findViewById(R.id.discoveryStatusText)
        logText = findViewById(R.id.discoveryLogText)
        logScroll = (logText.parent as ScrollView)

        findViewById<Button>(R.id.organizerButton).setOnClickListener { requestPermissionsThen(::startOrganizer) }
        findViewById<Button>(R.id.participantButton).setOnClickListener { requestPermissionsThen(::startParticipant) }
        findViewById<Button>(R.id.discoveryStopButton).setOnClickListener { stopAll() }

        engine.setActivity(this)
        engine.onEvent = { event -> runOnUiThread { handleEngineEvent(event) } }

        // Headless device-lab run support: `adb shell am start -n .../.EventDiscoveryActivity
        // --es role organizer|participant` to drive the spike without UI taps.
        when (intent.getStringExtra("role")) {
            "organizer" -> requestPermissionsThen(::startOrganizer)
            "participant" -> requestPermissionsThen(::startParticipant)
        }
    }

    override fun onDestroy() {
        stopAll()
        engine.dispose()
        super.onDestroy()
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        if (!engine.onRequestPermissionsResult(requestCode, permissions, grantResults)) {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        }
    }

    private fun requestPermissionsThen(action: () -> Unit) {
        engine.requestPermissions { result ->
            runOnUiThread {
                when (result) {
                    is BarnardPermissionResult.Granted -> {
                        val status = result.status
                        if (status.canScan && status.canAdvertise) {
                            action()
                        } else {
                            append("permissions_missing: canScan=${status.canScan} canAdvertise=${status.canAdvertise}")
                            engine.openAppSettings()
                        }
                    }
                    is BarnardPermissionResult.Failed -> {
                        append("permissions_failed: ${result.error.code} ${result.error.message}")
                    }
                }
            }
        }
    }

    // ---- Organizer role -----------------------------------------------

    private fun startOrganizer() {
        val eventId = "spike-evt-1"
        val eventCode = "SPIKE-EVENTCODE-${System.currentTimeMillis() % 100000}"
        val announcement = EventDiscovery.Announcement(
            eventId = eventId,
            eventCode = eventCode,
            expiresAtEpochSec = System.currentTimeMillis() / 1000L + ANNOUNCEMENT_TTL_SECONDS,
        )
        val payload = EventDiscovery.encode(announcement)
        append("organizer: eventId=$eventId eventCode=$eventCode payloadBytes=${payload.size}")

        val service = BluetoothGattService(
            EventDiscovery.DISCOVERY_SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY,
        )
        val characteristic = BluetoothGattCharacteristic(
            EventDiscovery.ANNOUNCEMENT_CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        )
        service.addCharacteristic(characteristic)

        gattServer = bluetoothManager.openGattServer(this, object : BluetoothGattServerCallback() {
            override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    append("organizer: gatt_connected device=${device.address}")
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    append("organizer: gatt_disconnected device=${device.address}")
                }
            }

            override fun onCharacteristicReadRequest(
                device: BluetoothDevice,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic,
            ) {
                if (characteristic.uuid != EventDiscovery.ANNOUNCEMENT_CHARACTERISTIC_UUID) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null)
                    return
                }
                append("organizer: announcement_read device=${device.address} offset=$offset")
                val value = if (offset < payload.size) payload.copyOfRange(offset, payload.size) else ByteArray(0)
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value)
            }
        })
        gattServer?.addService(service)

        val advertiser = android.bluetooth.BluetoothAdapter.getDefaultAdapter().bluetoothLeAdvertiser
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .build()
        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .addServiceUuid(ParcelUuid(EventDiscovery.DISCOVERY_SERVICE_UUID))
            .build()
        advertiser.startAdvertising(settings, data, object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                append("organizer: advertise_started")
                statusText.text = "Organizer: advertising eventId=$eventId"
            }

            override fun onStartFailure(errorCode: Int) {
                append("organizer: advertise_failed errorCode=$errorCode")
            }
        })

        // Organizer also joins its own event and runs stock detection so
        // mutual RPID detection can be observed end to end.
        engine.joinEvent(eventCode)
        engine.startAuto()
    }

    // ---- Participant role -----------------------------------------------

    private var scanCallback: ScanCallback? = null

    private fun startParticipant() {
        statusText.text = "Participant: scanning for announcement..."
        append("participant: scan_started")

        val scanner = android.bluetooth.BluetoothAdapter.getDefaultAdapter().bluetoothLeScanner
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(EventDiscovery.DISCOVERY_SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                append("participant: announcement_beacon_found device=${result.device.address} rssi=${result.rssi}")
                scanner.stopScan(this)
                connectAndReadAnnouncement(result.device)
            }

            override fun onScanFailed(errorCode: Int) {
                append("participant: scan_failed errorCode=$errorCode")
            }
        }
        scanCallback = callback
        scanner.startScan(listOf(filter), settings, callback)
    }

    private fun connectAndReadAnnouncement(device: BluetoothDevice) {
        device.connectGatt(this, false, object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    append("participant: gatt_connected")
                    gatt.discoverServices()
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    append("participant: gatt_disconnected")
                    gatt.close()
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                val characteristic = gatt
                    .getService(EventDiscovery.DISCOVERY_SERVICE_UUID)
                    ?.getCharacteristic(EventDiscovery.ANNOUNCEMENT_CHARACTERISTIC_UUID)
                if (characteristic == null) {
                    append("participant: announcement_characteristic_missing")
                    gatt.disconnect()
                    return
                }
                gatt.readCharacteristic(characteristic)
            }

            // API 33+ callback (has the value directly).
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
                status: Int,
            ) {
                onCharacteristicReadCompat(gatt, value, status)
            }

            // Pre-API-33 callback -- this is the one the OS actually calls on the
            // Android 8 emi lab devices (API 26/27); value comes from
            // characteristic.value instead of a callback parameter.
            @Suppress("DEPRECATION")
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                onCharacteristicReadCompat(gatt, characteristic.value ?: ByteArray(0), status)
            }

            private fun onCharacteristicReadCompat(gatt: BluetoothGatt, value: ByteArray, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    append("participant: announcement_read_failed status=$status")
                    gatt.disconnect()
                    return
                }
                val announcement = EventDiscovery.decode(value)
                if (announcement == null) {
                    append("participant: announcement_decode_failed bytes=${value.size}")
                    gatt.disconnect()
                    return
                }
                if (announcement.isExpired) {
                    append("participant: announcement_expired eventId=${announcement.eventId}")
                    gatt.disconnect()
                    return
                }
                append("participant: announcement_decoded eventId=${announcement.eventId} eventCode=${announcement.eventCode}")
                runOnUiThread {
                    autoJoin(announcement)
                }
                gatt.disconnect()
            }
        })
    }

    private fun autoJoin(announcement: EventDiscovery.Announcement) {
        if (joined) return
        joined = true
        append("participant: auto_join eventCode=${announcement.eventCode} (zero manual entry)")
        statusText.text = "Participant: joined eventId=${announcement.eventId}"
        engine.joinEvent(announcement.eventCode)
        engine.startAuto()
    }

    // ---- shared ----------------------------------------------------------

    private fun stopAll() {
        gattServer?.close()
        gattServer = null
        val adapter = android.bluetooth.BluetoothAdapter.getDefaultAdapter()
        adapter.bluetoothLeAdvertiser?.stopAdvertising(object : AdvertiseCallback() {})
        scanCallback?.let { adapter.bluetoothLeScanner?.stopScan(it) }
        scanCallback = null
        engine.stopAuto()
        append("stopped")
    }

    private fun handleEngineEvent(event: BarnardEvent) {
        when (event) {
            is BarnardEvent.State -> {
                val state = event.state
                append("engine_state: scanning=${state.isScanning} advertising=${state.isAdvertising}")
            }
            is BarnardEvent.Detection -> {
                val d = event.detection
                append("MUTUAL_DETECTION: rpid=${d.rpid} reporterRpid=${d.reporterRpid} rssi=${d.rssi} enin=${d.enin}")
            }
            is BarnardEvent.RssiUpdate -> {
                val u = event.update
                append("rssi_update: rpid=${u.rpid} rssi=${u.rssi}")
            }
            is BarnardEvent.Error -> append("engine_error: ${event.error.code} ${event.error.message}")
            is BarnardEvent.Constraint -> append("engine_constraint: ${event.constraint.code} ${event.constraint.message ?: ""}")
        }
    }

    private fun append(line: String) {
        Log.i(TAG, line)
        logLines.addLast(line)
        while (logLines.size > MAX_LOG_LINES) {
            logLines.removeFirst()
        }
        logText.text = logLines.joinToString("\n")
        logScroll.post { logScroll.fullScroll(ScrollView.FOCUS_DOWN) }
    }
}
