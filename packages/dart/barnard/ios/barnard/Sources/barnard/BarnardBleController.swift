// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import CoreBluetooth
import Flutter
import Foundation
import UIKit

/// Barnard v2 BLE controller.
///
/// GATT service (fixed UUID):
/// - B002 RPID (Read, 17 bytes)
/// - B003 displayId (Read, 4 bytes) — `SHA256(TEK)[0:4]`. v2 no longer serves TEK.
/// - B004 EventCodeHash (Read, 0 or 8 bytes)
///
/// TEK is never transmitted over BLE in v2.
final class BarnardBleController: NSObject {
  // MARK: - UUIDs

  private let discoveryServiceUUID = CBUUID(string: "0000B001-0000-1000-8000-00805F9B34FB")
  private let rpidCharacteristicUUID = CBUUID(string: "0000B002-0000-1000-8000-00805F9B34FB")
  private let displayIdCharacteristicUUID = CBUUID(string: "0000B003-0000-1000-8000-00805F9B34FB")
  private let eventCodeHashCharacteristicUUID = CBUUID(string: "0000B004-0000-1000-8000-00805F9B34FB")
  private let localName = "BNRD"

  private var debugLocalName: String {
    #if DEBUG
    let suffix = debugDeviceSuffix()
    return "BND-\(suffix)"
    #else
    return localName
    #endif
  }

  private func debugDeviceSuffix() -> String {
    let deviceSecret = rpid.getDeviceSecret()
    let tail = deviceSecret.suffix(2)
    let hex = tail.map { String(format: "%02x", $0) }.joined().uppercased()
    return hex.isEmpty ? "DEAD" : hex
  }

  private let iso8601: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
  }()

  // MARK: - Components

  private let rpid = BarnardRpidGenerator()

  // MARK: - BLE Managers

  private var centralManager: CBCentralManager!
  private var peripheralManager: CBPeripheralManager!

  // MARK: - GATT Characteristics (Peripheral)

  private var rpidCharacteristic: CBMutableCharacteristic?
  private var displayIdCharacteristic: CBMutableCharacteristic?
  private var eventCodeHashCharacteristic: CBMutableCharacteristic?

  // MARK: - State

  private var isScanning = false
  private var isAdvertising = false
  private var allowDuplicates = true
  private var formatVersion: UInt8 = 1

  private var lastDiscoveryNameById: [UUID: String] = [:]

  // MARK: - Discovery State

  private var discoveredRssi: [UUID: Int] = [:]
  private var discoveredAt: [UUID: Date] = [:]

  // MARK: - Connection Queue

  private var connectQueue: [UUID] = []
  private var peripheralsById: [UUID: CBPeripheral] = [:]
  private var lastConnectAttemptAt: [UUID: Date] = [:]
  private var activePeripheral: CBPeripheral?

  private let maxConcurrentConnections = 1
  private let cooldownPerPeerSeconds: TimeInterval = 10
  private let maxConnectQueue = 20

  // MARK: - Central GATT State (per connection)

  private var peripheralCharacteristics: [UUID: [CBUUID: CBCharacteristic]] = [:]
  private var peripheralReadValues: [UUID: PeripheralGattValues] = [:]

  /// Values read from a peripheral during v2 GATT exchange.
  private struct PeripheralGattValues {
    var eventCodeHash: Data?
    var rpid: Data?
    var detectedDisplayId: Data?
  }

  // MARK: - Known Peers (for high-rate RSSI updates)

  private struct KnownPeer {
    let rpid: Data
    var detectedDisplayId: String?
  }

  private var knownPeers: [UUID: KnownPeer] = [:]

  // MARK: - Event Sinks

  let eventsStreamHandler: BarnardStreamHandler
  let debugEventsStreamHandler: BarnardStreamHandler

  private var eventSink: FlutterEventSink?
  private var debugEventSink: FlutterEventSink?

  // MARK: - Initialization

  override init() {
    let eventsHandler = BarnardStreamHandler()
    let debugHandler = BarnardStreamHandler()
    eventsStreamHandler = eventsHandler
    debugEventsStreamHandler = debugHandler
    super.init()

    eventsHandler.onListen = { [weak self] sink in self?.eventSink = sink }
    eventsHandler.onCancel = { [weak self] in self?.eventSink = nil }
    debugHandler.onListen = { [weak self] sink in self?.debugEventSink = sink }
    debugHandler.onCancel = { [weak self] in self?.debugEventSink = nil }

    centralManager = CBCentralManager(delegate: self, queue: nil)
    peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
  }

  // MARK: - Platform Channel Handler

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getCapabilities":
      result([
        "supportedTransports": ["ble"],
        "supportsConnectionlessRpid": false,
        "supportsGattFallback": true,
        "supportsBackground": false,
        "supportsHighRateRssi": false,
      ])

    case "getState":
      result([
        "isScanning": isScanning,
        "isAdvertising": isAdvertising,
        "eventCode": rpid.eventCode as Any,
      ])

    case "getCurrentEventCode":
      result(rpid.eventCode)

    case "getMyDisplayId":
      result(BarnardCrypto.displayIdString(from: rpid.getCurrentTek()))

    case "getCurrentRpi":
      let rpik = BarnardCrypto.deriveRpik(from: rpid.getCurrentTek())
      let rpi = BarnardCrypto.generateRpi(rpik: rpik, enin: BarnardCrypto.calculateEnin(for: Date()))
      result(rpi.hexString)

    case "getCurrentEnin":
      result(Int(BarnardCrypto.calculateEnin(for: Date())))

    case "exportCurrentTek":
      // Explicit privacy egress. SDK never transmits TEK over BLE; caller
      // decides whether/how to transmit it via another channel.
      result(rpid.getCurrentTek().hexString)

    case "startScan":
      let args = (call.arguments as? [String: Any]) ?? [:]
      allowDuplicates = (args["allowDuplicates"] as? Bool) ?? true
      startScan()
      result(nil)

    case "stopScan":
      stopScan()
      result(nil)

    case "startAdvertise":
      let args = (call.arguments as? [String: Any]) ?? [:]
      if let v = args["formatVersion"] as? Int, v >= 0, v <= 255 { formatVersion = UInt8(v) }
      startAdvertise()
      result(nil)

    case "stopAdvertise":
      stopAdvertise()
      result(nil)

    case "startAuto":
      let args = (call.arguments as? [String: Any]) ?? [:]
      if let scan = args["scan"] as? [String: Any] {
        allowDuplicates = (scan["allowDuplicates"] as? Bool) ?? true
      }
      if let adv = args["advertise"] as? [String: Any] {
        if let v = adv["formatVersion"] as? Int, v >= 0, v <= 255 { formatVersion = UInt8(v) }
      }

      let wasScanning = isScanning
      let wasAdvertising = isAdvertising
      startScan()
      startAdvertise()
      result([
        "scanningStarted": (!wasScanning && isScanning),
        "advertisingStarted": (!wasAdvertising && isAdvertising),
        "issues": [],
      ])

    case "stopAuto":
      stopScan()
      stopAdvertise()
      result(nil)

    case "dispose":
      stopScan()
      stopAdvertise()
      result(nil)

    case "joinEvent":
      guard let args = call.arguments as? [String: Any],
        let eventCode = args["eventCode"] as? String
      else {
        result(FlutterError(code: "INVALID_ARGUMENT", message: "eventCode required", details: nil))
        return
      }
      rpid.joinEvent(eventCode)
      rebuildGattServiceIfNeeded()
      emitState(reasonCode: "join_event")
      emitDebug(level: "info", name: "join_event", data: [
        "eventCode": eventCode,
        "myDisplayId": rpid.getCurrentDisplayId(),
      ])
      result(nil)

    case "leaveEvent":
      rpid.leaveEvent()
      rebuildGattServiceIfNeeded()
      emitState(reasonCode: "leave_event")
      emitDebug(level: "info", name: "leave_event", data: nil)
      result(nil)

    default:
      result(FlutterMethodNotImplemented)
    }
  }

  // MARK: - Scan Control

  private func startScan() {
    guard centralManager.state == .poweredOn else {
      emitConstraint(code: "bluetooth_not_ready", message: "CentralManager state=\(centralManager.state.rawValue)")
      return
    }
    if isScanning { return }
    let options: [String: Any] = [CBCentralManagerScanOptionAllowDuplicatesKey: allowDuplicates]
    centralManager.scanForPeripherals(withServices: [discoveryServiceUUID], options: options)
    isScanning = true
    emitState(reasonCode: "scan_start")
    emitDebug(level: "info", name: "scan_start", data: ["allowDuplicates": allowDuplicates])
  }

  private func stopScan() {
    if !isScanning { return }
    centralManager.stopScan()
    isScanning = false
    connectQueue.removeAll()
    activePeripheral = nil

    discoveredRssi.removeAll()
    discoveredAt.removeAll()
    peripheralsById.removeAll()
    lastConnectAttemptAt.removeAll()
    peripheralCharacteristics.removeAll()
    peripheralReadValues.removeAll()
    lastDiscoveryNameById.removeAll()
    knownPeers.removeAll()

    emitState(reasonCode: "scan_stop")
    emitDebug(level: "info", name: "scan_stop", data: nil)
  }

  // MARK: - Advertise Control

  private func startAdvertise() {
    guard peripheralManager.state == .poweredOn else {
      emitConstraint(code: "bluetooth_not_ready", message: "PeripheralManager state=\(peripheralManager.state.rawValue)")
      return
    }
    if isAdvertising { return }
    ensureGattService()
    var ad: [String: Any] = [
      CBAdvertisementDataServiceUUIDsKey: [discoveryServiceUUID],
    ]
    #if DEBUG
    ad[CBAdvertisementDataLocalNameKey] = debugLocalName
    #endif
    peripheralManager.startAdvertising(ad)
    isAdvertising = true
    emitState(reasonCode: "advertise_start")
    emitDebug(
      level: "info",
      name: "advertise_start",
      data: [
        "formatVersion": Int(formatVersion),
        "serviceUuid": discoveryServiceUUID.uuidString,
        "localName": debugLocalName,
      ]
    )
  }

  private func stopAdvertise() {
    if !isAdvertising { return }
    peripheralManager.stopAdvertising()
    isAdvertising = false
    emitState(reasonCode: "advertise_stop")
    emitDebug(level: "info", name: "advertise_stop", data: nil)
  }

  // MARK: - GATT Service Management

  private func ensureGattService() {
    if rpidCharacteristic != nil { return }
    buildAndAddGattService()
  }

  private func rebuildGattServiceIfNeeded() {
    guard peripheralManager.state == .poweredOn else { return }

    peripheralManager.removeAllServices()
    rpidCharacteristic = nil
    displayIdCharacteristic = nil
    eventCodeHashCharacteristic = nil

    buildAndAddGattService()

    emitDebug(level: "info", name: "gatt_service_rebuilt", data: nil)
  }

  private func buildAndAddGattService() {
    // B002 RPID (Read only)
    let rpidCh = CBMutableCharacteristic(
      type: rpidCharacteristicUUID,
      properties: [.read],
      value: nil,
      permissions: [.readable]
    )

    // B003 displayId (Read only, 4 bytes) — v2: was TEK, now SHA256(TEK)[0:4]
    let displayIdCh = CBMutableCharacteristic(
      type: displayIdCharacteristicUUID,
      properties: [.read],
      value: nil,
      permissions: [.readable]
    )

    // B004 EventCodeHash (Read only)
    let eventCodeHashCh = CBMutableCharacteristic(
      type: eventCodeHashCharacteristicUUID,
      properties: [.read],
      value: nil,
      permissions: [.readable]
    )

    let svc = CBMutableService(type: discoveryServiceUUID, primary: true)
    svc.characteristics = [rpidCh, displayIdCh, eventCodeHashCh]
    peripheralManager.add(svc)

    rpidCharacteristic = rpidCh
    displayIdCharacteristic = displayIdCh
    eventCodeHashCharacteristic = eventCodeHashCh

    emitDebug(level: "info", name: "gatt_service_added", data: [
      "characteristics": ["RPID", "displayId", "EventCodeHash"],
    ])
  }

  // MARK: - Connection Queue

  private func enqueueConnect(_ peripheral: CBPeripheral) {
    let id = peripheral.identifier
    peripheralsById[id] = peripheral

    if connectQueue.contains(id) || (activePeripheral?.identifier == id) { return }

    if connectQueue.count >= maxConnectQueue {
      emitDebug(level: "warn", name: "connect_queue_full", data: ["max": maxConnectQueue])
      return
    }

    connectQueue.append(id)
    pumpConnectQueue()
  }

  private func pumpConnectQueue() {
    if maxConcurrentConnections <= 0 { return }
    if activePeripheral != nil { return }
    guard let nextId = connectQueue.first else { return }

    let now = Date()
    if let last = lastConnectAttemptAt[nextId], now.timeIntervalSince(last) < cooldownPerPeerSeconds {
      connectQueue.removeFirst()
      connectQueue.append(nextId)
      return
    }

    guard let p = peripheralsById[nextId] else {
      connectQueue.removeFirst()
      return
    }

    connectQueue.removeFirst()
    activePeripheral = p
    lastConnectAttemptAt[nextId] = now

    peripheralReadValues[nextId] = PeripheralGattValues()

    p.delegate = self
    centralManager.connect(p, options: nil)
    emitDebug(level: "trace", name: "connect_attempt", data: ["id": nextId.uuidString])
  }

  // MARK: - GATT Exchange (Central side, v2 flow: B004 → B002 → B003)

  private func startGattExchange(for peripheral: CBPeripheral, service: CBService) {
    let id = peripheral.identifier
    var charMap: [CBUUID: CBCharacteristic] = [:]

    guard let characteristics = service.characteristics else {
      finishConnection(peripheral)
      return
    }

    for ch in characteristics {
      charMap[ch.uuid] = ch
    }
    peripheralCharacteristics[id] = charMap

    // Step 1: EventCodeHash (informational; we emit regardless of match)
    if let eventCodeHashCh = charMap[eventCodeHashCharacteristicUUID] {
      peripheral.readValue(for: eventCodeHashCh)
    } else {
      readRpidCharacteristic(for: peripheral)
    }
  }

  private func readRpidCharacteristic(for peripheral: CBPeripheral) {
    let id = peripheral.identifier
    guard let charMap = peripheralCharacteristics[id],
      let rpidCh = charMap[rpidCharacteristicUUID]
    else {
      finishConnection(peripheral)
      return
    }
    peripheral.readValue(for: rpidCh)
  }

  private func readDisplayIdCharacteristic(for peripheral: CBPeripheral) {
    let id = peripheral.identifier
    guard let charMap = peripheralCharacteristics[id],
      let displayIdCh = charMap[displayIdCharacteristicUUID]
    else {
      // Missing B003 — per v2 policy, still emit detection with null displayId.
      emitDebug(level: "warn", name: "gatt_b003_missing", data: [
        "id": id.uuidString,
      ])
      completeGattExchange(for: peripheral)
      return
    }
    peripheral.readValue(for: displayIdCh)
  }

  private func completeGattExchange(for peripheral: CBPeripheral) {
    let id = peripheral.identifier
    guard let values = peripheralReadValues[id] else {
      finishConnection(peripheral)
      return
    }

    if let rpidData = values.rpid {
      let rssi = discoveredRssi[id] ?? 0
      let ts = discoveredAt[id] ?? Date()
      let detectedDisplayId = values.detectedDisplayId?.hexString
      emitDetection(
        timestamp: ts,
        rssi: rssi,
        payload: rpidData,
        detectedDisplayId: detectedDisplayId,
        debugLocalName: lastDiscoveryNameById[id]
      )

      if rpidData.count == 17 {
        knownPeers[id] = KnownPeer(rpid: rpidData, detectedDisplayId: detectedDisplayId)
      }
    }

    finishConnection(peripheral)
  }

  private func finishConnection(_ peripheral: CBPeripheral) {
    let id = peripheral.identifier
    peripheralCharacteristics.removeValue(forKey: id)
    peripheralReadValues.removeValue(forKey: id)
    lastDiscoveryNameById.removeValue(forKey: id)
    centralManager.cancelPeripheralConnection(peripheral)
  }

  // MARK: - Event Emission

  private func emitState(reasonCode: String?) {
    eventSink?([
      "type": "state",
      "timestamp": iso8601.string(from: Date()),
      "state": [
        "isScanning": isScanning,
        "isAdvertising": isAdvertising,
        "eventCode": rpid.eventCode as Any,
      ],
      "reasonCode": reasonCode as Any,
    ])
  }

  private func emitConstraint(code: String, message: String?) {
    eventSink?([
      "type": "constraint",
      "timestamp": iso8601.string(from: Date()),
      "code": code,
      "message": message as Any,
      "requiredAction": NSNull(),
    ])
  }

  private func emitError(code: String, message: String, recoverable: Bool? = nil) {
    eventSink?([
      "type": "error",
      "timestamp": iso8601.string(from: Date()),
      "code": code,
      "message": message,
      "recoverable": recoverable as Any,
    ])
  }

  /// Emit v2 detection event. Byte fields are lowercase hex.
  private func emitDetection(
    timestamp: Date,
    rssi: Int,
    payload: Data,
    detectedDisplayId: String?,
    debugLocalName: String? = nil
  ) {
    guard payload.count == 17 else {
      emitDebug(level: "warn", name: "payload_invalid_length", data: ["length": payload.count])
      return
    }
    let version = Int(payload[0])
    if version != 1 {
      emitDebug(level: "warn", name: "payload_unsupported_version", data: ["formatVersion": version])
      return
    }

    // Atomic snapshot: use the observation timestamp for both reporterRpid
    // and enin, so they always agree across ENIN boundaries.
    let reporterPayload = rpid.currentPayload(formatVersion: formatVersion, now: timestamp)
    let enin = Int(BarnardCrypto.calculateEnin(for: timestamp))

    var event: [String: Any] = [
      "type": "detection",
      "timestamp": iso8601.string(from: timestamp),
      "transport": "ble",
      "formatVersion": version,
      "rpid": payload.hexString,
      "reporterRpid": reporterPayload.hexString,
      "detectedDisplayId": detectedDisplayId as Any,
      "enin": enin,
      "rssi": rssi,
      "rssiSummary": NSNull(),
      "payloadRaw": payload.hexString,
    ]

    #if DEBUG
    if let name = debugLocalName {
      event["debugLocalName"] = name
    }
    #endif

    eventSink?(event)
  }

  private func emitRssiUpdate(peripheralId: UUID, rssi: Int, timestamp: Date) {
    guard let peer = knownPeers[peripheralId] else { return }

    var event: [String: Any] = [
      "type": "rssi_update",
      "timestamp": iso8601.string(from: timestamp),
      "rpid": peer.rpid.hexString,
      "rssi": rssi,
    ]

    if let detectedId = peer.detectedDisplayId {
      event["detectedDisplayId"] = detectedId
    }

    eventSink?(event)
  }

  private func emitDebug(level: String, name: String, data: [String: Any]?) {
    debugEventSink?([
      "type": "debug",
      "timestamp": iso8601.string(from: Date()),
      "level": level,
      "name": name,
      "data": data as Any,
    ])
  }
}

// MARK: - CBCentralManagerDelegate

extension BarnardBleController: CBCentralManagerDelegate {
  func centralManagerDidUpdateState(_ central: CBCentralManager) {
    emitDebug(level: "info", name: "central_state", data: ["state": central.state.rawValue])
    if central.state != .poweredOn, isScanning {
      stopScan()
    }
  }

  func centralManager(
    _ central: CBCentralManager,
    didDiscover peripheral: CBPeripheral,
    advertisementData: [String: Any],
    rssi RSSI: NSNumber
  ) {
    let now = Date()
    discoveredRssi[peripheral.identifier] = RSSI.intValue
    discoveredAt[peripheral.identifier] = now

    emitDebug(level: "trace", name: "ble_discovery_result", data: [
      "id": peripheral.identifier.uuidString,
      "rssi": RSSI.intValue,
      "name": (advertisementData[CBAdvertisementDataLocalNameKey] as? String) as Any,
    ])

    #if DEBUG
    if let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String, !name.isEmpty {
      lastDiscoveryNameById[peripheral.identifier] = name
    }
    #endif

    if knownPeers[peripheral.identifier] != nil {
      emitRssiUpdate(peripheralId: peripheral.identifier, rssi: RSSI.intValue, timestamp: now)
    } else {
      enqueueConnect(peripheral)
    }
  }

  func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
    emitDebug(level: "trace", name: "connected", data: ["id": peripheral.identifier.uuidString])
    peripheral.discoverServices([discoveryServiceUUID])
  }

  func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
    emitError(code: "connect_failed", message: error?.localizedDescription ?? "unknown", recoverable: true)
    let id = peripheral.identifier
    peripheralCharacteristics.removeValue(forKey: id)
    peripheralReadValues.removeValue(forKey: id)
    activePeripheral = nil
    pumpConnectQueue()
  }

  func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
    let id = peripheral.identifier
    peripheralCharacteristics.removeValue(forKey: id)
    peripheralReadValues.removeValue(forKey: id)
    activePeripheral = nil
    pumpConnectQueue()
  }
}

// MARK: - CBPeripheralDelegate

extension BarnardBleController: CBPeripheralDelegate {
  func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
    if let error = error {
      emitError(code: "service_discovery_failed", message: error.localizedDescription, recoverable: true)
      finishConnection(peripheral)
      return
    }
    guard let services = peripheral.services, let svc = services.first(where: { $0.uuid == discoveryServiceUUID }) else {
      emitError(code: "service_not_found", message: "Barnard service not found", recoverable: true)
      finishConnection(peripheral)
      return
    }
    peripheral.discoverCharacteristics(
      [rpidCharacteristicUUID, displayIdCharacteristicUUID, eventCodeHashCharacteristicUUID],
      for: svc
    )
  }

  func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
    if let error = error {
      emitError(code: "characteristic_discovery_failed", message: error.localizedDescription, recoverable: true)
      finishConnection(peripheral)
      return
    }
    startGattExchange(for: peripheral, service: service)
  }

  func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
    let id = peripheral.identifier

    // Distinguish B003 read failure (still emit detection with null) from
    // B002 read failure (drop the detection — no RPID, nothing to emit).
    if let error = error {
      if characteristic.uuid == displayIdCharacteristicUUID {
        emitDebug(level: "warn", name: "gatt_b003_read_failed", data: [
          "id": id.uuidString,
          "error": error.localizedDescription,
        ])
        peripheralReadValues[id]?.detectedDisplayId = nil
        completeGattExchange(for: peripheral)
        return
      }
      emitError(code: "read_failed", message: error.localizedDescription, recoverable: true)
      finishConnection(peripheral)
      return
    }

    let value = characteristic.value ?? Data()

    switch characteristic.uuid {
    case eventCodeHashCharacteristicUUID:
      peripheralReadValues[id]?.eventCodeHash = value
      emitDebug(level: "trace", name: "gatt_read_event_code_hash", data: [
        "id": id.uuidString,
        "bytes": value.count,
        "isEmpty": value.isEmpty,
      ])
      readRpidCharacteristic(for: peripheral)

    case rpidCharacteristicUUID:
      peripheralReadValues[id]?.rpid = value
      emitDebug(level: "trace", name: "gatt_read_rpid", data: [
        "id": id.uuidString,
        "bytes": value.count,
      ])
      readDisplayIdCharacteristic(for: peripheral)

    case displayIdCharacteristicUUID:
      if value.count == 4 {
        peripheralReadValues[id]?.detectedDisplayId = value
        emitDebug(level: "trace", name: "gatt_read_display_id", data: [
          "id": id.uuidString,
          "displayId": value.hexString,
        ])
      } else {
        emitDebug(level: "warn", name: "gatt_b003_invalid_length", data: [
          "id": id.uuidString,
          "length": value.count,
        ])
        peripheralReadValues[id]?.detectedDisplayId = nil
      }
      completeGattExchange(for: peripheral)

    default:
      break
    }
  }
}

// MARK: - CBPeripheralManagerDelegate

extension BarnardBleController: CBPeripheralManagerDelegate {
  func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
    emitDebug(level: "info", name: "peripheral_state", data: ["state": peripheral.state.rawValue])
    if peripheral.state != .poweredOn, isAdvertising {
      stopAdvertise()
    }
  }

  func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
    if let error = error {
      emitError(code: "gatt_service_add_failed", message: error.localizedDescription, recoverable: false)
    }
  }

  func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
    if let error = error {
      emitError(code: "advertise_failed", message: error.localizedDescription, recoverable: true)
      isAdvertising = false
      emitState(reasonCode: "advertise_failed")
    }
  }

  func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
    switch request.characteristic.uuid {
    case rpidCharacteristicUUID:
      let payload = rpid.currentPayload(formatVersion: formatVersion, now: Date())
      request.value = payload
      peripheral.respond(to: request, withResult: .success)

      emitDebug(
        level: "trace",
        name: "gatt_respond_rpid",
        data: [
          "bytes": payload.count,
          "formatVersion": Int(formatVersion),
        ]
      )

    case displayIdCharacteristicUUID:
      // v2: B003 always serves 4-byte SHA256(TEK)[0:4]. Read-only.
      let displayId = BarnardCrypto.displayId4(from: rpid.getCurrentTek())
      request.value = displayId
      peripheral.respond(to: request, withResult: .success)
      emitDebug(level: "trace", name: "gatt_respond_display_id", data: [
        "bytes": displayId.count,
      ])

    case eventCodeHashCharacteristicUUID:
      let hash = rpid.getEventCodeHash()
      request.value = hash
      peripheral.respond(to: request, withResult: .success)
      emitDebug(level: "trace", name: "gatt_respond_event_code_hash", data: [
        "bytes": hash.count,
        "isEmpty": hash.isEmpty,
      ])

    default:
      peripheral.respond(to: request, withResult: .attributeNotFound)
    }
  }

  // v2 has no writable characteristics. Reject any write attempt.
  func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
    for request in requests {
      peripheral.respond(to: request, withResult: .writeNotPermitted)
    }
    emitDebug(level: "warn", name: "gatt_write_rejected", data: [
      "count": requests.count,
    ])
  }
}
