// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import CoreBluetooth
import Foundation
import UIKit

/// Barnard v2 BLE controller (React Native bridge variant).
///
/// - B002 RPID (Read, 17 bytes)
/// - B003 displayId (Read, 4 bytes) — SHA256(TEK)[0:4]
/// - B004 EventCodeHash (Read, 0 or 8 bytes)
///
/// TEK is never transmitted over BLE in v2.
final class BarnardBleController: NSObject {
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

  private let rpid = BarnardRpidGenerator()

  private var centralManager: CBCentralManager!
  private var peripheralManager: CBPeripheralManager!

  private var rpidCharacteristic: CBMutableCharacteristic?
  private var displayIdCharacteristic: CBMutableCharacteristic?
  private var eventCodeHashCharacteristic: CBMutableCharacteristic?

  private var isScanning = false
  private var isAdvertising = false
  private var allowDuplicates = true
  private var formatVersion: UInt8 = 1

  private var lastDiscoveryNameById: [UUID: String] = [:]

  private var discoveredRssi: [UUID: Int] = [:]
  private var discoveredAt: [UUID: Date] = [:]

  private var connectQueue: [UUID] = []
  private var peripheralsById: [UUID: CBPeripheral] = [:]
  private var lastConnectAttemptAt: [UUID: Date] = [:]
  private var activePeripheral: CBPeripheral?

  private let maxConcurrentConnections = 1
  private let cooldownPerPeerSeconds: TimeInterval = 10
  private let maxConnectQueue = 20
  // See Flutter variant: CoreBluetooth's `connect()` has no deadline, so a
  // hung connection pins `activePeripheral` forever and starves the queue.
  private let connectTimeoutSeconds: TimeInterval = 8
  private var connectWatchdog: DispatchWorkItem?

  private var peripheralCharacteristics: [UUID: [CBUUID: CBCharacteristic]] = [:]
  private var peripheralReadValues: [UUID: PeripheralGattValues] = [:]

  private struct PeripheralGattValues {
    var eventCodeHash: Data?
    var rpid: Data?
    var detectedDisplayId: Data?
  }

  private struct KnownPeer {
    let rpid: Data
    var detectedDisplayId: String?
  }

  private var knownPeers: [UUID: KnownPeer] = [:]

  /// Event callback. `eventName` is one of: BarnardDetection, BarnardState,
  /// BarnardConstraint, BarnardError, BarnardRssiUpdate.
  var onEvent: ((String, [String: Any]) -> Void)?
  /// Debug event callback. `eventName` is always "BarnardDebug".
  var onDebugEvent: ((String, [String: Any]) -> Void)?

  override init() {
    super.init()
    centralManager = CBCentralManager(delegate: self, queue: nil)
    peripheralManager = CBPeripheralManager(delegate: self, queue: nil)

    NotificationCenter.default.addObserver(
      self,
      selector: #selector(appDidBecomeActive),
      name: UIApplication.didBecomeActiveNotification,
      object: nil
    )
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(appWillResignActive),
      name: UIApplication.willResignActiveNotification,
      object: nil
    )
  }

  deinit {
    NotificationCenter.default.removeObserver(self)
  }

  func dispose() {
    stopScan()
    stopAdvertise()
    onEvent = nil
    onDebugEvent = nil
  }

  // MARK: - Lifecycle

  // On background, iOS demotes our advertised service UUID from the AdvData
  // section to the overflow area, making us invisible to generic centrals.
  // iOS does not repromote on foreground resume, so bounce advertising to
  // repopulate AdvData. See issue #45.
  @objc private func appDidBecomeActive() {
    guard isAdvertising else {
      emitDebug(level: "trace", name: "foreground_resume", data: ["isAdvertising": false])
      return
    }
    let activeFormat = Int(formatVersion)
    peripheralManager.stopAdvertising()
    isAdvertising = false
    startAdvertise(formatVersion: activeFormat)
    emitDebug(level: "info", name: "advertise_restart_on_foreground", data: nil)
  }

  @objc private func appWillResignActive() {
    emitDebug(level: "info", name: "advertise_backgrounded", data: [
      "isAdvertising": isAdvertising,
    ])
  }

  // MARK: - Public API

  func getCapabilities() -> [String: Any] {
    [
      "supportedTransports": ["ble"],
      "supportsConnectionlessRpid": false,
      "supportsGattFallback": true,
      "supportsBackground": false,
      "supportsHighRateRssi": false,
    ]
  }

  func getState() -> [String: Any] {
    [
      "isScanning": isScanning,
      "isAdvertising": isAdvertising,
      "eventCode": rpid.eventCode as Any,
    ]
  }

  /// v2 API: current event code, or nil.
  func getCurrentEventCode() -> String? {
    rpid.eventCode
  }

  /// v2 API: 8-char lowercase hex `SHA256(TEK)[0:4]`.
  func getMyDisplayId() -> String {
    BarnardCrypto.displayIdString(from: rpid.getCurrentTek())
  }

  /// v2 API: inner 16-byte RPI for current ENIN, as hex string.
  func getCurrentRpi() -> String {
    let rpik = BarnardCrypto.deriveRpik(from: rpid.getCurrentTek())
    let rpi = BarnardCrypto.generateRpi(rpik: rpik, enin: BarnardCrypto.calculateEnin(for: Date()))
    return rpi.hexString
  }

  /// v2 API: current ENIN as Int.
  func getCurrentEnin() -> Int {
    Int(BarnardCrypto.calculateEnin(for: Date()))
  }

  /// v2 API: raw TEK as 32-char lowercase hex. Explicit privacy egress;
  /// the SDK never transmits TEK over BLE.
  func exportCurrentTek() -> String {
    rpid.getCurrentTek().hexString
  }

  func startScan(allowDuplicates: Bool) {
    self.allowDuplicates = allowDuplicates
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

  func stopScan() {
    if !isScanning { return }
    centralManager.stopScan()
    if let active = activePeripheral {
      centralManager.cancelPeripheralConnection(active)
    }
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

  func startAdvertise(formatVersion: Int) {
    self.formatVersion = acceptFormatVersion(formatVersion)
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
        "formatVersion": Int(self.formatVersion),
        "serviceUuid": discoveryServiceUUID.uuidString,
        "localName": debugLocalName,
      ]
    )
  }

  func stopAdvertise() {
    if !isAdvertising { return }
    peripheralManager.stopAdvertising()
    isAdvertising = false
    emitState(reasonCode: "advertise_stop")
    emitDebug(level: "info", name: "advertise_stop", data: nil)
  }

  func joinEvent(_ eventCode: String) {
    rpid.joinEvent(eventCode)
    rebuildGattServiceIfNeeded()
    emitState(reasonCode: "join_event")
    emitDebug(level: "info", name: "join_event", data: [
      "eventCode": eventCode,
      "myDisplayId": rpid.getCurrentDisplayId(),
    ])
  }

  func leaveEvent() {
    rpid.leaveEvent()
    rebuildGattServiceIfNeeded()
    emitState(reasonCode: "leave_event")
    emitDebug(level: "info", name: "leave_event", data: nil)
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
    let rpidCh = CBMutableCharacteristic(
      type: rpidCharacteristicUUID,
      properties: [.read],
      value: nil,
      permissions: [.readable]
    )

    // v2: B003 = 4-byte displayId, Read only.
    let displayIdCh = CBMutableCharacteristic(
      type: displayIdCharacteristicUUID,
      properties: [.read],
      value: nil,
      permissions: [.readable]
    )

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
    armConnectWatchdog(for: nextId)
  }

  private func armConnectWatchdog(for id: UUID) {
    connectWatchdog?.cancel()
    let work = DispatchWorkItem { [weak self] in
      guard let self = self else { return }
      guard let pinned = self.activePeripheral, pinned.identifier == id else {
        return
      }
      self.emitDebug(level: "warn", name: "connect_timeout", data: [
        "id": id.uuidString,
        "seconds": self.connectTimeoutSeconds,
      ])
      self.centralManager.cancelPeripheralConnection(pinned)
      self.peripheralCharacteristics.removeValue(forKey: id)
      self.peripheralReadValues.removeValue(forKey: id)
      self.lastDiscoveryNameById.removeValue(forKey: id)
      self.activePeripheral = nil
      self.pumpConnectQueue()
    }
    connectWatchdog = work
    DispatchQueue.main.asyncAfter(
      deadline: .now() + connectTimeoutSeconds,
      execute: work
    )
  }

  private func cancelConnectWatchdog() {
    connectWatchdog?.cancel()
    connectWatchdog = nil
  }

  // MARK: - GATT Exchange (Central, v2 flow: B004 -> B002 -> B003)

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
    let payload: [String: Any] = [
      "type": "state",
      "timestamp": iso8601.string(from: Date()),
      "state": [
        "isScanning": isScanning,
        "isAdvertising": isAdvertising,
        "eventCode": rpid.eventCode as Any,
      ],
      "reasonCode": reasonCode as Any,
    ]
    onEvent?("BarnardState", payload)
  }

  private func emitConstraint(code: String, message: String?) {
    let payload: [String: Any] = [
      "type": "constraint",
      "timestamp": iso8601.string(from: Date()),
      "code": code,
      "message": message as Any,
      "requiredAction": NSNull(),
    ]
    onEvent?("BarnardConstraint", payload)
  }

  private func emitError(code: String, message: String, recoverable: Bool? = nil) {
    var payload: [String: Any] = [
      "type": "error",
      "timestamp": iso8601.string(from: Date()),
      "code": code,
      "message": message,
    ]
    if let rec = recoverable {
      payload["recoverable"] = rec
    }
    onEvent?("BarnardError", payload)
  }

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

    // Atomic snapshot at the observation timestamp.
    let reporterPayload = rpid.currentPayload(formatVersion: formatVersion, now: timestamp)
    let enin = Int(BarnardCrypto.calculateEnin(for: timestamp))

    var eventPayload: [String: Any] = [
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
      eventPayload["debugLocalName"] = name
    }
    #endif

    onEvent?("BarnardDetection", eventPayload)
  }

  private func emitRssiUpdate(peripheralId: UUID, rssi: Int, timestamp: Date) {
    guard let peer = knownPeers[peripheralId] else { return }

    var eventPayload: [String: Any] = [
      "type": "rssi_update",
      "timestamp": iso8601.string(from: timestamp),
      "rpid": peer.rpid.hexString,
      "rssi": rssi,
    ]

    if let detectedId = peer.detectedDisplayId {
      eventPayload["detectedDisplayId"] = detectedId
    }

    onEvent?("BarnardRssiUpdate", eventPayload)
  }

  private func emitDebug(level: String, name: String, data: [String: Any]?) {
    var payload: [String: Any] = [
      "type": "debug",
      "timestamp": iso8601.string(from: Date()),
      "level": level,
      "name": name,
    ]
    if let value = data {
      payload["data"] = value
    }
    onDebugEvent?("BarnardDebug", payload)
  }

  /// Accept a caller-provided formatVersion. v2 only ships format 1, so
  /// clamp to 1 and emit a debug warning otherwise.
  private func acceptFormatVersion(_ raw: Int) -> UInt8 {
    if raw == 1 { return 1 }
    emitDebug(level: "warn", name: "format_version_clamped", data: [
      "requested": raw,
      "applied": 1,
    ])
    return 1
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
    cancelConnectWatchdog()
    emitDebug(level: "trace", name: "connected", data: ["id": peripheral.identifier.uuidString])
    peripheral.discoverServices([discoveryServiceUUID])
  }

  func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
    cancelConnectWatchdog()
    emitError(code: "connect_failed", message: error?.localizedDescription ?? "unknown", recoverable: true)
    let id = peripheral.identifier
    peripheralCharacteristics.removeValue(forKey: id)
    peripheralReadValues.removeValue(forKey: id)
    activePeripheral = nil
    pumpConnectQueue()
  }

  func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
    cancelConnectWatchdog()
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
    guard let services = peripheral.services,
      let svc = services.first(where: { $0.uuid == discoveryServiceUUID })
    else {
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

    // v2: B003 failure keeps detection flow alive (null detectedDisplayId).
    // B002/B004 failure drops the detection.
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

  // v2 has no writable characteristics. Reject all writes.
  func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
    for request in requests {
      peripheral.respond(to: request, withResult: .writeNotPermitted)
    }
    emitDebug(level: "warn", name: "gatt_write_rejected", data: [
      "count": requests.count,
    ])
  }
}
