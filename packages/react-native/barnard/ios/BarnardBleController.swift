// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import CoreBluetooth
import Foundation
import UIKit

/// Barnard v2 BLE controller (React Native bridge variant).
///
/// - B002 RPID (Read, 17 bytes)
/// - B003 displayId (Read, 4 bytes when joined to an event) — SHA256(TEK)[0:4]
/// - B004 EventCodeHash (Read, 0 or 8 bytes)
///
/// TEK is never transmitted over BLE in v2.
final class BarnardBleController: NSObject {
  private let discoveryServiceUUID = CBUUID(string: "0000B001-0000-1000-8000-00805F9B34FB")
  private let rpidCharacteristicUUID = CBUUID(string: "0000B002-0000-1000-8000-00805F9B34FB")
  private let displayIdCharacteristicUUID = CBUUID(string: "0000B003-0000-1000-8000-00805F9B34FB")
  private let eventCodeHashCharacteristicUUID = CBUUID(string: "0000B004-0000-1000-8000-00805F9B34FB")
  private let localName = "BNRD"
  private let unavailableRssi = 127

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

  private var centralManager: CBCentralManager?
  private var peripheralManager: CBPeripheralManager?
  private var pendingPermissionCompletions: [([String: Any]) -> Void] = []

  private var rpidCharacteristic: CBMutableCharacteristic?
  private var displayIdCharacteristic: CBMutableCharacteristic?
  private var eventCodeHashCharacteristic: CBMutableCharacteristic?

  private var isScanning = false
  private var isAdvertising = false
  private var shouldStartScanWhenReady = false
  private var shouldStartAdvertiseWhenReady = false
  private var allowDuplicates = true
  private var formatVersion: UInt8 = 1

  private var lastDiscoveryNameById: [UUID: String] = [:]

  private var discoveredRssi: [UUID: Int] = [:]
  private var discoveredAt: [UUID: Date] = [:]

  private var connectQueue: [UUID] = []
  private var peripheralsById: [UUID: CBPeripheral] = [:]
  private var lastConnectAttemptAt: [UUID: Date] = [:]
  private var resolutionBackoffUntil: [UUID: Date] = [:]
  private var activePeripheral: CBPeripheral?

  private let maxConcurrentConnections = 1
  private let cooldownPerPeerSeconds: TimeInterval = 10
  private let resolutionFailureBackoffSeconds: TimeInterval = 30
  private let resolutionRejectedBackoffSeconds: TimeInterval = 5 * 60
  private let maxConnectQueue = 20
  // See Flutter variant: CoreBluetooth's `connect()` has no deadline, so a
  // hung connection pins `activePeripheral` forever and starves the queue.
  private let connectTimeoutSeconds: TimeInterval = 8
  private var connectWatchdog: DispatchWorkItem?
  private var connectCooldownWorkItem: DispatchWorkItem?

  private var peripheralCharacteristics: [UUID: [CBUUID: CBCharacteristic]] = [:]
  private var peripheralReadValues: [UUID: PeripheralGattValues] = [:]
  private var b004ReadRetries: [UUID: Int] = [:]
  private let maxB004ReadRetries = 2
  private let b004ReadRetryDelaySeconds: TimeInterval = 0.25

  private struct PeripheralGattValues {
    var eventCodeHash: Data?
    var rpid: Data?
    var detectedDisplayId: Data?
  }

  private struct KnownPeer {
    let rpid: Data
    let enin: UInt32
    var detectedDisplayId: String?
  }

  private var knownPeers: [UUID: KnownPeer] = [:]

  private func shouldServeGattDisplayId() -> Bool {
    BarnardV2Policy.shouldServeGattDisplayId(eventCode: rpid.eventCode)
  }

  /// Event callback. `eventName` is one of: BarnardDetection, BarnardState,
  /// BarnardConstraint, BarnardError, BarnardRssiUpdate.
  var onEvent: ((String, [String: Any]) -> Void)?
  /// Debug event callback. `eventName` is always "BarnardDebug".
  var onDebugEvent: ((String, [String: Any]) -> Void)?

  override init() {
    super.init()

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

  private func ensureCentralManager() -> CBCentralManager {
    if let manager = centralManager {
      return manager
    }
    let manager = CBCentralManager(delegate: self, queue: nil)
    centralManager = manager
    return manager
  }

  private func ensurePeripheralManager() -> CBPeripheralManager {
    if let manager = peripheralManager {
      return manager
    }
    let manager = CBPeripheralManager(delegate: self, queue: nil)
    peripheralManager = manager
    return manager
  }

  private func ensureBleManagers() {
    _ = ensureCentralManager()
    _ = ensurePeripheralManager()
  }

  private func bluetoothPermissionStatus() -> String {
    switch CBManager.authorization {
    case .allowedAlways:
      return "granted"
    case .denied:
      return "denied"
    case .restricted:
      return "restricted"
    case .notDetermined:
      return "notDetermined"
    @unknown default:
      return "unknown"
    }
  }

  func getPermissionStatus() -> [String: Any] {
    let permissionName = "ios.bluetooth"
    let status = bluetoothPermissionStatus()
    let missing = status == "granted" ? [] : [permissionName]
    let blocked = (status == "denied" || status == "restricted") ? [permissionName] : []
    let requestable = missing.filter { !blocked.contains($0) }
    return [
      "platform": "ios",
      "permissions": [permissionName: status],
      "requiredPermissions": [permissionName],
      "missingPermissions": missing,
      "requestablePermissions": requestable,
      "blockedPermissions": blocked,
      "canScan": status == "granted",
      "canAdvertise": status == "granted",
    ]
  }

  func requestPermissions(completion: @escaping ([String: Any]) -> Void) {
    if bluetoothPermissionStatus() != "notDetermined" {
      completion(getPermissionStatus())
      return
    }

    pendingPermissionCompletions.append(completion)
    ensureBleManagers()
    resolvePendingPermissionCompletionsIfPossible()
  }

  private func resolvePendingPermissionCompletionsIfPossible() {
    guard !pendingPermissionCompletions.isEmpty else { return }
    guard bluetoothPermissionStatus() != "notDetermined" else { return }

    let payload = getPermissionStatus()
    let completions = pendingPermissionCompletions
    pendingPermissionCompletions.removeAll()
    for completion in completions {
      completion(payload)
    }
  }

  func openAppSettings() {
    guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
    DispatchQueue.main.async {
      UIApplication.shared.open(url)
    }
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
    peripheralManager?.stopAdvertising()
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
    let manager = ensureCentralManager()
    self.allowDuplicates = allowDuplicates
    if isScanning {
      shouldStartScanWhenReady = false
      return
    }
    guard manager.state == .poweredOn else {
      if manager.state == .unknown || manager.state == .resetting {
        shouldStartScanWhenReady = true
        emitDebug(level: "info", name: "scan_waiting_for_powered_on", data: [
          "state": manager.state.rawValue,
        ])
      } else {
        shouldStartScanWhenReady = false
        emitConstraint(code: "bluetooth_not_ready", message: "CentralManager state=\(manager.state.rawValue)")
      }
      return
    }
    shouldStartScanWhenReady = false
    let options: [String: Any] = [CBCentralManagerScanOptionAllowDuplicatesKey: allowDuplicates]
    manager.scanForPeripherals(withServices: [discoveryServiceUUID], options: options)
    isScanning = true
    emitState(reasonCode: "scan_start")
    emitDebug(level: "info", name: "scan_start", data: ["allowDuplicates": allowDuplicates])
  }

  func stopScan() {
    shouldStartScanWhenReady = false
    if !isScanning { return }
    centralManager?.stopScan()
    isScanning = false
    resetPeerDiscoveryState(reason: "scan_stop")

    emitState(reasonCode: "scan_stop")
    emitDebug(level: "info", name: "scan_stop", data: nil)
  }

  private func resetPeerDiscoveryState(reason: String) {
    connectQueue.removeAll()
    if let active = activePeripheral {
      centralManager?.cancelPeripheralConnection(active)
    }
    activePeripheral = nil
    cancelConnectWatchdog()
    cancelConnectCooldownWorkItem()

    discoveredRssi.removeAll()
    discoveredAt.removeAll()
    peripheralsById.removeAll()
    lastConnectAttemptAt.removeAll()
    resolutionBackoffUntil.removeAll()
    peripheralCharacteristics.removeAll()
    peripheralReadValues.removeAll()
    b004ReadRetries.removeAll()
    lastDiscoveryNameById.removeAll()
    knownPeers.removeAll()

    emitDebug(level: "info", name: "peer_cache_reset", data: ["reason": reason])
  }

  func startAdvertise(formatVersion: Int) {
    let manager = ensurePeripheralManager()
    self.formatVersion = acceptFormatVersion(formatVersion)
    if isAdvertising {
      shouldStartAdvertiseWhenReady = false
      return
    }
    guard manager.state == .poweredOn else {
      if manager.state == .unknown || manager.state == .resetting {
        shouldStartAdvertiseWhenReady = true
        emitDebug(level: "info", name: "advertise_waiting_for_powered_on", data: [
          "state": manager.state.rawValue,
        ])
      } else {
        shouldStartAdvertiseWhenReady = false
        emitConstraint(code: "bluetooth_not_ready", message: "PeripheralManager state=\(manager.state.rawValue)")
      }
      return
    }
    shouldStartAdvertiseWhenReady = false
    ensureGattService()
    var ad: [String: Any] = [
      CBAdvertisementDataServiceUUIDsKey: [discoveryServiceUUID],
    ]
    #if DEBUG
    ad[CBAdvertisementDataLocalNameKey] = debugLocalName
    #endif
    manager.startAdvertising(ad)
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
    shouldStartAdvertiseWhenReady = false
    if !isAdvertising { return }
    peripheralManager?.stopAdvertising()
    isAdvertising = false
    emitState(reasonCode: "advertise_stop")
    emitDebug(level: "info", name: "advertise_stop", data: nil)
  }

  func joinEvent(_ eventCode: String) {
    resetPeerDiscoveryState(reason: "join_event")
    rpid.joinEvent(eventCode)
    rebuildGattServiceIfNeeded()
    emitState(reasonCode: "join_event")
    emitDebug(level: "info", name: "join_event", data: [
      "eventCode": eventCode,
      "myDisplayId": rpid.getCurrentDisplayId(),
    ])
  }

  func leaveEvent() {
    resetPeerDiscoveryState(reason: "leave_event")
    rpid.leaveEvent()
    rebuildGattServiceIfNeeded()
    emitState(reasonCode: "leave_event")
    emitDebug(level: "info", name: "leave_event", data: nil)
  }

  // MARK: - GATT Service Management

  private func ensureGattService() {
    _ = ensurePeripheralManager()
    if rpidCharacteristic != nil { return }
    buildAndAddGattService()
  }

  private func rebuildGattServiceIfNeeded() {
    guard let manager = peripheralManager, manager.state == .poweredOn else { return }

    manager.removeAllServices()
    rpidCharacteristic = nil
    displayIdCharacteristic = nil
    eventCodeHashCharacteristic = nil

    buildAndAddGattService()

    emitDebug(level: "info", name: "gatt_service_rebuilt", data: nil)
  }

  private func buildAndAddGattService() {
    guard let manager = peripheralManager else { return }

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
    manager.add(svc)

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

    let now = Date()
    if isResolutionBackedOff(id, now: now) {
      emitResolutionBackoff(id, now: now)
      return
    }

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
    if let last = lastConnectAttemptAt[nextId] {
      let remaining = cooldownPerPeerSeconds - now.timeIntervalSince(last)
      if remaining > 0 {
        connectQueue.removeFirst()
        connectQueue.append(nextId)
        scheduleConnectQueuePump(after: remaining)
        return
      }
    }

    guard let p = peripheralsById[nextId] else {
      connectQueue.removeFirst()
      return
    }
    guard let manager = centralManager else { return }

    connectQueue.removeFirst()
    activePeripheral = p
    lastConnectAttemptAt[nextId] = now

    peripheralReadValues[nextId] = PeripheralGattValues()
    b004ReadRetries[nextId] = 0

    p.delegate = self
    manager.connect(p, options: nil)
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
      self.markGattResolutionFailed(
        id,
        reason: "connect_timeout",
        recoverable: true,
        extra: ["seconds": self.connectTimeoutSeconds]
      )
      self.centralManager?.cancelPeripheralConnection(pinned)
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

  private func scheduleConnectQueuePump(after delay: TimeInterval) {
    guard connectCooldownWorkItem == nil else { return }
    let work = DispatchWorkItem { [weak self] in
      guard let self = self else { return }
      self.connectCooldownWorkItem = nil
      self.pumpConnectQueue()
    }
    connectCooldownWorkItem = work
    DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: work)
  }

  private func cancelConnectCooldownWorkItem() {
    connectCooldownWorkItem?.cancel()
    connectCooldownWorkItem = nil
  }

  private func isResolutionBackedOff(_ id: UUID, now: Date) -> Bool {
    guard let until = resolutionBackoffUntil[id] else { return false }
    if now < until { return true }
    resolutionBackoffUntil.removeValue(forKey: id)
    return false
  }

  private func emitResolutionBackoff(_ id: UUID, now: Date) {
    guard let until = resolutionBackoffUntil[id] else { return }
    emitDebug(level: "trace", name: "gatt_resolution_backoff", data: [
      "id": id.uuidString,
      "remainingMs": max(0, Int(until.timeIntervalSince(now) * 1000)),
    ])
  }

  private func markGattResolutionFailed(
    _ id: UUID,
    reason: String,
    recoverable: Bool,
    extra: [String: Any] = [:]
  ) {
    let backoffSeconds = recoverable ? resolutionFailureBackoffSeconds : resolutionRejectedBackoffSeconds
    resolutionBackoffUntil[id] = Date().addingTimeInterval(backoffSeconds)
    var data: [String: Any] = [
      "id": id.uuidString,
      "reason": reason,
      "recoverable": recoverable,
      "backoffMs": Int(backoffSeconds * 1000),
    ]
    for (key, value) in extra {
      data[key] = value
    }
    emitDebug(
      level: recoverable ? "warn" : "info",
      name: "gatt_resolution_failed",
      data: data
    )
  }

  // MARK: - GATT Exchange (Central, v2 flow: B004 -> B002 -> B003)

  private func startGattExchange(for peripheral: CBPeripheral, service: CBService) {
    let id = peripheral.identifier
    var charMap: [CBUUID: CBCharacteristic] = [:]

    guard let characteristics = service.characteristics else {
      markGattResolutionFailed(id, reason: "characteristics_missing", recoverable: true)
      finishConnection(peripheral)
      return
    }

    for ch in characteristics {
      charMap[ch.uuid] = ch
    }
    peripheralCharacteristics[id] = charMap

    guard let eventCodeHashCh = charMap[eventCodeHashCharacteristicUUID] else {
      markGattResolutionFailed(id, reason: "b004_missing", recoverable: true)
      emitDebug(level: "warn", name: "gatt_b004_missing", data: [
        "id": id.uuidString,
      ])
      finishConnection(peripheral)
      return
    }
    peripheral.readValue(for: eventCodeHashCh)
  }

  private func eventCodeHashMatches(_ peerHash: Data) -> Bool {
    peerHash == rpid.getEventCodeHash()
  }

  private func readRpidCharacteristic(for peripheral: CBPeripheral) {
    let id = peripheral.identifier
    guard let charMap = peripheralCharacteristics[id],
      let rpidCh = charMap[rpidCharacteristicUUID]
    else {
      markGattResolutionFailed(id, reason: "b002_missing", recoverable: true)
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
        let peerEnin = BarnardCrypto.calculateEnin(for: ts)
        knownPeers[id] = KnownPeer(
          rpid: rpidData,
          enin: peerEnin,
          detectedDisplayId: detectedDisplayId
        )
        resolutionBackoffUntil.removeValue(forKey: id)
      }
    }

    finishConnection(peripheral)
  }

  private func finishConnection(_ peripheral: CBPeripheral) {
    let id = peripheral.identifier
    peripheralCharacteristics.removeValue(forKey: id)
    peripheralReadValues.removeValue(forKey: id)
    b004ReadRetries.removeValue(forKey: id)
    lastDiscoveryNameById.removeValue(forKey: id)
    centralManager?.cancelPeripheralConnection(peripheral)
  }

  private func characteristicName(_ uuid: CBUUID) -> String {
    switch uuid {
    case rpidCharacteristicUUID:
      return "B002_RPID"
    case displayIdCharacteristicUUID:
      return "B003_displayId"
    case eventCodeHashCharacteristicUUID:
      return "B004_eventCodeHash"
    default:
      return uuid.uuidString
    }
  }

  private func respondRead(
    _ peripheral: CBPeripheralManager,
    request: CBATTRequest,
    value: Data,
    debugName: String,
    debugData: [String: Any] = [:]
  ) {
    guard request.offset <= value.count else {
      peripheral.respond(to: request, withResult: .invalidOffset)
      emitDebug(level: "warn", name: "\(debugName)_invalid_offset", data: [
        "offset": request.offset,
        "bytes": value.count,
      ])
      return
    }
    request.value = value.subdata(in: request.offset..<value.count)
    peripheral.respond(to: request, withResult: .success)
    var data = debugData
    data["bytes"] = value.count
    data["offset"] = request.offset
    emitDebug(level: "trace", name: debugName, data: data)
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
    guard isUsableRssi(rssi) else { return }
    guard let peer = knownPeers[peripheralId] else { return }

    // Atomic reporter snapshot (same contract as DetectionEvent).
    let reporterPayload = rpid.currentPayload(formatVersion: formatVersion, now: timestamp)
    let enin = Int(BarnardCrypto.calculateEnin(for: timestamp))

    var eventPayload: [String: Any] = [
      "type": "rssi_update",
      "timestamp": iso8601.string(from: timestamp),
      "rpid": peer.rpid.hexString,
      "reporterRpid": reporterPayload.hexString,
      "enin": enin,
      "rssi": rssi,
    ]

    if let detectedId = peer.detectedDisplayId {
      eventPayload["detectedDisplayId"] = detectedId
    }

    onEvent?("BarnardRssiUpdate", eventPayload)
  }

  private func isUsableRssi(_ rssi: Int) -> Bool {
    rssi != unavailableRssi
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
    resolvePendingPermissionCompletionsIfPossible()
    emitDebug(level: "info", name: "central_state", data: ["state": central.state.rawValue])
    if central.state == .poweredOn, shouldStartScanWhenReady {
      startScan(allowDuplicates: allowDuplicates)
    } else if central.state != .poweredOn, isScanning {
      stopScan()
    }
  }

  func centralManager(
    _ central: CBCentralManager,
    didDiscover peripheral: CBPeripheral,
    advertisementData: [String: Any],
    rssi RSSI: NSNumber
  ) {
    let rssi = RSSI.intValue
    guard isUsableRssi(rssi) else {
      emitDebug(level: "trace", name: "ble_discovery_rssi_unavailable", data: [
        "id": peripheral.identifier.uuidString,
        "rssi": rssi,
        "name": (advertisementData[CBAdvertisementDataLocalNameKey] as? String) as Any,
      ])
      return
    }
    let now = Date()
    discoveredRssi[peripheral.identifier] = rssi
    discoveredAt[peripheral.identifier] = now

    emitDebug(level: "trace", name: "ble_discovery_result", data: [
      "id": peripheral.identifier.uuidString,
      "rssi": rssi,
      "name": (advertisementData[CBAdvertisementDataLocalNameKey] as? String) as Any,
    ])

    #if DEBUG
    if let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String, !name.isEmpty {
      lastDiscoveryNameById[peripheral.identifier] = name
    }
    #endif

    if let knownPeer = knownPeers[peripheral.identifier] {
      let currentEnin = BarnardCrypto.calculateEnin(for: now)
      if BarnardV2Policy.KnownPeerWindow(enin: knownPeer.enin).matches(currentEnin) {
        emitRssiUpdate(peripheralId: peripheral.identifier, rssi: rssi, timestamp: now)
      } else {
        knownPeers.removeValue(forKey: peripheral.identifier)
        emitDebug(level: "trace", name: "known_peer_rpid_expired", data: [
          "id": peripheral.identifier.uuidString,
          "cachedEnin": Int(knownPeer.enin),
          "currentEnin": Int(currentEnin),
        ])
        // Force a fresh resolution. enqueueConnect dedups against in-flight /
        // queued connects, so following advertisements on the same identifier
        // remain safe.
        enqueueConnect(peripheral)
      }
    } else if isResolutionBackedOff(peripheral.identifier, now: now) {
      emitResolutionBackoff(peripheral.identifier, now: now)
    } else {
      enqueueConnect(peripheral)
    }
  }

  func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
    guard activePeripheral?.identifier == peripheral.identifier else {
      emitDebug(level: "trace", name: "stale_connect_ignored", data: [
        "id": peripheral.identifier.uuidString,
      ])
      return
    }
    cancelConnectWatchdog()
    emitDebug(level: "trace", name: "connected", data: ["id": peripheral.identifier.uuidString])
    peripheral.discoverServices([discoveryServiceUUID])
  }

  func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
    guard activePeripheral?.identifier == peripheral.identifier else {
      emitDebug(level: "trace", name: "stale_connect_failed_ignored", data: [
        "id": peripheral.identifier.uuidString,
      ])
      return
    }
    cancelConnectWatchdog()
    emitError(code: "connect_failed", message: error?.localizedDescription ?? "unknown", recoverable: true)
    let id = peripheral.identifier
    markGattResolutionFailed(
      id,
      reason: "connect_failed",
      recoverable: true,
      extra: ["error": error?.localizedDescription ?? "unknown"]
    )
    peripheralCharacteristics.removeValue(forKey: id)
    peripheralReadValues.removeValue(forKey: id)
    activePeripheral = nil
    pumpConnectQueue()
  }

  func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
    guard activePeripheral?.identifier == peripheral.identifier else {
      emitDebug(level: "trace", name: "stale_disconnect_ignored", data: [
        "id": peripheral.identifier.uuidString,
      ])
      return
    }
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
      markGattResolutionFailed(
        peripheral.identifier,
        reason: "service_discovery_failed",
        recoverable: true,
        extra: ["error": error.localizedDescription]
      )
      emitError(code: "service_discovery_failed", message: error.localizedDescription, recoverable: true)
      finishConnection(peripheral)
      return
    }
    guard let services = peripheral.services,
      let svc = services.first(where: { $0.uuid == discoveryServiceUUID })
    else {
      markGattResolutionFailed(peripheral.identifier, reason: "service_not_found", recoverable: true)
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
      markGattResolutionFailed(
        peripheral.identifier,
        reason: "characteristic_discovery_failed",
        recoverable: true,
        extra: ["error": error.localizedDescription]
      )
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
      if characteristic.uuid == eventCodeHashCharacteristicUUID {
        let retries = b004ReadRetries[id] ?? 0
        if retries < maxB004ReadRetries {
          b004ReadRetries[id] = retries + 1
          emitDebug(level: "warn", name: "gatt_b004_read_retry", data: [
            "id": id.uuidString,
            "attempt": retries + 1,
            "max": maxB004ReadRetries,
            "error": error.localizedDescription,
          ])
          DispatchQueue.main.asyncAfter(deadline: .now() + b004ReadRetryDelaySeconds) { [weak self, weak peripheral] in
            guard let self = self, let peripheral = peripheral else { return }
            guard self.activePeripheral?.identifier == id else { return }
            peripheral.readValue(for: characteristic)
          }
          return
        }
      }
      let name = characteristicName(characteristic.uuid)
      markGattResolutionFailed(
        id,
        reason: "read_failed",
        recoverable: true,
        extra: [
          "characteristic": name,
          "error": error.localizedDescription,
        ]
      )
      emitDebug(level: "warn", name: "gatt_read_failed", data: [
        "id": id.uuidString,
        "characteristic": name,
        "error": error.localizedDescription,
      ])
      emitError(code: "read_failed", message: "\(name): \(error.localizedDescription)", recoverable: true)
      finishConnection(peripheral)
      return
    }

    let value = characteristic.value ?? Data()

    switch characteristic.uuid {
    case eventCodeHashCharacteristicUUID:
      peripheralReadValues[id]?.eventCodeHash = value
      let matches = eventCodeHashMatches(value)
      emitDebug(level: "trace", name: "gatt_read_event_code_hash", data: [
        "id": id.uuidString,
        "bytes": value.count,
        "isEmpty": value.isEmpty,
        "matches": matches,
      ])
      guard matches else {
        markGattResolutionFailed(
          id,
          reason: "b004_mismatch",
          recoverable: false,
          extra: ["bytes": value.count]
        )
        emitDebug(level: "info", name: "gatt_b004_mismatch", data: [
          "id": id.uuidString,
          "bytes": value.count,
        ])
        finishConnection(peripheral)
        return
      }
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
    resolvePendingPermissionCompletionsIfPossible()
    emitDebug(level: "info", name: "peripheral_state", data: ["state": peripheral.state.rawValue])
    if peripheral.state == .poweredOn, shouldStartAdvertiseWhenReady {
      startAdvertise(formatVersion: Int(formatVersion))
    } else if peripheral.state != .poweredOn, isAdvertising {
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
      respondRead(
        peripheral,
        request: request,
        value: payload,
        debugName: "gatt_respond_rpid",
        debugData: ["formatVersion": Int(formatVersion)]
      )

    case displayIdCharacteristicUUID:
      guard shouldServeGattDisplayId() else {
        peripheral.respond(to: request, withResult: .readNotPermitted)
        emitDebug(level: "trace", name: "gatt_reject_display_id_read", data: [
          "reason": "not_joined_to_event",
        ])
        return
      }

      let displayId = BarnardCrypto.displayId4(from: rpid.getCurrentTek())
      respondRead(
        peripheral,
        request: request,
        value: displayId,
        debugName: "gatt_respond_display_id"
      )

    case eventCodeHashCharacteristicUUID:
      let hash = rpid.getEventCodeHash()
      respondRead(
        peripheral,
        request: request,
        value: hash,
        debugName: "gatt_respond_event_code_hash",
        debugData: ["isEmpty": hash.isEmpty]
      )

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
