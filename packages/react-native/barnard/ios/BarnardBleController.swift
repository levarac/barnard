import CoreBluetooth
import Foundation

final class BarnardBleController: NSObject {
  private let discoveryServiceUUID = CBUUID(string: "0000B001-0000-1000-8000-00805F9B34FB")
  private let rpidCharacteristicUUID = CBUUID(string: "0000B002-0000-1000-8000-00805F9B34FB")
  private let tekCharacteristicUUID = CBUUID(string: "0000B003-0000-1000-8000-00805F9B34FB")
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
  private let tekStorage = BarnardTekStorage()

  private var centralManager: CBCentralManager!
  private var peripheralManager: CBPeripheralManager!

  private var rpidCharacteristic: CBMutableCharacteristic?
  private var tekCharacteristic: CBMutableCharacteristic?
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

  private var peripheralCharacteristics: [UUID: [CBUUID: CBCharacteristic]] = [:]
  private var peripheralReadValues: [UUID: PeripheralGattValues] = [:]

  private struct PeripheralGattValues {
    var eventCodeHash: Data?
    var rpid: Data?
    var tek: Data?
  }

  var onEvent: ((String, [String: Any]) -> Void)?
  var onDebugEvent: ((String, [String: Any]) -> Void)?

  override init() {
    super.init()
    centralManager = CBCentralManager(delegate: self, queue: nil)
    peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
  }

  func dispose() {
    stopScan()
    stopAdvertise()
    onEvent = nil
    onDebugEvent = nil
  }

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
      "eventMode": rpid.isEventMode ? "event" : "anonymous",
      "eventCode": rpid.eventCode as Any,
    ]
  }

  func getEventMode() -> [String: Any] {
    [
      "mode": rpid.isEventMode ? "event" : "anonymous",
      "eventCode": rpid.eventCode as Any,
    ]
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

    emitState(reasonCode: "scan_stop")
    emitDebug(level: "info", name: "scan_stop", data: nil)
  }

  func startAdvertise(formatVersion: Int) {
    self.formatVersion = UInt8(clamping: formatVersion)
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
    emitDebug(level: "info", name: "advertise_start", data: [
      "formatVersion": Int(formatVersion),
      "serviceUuid": discoveryServiceUUID.uuidString,
      "localName": debugLocalName,
      "eventMode": rpid.isEventMode,
    ])
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
      "displayId": rpid.getCurrentDisplayId(),
    ])
  }

  func leaveEvent() {
    rpid.leaveEvent()
    rebuildGattServiceIfNeeded()
    emitState(reasonCode: "leave_event")
    emitDebug(level: "info", name: "leave_event", data: nil)
  }

  func getExchangedTeks(eventCode: String) -> [[String: Any]] {
    let eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
    let entries = tekStorage.getEntries(for: eventCodeHash)
    return entries.map { $0.toDict() }
  }

  func clearTeksForEvent(eventCode: String) -> Int {
    let eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode)
    let count = tekStorage.clear(for: eventCodeHash)
    emitDebug(level: "info", name: "clear_teks_for_event", data: [
      "eventCode": eventCode,
      "count": count,
    ])
    return count
  }

  func clearAllTeks() -> Int {
    let count = tekStorage.clearAll()
    emitDebug(level: "info", name: "clear_all_teks", data: ["count": count])
    return count
  }

  private func ensureGattService() {
    if rpidCharacteristic != nil { return }
    buildAndAddGattService()
  }

  private func rebuildGattServiceIfNeeded() {
    guard peripheralManager.state == .poweredOn else { return }

    peripheralManager.removeAllServices()
    rpidCharacteristic = nil
    tekCharacteristic = nil
    eventCodeHashCharacteristic = nil

    buildAndAddGattService()

    emitDebug(level: "info", name: "gatt_service_rebuilt", data: [
      "eventMode": rpid.isEventMode,
    ])
  }

  private func buildAndAddGattService() {
    let rpidCh = CBMutableCharacteristic(
      type: rpidCharacteristicUUID,
      properties: [.read],
      value: nil,
      permissions: [.readable]
    )

    let tekCh = CBMutableCharacteristic(
      type: tekCharacteristicUUID,
      properties: [.read, .write],
      value: nil,
      permissions: [.readable, .writeable]
    )

    let eventCodeHashCh = CBMutableCharacteristic(
      type: eventCodeHashCharacteristicUUID,
      properties: [.read],
      value: nil,
      permissions: [.readable]
    )

    let svc = CBMutableService(type: discoveryServiceUUID, primary: true)
    svc.characteristics = [rpidCh, tekCh, eventCodeHashCh]
    peripheralManager.add(svc)

    rpidCharacteristic = rpidCh
    tekCharacteristic = tekCh
    eventCodeHashCharacteristic = eventCodeHashCh

    emitDebug(level: "info", name: "gatt_service_added", data: [
      "characteristics": ["RPID", "TEK", "EventCodeHash"],
    ])
  }

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

    guard let peripheral = peripheralsById[nextId] else {
      connectQueue.removeFirst()
      return
    }

    connectQueue.removeFirst()
    activePeripheral = peripheral
    lastConnectAttemptAt[nextId] = now

    peripheralReadValues[nextId] = PeripheralGattValues()

    peripheral.delegate = self
    centralManager.connect(peripheral, options: nil)
    emitDebug(level: "trace", name: "connect_attempt", data: ["id": nextId.uuidString])
  }

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

  private func readTekCharacteristic(for peripheral: CBPeripheral) {
    let id = peripheral.identifier
    guard let charMap = peripheralCharacteristics[id],
      let tekCh = charMap[tekCharacteristicUUID]
    else {
      completeGattExchange(for: peripheral)
      return
    }
    peripheral.readValue(for: tekCh)
  }

  private func writeTekCharacteristic(for peripheral: CBPeripheral) {
    let id = peripheral.identifier
    guard let charMap = peripheralCharacteristics[id],
      let tekCh = charMap[tekCharacteristicUUID]
    else {
      completeGattExchange(for: peripheral)
      return
    }

    let myTek = rpid.getCurrentTek()
    peripheral.writeValue(myTek, for: tekCh, type: .withResponse)
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
      emitDetection(
        timestamp: ts,
        rssi: rssi,
        payload: rpidData,
        resolvedTek: values.tek,
        debugLocalName: lastDiscoveryNameById[id]
      )
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

  private func shouldExchangeTek(remoteEventCodeHash: Data?) -> Bool {
    guard rpid.isEventMode else { return false }
    guard let remoteHash = remoteEventCodeHash, !remoteHash.isEmpty else { return false }

    let myHash = rpid.getEventCodeHash()
    return myHash == remoteHash
  }

  private func emitState(reasonCode: String?) {
    var payload: [String: Any] = [
      "type": "state",
      "timestamp": iso8601.string(from: Date()),
      "state": [
        "isScanning": isScanning,
        "isAdvertising": isAdvertising,
        "eventMode": rpid.isEventMode ? "event" : "anonymous",
        "eventCode": rpid.eventCode as Any,
      ],
    ]
    if let rc = reasonCode {
      payload["reasonCode"] = rc
    }
    onEvent?("BarnardState", payload)
  }

  private func emitConstraint(code: String, message: String?) {
    var payload: [String: Any] = [
      "type": "constraint",
      "timestamp": iso8601.string(from: Date()),
      "code": code,
      "requiredAction": NSNull(),
    ]
    if let msg = message {
      payload["message"] = msg
    }
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
    resolvedTek: Data? = nil,
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

    let rpidBytes = payload.subdata(in: 1 ..< 17)
    let displayId = rpidBytes.prefix(4).map { String(format: "%02x", $0) }.joined()

    var resolvedTekToEmit: Data? = resolvedTek
    var resolvedDisplayId: String?

    if resolvedTekToEmit == nil, rpid.isEventMode {
      let eventCodeHash = rpid.getEventCodeHash()
      let knownTeks = tekStorage.getTeks(for: eventCodeHash)

      if let matched = BarnardCrypto.resolveRpi(rpidBytes, knownTeks: knownTeks) {
        resolvedTekToEmit = matched
        tekStorage.updateLastSeen(tek: matched, eventCodeHash: eventCodeHash)
      }
    }

    if let tek = resolvedTekToEmit {
      resolvedDisplayId = BarnardCrypto.displayId(from: tek)
    }

    var eventPayload: [String: Any] = [
      "type": "detection",
      "timestamp": iso8601.string(from: timestamp),
      "transport": "ble",
      "formatVersion": version,
      "rpid": rpidBytes.base64EncodedString(),
      "displayId": displayId,
      "rssi": rssi,
      "rssiSummary": NSNull(),
      "payloadRaw": payload.base64EncodedString(),
    ]

    if let tek = resolvedTekToEmit {
      eventPayload["resolvedTek"] = tek.base64EncodedString()
    }
    if let dispId = resolvedDisplayId {
      eventPayload["resolvedDisplayId"] = dispId
    }
    #if DEBUG
    if let name = debugLocalName {
      eventPayload["debugLocalName"] = name
    }
    #endif

    onEvent?("BarnardDetection", eventPayload)
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
}

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

    enqueueConnect(peripheral)
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
      [rpidCharacteristicUUID, tekCharacteristicUUID, eventCodeHashCharacteristicUUID],
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

    if let error = error {
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
      let remoteHash = peripheralReadValues[id]?.eventCodeHash
      if shouldExchangeTek(remoteEventCodeHash: remoteHash) {
        readTekCharacteristic(for: peripheral)
      } else {
        completeGattExchange(for: peripheral)
      }

    case tekCharacteristicUUID:
      peripheralReadValues[id]?.tek = value
      emitDebug(level: "trace", name: "gatt_read_tek", data: [
        "id": id.uuidString,
        "bytes": value.count,
      ])

      if value.count == 16,
        let remoteHash = peripheralReadValues[id]?.eventCodeHash,
        remoteHash.count == 8
      {
        let entry = TekEntry(
          tek: value,
          eventCodeHash: remoteHash,
          exchangedAt: Date(),
          lastSeenAt: Date()
        )
        tekStorage.store(entry: entry)
        emitDebug(level: "info", name: "tek_received", data: [
          "displayId": BarnardCrypto.displayId(from: value),
        ])
      }

      writeTekCharacteristic(for: peripheral)

    default:
      break
    }
  }

  func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
    if let error = error {
      emitError(code: "write_failed", message: error.localizedDescription, recoverable: true)
    } else {
      emitDebug(level: "trace", name: "gatt_write_tek", data: [
        "id": peripheral.identifier.uuidString,
        "displayId": rpid.getCurrentDisplayId(),
      ])
    }
    completeGattExchange(for: peripheral)
  }
}

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

      var displayId = ""
      if payload.count >= 5 {
        let bytes = payload.subdata(in: 1 ..< 5)
        displayId = bytes.map { String(format: "%02x", $0) }.joined()
      }
      emitDebug(level: "trace", name: "gatt_read_rpid", data: [
        "bytes": payload.count,
        "formatVersion": Int(formatVersion),
        "displayId": displayId,
      ])

    case tekCharacteristicUUID:
      if rpid.isEventMode {
        let tekData = rpid.getCurrentTek()
        request.value = tekData
        peripheral.respond(to: request, withResult: .success)
        emitDebug(level: "trace", name: "gatt_respond_tek_read", data: [
          "displayId": rpid.getCurrentDisplayId(),
        ])
      } else {
        peripheral.respond(to: request, withResult: .readNotPermitted)
        emitDebug(level: "trace", name: "gatt_reject_tek_read", data: [
          "reason": "anonymous_mode",
        ])
      }

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

  func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
    for request in requests {
      guard request.characteristic.uuid == tekCharacteristicUUID else {
        peripheral.respond(to: request, withResult: .writeNotPermitted)
        continue
      }

      guard let value = request.value, value.count == 16 else {
        peripheral.respond(to: request, withResult: .invalidAttributeValueLength)
        continue
      }

      guard rpid.isEventMode else {
        peripheral.respond(to: request, withResult: .writeNotPermitted)
        emitDebug(level: "trace", name: "gatt_reject_tek_write", data: [
          "reason": "anonymous_mode",
        ])
        continue
      }

      let eventCodeHash = rpid.getEventCodeHash()
      let entry = TekEntry(
        tek: value,
        eventCodeHash: eventCodeHash,
        exchangedAt: Date(),
        lastSeenAt: Date()
      )
      tekStorage.store(entry: entry)

      peripheral.respond(to: request, withResult: .success)
      emitDebug(level: "info", name: "tek_received_via_write", data: [
        "displayId": BarnardCrypto.displayId(from: value),
      ])
    }
  }
}
