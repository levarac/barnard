import Foundation
import React

@objc(Barnard)
class Barnard: RCTEventEmitter {
  private var controller: BarnardBleController?
  private var hasListeners = false

  override init() {
    super.init()
    setupController()
  }

  private func setupController() {
    let ctrl = BarnardBleController()

    ctrl.onEvent = { [weak self] eventName, payload in
      guard let self = self, self.hasListeners else { return }
      self.sendEvent(withName: eventName, body: payload)
    }

    ctrl.onDebugEvent = { [weak self] eventName, payload in
      guard let self = self, self.hasListeners else { return }
      self.sendEvent(withName: eventName, body: payload)
    }

    controller = ctrl
  }

  override func supportedEvents() -> [String]! {
    return [
      "BarnardDetection",
      "BarnardRssiUpdate",
      "BarnardState",
      "BarnardConstraint",
      "BarnardError",
      "BarnardDebug"
    ]
  }

  override func startObserving() {
    hasListeners = true
  }

  override func stopObserving() {
    hasListeners = false
  }

  override static func requiresMainQueueSetup() -> Bool {
    return false
  }

  @objc
  func getCapabilities(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getCapabilities())
  }

  @objc
  func getState(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getState())
  }

  @objc
  func getPermissionStatus(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getPermissionStatus())
  }

  @objc
  func requestPermissions(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    controller.requestPermissions { payload in
      resolve(payload)
    }
  }

  @objc
  func openAppSettings(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    controller.openAppSettings()
    resolve(nil)
  }

  @objc
  func configure(
    _ config: NSDictionary?,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    let modeName = config?["eninMode"] as? String
    let mode: BarnardCrypto.EninMode = modeName == "beaconSlot" ? .beaconSlot : .fixedLength
    let eninSeconds = (config?["eninSeconds"] as? NSNumber)?.intValue ?? 300
    let beaconMap = config?["beaconChain"] as? NSDictionary
    let beaconChain = BarnardCrypto.BeaconChainConfig(
      chainId: beaconMap?["chainId"] as? String ?? "mainnet",
      genesisUnixSeconds: (beaconMap?["genesisUnixSeconds"] as? NSNumber)?.intValue ?? 1_606_824_023,
      slotSeconds: (beaconMap?["slotSeconds"] as? NSNumber)?.intValue ?? 12
    )
    controller.configure(
      eninMode: mode,
      eninSeconds: eninSeconds,
      beaconChain: beaconChain,
      eventCode: config?["eventCode"] as? String
    )
    resolve(nil)
  }

  // v2 API

  @objc
  func getCurrentEventCode(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getCurrentEventCode())
  }

  @objc
  func getMyDisplayId(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getMyDisplayId())
  }

  @objc
  func getCurrentRpi(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getCurrentRpi())
  }

  @objc
  func getCurrentEnin(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getCurrentEnin())
  }

  @objc
  func exportCurrentTek(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.exportCurrentTek())
  }

  @objc
  func startScan(
    _ config: NSDictionary?,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    let allowDuplicates = config?["allowDuplicates"] as? Bool ?? true
    controller.startScan(allowDuplicates: allowDuplicates)
    resolve(nil)
  }

  @objc
  func stopScan(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    controller.stopScan()
    resolve(nil)
  }

  @objc
  func startAdvertise(
    _ config: NSDictionary?,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    let formatVersion = config?["formatVersion"] as? Int ?? 1
    controller.startAdvertise(formatVersion: formatVersion)
    resolve(nil)
  }

  @objc
  func stopAdvertise(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    controller.stopAdvertise()
    resolve(nil)
  }

  @objc
  func startAuto(
    _ config: NSDictionary?,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }

    var allowDuplicates = true
    var formatVersion = 1

    if let scan = config?["scan"] as? NSDictionary {
      allowDuplicates = scan["allowDuplicates"] as? Bool ?? true
    }

    if let advertise = config?["advertise"] as? NSDictionary {
      formatVersion = advertise["formatVersion"] as? Int ?? 1
    }

    let wasScanning = controller.getState()["isScanning"] as? Bool ?? false
    let wasAdvertising = controller.getState()["isAdvertising"] as? Bool ?? false

    controller.startScan(allowDuplicates: allowDuplicates)
    controller.startAdvertise(formatVersion: formatVersion)

    let nowScanning = controller.getState()["isScanning"] as? Bool ?? false
    let nowAdvertising = controller.getState()["isAdvertising"] as? Bool ?? false

    let result: [String: Any] = [
      "scanningStarted": !wasScanning && nowScanning,
      "advertisingStarted": !wasAdvertising && nowAdvertising,
      "issues": []
    ]

    resolve(result)
  }

  @objc
  func stopAuto(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    controller.stopScan()
    controller.stopAdvertise()
    resolve(nil)
  }

  @objc
  func joinEvent(
    _ eventCode: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    guard !eventCode.isEmpty else {
      reject("E_INVALID_ARGUMENT", "eventCode required", nil)
      return
    }
    controller.joinEvent(eventCode)
    resolve(nil)
  }

  @objc
  func leaveEvent(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    controller.leaveEvent()
    resolve(nil)
  }

  @objc
  func dispose(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    controller?.dispose()
    controller = nil
    resolve(nil)
  }
}
