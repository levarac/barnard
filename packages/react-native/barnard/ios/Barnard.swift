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
  func getEventMode(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.getEventMode())
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
  func getExchangedTeks(
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
    resolve(controller.getExchangedTeks(eventCode: eventCode))
  }

  @objc
  func clearTeksForEvent(
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
    resolve(controller.clearTeksForEvent(eventCode: eventCode))
  }

  @objc
  func clearAllTeks(
    _ resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) {
    guard let controller = controller else {
      reject("E_NOT_INITIALIZED", "Controller not initialized", nil)
      return
    }
    resolve(controller.clearAllTeks())
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
