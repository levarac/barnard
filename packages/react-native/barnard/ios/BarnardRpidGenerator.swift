import Foundation

final class BarnardRpidGenerator {
  private let deviceSecretKey = "barnard.rpidSeed"
  private let eventCodeKey = "barnard.eventCode"

  private(set) var eventCode: String? {
    didSet {
      if eventCode != oldValue {
        regenerateTek()
      }
    }
  }

  private var currentTek: Data

  init() {
    let defaults = UserDefaults.standard
    eventCode = defaults.string(forKey: eventCodeKey)
    currentTek = Data()
    regenerateTek()
  }

  func joinEvent(_ code: String) {
    let defaults = UserDefaults.standard
    defaults.set(code, forKey: eventCodeKey)
    eventCode = code
  }

  func leaveEvent() {
    let defaults = UserDefaults.standard
    defaults.removeObject(forKey: eventCodeKey)
    eventCode = nil
  }

  var isEventMode: Bool {
    eventCode != nil
  }

  func getCurrentTek() -> Data {
    currentTek
  }

  private func regenerateTek() {
    let deviceSecret = getOrCreateDeviceSecret()
    if let code = eventCode {
      currentTek = BarnardCrypto.deriveTekForEvent(deviceSecret: deviceSecret, eventCode: code)
    } else {
      currentTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret: deviceSecret)
    }
  }

  func getEventCodeHash() -> Data {
    guard let code = eventCode else {
      return Data()
    }
    return BarnardCrypto.computeEventCodeHash(code)
  }

  func currentPayload(formatVersion: UInt8 = 1, now: Date = Date()) -> Data {
    let enin = BarnardCrypto.calculateEnin(for: now)
    let rpik = BarnardCrypto.deriveRpik(from: currentTek)
    let rpi = BarnardCrypto.generateRpi(rpik: rpik, enin: enin)

    var payload = Data([formatVersion])
    payload.append(rpi)
    return payload
  }

  private func getOrCreateDeviceSecret() -> Data {
    let defaults = UserDefaults.standard

    if let existing = defaults.data(forKey: deviceSecretKey), existing.count >= 32 {
      return existing
    }

    let newSecret = BarnardCrypto.generateRandomBytes(32)
    defaults.set(newSecret, forKey: deviceSecretKey)
    return newSecret
  }

  func getDeviceSecret() -> Data {
    getOrCreateDeviceSecret()
  }

  /// v2 displayId for the current TEK: `SHA256(TEK)[0:4]` as 8 hex chars.
  func getCurrentDisplayId() -> String {
    BarnardCrypto.displayIdString(from: currentTek)
  }
}
