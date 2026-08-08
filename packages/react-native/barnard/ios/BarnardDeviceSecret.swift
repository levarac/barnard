import Foundation

/// Shared in-process DeviceSecret creation for the React Native iOS package.
///
/// Both the sensing client and signing identity use this key. Keep the full
/// read-check-generate-write transaction under one lock so separate native
/// module instances cannot create competing secrets during a cold start.
enum BarnardDeviceSecretStore {
  private static let lock = NSLock()
  private static let key = "barnard.rpidSeed"

  static func loadOrCreate() -> Data {
    lock.lock()
    defer { lock.unlock() }

    let defaults = UserDefaults.standard
    if let existing = defaults.data(forKey: key), existing.count >= 32 {
      return existing
    }
    let generated = BarnardCrypto.generateRandomBytes(32)
    defaults.set(generated, forKey: key)
    return generated
  }
}
