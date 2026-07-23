import Foundation

/// Compile probes for every Foundation surface used by the deterministic
/// Barnard sources, plus UserDefaults to distinguish storage from pure logic.
public enum FoundationProbe {
  public static func enin(unixSeconds: Double, windowSeconds: Int = 300) -> UInt32 {
    let date = Date(timeIntervalSince1970: unixSeconds)
    let effectiveSeconds = min(max(windowSeconds, 12), 3_600)
    return UInt32(Int(date.timeIntervalSince1970) / effectiveSeconds)
  }

  public static func dataRoundTrip(_ bytes: [UInt8]) -> String {
    let data = Data(bytes)
    return data.map { String(format: "%02x", $0) }.joined()
  }

  public static func storedData(
    forKey key: String,
    defaults: UserDefaults = .standard
  ) -> Data? {
    defaults.data(forKey: key)
  }
}
