import CommonCrypto
import CryptoKit
import Foundation

enum BarnardCrypto {
  static func deriveTekForEvent(deviceSecret: Data, eventCode: String) -> Data {
    guard let eventCodeData = eventCode.data(using: .utf8) else {
      return generateRandomBytes(16)
    }

    var combined = deviceSecret
    combined.append(eventCodeData)

    let key = SymmetricKey(data: combined)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      info: "barnard-tek".data(using: .utf8)!,
      outputByteCount: 16
    )

    return derived.withUnsafeBytes { Data($0) }
  }

  static func deriveTekForAnonymous(deviceSecret: Data) -> Data {
    let key = SymmetricKey(data: deviceSecret)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      info: "barnard-tek-anonymous".data(using: .utf8)!,
      outputByteCount: 16
    )
    return derived.withUnsafeBytes { Data($0) }
  }

  static func deriveRpik(from tek: Data) -> Data {
    guard tek.count == 16 else {
      return Data(count: 16)
    }

    let key = SymmetricKey(data: tek)
    let derived = HKDF<SHA256>.deriveKey(
      inputKeyMaterial: key,
      info: "EN-RPIK".data(using: .utf8)!,
      outputByteCount: 16
    )

    return derived.withUnsafeBytes { Data($0) }
  }

  static func generateRpi(rpik: Data, enin: UInt32) -> Data {
    guard rpik.count == 16 else {
      return Data(count: 16)
    }

    var paddedData = Data(count: 16)

    let prefix = "EN-RPI".data(using: .utf8)!
    paddedData.replaceSubrange(0 ..< 6, with: prefix)

    var eninBE = enin.bigEndian
    let eninBytes = Data(bytes: &eninBE, count: 4)
    paddedData.replaceSubrange(12 ..< 16, with: eninBytes)

    return aes128EcbEncrypt(key: rpik, plaintext: paddedData)
  }

  private static func aes128EcbEncrypt(key: Data, plaintext: Data) -> Data {
    guard key.count == 16, plaintext.count == 16 else {
      return Data(count: 16)
    }

    var outputBuffer = [UInt8](repeating: 0, count: 16)
    var dataOutMoved = 0

    let status = key.withUnsafeBytes { keyPtr in
      plaintext.withUnsafeBytes { inputPtr in
        CCCrypt(
          CCOperation(kCCEncrypt),
          CCAlgorithm(kCCAlgorithmAES128),
          CCOptions(kCCOptionECBMode),
          keyPtr.baseAddress,
          key.count,
          nil,
          inputPtr.baseAddress,
          plaintext.count,
          &outputBuffer,
          outputBuffer.count,
          &dataOutMoved
        )
      }
    }

    return status == kCCSuccess ? Data(outputBuffer) : Data(count: 16)
  }

  static func calculateEnin(for date: Date = Date()) -> UInt32 {
    UInt32(Int(date.timeIntervalSince1970) / 600)
  }

  static func computeEventCodeHash(_ eventCode: String) -> Data {
    guard let eventCodeData = eventCode.data(using: .utf8) else {
      return Data(count: 8)
    }

    let hash = SHA256.hash(data: eventCodeData)
    return Data(hash).prefix(8)
  }

  static func resolveRpi(_ rpi: Data, knownTeks: [Data], currentEnin: UInt32? = nil) -> Data? {
    guard rpi.count == 16 else { return nil }

    let enin = currentEnin ?? calculateEnin()

    for tek in knownTeks {
      guard tek.count == 16 else { continue }

      let rpik = deriveRpik(from: tek)

      for offset in -6 ... 1 {
        let testEnin = UInt32(Int(enin) + offset)
        let candidate = generateRpi(rpik: rpik, enin: testEnin)

        if candidate == rpi {
          return tek
        }
      }
    }

    return nil
  }

  static func displayId(from tek: Data) -> String {
    tek.prefix(3).map { String(format: "%02x", $0) }.joined()
  }

  static func generateRandomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
  }
}
