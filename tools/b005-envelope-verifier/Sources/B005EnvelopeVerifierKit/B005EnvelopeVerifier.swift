import Foundation
import Barnard
import BarnardCore

public struct B005EnvelopeVerifierResult: Equatable {
  public let status: Int32
  public let stdout: String
  public let stderr: String

  public init(status: Int32, stdout: String, stderr: String) {
    self.status = status
    self.stdout = stdout
    self.stderr = stderr
  }
}

public enum B005EnvelopeVerifier {
  public static let failureMessage = "B005_ENVELOPE_VERIFICATION_FAILED"
  public static let maxInputBytes = 2_048
  private static let maxSignedEnvelopeBytes = 508

  public static func run(input: Data) -> B005EnvelopeVerifierResult {
    guard input.count <= maxInputBytes,
          let request = decodeRequest(input),
          let signedEnvelope = decodeLowercaseHex(request.signedEnvelopeHex),
          signedEnvelope.count <= maxSignedEnvelopeBytes,
          let container = BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 0, signedEnvelope: signedEnvelope),
          let verified = BarnardB005EnvelopeV2.verify(
            container: container,
            currentEnin: request.currentEnin,
            nameValidator: BarnardB005NativeDisplayNameNormalizer(),
            recoverer: BarnardB005NativeRecoverer()
          ),
          let output = encodeReceipt(verified)
    else {
      return failure()
    }

    return B005EnvelopeVerifierResult(status: 0, stdout: output + "\n", stderr: "")
  }

  private static func failure() -> B005EnvelopeVerifierResult {
    B005EnvelopeVerifierResult(status: 1, stdout: "", stderr: failureMessage + "\n")
  }

  private static func decodeRequest(_ input: Data) -> Request? {
    guard let object = try? JSONSerialization.jsonObject(with: input),
          let dictionary = object as? [String: Any],
          Set(dictionary.keys) == ["signedEnvelopeHex", "currentEnin"],
          hasExactlyTwoDistinctKeys(input)
    else {
      return nil
    }
    return try? JSONDecoder().decode(Request.self, from: input)
  }

  // JSONSerialization and JSONDecoder collapse repeated object keys. Inspect the
  // original bytes so the documented two-member request cannot be ambiguous.
  private static func hasExactlyTwoDistinctKeys(_ input: Data) -> Bool {
    let bytes = Array(input)
    var index = 0

    func skipWhitespace() {
      while index < bytes.count && [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
    }

    func consume(_ byte: UInt8) -> Bool {
      skipWhitespace()
      guard index < bytes.count, bytes[index] == byte else { return false }
      index += 1
      return true
    }

    func readString() -> String? {
      skipWhitespace()
      guard index < bytes.count, bytes[index] == 34 else { return nil }
      let start = index
      index += 1
      while index < bytes.count {
        if bytes[index] == 92 {
          index += 2
        } else if bytes[index] == 34 {
          index += 1
          return try? JSONSerialization.jsonObject(
            with: Data(bytes[start..<index]), options: [.fragmentsAllowed]
          ) as? String
        } else {
          index += 1
        }
      }
      return nil
    }

    guard consume(123) else { return false } // {
    var keys: [String] = []
    for member in 0..<2 {
      guard let key = readString(), consume(58) else { return false } // :
      keys.append(key)
      skipWhitespace()
      if key == "signedEnvelopeHex" {
        guard readString() != nil else { return false }
      } else if key == "currentEnin" {
        let start = index
        while index < bytes.count && bytes[index] != 44 && bytes[index] != 125 { index += 1 }
        guard index > start else { return false }
      } else {
        return false
      }
      if member == 0 && !consume(44) { return false } // ,
    }
    guard consume(125) else { return false } // }
    skipWhitespace()
    return index == bytes.count && Set(keys) == ["signedEnvelopeHex", "currentEnin"]
  }

  private static func decodeLowercaseHex(_ hex: String) -> [UInt8]? {
    guard !hex.isEmpty, hex.count.isMultiple(of: 2), hex.utf8.count == hex.count,
          hex.count <= maxSignedEnvelopeBytes * 2,
          hex.utf8.allSatisfy({ byte in (48...57).contains(byte) || (97...102).contains(byte) })
    else {
      return nil
    }

    var bytes: [UInt8] = []
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let end = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<end], radix: 16) else { return nil }
      bytes.append(byte)
      index = end
    }
    return bytes
  }

  private static func encodeReceipt(_ verified: BarnardB005VerifiedEnvelope) -> String? {
    let receipt = Receipt(
      kind: "BARNARD_B005_VERIFIED_V1",
      eventIdHex: verified.eventId.map { String(format: "%02x", $0) }.joined(),
      joinMode: verified.joinMode,
      validFromEnin: verified.validFromEnin,
      validThroughEnin: verified.validThroughEnin,
      relayExpiresAtEnin: verified.relayExpiresAtEnin
    )
    guard let data = try? JSONEncoder().encode(receipt), data.count <= 512 else { return nil }
    return String(data: data, encoding: .utf8)
  }

  private struct Request: Decodable {
    let signedEnvelopeHex: String
    let currentEnin: Int64
  }

  private struct Receipt: Encodable {
    let kind: String
    let eventIdHex: String
    let joinMode: UInt8
    let validFromEnin: Int64
    let validThroughEnin: Int64
    let relayExpiresAtEnin: Int64
  }
}
