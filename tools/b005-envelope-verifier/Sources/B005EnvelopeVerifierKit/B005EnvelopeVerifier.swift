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

public enum B005AuthorityVerifier {
  public static let maxInputBytes = 8_192
  public static let maxOutputBytes = 1_024

  public static func run(input: Data) -> B005EnvelopeVerifierResult {
    guard input.count <= maxInputBytes, !input.contains(0),
          String(data: input, encoding: .utf8) != nil,
          let object = try? JSONSerialization.jsonObject(with: input) as? [String: Any],
          Set(object.keys) == ["kind", "signedEnvelopeHex", "verificationEnin", "authorizationContext"],
          hasUniqueObjectKeys(input),
          let request = try? JSONDecoder().decode(Request.self, from: input),
          request.kind == "BARNARD_B005_AUTHORITY_VERIFY_REQUEST_V1",
          (0...Int64(UInt32.max)).contains(request.verificationEnin),
          let contextObject = object["authorizationContext"] as? [String: Any],
          Set(contextObject.keys) == ["eventIdHex", "definitionSha256Hex", "contextDigestHex", "signers"],
          let signerObjects = contextObject["signers"] as? [[String: Any]],
          signerObjects.allSatisfy({ Set($0.keys) == ["publicKeyHex", "role"] }),
          let context = validateContext(request.authorizationContext)
    else { return failure(.invalidAuthorizationContext) }
    guard let envelope = decodeHex(request.signedEnvelopeHex, count: nil), envelope.count <= 508,
          let container = BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 0, signedEnvelope: envelope) else {
      return failure(.signatureVerificationFailed)
    }
    let verify: (Int64) -> BarnardB005VerifiedEnvelope? = { enin in
      BarnardB005EnvelopeV2.verify(container: container, currentEnin: enin,
        nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: BarnardB005NativeRecoverer())
    }
    let current = verify(request.verificationEnin)
    var expired: BarnardB005VerifiedEnvelope?
    // Structural scheduling data only selects a second SDK verification for error reporting.
    if current == nil, let fields = BarnardB005EnvelopeV2.schedulingFields(container: container),
       request.verificationEnin >= fields.relayExpiresAtEnin {
      expired = verify(fields.validFromEnin)
    }
    guard let verified = current ?? expired else { return failure(.signatureVerificationFailed) }
    guard hex(verified.eventId) == context.eventIdHex else { return failure(.signerUnauthorized) }
    let signerHex = hex(verified.signerPublicKey)
    guard context.signers.contains(where: { $0.publicKeyHex == signerHex && $0.role == verified.signerRole.rawValue }) else {
      return failure(.signerUnauthorized)
    }
    guard current != nil else { return failure(.signedWindowExpired) }

    let receipt = Receipt(
      kind: "BARNARD_B005_AUTHORITY_VERIFIED_V1",
      envelopeSha256Hex: hex(BarnardCoreCrypto.sha256(envelope)),
      authorizationContextDigestHex: context.contextDigestHex,
      eventIdHex: context.eventIdHex,
      signerPublicKeyHex: signerHex,
      signerRole: verified.signerRole.rawValue,
      validFromEnin: verified.validFromEnin,
      validThroughEnin: verified.validThroughEnin,
      relayExpiresAtEnin: verified.relayExpiresAtEnin
    )
    guard let data = try? JSONEncoder().encode(receipt), data.count + 1 <= maxOutputBytes else { return failure(.signatureVerificationFailed) }
    return B005EnvelopeVerifierResult(status: 0, stdout: String(decoding: data, as: UTF8.self) + "\n", stderr: "")
  }

  // Foundation validates the JSON syntax but collapses duplicate object keys.
  // Scan the validated input so both the caller and verifier see one member per key.
  private static func hasUniqueObjectKeys(_ input: Data) -> Bool {
    let bytes = Array(input)
    var objectKeys: [Set<String>] = []
    var index = 0
    while index < bytes.count {
      switch bytes[index] {
      case 123: // {
        objectKeys.append([])
      case 125: // }
        guard !objectKeys.isEmpty else { return false }
        objectKeys.removeLast()
      case 34: // "
        let start = index
        index += 1
        while index < bytes.count && bytes[index] != 34 {
          index += bytes[index] == 92 ? 2 : 1
        }
        guard index < bytes.count else { return false }
        let end = index + 1
        index = end
        while index < bytes.count && [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
        if index < bytes.count && bytes[index] == 58 { // :
          guard let scope = objectKeys.indices.last,
                let key = try? JSONDecoder().decode(String.self, from: Data(bytes[start..<end])),
                objectKeys[scope].insert(key).inserted
          else { return false }
        }
        continue
      default:
        break
      }
      index += 1
    }
    return objectKeys.isEmpty
  }

  private static func validateContext(_ context: AuthorizationContext) -> AuthorizationContext? {
    guard let eventId = decodeHex(context.eventIdHex, count: 32),
          let definitionDigest = decodeHex(context.definitionSha256Hex, count: 32),
          decodeHex(context.contextDigestHex, count: 32) != nil,
          (1...64).contains(context.signers.count) else { return nil }
    var previous: (String, String)?
    var encoded = Array("barnard-b005-authorization-context:v1\0".utf8) + definitionDigest + eventId + [UInt8(context.signers.count)]
    for signer in context.signers {
      guard let key = decodeHex(signer.publicKeyHex, count: 33), ["authority-direct", "delegate"].contains(signer.role),
            BarnardB005NativeRecoverer().isValidCompressedKey(key) else { return nil }
      let current = (signer.publicKeyHex, signer.role)
      if let previous, !(previous.0 < current.0 || (previous.0 == current.0 && previous.1 < current.1)) { return nil }
      previous = current
      encoded += key + [signer.role == "authority-direct" ? 0 : 1]
    }
    guard hex(BarnardCoreCrypto.sha256(encoded)) == context.contextDigestHex else { return nil }
    return context
  }

  private static func failure(_ code: ErrorCode) -> B005EnvelopeVerifierResult {
    B005EnvelopeVerifierResult(status: 1, stdout: "", stderr: code.rawValue + "\n")
  }
  private static func decodeHex(_ value: String, count: Int?) -> [UInt8]? {
    guard !value.isEmpty, value.count.isMultiple(of: 2), value.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), count == nil || value.count == count! * 2 else { return nil }
    return stride(from: 0, to: value.count, by: 2).compactMap { offset in
      let start = value.index(value.startIndex, offsetBy: offset); let end = value.index(start, offsetBy: 2)
      return UInt8(value[start..<end], radix: 16)
    }
  }
  private static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

  public enum ErrorCode: String { case invalidAuthorizationContext = "B005_AUTH_INVALID_CONTEXT", signerUnauthorized = "B005_AUTH_SIGNER_UNAUTHORIZED", signatureVerificationFailed = "B005_AUTH_SIGNATURE_VERIFICATION_FAILED", signedWindowExpired = "B005_AUTH_SIGNED_WINDOW_EXPIRED" }
  private struct Request: Decodable { let kind: String; let signedEnvelopeHex: String; let verificationEnin: Int64; let authorizationContext: AuthorizationContext }
  private struct AuthorizationContext: Codable { let eventIdHex: String; let definitionSha256Hex: String; let contextDigestHex: String; let signers: [Signer] }
  private struct Signer: Codable { let publicKeyHex: String; let role: String }
  private struct Receipt: Encodable { let kind, envelopeSha256Hex, authorizationContextDigestHex, eventIdHex, signerPublicKeyHex, signerRole: String; let validFromEnin, validThroughEnin, relayExpiresAtEnin: Int64 }
}
