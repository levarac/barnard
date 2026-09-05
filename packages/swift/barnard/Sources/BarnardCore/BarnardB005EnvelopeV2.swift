// Use of this source code is governed by a BSD-style license.

// BarnardCore is stdlib-only: full Unicode NFC normalization needs composition and
// decomposition tables the bare standard library does not expose, so the NFC check spec 122
// step 3 requires is injected via this protocol rather than done in-tree. The concrete
// implementation backed by the platform's own Unicode support lives in the outer Barnard
// module (see `BarnardB005NativeDisplayNameNormalizer`), matching how
// `BarnardB005PublicKeyRecovering` keeps the crypto backend out of BarnardCore.
public protocol BarnardB005DisplayNameNormalizing {
  /// Returns whether `value` is already in Unicode Normalization Form C.
  func isNormalizedNFC(_ value: String) -> Bool
}

public enum BarnardB005ReceiverState: Equatable {
  case UNVERIFIED
  case RADIO_SELF_VERIFIED
  case REGISTRY_VERIFIED
}

public protocol BarnardB005PublicKeyRecovering {
  func recover(recoveryId: Int, r: [UInt8], s: [UInt8], digest: [UInt8]) -> [UInt8]?
  func isValidCompressedKey(_ key: [UInt8]) -> Bool
}

public struct BarnardB005NativeRecoverer: BarnardB005PublicKeyRecovering {
  public init() {}
  public func recover(recoveryId: Int, r: [UInt8], s: [UInt8], digest: [UInt8]) -> [UInt8]? {
    BarnardCoreSigning.recoverPublicKey(recoveryId: recoveryId, r: r, s: s, messageHash32: digest)
  }
  public func isValidCompressedKey(_ key: [UInt8]) -> Bool {
    BarnardCoreSigning.serializeUncompressedPublicKey(key) != nil
  }
}

public struct BarnardB005VerifiedEnvelope {
  public let receiverState: BarnardB005ReceiverState
  public let relayHopCount: UInt8
  public let eventId: [UInt8]
  public let keySetDigest: [UInt8]
  public let eventCodeHash: [UInt8]
  public let eventDisplayName: String
  public let signedEnvelope: [UInt8]

  public func confirmingRegistry(_ agrees: Bool) -> BarnardB005ReceiverState {
    agrees ? .REGISTRY_VERIFIED : .RADIO_SELF_VERIFIED
  }
}

public enum BarnardB005EnvelopeV2 {
  public static let formatVersion: UInt8 = 3
  public static let envelopeVersion: UInt8 = 1
  private static let signatureDomain = Array("barnard-b005-event-info:v1".utf8)

  public static func eventKeySetBytes(_ keys: [[UInt8]]) -> [UInt8]? {
    guard (1...8).contains(keys.count), keys.allSatisfy({ $0.count == 33 }) else { return nil }
    var out: [UInt8] = [0xa3, 0x01, 0x01, 0x02, 0x80 | UInt8(keys.count)]
    for key in keys { out += [0x58, 0x21] + key }
    return out + [0x03, 0x01]
  }

  public static func keySetDigest(_ keys: [[UInt8]]) -> [UInt8]? {
    guard let encoded = eventKeySetBytes(keys) else { return nil }
    return BarnardCoreCrypto.sha256(Array("levarac:event-key-set-digest:v1\0".utf8) + encoded)
  }

  public static func computeEventId(registrar: [UInt8], anchorOperator: [UInt8], nonce: [UInt8], keySetDigest: [UInt8]) -> [UInt8]? {
    guard registrar.count == 20, anchorOperator.count == 20, nonce.count == 32, keySetDigest.count == 32 else { return nil }
    let domain = BarnardCoreCrypto.keccak256(Array("levarac:event:v1".utf8))
    return BarnardCoreCrypto.keccak256(domain + [UInt8](repeating: 0, count: 12) + registrar + [UInt8](repeating: 0, count: 12) + anchorOperator + nonce + keySetDigest)
  }

  public static func openEventCodeHash(eventId: [UInt8]) -> [UInt8]? {
    guard eventId.count == 32 else { return nil }
    let code = eventId.map { String(formatByte: $0) }.joined()
    return Array(BarnardCoreCrypto.sha256(Array(code.utf8)).prefix(8))
  }

  public static func encodeContainer(relayHopCount: UInt8, signedEnvelope: [UInt8]) -> [UInt8]? {
    guard relayHopCount <= 2, signedEnvelope.count <= 508 else { return nil }
    return [3, relayHopCount, UInt8(signedEnvelope.count >> 8), UInt8(signedEnvelope.count & 255)] + signedEnvelope
  }

  public static func verify(container: [UInt8], currentEnin: Int64?, nameValidator: any BarnardB005DisplayNameNormalizing, registryConfirmed: Bool = false, recoverer: any BarnardB005PublicKeyRecovering = BarnardB005NativeRecoverer()) -> BarnardB005VerifiedEnvelope? {
    guard container.count <= 512, container.count >= 4, container[0] == 3, container[1] <= 2 else { return nil }
    let envelopeLength = Int(container[2]) << 8 | Int(container[3])
    guard envelopeLength <= 508, envelopeLength == container.count - 4, let now = currentEnin, now >= 0 else { return nil }
    let envelope = Array(container[4...])
    guard envelope.count >= 199, envelope[0] == 1 else { return nil }
    let registrar = Array(envelope[1..<21]), anchor = Array(envelope[21..<41]), nonce = Array(envelope[41..<73])
    let n = Int(envelope[73]); guard (1...8).contains(n) else { return nil }
    let a = 74 + 33 * n; guard a + 26 + 65 <= envelope.count else { return nil }
    var keys: [[UInt8]] = []
    for i in 0..<n {
      let key = Array(envelope[(74 + i * 33)..<(107 + i * 33)])
      guard recoverer.isValidCompressedKey(key), keys.last.map({ lexicographicallyLess($0, key) }) ?? true else { return nil }
      keys.append(key)
    }
    let joinMode = envelope[a]; guard joinMode <= 1 else { return nil }
    let eninSeconds = read16(envelope, a + 1); guard eninSeconds != 0 else { return nil }
    let validFrom = Int64(read32(envelope, a + 3)), validThrough = Int64(read32(envelope, a + 7)), expires = Int64(read32(envelope, a + 11))
    guard envelope[a + 15] == 2 else { return nil }
    let codeHash = Array(envelope[(a + 16)..<(a + 24)])
    let nameLength = Int(envelope[a + 24]); guard (1...64).contains(nameLength) else { return nil }
    let nameStart = a + 25, certLengthOffset = nameStart + nameLength
    guard certLengthOffset < envelope.count else { return nil }
    let certLength = Int(envelope[certLengthOffset]), expected = 165 + 33 * n + nameLength + certLength
    guard expected == envelope.count else { return nil }
    let nameBytes = Array(envelope[nameStart..<certLengthOffset])
    guard let name = strictDisplayName(nameBytes, nameValidator: nameValidator) else { return nil }
    guard let ksDigest = keySetDigest(keys), let eventId = computeEventId(registrar: registrar, anchorOperator: anchor, nonce: nonce, keySetDigest: ksDigest) else { return nil }
    guard validFrom <= now, now < expires, expires <= validThrough, expires >= validFrom, expires - validFrom <= 12 else { return nil }
    if joinMode == 0 {
      guard codeHash == openEventCodeHash(eventId: eventId) else { return nil }
    }
    let certStart = certLengthOffset + 1, signatureStart = certStart + certLength
    let expectedSigner: [UInt8]?
    if certLength == 0 { expectedSigner = nil }
    else {
      let cert = Array(envelope[certStart..<signatureStart])
      guard let parsed = parseCertificate(cert), parsed.eventId == eventId, parsed.roles == 1,
            parsed.eninStart <= UInt64(now), UInt64(now) <= parsed.eninEnd,
            recoverer.isValidCompressedKey(parsed.delegateKey) else { return nil }
      let candidates = keys.filter { key in
        Array(BarnardCoreCrypto.sha256(Array("levarac:cose-kid:v1\0".utf8) + key).prefix(8)) == parsed.kid
      }
      guard candidates.count == 1 else { return nil }
      let certDigest = BarnardCoreCrypto.sha256(buildSigStructure(protected: parsed.protected, payload: parsed.payload))
      guard signatureMatches(parsed.signature, digest: certDigest, key: candidates[0], recoverer: recoverer, hasRecoveryByte: false) else { return nil }
      expectedSigner = parsed.delegateKey
    }
    let tbs = Array(envelope[..<signatureStart]), signature = Array(envelope[signatureStart...])
    let digest = BarnardCoreCrypto.sha256(signatureDomain + tbs)
    let signatureKey: [UInt8]?
    if let expectedSigner {
      signatureKey = signatureMatches(signature, digest: digest, key: expectedSigner, recoverer: recoverer, hasRecoveryByte: true) ? expectedSigner : nil
    } else {
      signatureKey = keys.first { signatureMatches(signature, digest: digest, key: $0, recoverer: recoverer, hasRecoveryByte: true) }
    }
    guard signatureKey != nil else { return nil }
    return BarnardB005VerifiedEnvelope(receiverState: registryConfirmed ? .REGISTRY_VERIFIED : .RADIO_SELF_VERIFIED, relayHopCount: container[1], eventId: eventId, keySetDigest: ksDigest, eventCodeHash: codeHash, eventDisplayName: name, signedEnvelope: envelope)
  }

  public static func buildSigStructure(protected: [UInt8], payload: [UInt8]) -> [UInt8] {
    [0x84, 0x6a] + Array("Signature1".utf8) + cborBytes(protected) + [0x40] + cborBytes(payload)
  }

  private struct Cert { let protected: [UInt8]; let payload: [UInt8]; let signature: [UInt8]; let kid: [UInt8]; let eventId: [UInt8]; let delegateKey: [UInt8]; let roles: UInt64; let eninStart: UInt64; let eninEnd: UInt64 }
  private static func parseCertificate(_ bytes: [UInt8]) -> Cert? {
    guard bytes.count <= 255 else { return nil }
    var r = CborReader(bytes)
    guard r.tag() == 18, r.array() == 4, let protected = r.bytes(), r.map() == 0, let payload = r.bytes(), let signature = r.bytes(), signature.count == 64, r.finished else { return nil }
    var h = CborReader(protected); guard h.map() == 3 else { return nil }
    guard h.uint() == 1, h.negative() == -47, h.uint() == 3, h.text() == "application/vnd.levarac.delegation-cert+cbor", h.uint() == 4, let kid = h.bytes(), kid.count == 8, h.finished else { return nil }
    var p = CborReader(payload); guard p.map() == 6,
      p.uint() == 1, p.uint() == 1,
      p.uint() == 2, let eventId = p.bytes(), eventId.count == 32,
      p.uint() == 3, let delegate = p.bytes(), delegate.count == 33,
      p.uint() == 4, let roles = p.uint(),
      p.uint() == 5, let start = p.uint(), start <= 9_007_199_254_740_992,
      p.uint() == 6, let end = p.uint(), end <= 9_007_199_254_740_992, start <= end, p.finished else { return nil }
    return Cert(protected: protected, payload: payload, signature: signature, kid: kid, eventId: eventId, delegateKey: delegate, roles: roles, eninStart: start, eninEnd: end)
  }

  private static func signatureMatches(_ signature: [UInt8], digest: [UInt8], key: [UInt8], recoverer: any BarnardB005PublicKeyRecovering, hasRecoveryByte: Bool) -> Bool {
    guard signature.count == (hasRecoveryByte ? 65 : 64) else { return false }
    let r = Array(signature[0..<32]), s = Array(signature[32..<64])
    if hasRecoveryByte {
      let v = Int(signature[64]); guard v <= 1 else { return false }
      return recoverer.recover(recoveryId: v, r: r, s: s, digest: digest) == key
    }
    return (0...1).contains { recoverer.recover(recoveryId: $0, r: r, s: s, digest: digest) == key }
  }

  private static func strictDisplayName(_ bytes: [UInt8], nameValidator: any BarnardB005DisplayNameNormalizing) -> String? {
    let value = String(decoding: bytes, as: UTF8.self)
    guard Array(value.utf8) == bytes else { return nil }
    for scalar in value.unicodeScalars {
      let v = scalar.value
      if v <= 0x1f || v == 0x7f { return nil }
    }
    guard nameValidator.isNormalizedNFC(value) else { return nil }
    return value
  }
  private static func lexicographicallyLess(_ a: [UInt8], _ b: [UInt8]) -> Bool { for i in a.indices { if a[i] != b[i] { return a[i] < b[i] } }; return false }
  private static func read16(_ b: [UInt8], _ i: Int) -> UInt16 { UInt16(b[i]) << 8 | UInt16(b[i + 1]) }
  private static func read32(_ b: [UInt8], _ i: Int) -> UInt32 { UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3]) }
  private static func cborBytes(_ b: [UInt8]) -> [UInt8] { b.count < 24 ? [0x40 | UInt8(b.count)] + b : [0x58, UInt8(b.count)] + b }
}

private struct CborReader {
  let input: [UInt8]; var offset = 0
  init(_ input: [UInt8]) { self.input = input }
  var finished: Bool { offset == input.count }
  mutating func head(_ major: UInt8) -> UInt64? {
    guard offset < input.count else { return nil }; let initial = input[offset]; offset += 1
    guard initial >> 5 == major else { return nil }; let ai = initial & 31
    if ai < 24 { return UInt64(ai) }
    let count: Int; switch ai { case 24: count = 1; case 25: count = 2; case 26: count = 4; case 27: count = 8; default: return nil }
    guard offset + count <= input.count else { return nil }; var v: UInt64 = 0
    for _ in 0..<count { v = (v << 8) | UInt64(input[offset]); offset += 1 }
    let minimum: UInt64 = count == 1 ? 24 : (count == 2 ? 256 : (count == 4 ? 65_536 : 4_294_967_296))
    return v >= minimum ? v : nil
  }
  mutating func uint() -> UInt64? { head(0) }
  mutating func negative() -> Int64? { guard let v = head(1), v <= UInt64(Int64.max) else { return nil }; return -1 - Int64(v) }
  mutating func bytes() -> [UInt8]? { guard let n = head(2), n <= UInt64(input.count - offset) else { return nil }; let end = offset + Int(n); defer { offset = end }; return Array(input[offset..<end]) }
  mutating func text() -> String? { guard let b = bytesMajor3() else { return nil }; let s = String(decoding: b, as: UTF8.self); return Array(s.utf8) == b ? s : nil }
  mutating func bytesMajor3() -> [UInt8]? { guard let n = head(3), n <= UInt64(input.count - offset) else { return nil }; let end = offset + Int(n); defer { offset = end }; return Array(input[offset..<end]) }
  mutating func array() -> UInt64? { head(4) }
  mutating func map() -> UInt64? { head(5) }
  mutating func tag() -> UInt64? { head(6) }
}

private extension String {
  init(formatByte byte: UInt8) {
    let digits = Array("0123456789abcdef".utf8)
    self = String(decoding: [digits[Int(byte >> 4)], digits[Int(byte & 15)]], as: UTF8.self)
  }
}
