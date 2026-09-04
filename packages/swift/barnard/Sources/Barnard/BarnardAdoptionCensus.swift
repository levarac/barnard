// Use of this source code is governed by a BSD-style license.

import Foundation

/// Errors raised while decoding or binding the versioned AdoptionCredential
/// and SignedWindowCensus artifacts. These errors deliberately distinguish a
/// malformed/canonical wire artifact from an untrusted registry decision.
public enum BarnardAdoptionProtocolError: Error, Equatable {
  case invalidLength
  case unsupportedCredentialVersion
  case unsupportedCensusVersion
  case invalidAdmissionMode
  case invalidField
  case invalidValidityWindow
  case invalidCensusWindow
  case nonCanonicalSignature
  case invalidCredentialSignature
  case invalidCensusSignature
  case eventIdNotAnchored
  case nonCanonicalMerkleRoot
  case invalidCensusCounts
  case invalidB005V2
  case missingRequiredTlv
  case invalidDisplayName
  case credentialScopeMismatch
  case credentialDisplayNameMismatch
  case censusCredentialMismatch
}

/// The credential's explicit admission posture. A registry-verified open
/// credential can take the zero-tap path; a gated credential always falls
/// back to a host-controlled chooser/confirmation flow.
public enum BarnardAdoptionAdmissionMode: UInt8, Equatable {
  case open = 1
  case gated = 2
}

/// Host-supplied registry verification result. A recovered credential
/// authority key self-certifies `eventId`, but only this separate host trust
/// anchor makes it eligible for automatic admission.
public enum BarnardRegistryVerification: Equatable {
  case verified
  case unverified
}

private enum BarnardAdoptionWire {
  static let credentialVersion: UInt8 = 1
  static let censusVersion: UInt8 = 1
  static let credentialUnsignedLength = 94
  static let censusUnsignedLength = 77
  static let recoverableSignatureLength = 65
  static let credentialFullLength = credentialUnsignedLength + recoverableSignatureLength
  static let censusFullLength = censusUnsignedLength + recoverableSignatureLength
  static let credentialDomainTag = "barnard-adoption-credential:v1"
  static let censusDomainTag = "barnard-signed-window-census:v1"

  static let zeroScalar = Secp256k1.UInt256(bytes: [UInt8](repeating: 0, count: 32))

  static func appendUInt16(_ value: UInt16, to bytes: inout Data) {
    bytes.append(UInt8((value >> 8) & 0xff))
    bytes.append(UInt8(value & 0xff))
  }

  static func appendUInt32(_ value: UInt32, to bytes: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
      bytes.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
  }

  static func appendUInt64(_ value: UInt64, to bytes: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
      bytes.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
  }

  static func messageHash(domainTag: String, body: Data) -> Data {
    BarnardCrypto.sha256(Data(domainTag.utf8) + body)
  }

  static func validateCanonicalSignature(_ bytes: Data) throws -> (r: Secp256k1.UInt256, s: Secp256k1.UInt256, recoveryId: Int) {
    guard bytes.count == recoverableSignatureLength else {
      throw BarnardAdoptionProtocolError.invalidLength
    }
    let r = Secp256k1.UInt256(data: Data(bytes.prefix(32)))
    let s = Secp256k1.UInt256(data: Data(bytes.dropFirst(32).prefix(32)))
    let recoveryId = Int(bytes[64])
    let halfOrder = Secp256k1.N.shiftedRight1()
    guard r > zeroScalar, r < Secp256k1.N,
      s > zeroScalar, s <= halfOrder,
      (0...1).contains(recoveryId)
    else {
      throw BarnardAdoptionProtocolError.nonCanonicalSignature
    }
    return (r, s, recoveryId)
  }

  static func recoveredPublicKey(
    signature: Data,
    messageHash: Data
  ) throws -> Data {
    let parsed = try validateCanonicalSignature(signature)
    guard let recovered = BarnardSigning.recoverPublicKey(
      recId: parsed.recoveryId,
      r: parsed.r,
      s: parsed.s,
      messageHash32: messageHash
    ) else {
      throw BarnardAdoptionProtocolError.nonCanonicalSignature
    }
    return recovered
  }

  static func encodeSignature(_ signature: BarnardSigning.RecoverableSignature) -> Data {
    var encoded = Data()
    encoded.append(signature.r)
    encoded.append(signature.s)
    encoded.append(UInt8(signature.v))
    return encoded
  }
}

private struct BarnardAdoptionReader {
  private let bytes: Data
  private var offset = 0

  init(_ bytes: Data) { self.bytes = bytes }

  mutating func readByte() throws -> UInt8 {
    guard offset < bytes.count else { throw BarnardAdoptionProtocolError.invalidLength }
    defer { offset += 1 }
    return bytes[offset]
  }

  mutating func readData(_ count: Int) throws -> Data {
    guard count >= 0, offset + count <= bytes.count else {
      throw BarnardAdoptionProtocolError.invalidLength
    }
    defer { offset += count }
    return bytes.subdata(in: offset..<(offset + count))
  }

  mutating func readUInt16() throws -> UInt16 {
    let data = try readData(2)
    return (UInt16(data[0]) << 8) | UInt16(data[1])
  }

  mutating func readUInt32() throws -> UInt32 {
    let data = try readData(4)
    var result: UInt32 = 0
    for byte in data { result = (result << 8) | UInt32(byte) }
    return result
  }

  mutating func readUInt64() throws -> UInt64 {
    let data = try readData(8)
    var result: UInt64 = 0
    for byte in data { result = (result << 8) | UInt64(byte) }
    return result
  }
}

/// A signed event-authority artifact. Its 94-byte unsigned body is the stable
/// identity input; its recoverable signature is verified and preserved, but
/// never included in `credentialId` so a canonical re-signature cannot split
/// admission, key derivation, census, or relay identities.
public struct BarnardAdoptionCredential: Equatable {
  public struct UnsignedBody: Equatable {
    public let admissionMode: BarnardAdoptionAdmissionMode
    public let eventId: Data
    public let b004AdoptionScopeHash: Data
    public let displayNameHash: Data
    public let validFromUnixSeconds: UInt64
    public let validUntilUnixSeconds: UInt64
    public let censusWindowSeconds: UInt32

    public init(
      admissionMode: BarnardAdoptionAdmissionMode,
      eventId: Data,
      b004AdoptionScopeHash: Data,
      displayNameHash: Data,
      validFromUnixSeconds: UInt64,
      validUntilUnixSeconds: UInt64,
      censusWindowSeconds: UInt32
    ) throws {
      guard eventId.count == 32,
        b004AdoptionScopeHash.count == 8,
        displayNameHash.count == 32
      else { throw BarnardAdoptionProtocolError.invalidField }
      guard validFromUnixSeconds < validUntilUnixSeconds else {
        throw BarnardAdoptionProtocolError.invalidValidityWindow
      }
      guard (12...3_600).contains(censusWindowSeconds) else {
        throw BarnardAdoptionProtocolError.invalidCensusWindow
      }
      self.admissionMode = admissionMode
      self.eventId = eventId
      self.b004AdoptionScopeHash = b004AdoptionScopeHash
      self.displayNameHash = displayNameHash
      self.validFromUnixSeconds = validFromUnixSeconds
      self.validUntilUnixSeconds = validUntilUnixSeconds
      self.censusWindowSeconds = censusWindowSeconds
    }

    public static func decode(_ bytes: Data) throws -> UnsignedBody {
      guard bytes.count == BarnardAdoptionWire.credentialUnsignedLength else {
        throw BarnardAdoptionProtocolError.invalidLength
      }
      var reader = BarnardAdoptionReader(bytes)
      guard try reader.readByte() == BarnardAdoptionWire.credentialVersion else {
        throw BarnardAdoptionProtocolError.unsupportedCredentialVersion
      }
      guard let admissionMode = BarnardAdoptionAdmissionMode(rawValue: try reader.readByte()) else {
        throw BarnardAdoptionProtocolError.invalidAdmissionMode
      }
      return try UnsignedBody(
        admissionMode: admissionMode,
        eventId: reader.readData(32),
        b004AdoptionScopeHash: reader.readData(8),
        displayNameHash: reader.readData(32),
        validFromUnixSeconds: reader.readUInt64(),
        validUntilUnixSeconds: reader.readUInt64(),
        censusWindowSeconds: reader.readUInt32()
      )
    }

    public func canonicalBytes() -> Data {
      var bytes = Data([BarnardAdoptionWire.credentialVersion, admissionMode.rawValue])
      bytes.append(eventId)
      bytes.append(b004AdoptionScopeHash)
      bytes.append(displayNameHash)
      BarnardAdoptionWire.appendUInt64(validFromUnixSeconds, to: &bytes)
      BarnardAdoptionWire.appendUInt64(validUntilUnixSeconds, to: &bytes)
      BarnardAdoptionWire.appendUInt32(censusWindowSeconds, to: &bytes)
      return bytes
    }

    public var credentialId: Data { BarnardCrypto.sha256(canonicalBytes()) }
  }

  public let unsignedBody: UnsignedBody
  public let signature: Data
  /// The recovered compressed secp256k1 credential-authority key (33 bytes).
  public let authorityPublicKey: Data

  public var credentialId: Data { unsignedBody.credentialId }
  public var canonicalBytes: Data { unsignedBody.canonicalBytes() + signature }

  public static func decode(_ bytes: Data) throws -> BarnardAdoptionCredential {
    guard bytes.count == BarnardAdoptionWire.credentialFullLength else {
      throw BarnardAdoptionProtocolError.invalidLength
    }
    let bodyBytes = Data(bytes.prefix(BarnardAdoptionWire.credentialUnsignedLength))
    let unsignedBody = try UnsignedBody.decode(bodyBytes)
    let signature = Data(bytes.suffix(BarnardAdoptionWire.recoverableSignatureLength))
    let recovered: Data
    do {
      recovered = try BarnardAdoptionWire.recoveredPublicKey(
        signature: signature,
        messageHash: BarnardAdoptionWire.messageHash(
          domainTag: BarnardAdoptionWire.credentialDomainTag,
          body: bodyBytes
        )
      )
    } catch {
      if error as? BarnardAdoptionProtocolError == .nonCanonicalSignature {
        throw BarnardAdoptionProtocolError.nonCanonicalSignature
      }
      throw BarnardAdoptionProtocolError.invalidCredentialSignature
    }
    guard BarnardCrypto.sha256(recovered) == unsignedBody.eventId else {
      throw BarnardAdoptionProtocolError.eventIdNotAnchored
    }
    return BarnardAdoptionCredential(
      unsignedBody: unsignedBody,
      signature: signature,
      authorityPublicKey: recovered
    )
  }

  /// Canonically signs a test or authority-supplied unsigned body. This helper
  /// creates only the local artifact; it never makes an authority registry
  /// claim and the resulting credential still needs host registry binding.
  static func encodeSigned(
    unsignedBody: UnsignedBody,
    authorityPrivateKey: Data
  ) throws -> Data {
    guard authorityPrivateKey.count == 32 else { throw BarnardAdoptionProtocolError.invalidField }
    let signature = BarnardSigning.signRecoverable(
      privateKey: Secp256k1.UInt256(data: authorityPrivateKey),
      messageHash32: BarnardAdoptionWire.messageHash(
        domainTag: BarnardAdoptionWire.credentialDomainTag,
        body: unsignedBody.canonicalBytes()
      )
    )
    return unsignedBody.canonicalBytes() + BarnardAdoptionWire.encodeSignature(signature)
  }
}

/// The per-domain, signed count artifact. v1 reserves the fixed 32-byte
/// Merkle-root field and requires it to be all zero; a future proof-bearing
/// version must allocate a new census version rather than redefining v1.
public struct BarnardSignedWindowCensus: Equatable {
  public struct UnsignedBody: Equatable {
    public let credentialId: Data
    public let windowIndex: UInt64
    public let qualifiedVoterCount: UInt16
    public let eligibleVoterCount: UInt16
    public let countedSetMerkleRoot: Data

    public init(
      credentialId: Data,
      windowIndex: UInt64,
      qualifiedVoterCount: UInt16,
      eligibleVoterCount: UInt16,
      countedSetMerkleRoot: Data
    ) throws {
      guard credentialId.count == 32, countedSetMerkleRoot.count == 32 else {
        throw BarnardAdoptionProtocolError.invalidField
      }
      guard countedSetMerkleRoot.allSatisfy({ $0 == 0 }) else {
        throw BarnardAdoptionProtocolError.nonCanonicalMerkleRoot
      }
      guard qualifiedVoterCount <= eligibleVoterCount else {
        throw BarnardAdoptionProtocolError.invalidCensusCounts
      }
      self.credentialId = credentialId
      self.windowIndex = windowIndex
      self.qualifiedVoterCount = qualifiedVoterCount
      self.eligibleVoterCount = eligibleVoterCount
      self.countedSetMerkleRoot = countedSetMerkleRoot
    }

    public static func decode(_ bytes: Data) throws -> UnsignedBody {
      guard bytes.count == BarnardAdoptionWire.censusUnsignedLength else {
        throw BarnardAdoptionProtocolError.invalidLength
      }
      var reader = BarnardAdoptionReader(bytes)
      guard try reader.readByte() == BarnardAdoptionWire.censusVersion else {
        throw BarnardAdoptionProtocolError.unsupportedCensusVersion
      }
      return try UnsignedBody(
        credentialId: reader.readData(32),
        windowIndex: reader.readUInt64(),
        qualifiedVoterCount: reader.readUInt16(),
        eligibleVoterCount: reader.readUInt16(),
        countedSetMerkleRoot: reader.readData(32)
      )
    }

    public func canonicalBytes() -> Data {
      var bytes = Data([BarnardAdoptionWire.censusVersion])
      bytes.append(credentialId)
      BarnardAdoptionWire.appendUInt64(windowIndex, to: &bytes)
      BarnardAdoptionWire.appendUInt16(qualifiedVoterCount, to: &bytes)
      BarnardAdoptionWire.appendUInt16(eligibleVoterCount, to: &bytes)
      bytes.append(countedSetMerkleRoot)
      return bytes
    }
  }

  public let unsignedBody: UnsignedBody
  public let signature: Data
  /// The recovered compressed secp256k1 Census Authority key (33 bytes).
  public let authorityPublicKey: Data

  public var canonicalBytes: Data { unsignedBody.canonicalBytes() + signature }

  public static func decode(_ bytes: Data) throws -> BarnardSignedWindowCensus {
    guard bytes.count == BarnardAdoptionWire.censusFullLength else {
      throw BarnardAdoptionProtocolError.invalidLength
    }
    let bodyBytes = Data(bytes.prefix(BarnardAdoptionWire.censusUnsignedLength))
    let unsignedBody = try UnsignedBody.decode(bodyBytes)
    let signature = Data(bytes.suffix(BarnardAdoptionWire.recoverableSignatureLength))
    let recovered: Data
    do {
      recovered = try BarnardAdoptionWire.recoveredPublicKey(
        signature: signature,
        messageHash: BarnardAdoptionWire.messageHash(
          domainTag: BarnardAdoptionWire.censusDomainTag,
          body: bodyBytes
        )
      )
    } catch {
      if error as? BarnardAdoptionProtocolError == .nonCanonicalSignature {
        throw BarnardAdoptionProtocolError.nonCanonicalSignature
      }
      throw BarnardAdoptionProtocolError.invalidCensusSignature
    }
    return BarnardSignedWindowCensus(
      unsignedBody: unsignedBody,
      signature: signature,
      authorityPublicKey: recovered
    )
  }

  static func encodeSigned(
    unsignedBody: UnsignedBody,
    authorityPrivateKey: Data
  ) throws -> Data {
    guard authorityPrivateKey.count == 32 else { throw BarnardAdoptionProtocolError.invalidField }
    let signature = BarnardSigning.signRecoverable(
      privateKey: Secp256k1.UInt256(data: authorityPrivateKey),
      messageHash32: BarnardAdoptionWire.messageHash(
        domainTag: BarnardAdoptionWire.censusDomainTag,
        body: unsignedBody.canonicalBytes()
      )
    )
    return unsignedBody.canonicalBytes() + BarnardAdoptionWire.encodeSignature(signature)
  }
}

/// The strict v2 B005 surface. It is still GATT discovery data, not a vote or
/// a registry. It contains no EventCode, RPID, peripheral identifier, raw
/// observation count, or relayer count.
public struct BarnardB005V2Payload: Equatable {
  public let eventDisplayName: String
  public let b004AdoptionScopeHash: Data
  public let credential: BarnardAdoptionCredential
  public let census: BarnardSignedWindowCensus
}

public enum BarnardB005V2Codec {
  public static let formatVersion: UInt8 = 2
  public static let maximumPayloadBytes = 386
  public static let maximumDisplayNameBytes = 64

  public static func serialize(_ payload: BarnardB005V2Payload) throws -> Data {
    let displayNameBytes = try canonicalDisplayNameBytes(payload.eventDisplayName)
    guard payload.b004AdoptionScopeHash.count == 8,
      payload.credential.unsignedBody.b004AdoptionScopeHash == payload.b004AdoptionScopeHash
    else { throw BarnardAdoptionProtocolError.credentialScopeMismatch }
    guard BarnardCrypto.sha256(displayNameBytes) == payload.credential.unsignedBody.displayNameHash else {
      throw BarnardAdoptionProtocolError.credentialDisplayNameMismatch
    }
    guard payload.census.unsignedBody.credentialId == payload.credential.credentialId else {
      throw BarnardAdoptionProtocolError.censusCredentialMismatch
    }
    var bytes = Data([formatVersion])
    appendTlv(type: 0x01, value: displayNameBytes, to: &bytes)
    appendTlv(type: 0x02, value: payload.b004AdoptionScopeHash, to: &bytes)
    appendTlv(type: 0x20, value: payload.credential.canonicalBytes, to: &bytes)
    appendTlv(type: 0x21, value: payload.census.canonicalBytes, to: &bytes)
    guard bytes.count <= maximumPayloadBytes else { throw BarnardAdoptionProtocolError.invalidB005V2 }
    return bytes
  }

  public static func decode(_ bytes: Data) throws -> BarnardB005V2Payload {
    // `bytes` may be a slice of a larger buffer (e.g. a TLV value extracted
    // from a scan record upstream), and `Data` slices preserve the original
    // buffer's indices rather than renumbering from zero. Copy into a fresh
    // zero-based `Data` before doing any absolute offset arithmetic below.
    let bytes = Data(bytes)
    guard bytes.count <= maximumPayloadBytes, bytes.first == formatVersion else {
      throw BarnardAdoptionProtocolError.invalidB005V2
    }
    var offset = 1
    var previousType: UInt8 = 0
    var displayNameBytes: Data?
    var scopeHash: Data?
    var credentialBytes: Data?
    var censusBytes: Data?
    while offset < bytes.count {
      guard offset + 3 <= bytes.count else { throw BarnardAdoptionProtocolError.invalidB005V2 }
      let type = bytes[offset]
      let length = (Int(bytes[offset + 1]) << 8) | Int(bytes[offset + 2])
      offset += 3
      guard type > previousType, type != 0, offset + length <= bytes.count else {
        throw BarnardAdoptionProtocolError.invalidB005V2
      }
      previousType = type
      let value = bytes.subdata(in: offset..<(offset + length))
      offset += length
      switch type {
      case 0x01: displayNameBytes = value
      case 0x02: scopeHash = value
      case 0x20: credentialBytes = value
      case 0x21: censusBytes = value
      default: throw BarnardAdoptionProtocolError.invalidB005V2
      }
    }
    guard offset == bytes.count,
      let displayNameBytes,
      let scopeHash,
      let credentialBytes,
      let censusBytes
    else { throw BarnardAdoptionProtocolError.missingRequiredTlv }
    let displayName = try validatedDisplayName(displayNameBytes)
    guard scopeHash.count == 8 else { throw BarnardAdoptionProtocolError.invalidB005V2 }
    let credential: BarnardAdoptionCredential
    do { credential = try BarnardAdoptionCredential.decode(credentialBytes) }
    catch { throw BarnardAdoptionProtocolError.invalidCredentialSignature }
    let census: BarnardSignedWindowCensus
    do { census = try BarnardSignedWindowCensus.decode(censusBytes) }
    catch { throw BarnardAdoptionProtocolError.invalidCensusSignature }
    let payload = BarnardB005V2Payload(
      eventDisplayName: displayName,
      b004AdoptionScopeHash: scopeHash,
      credential: credential,
      census: census
    )
    _ = try serialize(payload) // Reapply all cross-field canonical constraints.
    return payload
  }

  private static func appendTlv(type: UInt8, value: Data, to bytes: inout Data) {
    bytes.append(type)
    BarnardAdoptionWire.appendUInt16(UInt16(value.count), to: &bytes)
    bytes.append(value)
  }

  private static func canonicalDisplayNameBytes(_ value: String) throws -> Data {
    let bytes = Data(value.utf8)
    guard bytes == Data(value.precomposedStringWithCanonicalMapping.utf8),
      (1...maximumDisplayNameBytes).contains(bytes.count),
      value.unicodeScalars.allSatisfy({
        $0.value > 0x1f && !((0x7f...0x9f).contains($0.value))
      })
    else { throw BarnardAdoptionProtocolError.invalidDisplayName }
    return bytes
  }

  private static func validatedDisplayName(_ bytes: Data) throws -> String {
    guard let value = String(data: bytes, encoding: .utf8) else {
      throw BarnardAdoptionProtocolError.invalidDisplayName
    }
    _ = try canonicalDisplayNameBytes(value)
    return value
  }
}

/// The host passes this only after it has authenticated the Registry Event
/// Definition using its own registry trust root. The SDK checks the exact
/// byte bindings here; it deliberately does not invent a connected backend or
/// claim that possession of a self-certifying event key proves approval.
public struct BarnardRegistryEventDefinition: Equatable {
  public let eventId: Data
  public let credentialId: Data
  public let b004AdoptionScopeHash: Data
  public let displayNameHash: Data
  public let validFromUnixSeconds: UInt64
  public let validUntilUnixSeconds: UInt64
  public let admissionMode: BarnardAdoptionAdmissionMode
  public let censusDomainPolicy: BarnardCensusDomainPolicy
  /// Registry-only rotation reference. It is never serialized into B005.
  public let replacesCredentialId: Data?
  /// Registry-only future census window for a replacement credential.
  public let effectiveWindowIndex: UInt64?

  public init(
    eventId: Data,
    credentialId: Data,
    b004AdoptionScopeHash: Data,
    displayNameHash: Data,
    validFromUnixSeconds: UInt64,
    validUntilUnixSeconds: UInt64,
    admissionMode: BarnardAdoptionAdmissionMode,
    censusDomainPolicy: BarnardCensusDomainPolicy,
    replacesCredentialId: Data? = nil,
    effectiveWindowIndex: UInt64? = nil
  ) {
    self.eventId = eventId
    self.credentialId = credentialId
    self.b004AdoptionScopeHash = b004AdoptionScopeHash
    self.displayNameHash = displayNameHash
    self.validFromUnixSeconds = validFromUnixSeconds
    self.validUntilUnixSeconds = validUntilUnixSeconds
    self.admissionMode = admissionMode
    self.censusDomainPolicy = censusDomainPolicy
    self.replacesCredentialId = replacesCredentialId
    self.effectiveWindowIndex = effectiveWindowIndex
  }

  public func verify(
    credential: BarnardAdoptionCredential,
    census: BarnardSignedWindowCensus,
    nowUnixSeconds: UInt64
  ) -> BarnardRegistryVerification {
    let body = credential.unsignedBody
    guard eventId.count == 32,
      credentialId.count == 32,
      b004AdoptionScopeHash.count == 8,
      displayNameHash.count == 32,
      body.eventId == eventId,
      credential.credentialId == credentialId,
      body.b004AdoptionScopeHash == b004AdoptionScopeHash,
      body.displayNameHash == displayNameHash,
      body.admissionMode == admissionMode,
      body.validFromUnixSeconds == validFromUnixSeconds,
      body.validUntilUnixSeconds == validUntilUnixSeconds,
      nowUnixSeconds >= validFromUnixSeconds,
      nowUnixSeconds < validUntilUnixSeconds,
      body.censusWindowSeconds == censusDomainPolicy.censusWindowSeconds,
      census.unsignedBody.credentialId == credentialId,
      BarnardCrypto.sha256(census.authorityPublicKey) == censusDomainPolicy.authorizedAuthorityKeyHash,
      censusDomainPolicy.isStructurallyValid,
      rotationFieldsAreStructurallyValid
    else { return .unverified }
    return .verified
  }

  private var rotationFieldsAreStructurallyValid: Bool {
    switch (replacesCredentialId, effectiveWindowIndex) {
    case (nil, nil):
      return true
    case let (replacesCredentialId?, _?):
      return replacesCredentialId.count == 32 && replacesCredentialId != credentialId
    default:
      return false
    }
  }
}

/// One registry-authorized Census Authority is valid for one physical domain,
/// window duration, and authority-policy epoch in census v1. A second signer
/// for the same tuple is an explicit fail-closed inconsistency, not a second
/// group that can create a separate automatic winner.
public struct BarnardCensusDomainPolicy: Equatable {
  public let censusDomainId: Data
  public let censusWindowSeconds: UInt32
  public let authorityPolicyEpoch: UInt32
  public let authorizedAuthorityKeyHash: Data
  public let minimumEligibleVoterCount: UInt16
  public let minimumQualifiedVoterCount: UInt16
  public let maximumCandidateAgeSeconds: UInt64

  public init(
    censusDomainId: Data,
    censusWindowSeconds: UInt32,
    authorityPolicyEpoch: UInt32,
    authorizedAuthorityKeyHash: Data,
    minimumEligibleVoterCount: UInt16,
    minimumQualifiedVoterCount: UInt16,
    maximumCandidateAgeSeconds: UInt64 = 60
  ) {
    self.censusDomainId = censusDomainId
    self.censusWindowSeconds = censusWindowSeconds
    self.authorityPolicyEpoch = authorityPolicyEpoch
    self.authorizedAuthorityKeyHash = authorizedAuthorityKeyHash
    self.minimumEligibleVoterCount = minimumEligibleVoterCount
    self.minimumQualifiedVoterCount = minimumQualifiedVoterCount
    self.maximumCandidateAgeSeconds = maximumCandidateAgeSeconds
  }

  fileprivate var isStructurallyValid: Bool {
    censusDomainId.count == 32
      && authorizedAuthorityKeyHash.count == 32
      && (12...3_600).contains(censusWindowSeconds)
      && minimumQualifiedVoterCount <= minimumEligibleVoterCount
  }
}

public struct BarnardCensusTuple: Hashable {
  public let credentialId: Data
  public let censusDomainId: Data
  public let authorityPolicyEpoch: UInt32
  public let censusAuthorityKeyHash: Data
  public let windowIndex: UInt64
}

/// A candidate after signature verification and host Registry Event Definition
/// binding. `qualifiedVoterCount` and `eligibleVoterCount` remain an
/// authority-signed aggregate; they are never inferred from RPI, peripheral
/// IDs, raw observation counts, or relayer counts.
public struct BarnardVerifiedCensusCandidate: Equatable {
  /// The exact B005 bytes that were decoded, signature-verified, and bound
  /// to the Registry Event Definition. Relay code must use this value rather
  /// than accepting a separately supplied byte string.
  public let exactB005Bytes: Data
  public let credentialId: Data
  public let eventId: Data
  public let admissionMode: BarnardAdoptionAdmissionMode
  public let censusDomainId: Data
  public let censusWindowSeconds: UInt32
  public let authorityPolicyEpoch: UInt32
  public let censusAuthorityKeyHash: Data
  public let windowIndex: UInt64
  public let qualifiedVoterCount: UInt16
  public let eligibleVoterCount: UInt16
  public let observedAtUnixSeconds: UInt64
  public let registryVerification: BarnardRegistryVerification

  private init(
    exactB005Bytes: Data,
    payload: BarnardB005V2Payload,
    registryDefinition: BarnardRegistryEventDefinition,
    observedAtUnixSeconds: UInt64
  ) {
    let credential = payload.credential
    let census = payload.census
    let policy = registryDefinition.censusDomainPolicy
    self.exactB005Bytes = exactB005Bytes
    self.credentialId = credential.credentialId
    self.eventId = credential.unsignedBody.eventId
    self.admissionMode = credential.unsignedBody.admissionMode
    self.censusDomainId = policy.censusDomainId
    self.censusWindowSeconds = policy.censusWindowSeconds
    self.authorityPolicyEpoch = policy.authorityPolicyEpoch
    self.censusAuthorityKeyHash = BarnardCrypto.sha256(census.authorityPublicKey)
    self.windowIndex = census.unsignedBody.windowIndex
    self.qualifiedVoterCount = census.unsignedBody.qualifiedVoterCount
    self.eligibleVoterCount = census.unsignedBody.eligibleVoterCount
    self.observedAtUnixSeconds = observedAtUnixSeconds
    self.registryVerification = .verified
  }

  /// The only verified-candidate construction path. It decodes the exact
  /// signed B005 bytes, verifies both signatures, and then requires an exact
  /// host-authenticated Registry Event Definition binding before exposing any
  /// census count, window, credential, event, domain, or authority field.
  public static func decodeAndBind(
    b005Bytes: Data,
    registryDefinition: BarnardRegistryEventDefinition,
    observedAtUnixSeconds: UInt64
  ) throws -> BarnardVerifiedCensusCandidate {
    let payload = try BarnardB005V2Codec.decode(b005Bytes)
    guard registryDefinition.verify(
      credential: payload.credential,
      census: payload.census,
      nowUnixSeconds: observedAtUnixSeconds
    ) == .verified else {
      throw BarnardAdoptionProtocolError.invalidField
    }
    return BarnardVerifiedCensusCandidate(
      exactB005Bytes: b005Bytes,
      payload: payload,
      registryDefinition: registryDefinition,
      observedAtUnixSeconds: observedAtUnixSeconds
    )
  }

  public var censusTuple: BarnardCensusTuple {
    BarnardCensusTuple(
      credentialId: credentialId,
      censusDomainId: censusDomainId,
      authorityPolicyEpoch: authorityPolicyEpoch,
      censusAuthorityKeyHash: censusAuthorityKeyHash,
      windowIndex: windowIndex
    )
  }

}

public enum BarnardAdoptionFallbackReason: Equatable {
  case registryUnverified
  case gated
  case noClearMajority
  case insufficientEvidence
  case staleCandidate
  case wrongCensusWindow
  case inconsistentEligibility
  case domainMismatch
  case noAuthoritativeCensus
  case invalidDomainPolicy
  case noCandidateInDomain
}

public enum BarnardAdoptionDecisionResult: Equatable {
  case autoAdopt(credentialId: Data)
  case requiresChooser(BarnardAdoptionFallbackReason)
  case domainAuthorityInconsistency
}

/// Applies the trusted-authority aggregate as a *cross-event local* majority:
/// every candidate's eligible count is the authority's deduplicated union of
/// admitted nearby devices for the same domain/window, not the candidate's
/// own registered attendance. The SDK verifies consistency and makes a local
/// decision; it never recreates the Census Authority's observation pipeline.
public enum BarnardAdoptionDecision {
  public static func evaluate(
    candidates: [BarnardVerifiedCensusCandidate],
    domainPolicy: BarnardCensusDomainPolicy,
    nowUnixSeconds: UInt64
  ) -> BarnardAdoptionDecisionResult {
    guard !candidates.isEmpty else {
      return .requiresChooser(.noAuthoritativeCensus)
    }
    guard domainPolicy.isStructurallyValid else {
      return .requiresChooser(.invalidDomainPolicy)
    }
    if candidates.contains(where: { $0.registryVerification != .verified }) {
      return .requiresChooser(.registryUnverified)
    }
    let domainMatches: (BarnardVerifiedCensusCandidate) -> Bool = {
      $0.censusDomainId == domainPolicy.censusDomainId
        && $0.censusWindowSeconds == domainPolicy.censusWindowSeconds
        && $0.authorityPolicyEpoch == domainPolicy.authorityPolicyEpoch
    }
    if candidates.allSatisfy({ !domainMatches($0) }) {
      return .requiresChooser(.noCandidateInDomain)
    }
    if candidates.contains(where: { !domainMatches($0) }) {
      return .requiresChooser(.domainMismatch)
    }
    if candidates.contains(where: { $0.censusAuthorityKeyHash != domainPolicy.authorizedAuthorityKeyHash }) {
      return .domainAuthorityInconsistency
    }
    if candidates.contains(where: { $0.admissionMode != .open }) {
      return .requiresChooser(.gated)
    }
    let expectedWindow = nowUnixSeconds / UInt64(domainPolicy.censusWindowSeconds)
    if candidates.contains(where: { $0.windowIndex != expectedWindow }) {
      return .requiresChooser(.wrongCensusWindow)
    }
    if candidates.contains(where: {
      nowUnixSeconds < $0.observedAtUnixSeconds
        || nowUnixSeconds - $0.observedAtUnixSeconds > domainPolicy.maximumCandidateAgeSeconds
    }) {
      return .requiresChooser(.staleCandidate)
    }
    if candidates.contains(where: { $0.qualifiedVoterCount > $0.eligibleVoterCount }) {
      return .requiresChooser(.inconsistentEligibility)
    }
    let denominators = Set(candidates.map(\.eligibleVoterCount))
    guard denominators.count == 1, let eligible = denominators.first else {
      return .requiresChooser(.inconsistentEligibility)
    }
    let aggregateQualified = candidates.reduce(UInt64(0)) { $0 + UInt64($1.qualifiedVoterCount) }
    guard aggregateQualified <= UInt64(eligible) else {
      return .requiresChooser(.inconsistentEligibility)
    }
    guard eligible >= domainPolicy.minimumEligibleVoterCount else {
      return .requiresChooser(.insufficientEvidence)
    }
    guard let winner = candidates.max(by: { $0.qualifiedVoterCount < $1.qualifiedVoterCount }) else {
      return .requiresChooser(.noClearMajority)
    }
    let topCount = candidates.filter { $0.qualifiedVoterCount == winner.qualifiedVoterCount }.count
    guard topCount == 1,
      winner.qualifiedVoterCount >= domainPolicy.minimumQualifiedVoterCount,
      UInt64(winner.qualifiedVoterCount) * 2 > UInt64(eligible)
    else { return .requiresChooser(.noClearMajority) }
    return .autoAdopt(credentialId: winner.credentialId)
  }
}

public enum BarnardCredentialRotationResult: Equatable {
  case validBoundaryReplacement
  case credentialRotationInconsistency
}

/// Checks only the local shape of the registry-signed chain. The Registry
/// Event Definition owns the authorization and non-overlap policy; callers
/// provide the currently active census window so same-window replacement is
/// rejected rather than creating two active stable credential IDs.
public enum BarnardCredentialRotation {
  public static func validate(
    activeCredentialId: Data,
    replacementCredentialId: Data,
    replacesCredentialId: Data?,
    activeWindowIndex: UInt64,
    effectiveWindowIndex: UInt64
  ) -> BarnardCredentialRotationResult {
    guard activeCredentialId.count == 32,
      replacementCredentialId.count == 32,
      activeCredentialId != replacementCredentialId,
      replacesCredentialId == activeCredentialId,
      effectiveWindowIndex > activeWindowIndex
    else { return .credentialRotationInconsistency }
    return .validBoundaryReplacement
  }
}

public enum BarnardRelayCacheResult: Equatable {
  case acceptedForRelay
  case duplicate
  case censusEquivocation
  case capacityExceeded
  case expired
}

public enum BarnardRelayDisposition: Equatable {
  case notObserved
  case relayable
  case blockedByEquivocation
  case expired
}

/// Bounded exact-byte retention. It preserves the first two distinct signed
/// payloads for a tuple so a second valid artifact is reported as an explicit
/// equivocation instead of being discarded by first-seen-wins behavior.
/// Transport metadata, RPI, raw observations, and relayer count are excluded:
/// only a bound, verified candidate can enter this cache.
public final class BarnardCensusRelayCache {
  private struct Entry {
    var payloads: [Data]
    var equivocated: Bool
  }

  private let lock = NSLock()
  private let maximumActiveTuples: Int
  private let maximumPayloadsPerConflict: Int
  private var entries: [BarnardCensusTuple: Entry] = [:]
  private var expired: Set<BarnardCensusTuple> = []
  private var expiredOrder: [BarnardCensusTuple] = []
  /// Exclusive monotonic floor. It survives bounded tombstone eviction, so a
  /// candidate from an expired window cannot re-enter once its exact tuple's
  /// tombstone has been displaced.
  private var expiredWindowFloor: UInt64 = 0

  public init(maximumActiveTuples: Int, maximumPayloadsPerConflict: Int) {
    self.maximumActiveTuples = max(1, maximumActiveTuples)
    self.maximumPayloadsPerConflict = min(2, max(2, maximumPayloadsPerConflict))
  }

  public func record(_ candidate: BarnardVerifiedCensusCandidate) -> BarnardRelayCacheResult {
    lock.lock()
    defer { lock.unlock() }
    let tuple = candidate.censusTuple
    if tuple.windowIndex < expiredWindowFloor || expired.contains(tuple) { return .expired }
    if var entry = entries[tuple] {
      if entry.payloads.contains(candidate.exactB005Bytes) { return .duplicate }
      if entry.payloads.count < maximumPayloadsPerConflict {
        entry.payloads.append(candidate.exactB005Bytes)
      }
      entry.equivocated = true
      entries[tuple] = entry
      return .censusEquivocation
    }
    guard entries.count < maximumActiveTuples else { return .capacityExceeded }
    entries[tuple] = Entry(payloads: [candidate.exactB005Bytes], equivocated: false)
    return .acceptedForRelay
  }

  public func relayDisposition(for tuple: BarnardCensusTuple) -> BarnardRelayDisposition {
    lock.lock()
    defer { lock.unlock() }
    if tuple.windowIndex < expiredWindowFloor || expired.contains(tuple) { return .expired }
    guard let entry = entries[tuple] else { return .notObserved }
    return entry.equivocated ? .blockedByEquivocation : .relayable
  }

  public func retainedPayloadCount(for tuple: BarnardCensusTuple) -> Int {
    lock.lock()
    defer { lock.unlock() }
    return entries[tuple]?.payloads.count ?? 0
  }

  public func prune(expiredThroughWindow: UInt64) {
    lock.lock()
    defer { lock.unlock() }
    expiredWindowFloor = max(expiredWindowFloor, expiredThroughWindow)
    let tuples = entries.keys.filter { $0.windowIndex < expiredWindowFloor }
    for tuple in tuples {
      entries.removeValue(forKey: tuple)
      rememberExpired(tuple)
    }
  }

  private func rememberExpired(_ tuple: BarnardCensusTuple) {
    guard expired.insert(tuple).inserted else { return }
    expiredOrder.append(tuple)
    while expiredOrder.count > maximumActiveTuples {
      expired.remove(expiredOrder.removeFirst())
    }
  }
}

public struct BarnardDirectGattPeerObservation {
  public let ephemeralPeerHandle: String
  public let b004Value: Data
  public let b002Value: Data
  public let verifiedB005CredentialId: Data
  public let registryVerification: BarnardRegistryVerification

  public init(
    ephemeralPeerHandle: String,
    b004Value: Data,
    b002Value: Data,
    verifiedB005CredentialId: Data,
    registryVerification: BarnardRegistryVerification
  ) {
    self.ephemeralPeerHandle = ephemeralPeerHandle
    self.b004Value = b004Value
    self.b002Value = b002Value
    self.verifiedB005CredentialId = verifiedB005CredentialId
    self.registryVerification = registryVerification
  }
}

public enum BarnardSelfCheckObservationResult: Equatable {
  case peerConfirmed
  case ignored
}

public enum BarnardSelfCheckWindowResult: Equatable {
  case continueChecking
  case presentSwitchPrompt
}

/// Post-join no-peer self-check. A positive observation means only that a
/// direct same-GATT-session peer served a verified same-credential B005 with
/// matching B004 and a supported-shape B002. It intentionally proves neither
/// cross-device TEK resolution nor device ownership or RF mutuality.
public final class BarnardAutoAdoptionSelfCheck {
  private let credentialId: Data
  private let b004AdoptionScopeHash: Data
  private let requiredCompleteWindows: Int
  private var peerConfirmed = false
  private var completedWindows: Set<UInt64> = []

  public init(
    credentialId: Data,
    b004AdoptionScopeHash: Data,
    requiredCompleteWindows: Int
  ) {
    self.credentialId = credentialId
    self.b004AdoptionScopeHash = b004AdoptionScopeHash
    self.requiredCompleteWindows = max(1, requiredCompleteWindows)
  }

  @discardableResult
  public func observe(
    _ observation: BarnardDirectGattPeerObservation,
    inWindow windowIndex: UInt64
  ) -> BarnardSelfCheckObservationResult {
    let supportedB002 = observation.b002Value.count == 17 && observation.b002Value.first == 0x01
    guard observation.registryVerification == .verified,
      observation.b004Value == b004AdoptionScopeHash,
      observation.verifiedB005CredentialId == credentialId,
      supportedB002
    else { return .ignored }
    // `ephemeralPeerHandle` is deliberately not retained or used as identity.
    peerConfirmed = true
    return .peerConfirmed
  }

  public func completeWindow(_ windowIndex: UInt64) -> BarnardSelfCheckWindowResult {
    if completedWindows.count < requiredCompleteWindows {
      completedWindows.insert(windowIndex)
    }
    guard !peerConfirmed, completedWindows.count >= requiredCompleteWindows else {
      return .continueChecking
    }
    return .presentSwitchPrompt
  }
}

/// Public code-less key derivation APIs. They require only the locally held
/// device secret and a *verified* stable credential ID; EventCode methods stay
/// available exclusively for the legacy B005 v1 path.
public enum BarnardAdoptionKeyDerivation {
  public static func deriveTek(deviceSecret: Data, credentialId: Data) throws -> Data {
    try BarnardCrypto.deriveTekForAdoptionCredential(
      deviceSecret: deviceSecret,
      credentialId: credentialId
    )
  }

  public static func deriveSigningPublicKey(deviceSecret: Data, credentialId: Data) throws -> Data {
    try BarnardSigning.deriveSigningKeyPairForAdoptionCredential(
      deviceSecret: deviceSecret,
      credentialId: credentialId
    ).publicKeyCompressed
  }
}
