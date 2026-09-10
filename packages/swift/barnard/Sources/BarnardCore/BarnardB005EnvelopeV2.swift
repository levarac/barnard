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

/// A plain struct with an `internal` initializer -- not `public` -- so a consumer outside this
/// module cannot construct one (in particular, cannot fabricate `receiverState =
/// .REGISTRY_VERIFIED` directly). The only way to obtain one is `BarnardB005EnvelopeV2.verify`,
/// which always produces `.UNVERIFIED` or `.RADIO_SELF_VERIFIED`. This SDK never assigns
/// `.REGISTRY_VERIFIED`: doing so is the responsibility of the component that performed the
/// authenticated registry read (the host app), per spec 122's receiver policy; tracked as
/// beid#367 / dispatch#11 (P4).
public struct BarnardB005VerifiedEnvelope {
  public let receiverState: BarnardB005ReceiverState
  public let relayHopCount: UInt8
  public let eventId: [UInt8]
  public let keySetDigest: [UInt8]
  public let joinMode: UInt8
  public let eventCodeHash: [UInt8]
  public let eventDisplayName: String
  public let validFromEnin: Int64
  public let validThroughEnin: Int64
  /// The signed relay expiry, and the **exclusive** end of the half-open relay window
  /// `[validFromEnin, relayExpiresAtEnin)` (spec 134: an envelope is relayable while
  /// `currentEnin < relayExpiresAtEnin` and stops the moment `currentEnin` reaches it).
  /// `verify` has already enforced `relayExpiresAtEnin <= validThroughEnin` and the 12-ENIN
  /// lifetime cap, so a host may use this directly as a relay lease bound instead of falling
  /// back to a pessimistic `currentEnin + 1`.
  ///
  /// Both conventions a host needs to read this window are settled. `relayExpiresAtEnin` is the
  /// **exclusive** end of the relay window, fixed by spec 134. `validThroughEnin` is the
  /// **inclusive** last ENIN lying wholly inside the definition's validity window, per the
  /// maintainer decision of 2026-09-10 on barnard#180, which also fixes the issuer derivation:
  /// `validThroughEnin = floorDiv(validUntil + 1, eninSeconds) - 1` and
  /// `validFromEnin = ceilDiv(validFrom, eninSeconds)`, the formulas `registryAgreement`
  /// computes as `registryEndEnin` and `registryStartEnin`. Any other issuer derivation fails
  /// spec 134 step 4. A host reading these values therefore applies the same rule the SDK does.
  ///
  /// One consequence of the two conventions together, recorded rather than hidden: because step 5
  /// requires `currentEnin < relayExpiresAtEnin <= validThroughEnin`, no envelope is servable at
  /// `currentEnin == validThroughEnin`. Whether that final ENIN should become servable is the
  /// part of barnard#180 still open, and it does not affect the meaning of this field.
  public let relayExpiresAtEnin: Int64
  public let eninSeconds: UInt16
  public let signedEnvelope: [UInt8]

  /// This SDK never assigns `.REGISTRY_VERIFIED`: doing so is the responsibility of the
  /// component that performed the authenticated registry read (the host app), per spec 122's
  /// receiver policy; tracked as beid#367 / dispatch#11 (P4).
  internal init(receiverState: BarnardB005ReceiverState, relayHopCount: UInt8, eventId: [UInt8], keySetDigest: [UInt8], joinMode: UInt8, eventCodeHash: [UInt8], eventDisplayName: String, validFromEnin: Int64, validThroughEnin: Int64, relayExpiresAtEnin: Int64, eninSeconds: UInt16, signedEnvelope: [UInt8]) {
    self.receiverState = receiverState
    self.relayHopCount = relayHopCount
    self.eventId = eventId
    self.keySetDigest = keySetDigest
    self.joinMode = joinMode
    self.eventCodeHash = eventCodeHash
    self.eventDisplayName = eventDisplayName
    self.validFromEnin = validFromEnin
    self.validThroughEnin = validThroughEnin
    self.relayExpiresAtEnin = relayExpiresAtEnin
    self.eninSeconds = eninSeconds
    self.signedEnvelope = signedEnvelope
  }

}

/// Why a set of envelope fields cannot be encoded. Each case names the rule from
/// `specification 122`'s signed-envelope table that the input breaks.
///
/// Every case here is a shape the shipped verifier would reject, so the encoder refuses to
/// produce it: a producer that can emit bytes `verify` rejects is a defect in the producer.
public enum BarnardB005EncodeError: Error, Equatable {
  case registrarLength, anchorOperatorLength, nonceLength
  case keyCount, keyLength, keyOrder, keyNotOnCurve
  case joinMode, eninSeconds
  case eventCodeHashLength
  /// `joinMode == open` requires `eventCodeHash == SHA256(UTF8(lowercaseHex(eventId)))[0:8]`.
  case openEventCodeHashMismatch
  case displayNameLength, displayNameCharacters
  /// The display name is not NFC. `verify` enforces this through its name validator, so an
  /// encoder that could not check it was able to emit a name the verifier rejects.
  case displayNameNotNormalized
  /// An authority key is not a valid compressed secp256k1 point. `verify` checks every key with
  /// `isValidCompressedKey`, so this closes the same gap on the producing side.
  case certLength
  /// The window relations `verify` enforces: `validFromEnin < relayExpiresAtEnin <=
  /// validThroughEnin`. An inverted or empty window is unsatisfiable there, so it is refused here.
  case validityWindow
  /// `relayExpiresAtEnin - validFromEnin` exceeds the 12-ENIN relay lifetime cap.
  case relayLifetime
  /// The assembled envelope would not fit the 508-byte `signedEnvelope` bound.
  case envelopeLength
  case signatureLength
}

/// The typed fields of a B005 v2 signed envelope, in the order
/// [`specification 122`](https://github.com/levarac/barnard/blob/main/specs/122-b005-v2-signed-envelope/spec.md)
/// lays them out. This is the encoder's input; `BarnardB005VerifiedEnvelope` is the decoder's
/// output, and the two are deliberately separate types — one carries what an issuer chose, the
/// other carries what a receiver established.
public struct BarnardB005EnvelopeFields {
  public let registrar: [UInt8]
  public let anchorOperator: [UInt8]
  public let nonce: [UInt8]
  /// Compressed secp256k1 points, `1...8`, strictly ascending and unique.
  public let authorityKeys: [[UInt8]]
  public let joinMode: UInt8
  public let eninSeconds: UInt16
  public let validFromEnin: UInt32
  public let validThroughEnin: UInt32
  public let relayExpiresAtEnin: UInt32
  public let eventCodeHash: [UInt8]
  public let eventDisplayName: String
  /// COSE_Sign1 delegation certificate, byte-identical to the bundle copy. Empty is
  /// authority-direct mode.
  public let delegationCert: [UInt8]

  public init(registrar: [UInt8], anchorOperator: [UInt8], nonce: [UInt8], authorityKeys: [[UInt8]], joinMode: UInt8, eninSeconds: UInt16, validFromEnin: UInt32, validThroughEnin: UInt32, relayExpiresAtEnin: UInt32, eventCodeHash: [UInt8], eventDisplayName: String, delegationCert: [UInt8] = []) {
    self.registrar = registrar
    self.anchorOperator = anchorOperator
    self.nonce = nonce
    self.authorityKeys = authorityKeys
    self.joinMode = joinMode
    self.eninSeconds = eninSeconds
    self.validFromEnin = validFromEnin
    self.validThroughEnin = validThroughEnin
    self.relayExpiresAtEnin = relayExpiresAtEnin
    self.eventCodeHash = eventCodeHash
    self.eventDisplayName = eventDisplayName
    self.delegationCert = delegationCert
  }
}

/// What an issuer signs, and what it signs it over.
public struct BarnardB005UnsignedEnvelope {
  /// The envelope from offset 0 up to but excluding the 65-byte signature — spec 122's `tbs`.
  public let toBeSigned: [UInt8]
  /// `SHA256("barnard-b005-event-info:v1" || tbs)`, the value an issuer signs (spec 122).
  public let signatureDigest: [UInt8]

  internal init(toBeSigned: [UInt8], signatureDigest: [UInt8]) {
    self.toBeSigned = toBeSigned
    self.signatureDigest = signatureDigest
  }
}

/// The four scheduling fields a B005 v2 container carries, read after **structure validation
/// only**: no signature check, no key recovery, no registry read, and no current ENIN.
///
/// **Trust boundary, in one sentence: a window a host acts on comes only from a verified
/// envelope, and these values may be used solely to choose the ENIN it asks `verify` to run
/// at.** An attacker controls every byte here, so treating any of them as a fact about the
/// event is a defect; using them to decide *what to ask* is not, because the answer still
/// comes from `verify`.
///
/// This exists because decode and time-parameterised verification are fused: `verify` takes a
/// container and a `currentEnin`, so a host holding several pre-signed envelopes for one event
/// must already know an envelope's window in order to verify it, and that window lives in bytes
/// it has not decoded. Two alternatives were rejected and should not be reintroduced. A
/// host-side parser copies spec 122's offsets into the host and creates removal debt. An
/// unsigned schedule hint carried beside the envelopes is unverifiable by construction: `verify`
/// sees only the container and `currentEnin` and never sees the hint, so a hint claiming
/// `[100, 112)` over a signed `[100, 105)` verifies at the hinted start and the extra ENINs are
/// checked by nothing.
public struct BarnardB005SchedulingFields {
  public let validFromEnin: Int64
  public let validThroughEnin: Int64
  /// Exclusive end of the half-open relay window, as on `BarnardB005VerifiedEnvelope`.
  public let relayExpiresAtEnin: Int64
  public let eninSeconds: UInt16

  internal init(validFromEnin: Int64, validThroughEnin: Int64, relayExpiresAtEnin: Int64, eninSeconds: UInt16) {
    self.validFromEnin = validFromEnin
    self.validThroughEnin = validThroughEnin
    self.relayExpiresAtEnin = relayExpiresAtEnin
    self.eninSeconds = eninSeconds
  }
}

/// The subset of parallax's anchored `EventDefinitionV1` (protocol/spec/v0.1/event-definition.md)
/// that spec 134 step 4 requires a receiver to agree against: `eventId`, the authority key-set
/// digest (signer-authority agreement), `joinMode`, `eventCodeHash`, and the registered Unix-time
/// validity window.
public struct BarnardEventDefinitionV1 {
  public let eventId: [UInt8]
  public let keySetDigest: [UInt8]
  public let joinMode: UInt8
  public let eventCodeHash: [UInt8]
  public let validFromUnixSeconds: Int64
  public let validUntilUnixSeconds: Int64

  public init(eventId: [UInt8], keySetDigest: [UInt8], joinMode: UInt8, eventCodeHash: [UInt8], validFromUnixSeconds: Int64, validUntilUnixSeconds: Int64) {
    self.eventId = eventId
    self.keySetDigest = keySetDigest
    self.joinMode = joinMode
    self.eventCodeHash = eventCodeHash
    self.validFromUnixSeconds = validFromUnixSeconds
    self.validUntilUnixSeconds = validUntilUnixSeconds
  }
}

/// A single field on which `registryAgreement` can find a mismatch between an envelope and a
/// registered `EventDefinitionV1`.
public enum BarnardRegistryMismatchField: Equatable {
  case EVENT_ID, EVENT_CODE_HASH, KEY_SET_DIGEST, JOIN_MODE, VALIDITY_WINDOW
}

/// The result of comparing a `.RADIO_SELF_VERIFIED` envelope against a registered
/// `EventDefinitionV1`: either the two agree, or `mismatchedFields` names every field that
/// disagreed. Either way this is a pure comparison -- it never changes the envelope's
/// `BarnardB005ReceiverState`. Assigning `.REGISTRY_VERIFIED` is the responsibility of the
/// component that performed the authenticated registry read (the host app), per spec 122's
/// receiver policy; tracked as beid#367 / dispatch#11 (P4).
public enum BarnardRegistryAgreement: Equatable {
  case agrees
  case mismatched(mismatchedFields: Set<BarnardRegistryMismatchField>)
}

/// Why a B005 v2 container failed the clock-independent structural checks.
///
/// These are exactly the guards that depend on nothing but the bytes: no
/// current ENIN, no signature or key recovery, no display-name normalisation.
/// `BarnardB005EnvelopeV2.verify` runs them first, and a host serving its own
/// container runs them on their own, so both paths accept and reject the same
/// shapes.
public enum BarnardB005StructureError: Equatable {
  /// Container outside `4...512` bytes.
  case containerLength
  /// Byte 0 is not `BarnardB005EnvelopeV2.formatVersion`.
  case formatVersion
  /// Byte 1 exceeds the spec 134 hop limit of 2.
  case hopCount
  /// The big-endian length at bytes 2-3 exceeds 508 or disagrees with the
  /// byte count.
  case envelopeLength
  /// Envelope byte 0 is not `BarnardB005EnvelopeV2.envelopeVersion`.
  case envelopeVersion
  /// The envelope is shorter than the 199-byte floor its fixed fields need.
  case envelopeTooSmall
  /// The authority key count is outside `1...8`.
  case keyCount
  /// A declared length runs past the envelope, or the total size disagrees
  /// with the sum of its parts.
  case fieldLayout
  /// `joinMode` is neither 0 nor 1.
  case joinMode
  /// `eninSeconds` is zero, which no ENIN arithmetic can use.
  case eninSeconds
  /// The event-code-hash TLV type byte is not 2.
  case eventCodeHashTlvType
  /// The display-name length is outside `1...64`.
  case displayNameLength
}

public enum BarnardB005EnvelopeV2 {
  public static let formatVersion: UInt8 = 3
  public static let envelopeVersion: UInt8 = 1

  /// Clock-independent structural validation of a container, shared by
  /// `verify` and by any caller that must judge a container's shape without a
  /// current ENIN, a signature check, or key recovery.
  ///
  /// Returns nil when the container is well formed at this layer. Passing says
  /// nothing about authenticity: the signature, the validity window, the key
  /// set and the display-name normalisation are all still unchecked, because
  /// each of those needs an input this function deliberately does not take.
  public static func validateStructure(container: [UInt8]) -> BarnardB005StructureError? {
    guard container.count >= 4, container.count <= 512 else { return .containerLength }
    guard container[0] == formatVersion else { return .formatVersion }
    guard container[1] <= 2 else { return .hopCount }
    let envelopeLength = Int(container[2]) << 8 | Int(container[3])
    guard envelopeLength <= 508, envelopeLength == container.count - 4 else { return .envelopeLength }
    let envelope = Array(container[4...])
    guard envelope.count >= 199 else { return .envelopeTooSmall }
    guard envelope[0] == envelopeVersion else { return .envelopeVersion }
    let n = Int(envelope[73])
    guard (1...8).contains(n) else { return .keyCount }
    let a = 74 + 33 * n
    guard a + 26 + 65 <= envelope.count else { return .fieldLayout }
    guard envelope[a] <= 1 else { return .joinMode }
    guard read16(envelope, a + 1) != 0 else { return .eninSeconds }
    guard envelope[a + 15] == 2 else { return .eventCodeHashTlvType }
    let nameLength = Int(envelope[a + 24])
    guard (1...64).contains(nameLength) else { return .displayNameLength }
    let certLengthOffset = a + 25 + nameLength
    guard certLengthOffset < envelope.count else { return .fieldLayout }
    let certLength = Int(envelope[certLengthOffset])
    guard 165 + 33 * n + nameLength + certLength == envelope.count else { return .fieldLayout }
    return nil
  }
  /// Reads the four scheduling fields at the offsets spec 122 fixes, from an envelope body that
  /// has already passed `validateStructure`. `a` is the post-key-set base offset,
  /// `74 + 33 * n`.
  ///
  /// This is the single offset table for those four fields: `verify` and
  /// `schedulingFields(container:)` both read through it, so the trusted and untrusted paths
  /// cannot come to disagree about where a window lives in the bytes.
  private static func readSchedulingFields(_ envelope: [UInt8], _ a: Int) -> BarnardB005SchedulingFields {
    BarnardB005SchedulingFields(
      validFromEnin: Int64(read32(envelope, a + 3)),
      validThroughEnin: Int64(read32(envelope, a + 7)),
      relayExpiresAtEnin: Int64(read32(envelope, a + 11)),
      eninSeconds: read16(envelope, a + 1))
  }

  /// Structure-only scheduling accessor: the window a container claims, before any signature,
  /// key recovery, registry read or clock. Returns nil when `validateStructure` rejects the
  /// container, so a caller receives four fields or none -- never a partial read of a malformed
  /// container.
  ///
  /// **The values are untrusted.** See `BarnardB005SchedulingFields` for the trust boundary:
  /// use them only to choose the `currentEnin` to pass to `verify`, and take every value a host
  /// acts on from `verify`'s result.
  public static func schedulingFields(container: [UInt8]) -> BarnardB005SchedulingFields? {
    guard validateStructure(container: container) == nil else { return nil }
    let envelope = Array(container[4...])
    return readSchedulingFields(envelope, 74 + 33 * Int(envelope[73]))
  }

  /// The value at spec 122's offset `A+15`, which that table names `maxRelayHops` and pins to
  /// `0x02` for `envelopeVersion 0x01`. Spec 134 requires the same value.
  ///
  /// Note for a future version: both cores validate this byte but neither reads it as a hop
  /// limit — the two-hop bound is enforced by a separate constant — so a version that permitted
  /// another value would need the relay path changed too. Tracked as barnard#209.
  public static let maxRelayHops: UInt8 = 2

  /// Encodes the canonical unsigned envelope for `fields`, together with the digest an issuer
  /// signs, per `specification 122`'s signed-envelope table. Returns the error naming the rule
  /// broken, rather than nil, so a caller learns which field to fix.
  ///
  /// **The encoder refuses anything `verify` would reject.** That is the point of it: an issuer
  /// that can produce unverifiable bytes has only moved the failure later, to a venue with no
  /// connectivity. So the window relations, the 12-ENIN relay cap, the open-mode event-code-hash
  /// binding, key ordering and the length bound are all enforced here, on the producing side,
  /// even though `verify` enforces them again on the consuming side.
  ///
  /// The layout is taken from the spec text rather than from `verify`'s reverse: an encoder
  /// written as the decoder's inverse agrees with the decoder by construction and inherits
  /// whatever the decoder assumes, which a round-trip test cannot detect because both sides
  /// share the assumption. Byte-reproduction against the committed vectors is the check that
  /// can actually fail.
  /// `nameValidator` and `recoverer` are the same injected capabilities `verify` takes, and for
  /// the same reason: `BarnardCore` is stdlib-only, so NFC normalisation and curve arithmetic have
  /// to arrive from the platform. Without them an encoder cannot perform two of the checks
  /// `verify` performs, and "refuses anything `verify` would reject" would be false — which it was
  /// before they were added.
  public static func encodeUnsignedEnvelope(_ fields: BarnardB005EnvelopeFields, nameValidator: any BarnardB005DisplayNameNormalizing, recoverer: any BarnardB005PublicKeyRecovering = BarnardB005NativeRecoverer()) -> Result<BarnardB005UnsignedEnvelope, BarnardB005EncodeError> {
    guard fields.registrar.count == 20 else { return .failure(.registrarLength) }
    guard fields.anchorOperator.count == 20 else { return .failure(.anchorOperatorLength) }
    guard fields.nonce.count == 32 else { return .failure(.nonceLength) }
    guard (1...8).contains(fields.authorityKeys.count) else { return .failure(.keyCount) }
    guard fields.authorityKeys.allSatisfy({ $0.count == 33 }) else { return .failure(.keyLength) }
    guard fields.authorityKeys.allSatisfy({ recoverer.isValidCompressedKey($0) }) else { return .failure(.keyNotOnCurve) }
    for i in 1..<fields.authorityKeys.count {
      guard lexicographicallyLess(fields.authorityKeys[i - 1], fields.authorityKeys[i]) else { return .failure(.keyOrder) }
    }
    guard fields.joinMode <= 1 else { return .failure(.joinMode) }
    guard fields.eninSeconds != 0 else { return .failure(.eninSeconds) }
    guard fields.eventCodeHash.count == 8 else { return .failure(.eventCodeHashLength) }

    // verify requires validFromEnin <= currentEnin < relayExpiresAtEnin <= validThroughEnin, so a
    // window that is inverted, or whose relay expiry sits at or before its start, is unsatisfiable
    // there for every currentEnin. Refuse it here rather than emit bytes nobody can verify.
    guard fields.validFromEnin < fields.relayExpiresAtEnin,
          fields.relayExpiresAtEnin <= fields.validThroughEnin else { return .failure(.validityWindow) }
    guard UInt64(fields.relayExpiresAtEnin) - UInt64(fields.validFromEnin) <= 12 else { return .failure(.relayLifetime) }

    let nameBytes = Array(fields.eventDisplayName.utf8)
    guard (1...64).contains(nameBytes.count) else { return .failure(.displayNameLength) }
    guard fields.eventDisplayName.unicodeScalars.allSatisfy({ $0.value > 0x1f && $0.value != 0x7f }) else { return .failure(.displayNameCharacters) }
    // Round-trips the encoded bytes through the same check verify applies, rather than
    // reimplementing it: whatever verify would refuse to decode, this refuses to encode.
    guard strictDisplayName(nameBytes, nameValidator: nameValidator) == fields.eventDisplayName else { return .failure(.displayNameNotNormalized) }
    guard fields.delegationCert.count <= 255 else { return .failure(.certLength) }

    guard let keySet = keySetDigest(fields.authorityKeys),
          let eventId = computeEventId(registrar: fields.registrar, anchorOperator: fields.anchorOperator, nonce: fields.nonce, keySetDigest: keySet) else {
      return .failure(.keyLength)
    }
    if fields.joinMode == 0 {
      guard fields.eventCodeHash == openEventCodeHash(eventId: eventId) else { return .failure(.openEventCodeHashMismatch) }
    }

    var envelope: [UInt8] = [envelopeVersion]
    envelope += fields.registrar
    envelope += fields.anchorOperator
    envelope += fields.nonce
    envelope += [UInt8(fields.authorityKeys.count)]
    for key in fields.authorityKeys { envelope += key }
    envelope += [fields.joinMode]
    envelope += [UInt8(fields.eninSeconds >> 8), UInt8(fields.eninSeconds & 0xff)]
    envelope += be32(fields.validFromEnin)
    envelope += be32(fields.validThroughEnin)
    envelope += be32(fields.relayExpiresAtEnin)
    envelope += [maxRelayHops]
    envelope += fields.eventCodeHash
    envelope += [UInt8(nameBytes.count)]
    envelope += nameBytes
    envelope += [UInt8(fields.delegationCert.count)]
    envelope += fields.delegationCert

    // Spec 122: the total is 165 + 33n + L + C, and the signature is the trailing 65 bytes.
    guard envelope.count + 65 == 165 + 33 * fields.authorityKeys.count + nameBytes.count + fields.delegationCert.count,
          envelope.count + 65 <= 508 else { return .failure(.envelopeLength) }

    return .success(BarnardB005UnsignedEnvelope(toBeSigned: envelope, signatureDigest: BarnardCoreCrypto.sha256(signatureDomain + envelope)))
  }

  /// Appends the 65-byte `r‖s‖v` signature to a `toBeSigned` range, producing the signed envelope
  /// that `encodeContainer` wraps. Split from `encodeUnsignedEnvelope` because the signature is
  /// not knowable until after signing, and because an issuer's signing key may live elsewhere.
  public static func assembleSignedEnvelope(toBeSigned: [UInt8], signature: [UInt8]) -> Result<[UInt8], BarnardB005EncodeError> {
    guard signature.count == 65 else { return .failure(.signatureLength) }
    guard toBeSigned.count + 65 <= 508 else { return .failure(.envelopeLength) }
    return .success(toBeSigned + signature)
  }

  private static func be32(_ value: UInt32) -> [UInt8] {
    [UInt8(value >> 24), UInt8((value >> 16) & 0xff), UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
  }

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

  public static func verify(container: [UInt8], currentEnin: Int64?, nameValidator: any BarnardB005DisplayNameNormalizing, recoverer: any BarnardB005PublicKeyRecovering = BarnardB005NativeRecoverer()) -> BarnardB005VerifiedEnvelope? {
    // Every clock-independent shape check lives in one place, so a host
    // serving its own container rejects exactly what a receiver would.
    guard validateStructure(container: container) == nil else { return nil }
    guard let now = currentEnin, now >= 0 else { return nil }
    let envelope = Array(container[4...])
    let registrar = Array(envelope[1..<21]), anchor = Array(envelope[21..<41]), nonce = Array(envelope[41..<73])
    let n = Int(envelope[73])
    let a = 74 + 33 * n
    var keys: [[UInt8]] = []
    for i in 0..<n {
      let key = Array(envelope[(74 + i * 33)..<(107 + i * 33)])
      guard recoverer.isValidCompressedKey(key), keys.last.map({ lexicographicallyLess($0, key) }) ?? true else { return nil }
      keys.append(key)
    }
    let joinMode = envelope[a]
    let scheduling = readSchedulingFields(envelope, a)
    let eninSeconds = scheduling.eninSeconds
    let validFrom = scheduling.validFromEnin, validThrough = scheduling.validThroughEnin, expires = scheduling.relayExpiresAtEnin
    let codeHash = Array(envelope[(a + 16)..<(a + 24)])
    let nameLength = Int(envelope[a + 24])
    let nameStart = a + 25, certLengthOffset = nameStart + nameLength
    let certLength = Int(envelope[certLengthOffset])
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
      guard let sigStructure = buildSigStructure(protected: parsed.protected, payload: parsed.payload) else { return nil }
      let certDigest = BarnardCoreCrypto.sha256(sigStructure)
      guard signatureMatches(parsed.signature, digest: certDigest, key: candidates[0], recoverer: recoverer, hasRecoveryByte: false) else { return nil }
      expectedSigner = parsed.delegateKey
    }
    let tbs = Array(envelope[..<signatureStart]), signature = Array(envelope[signatureStart...])
    let digest = BarnardCoreCrypto.sha256(signatureDomain + tbs)
    let signatureKey: [UInt8]?
    if let expectedSigner {
      signatureKey = signatureMatches(signature, digest: digest, key: expectedSigner, recoverer: recoverer, hasRecoveryByte: true) ? expectedSigner : nil
    } else {
      // Recover once: the recovered pubkey depends only on (r, s, v, digest), not on which
      // authority key it is compared against, so recovering per candidate key would recover the
      // identical point up to n times. Recover once and test set membership on the result.
      signatureKey = recoverMember(signature, digest: digest, keys: keys, recoverer: recoverer)
    }
    guard signatureKey != nil else { return nil }
    return BarnardB005VerifiedEnvelope(receiverState: .RADIO_SELF_VERIFIED, relayHopCount: container[1], eventId: eventId, keySetDigest: ksDigest, joinMode: joinMode, eventCodeHash: codeHash, eventDisplayName: name, validFromEnin: validFrom, validThroughEnin: validThrough, relayExpiresAtEnin: expires, eninSeconds: eninSeconds, signedEnvelope: envelope)
  }

  /// Pure comparison of a `.RADIO_SELF_VERIFIED` envelope against a registered
  /// `EventDefinitionV1` for this `eventId` (spec 122 receiver policy, step 8; spec 134 step 4 as
  /// amended by errata #173, which drops the unsatisfiable display-name agreement). This never
  /// changes the envelope's `receiverState` -- assigning `.REGISTRY_VERIFIED` is the
  /// responsibility of the component that performed the authenticated registry read (the host
  /// app), per spec 122's receiver policy; tracked as beid#367 / dispatch#11 (P4).
  ///
  /// Spec 134 step 4 requires validity-window CONTAINMENT, not equality: the envelope's window
  /// must lie inside the definition's, `definitionStart <= validFromEnin` and `validThroughEnin <=
  /// definitionEnd` (spec 134 erratum of 2026-09-10; see barnard#200). Equality made the rule
  /// unsatisfiable for any definition longer than the 12-ENIN relay cap: spec 134:122-123 directs
  /// an issuer to refresh with a LATER `validFromEnin`, and equality rejected every such refresh as
  /// a `.VALIDITY_WINDOW` mismatch, so nothing was servable after the first 12 ENINs. The cap
  /// itself (`relayExpiresAtEnin - validFromEnin <= 12`) and step 5 are unchanged and stay in
  /// `verify`. Spec 122:477-482 calls `validFromEnin` the issue point, which likewise presumes it
  /// can move.
  /// `validThroughEnin` is treated as the INCLUSIVE last valid ENIN (window `[validFromEnin,
  /// validThroughEnin]`): spec 122 never states its own convention for this field, but parallax's
  /// `event-definition.md` (`validFrom`/`validUntil`, lines 52-53) is explicitly inclusive on both
  /// ends, and spec 122's only other ENIN range (the delegation cert's `eninStart`/`eninEnd`, spec
  /// 122:211) is likewise inclusive -- this is an issuer derivation erratum, tracked in the spec
  /// 122 errata. `eninSeconds`-denominated ENINs each cover `eninSeconds` consecutive Unix seconds,
  /// so the registry's inclusive Unix-second window is converted to the same inclusive ENIN shape
  /// conservatively (start rounded up, end rounded down) before the envelope's window is tested
  /// for containment in it. A registry window that does not fall on ENIN boundaries converts to an
  /// empty range and still agrees with nothing: containment also requires the envelope's own window
  /// to be well formed (`validFromEnin <= validThroughEnin`), so the chain `registryStart <=
  /// validFromEnin <= validThroughEnin <= registryEnd` is unsatisfiable whenever `registryEnd <
  /// registryStart`. Under equality that emptiness argument needed nothing from the envelope; under
  /// containment it does, so well-formedness is re-checked here rather than inherited from
  /// `verify`'s `validFromEnin <= currentEnin < relayExpiresAtEnin <= validThroughEnin` -- the same
  /// defense-in-depth footing as the `eninSeconds <= 0` rejection below.
  ///
  /// The conversion is `expectedFrom = ceilDiv(validFromUnixSeconds, eninSeconds)` and
  /// `expectedThrough = floorDiv(validUntilUnixSeconds + 1, eninSeconds) - 1` (spec 122 erratum for
  /// the issuer-side derivation; see barnard#180). `expectedThrough` is computed without ever
  /// forming `validUntilUnixSeconds + 1`, so it stays overflow-safe for an adversarial registry
  /// read. A registry definition with `validFromUnixSeconds < 0`, `validUntilUnixSeconds < 0`,
  /// `validFromUnixSeconds > validUntilUnixSeconds`, or `eninSeconds <= 0` is rejected as a
  /// `.VALIDITY_WINDOW` mismatch before any of this arithmetic runs, so every input to it stays
  /// non-negative and the conversion never negates `Int64.min` (which traps in Swift).
  public static func registryAgreement(_ verified: BarnardB005VerifiedEnvelope, definition: BarnardEventDefinitionV1) -> BarnardRegistryAgreement {
    let eninPerSecond = Int64(verified.eninSeconds)
    let validFrom = definition.validFromUnixSeconds
    let validUntil = definition.validUntilUnixSeconds
    let windowIsWellFormed = eninPerSecond > 0 && validFrom >= 0 && validUntil >= 0 && validFrom <= validUntil
    let registryStartEnin: Int64? = windowIsWellFormed ? -floorDiv(-validFrom, eninPerSecond) : nil
    let registryEndEnin: Int64? = windowIsWellFormed ? {
      // expectedThrough = floorDiv(validUntil + 1, eninPerSecond) - 1, via the floorMod identity
      // (see the Kotlin counterpart's comment) so validUntil + 1 is never actually formed.
      let q = floorDiv(validUntil, eninPerSecond)
      let r = floorMod(validUntil, eninPerSecond)
      return r == eninPerSecond - 1 ? q : q - 1
    }() : nil
    var mismatches: Set<BarnardRegistryMismatchField> = []
    if verified.eventId != definition.eventId { mismatches.insert(.EVENT_ID) }
    if verified.eventCodeHash != definition.eventCodeHash { mismatches.insert(.EVENT_CODE_HASH) }
    if verified.keySetDigest != definition.keySetDigest { mismatches.insert(.KEY_SET_DIGEST) }
    if verified.joinMode != definition.joinMode { mismatches.insert(.JOIN_MODE) }
    let windowIsContained: Bool
    if let registryStart = registryStartEnin, let registryEnd = registryEndEnin {
      windowIsContained = verified.validFromEnin <= verified.validThroughEnin
        && registryStart <= verified.validFromEnin
        && verified.validThroughEnin <= registryEnd
    } else {
      windowIsContained = false
    }
    if !windowIsContained { mismatches.insert(.VALIDITY_WINDOW) }
    return mismatches.isEmpty ? .agrees : .mismatched(mismatchedFields: mismatches)
  }

  /// Floor division for `Int64`, matching Kotlin's `Math.floorDiv`: rounds toward negative
  /// infinity rather than toward zero (Swift's `/` truncates toward zero).
  private static func floorDiv(_ a: Int64, _ b: Int64) -> Int64 {
    let q = a / b, r = a % b
    return (r != 0 && (r < 0) != (b < 0)) ? q - 1 : q
  }

  /// Floor modulo for `Int64`, matching Kotlin's `Math.floorMod`: the result always has the same
  /// sign as `b` (Swift's `%` can return a negative remainder for a positive `b`).
  private static func floorMod(_ a: Int64, _ b: Int64) -> Int64 {
    let r = a % b
    return (r != 0 && (r < 0) != (b < 0)) ? r + b : r
  }

  public static func buildSigStructure(protected: [UInt8], payload: [UInt8]) -> [UInt8]? {
    guard let p = cborBytes(protected), let pl = cborBytes(payload) else { return nil }
    return [0x84, 0x6a] + Array("Signature1".utf8) + p + [0x40] + pl
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
      p.uint() == 5, let start = p.uint(), start <= 9_007_199_254_740_991,
      p.uint() == 6, let end = p.uint(), end <= 9_007_199_254_740_991, start <= end, p.finished else { return nil }
    return Cert(protected: protected, payload: payload, signature: signature, kid: kid, eventId: eventId, delegateKey: delegate, roles: roles, eninStart: start, eninEnd: end)
  }

  // secp256k1 group order n, and n/2 (BIP-62/146 low-S bound), both big-endian.
  private static let curveOrder: [UInt8] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
  ]
  private static let curveOrderHalf: [UInt8] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
  ]

  private static func isZero(_ b: [UInt8]) -> Bool { b.allSatisfy { $0 == 0 } }

  /// Enforces `0 < r < N` and `0 < s <= N/2` independent of the injected recoverer: the public
  /// `BarnardB005PublicKeyRecovering` protocol carries no contract that a conforming backend
  /// rejects a high-S or out-of-range signature on its own, so this MUST be checked here.
  private static func isLowSInRange(r: [UInt8], s: [UInt8]) -> Bool {
    !isZero(r) && lexicographicallyLess(r, curveOrder)
      && !isZero(s) && !lexicographicallyLess(curveOrderHalf, s)
  }

  private static func signatureMatches(_ signature: [UInt8], digest: [UInt8], key: [UInt8], recoverer: any BarnardB005PublicKeyRecovering, hasRecoveryByte: Bool) -> Bool {
    guard signature.count == (hasRecoveryByte ? 65 : 64) else { return false }
    let r = Array(signature[0..<32]), s = Array(signature[32..<64])
    guard isLowSInRange(r: r, s: s) else { return false }
    if hasRecoveryByte {
      let v = Int(signature[64]); guard v <= 1 else { return false }
      return recoverer.recover(recoveryId: v, r: r, s: s, digest: digest) == key
    }
    return (0...1).contains { recoverer.recover(recoveryId: $0, r: r, s: s, digest: digest) == key }
  }

  /// Recovers the signer exactly once (the recovery id is carried in the signature, so there is
  /// no ambiguity to resolve by trying candidates), then tests set membership on the result.
  private static func recoverMember(_ signature: [UInt8], digest: [UInt8], keys: [[UInt8]], recoverer: any BarnardB005PublicKeyRecovering) -> [UInt8]? {
    guard signature.count == 65 else { return nil }
    let r = Array(signature[0..<32]), s = Array(signature[32..<64])
    guard isLowSInRange(r: r, s: s) else { return nil }
    let v = Int(signature[64]); guard v <= 1 else { return nil }
    guard let recovered = recoverer.recover(recoveryId: v, r: r, s: s, digest: digest) else { return nil }
    return keys.contains(recovered) ? recovered : nil
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
  private static func cborBytes(_ b: [UInt8]) -> [UInt8]? {
    switch b.count {
    case 0..<24: return [0x40 | UInt8(b.count)] + b
    case 24..<256: return [0x58, UInt8(b.count)] + b
    case 256..<65536: return [0x59, UInt8(b.count >> 8), UInt8(b.count & 0xff)] + b
    default: return nil
    }
  }
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
