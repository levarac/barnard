// Use of this source code is governed by a BSD-style license.

import Barnard
import BarnardCore
import Foundation

/// Everything a caller supplies to produce one signed B005 v2 envelope. Field names mirror
/// `BarnardB005EnvelopeFields`; byte values travel as lowercase hex because this is the shape a
/// CLI JSON input or a ceremony handoff file naturally takes.
///
/// This type carries no defaults for `registrar` / `anchorOperator` / `nonce` / `authorityKeys`:
/// those come from wherever the real ceremony (parallax#83, not yet built) or a test fixture
/// puts them. `VenueEnvelopeProducer` does not invent any of them.
public struct VenueEnvelopeProducerInput: Decodable, Equatable {
  /// 20-byte registrar identifier, hex.
  public let registrarHex: String
  /// 20-byte anchor operator identifier, hex.
  public let anchorOperatorHex: String
  /// 32-byte event nonce, hex.
  public let nonceHex: String
  /// 1...8 compressed secp256k1 authority public keys, hex, strictly ascending.
  public let authorityKeysHex: [String]
  /// The 32-byte private key, hex, for whichever `authorityKeysHex` entry signs this envelope.
  /// This is the ceremony's throwaway authority key in the real deployment (beid#432): the venue
  /// device itself holds no key.
  public let signingPrivateKeyHex: String
  /// 0 = open, 1 = gated (`BarnardB005EnvelopeFields.joinMode`).
  public let joinMode: UInt8
  public let eninSeconds: UInt16
  public let validFromEnin: UInt32
  public let validThroughEnin: UInt32
  public let relayExpiresAtEnin: UInt32
  /// Required when `joinMode == 1` (gated); ignored when `joinMode == 0`, because open mode's
  /// event-code-hash is derived from `eventId`, not supplied -- see `openEventCodeHash`.
  public let eventCodeHashHex: String?
  public let eventDisplayName: String
  /// 0...2, per spec 134's relay hop bound. A freshly issued envelope is hop 0.
  public let relayHopCount: UInt8

  public init(registrarHex: String, anchorOperatorHex: String, nonceHex: String, authorityKeysHex: [String], signingPrivateKeyHex: String, joinMode: UInt8, eninSeconds: UInt16, validFromEnin: UInt32, validThroughEnin: UInt32, relayExpiresAtEnin: UInt32, eventCodeHashHex: String?, eventDisplayName: String, relayHopCount: UInt8) {
    self.registrarHex = registrarHex
    self.anchorOperatorHex = anchorOperatorHex
    self.nonceHex = nonceHex
    self.authorityKeysHex = authorityKeysHex
    self.signingPrivateKeyHex = signingPrivateKeyHex
    self.joinMode = joinMode
    self.eninSeconds = eninSeconds
    self.validFromEnin = validFromEnin
    self.validThroughEnin = validThroughEnin
    self.relayExpiresAtEnin = relayExpiresAtEnin
    self.eventCodeHashHex = eventCodeHashHex
    self.eventDisplayName = eventDisplayName
    self.relayHopCount = relayHopCount
  }
}

public enum VenueEnvelopeProducerError: Error, Equatable, CustomStringConvertible {
  case invalidHex(field: String)
  case signingKeyNotAnAuthorityKey
  case gatedModeRequiresEventCodeHash
  case derivationFailed
  case encode(BarnardB005EncodeError)
  case assemble(BarnardB005EncodeError)
  case containerTooLarge

  public var description: String {
    switch self {
    case .invalidHex(let field): return "invalid hex in field '\(field)'"
    case .signingKeyNotAnAuthorityKey: return "signingPrivateKeyHex does not correspond to any key in authorityKeysHex"
    case .gatedModeRequiresEventCodeHash: return "joinMode == 1 (gated) requires eventCodeHashHex"
    case .derivationFailed: return "computeEventId/keySetDigest failed -- check authorityKeysHex/registrarHex/anchorOperatorHex/nonceHex lengths"
    case .encode(let e): return "encodeUnsignedEnvelope refused: \(e)"
    case .assemble(let e): return "assembleSignedEnvelope refused: \(e)"
    case .containerTooLarge: return "encodeContainer refused (signed envelope exceeds 508 bytes)"
    }
  }
}

/// The real product of this tool: `container` is the exact byte sequence a venue device
/// broadcasts, and `eventId` / `signerPublicKeyHex` are surfaced so a caller (or a test) can
/// cross-check the result without re-deriving it by hand.
public struct VenueEnvelopeProducerOutput {
  public let container: [UInt8]
  public let eventId: [UInt8]
  public let signerPublicKeyHex: String
}

/// Runs the exact four-call chain `BarnardB005EnvelopeV2.encodeUnsignedEnvelope` ->
/// `BarnardCoreSigning.signRecoverable` -> `BarnardB005EnvelopeV2.assembleSignedEnvelope` ->
/// `BarnardB005EnvelopeV2.encodeContainer`, so both the CLI entry point and the test suite drive
/// the identical code path.
///
/// Two things this deliberately does NOT do, because getting them wrong silently produces an
/// envelope no real device accepts: it passes `signatureDigest` straight to `signRecoverable`
/// without re-hashing it, and it never touches `computeEip191Digest` or `buildSigStructure` --
/// those belong to unrelated signing paths (EIP-191 messages, and the delegation-certificate COSE
/// structure), not to a B005 v2 envelope signed authority-direct.
public enum VenueEnvelopeProducer {
  public static func produce(_ input: VenueEnvelopeProducerInput) -> Result<VenueEnvelopeProducerOutput, VenueEnvelopeProducerError> {
    guard let registrar = hex(input.registrarHex) else { return .failure(.invalidHex(field: "registrarHex")) }
    guard let anchorOperator = hex(input.anchorOperatorHex) else { return .failure(.invalidHex(field: "anchorOperatorHex")) }
    guard let nonce = hex(input.nonceHex) else { return .failure(.invalidHex(field: "nonceHex")) }
    guard let authorityKeys = optionalMap(input.authorityKeysHex, hex) else { return .failure(.invalidHex(field: "authorityKeysHex")) }
    guard let signingPrivateKey = hex(input.signingPrivateKeyHex) else { return .failure(.invalidHex(field: "signingPrivateKeyHex")) }

    // The signer must be one of the embedded authority keys, or `verify` will recover a key that
    // matches nothing in the envelope and reject -- catch that here with a named error rather
    // than let it surface as an opaque `.encode`/`.assemble` success followed by a verify failure.
    guard signingPrivateKey.count == 32 else { return .failure(.invalidHex(field: "signingPrivateKeyHex")) }
    guard let signerPublicKey = compressedPublicKey(fromPrivateKey: signingPrivateKey) else {
      return .failure(.invalidHex(field: "signingPrivateKeyHex"))
    }
    guard authorityKeys.contains(signerPublicKey) else { return .failure(.signingKeyNotAnAuthorityKey) }

    let recoverer = BarnardB005NativeRecoverer()
    guard let keySet = BarnardB005EnvelopeV2.keySetDigest(authorityKeys),
          let eventId = BarnardB005EnvelopeV2.computeEventId(registrar: registrar, anchorOperator: anchorOperator, nonce: nonce, keySetDigest: keySet)
    else { return .failure(.derivationFailed) }

    let eventCodeHash: [UInt8]
    if input.joinMode == 0 {
      guard let derived = BarnardB005EnvelopeV2.openEventCodeHash(eventId: eventId) else { return .failure(.derivationFailed) }
      eventCodeHash = derived
    } else {
      guard let suppliedHex = input.eventCodeHashHex, let supplied = hex(suppliedHex) else {
        return .failure(.gatedModeRequiresEventCodeHash)
      }
      eventCodeHash = supplied
    }

    let fields = BarnardB005EnvelopeFields(
      registrar: registrar,
      anchorOperator: anchorOperator,
      nonce: nonce,
      authorityKeys: authorityKeys,
      joinMode: input.joinMode,
      eninSeconds: input.eninSeconds,
      validFromEnin: input.validFromEnin,
      validThroughEnin: input.validThroughEnin,
      relayExpiresAtEnin: input.relayExpiresAtEnin,
      eventCodeHash: eventCodeHash,
      eventDisplayName: input.eventDisplayName
      // delegationCert defaults to [] -- authority-direct mode, per the design's venue device
      // holding no key (beid#432) and parallax/protocol/spec/v0.1/venue-bundle.md:75-78.
    )

    let unsigned: BarnardB005UnsignedEnvelope
    switch BarnardB005EnvelopeV2.encodeUnsignedEnvelope(fields, nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: recoverer) {
    case .failure(let e): return .failure(.encode(e))
    case .success(let u): unsigned = u
    }

    // Pass signatureDigest straight through -- it is already SHA256("barnard-b005-event-info:v1"
    // || tbs). Re-hashing it, or routing through computeEip191Digest, would sign a different
    // message than `verify` checks against and produce bytes no real device accepts.
    let signature = BarnardCoreSigning.signRecoverable(privateKey: signingPrivateKey, messageHash32: unsigned.signatureDigest)
    // r || s || v: the one piece of glue `assembleSignedEnvelope` leaves to the caller. `v` here
    // is the bare recovery id (0 or 1, per signRecoverable's low-S normalization) -- NOT the
    // Ethereum-style `v + 27` the EIP-191 signing paths elsewhere in this SDK use.
    let signature65 = signature.r + signature.s + [UInt8(signature.v)]

    let signed: [UInt8]
    switch BarnardB005EnvelopeV2.assembleSignedEnvelope(toBeSigned: unsigned.toBeSigned, signature: signature65) {
    case .failure(let e): return .failure(.assemble(e))
    case .success(let s): signed = s
    }

    guard let container = BarnardB005EnvelopeV2.encodeContainer(relayHopCount: input.relayHopCount, signedEnvelope: signed) else {
      return .failure(.containerTooLarge)
    }

    return .success(VenueEnvelopeProducerOutput(container: container, eventId: eventId, signerPublicKeyHex: hexString(signerPublicKey)))
  }

  /// Recomputes the compressed public key for a raw 32-byte private key. BarnardCore exposes no
  /// direct "scalar -> compressed point" function outside its own module, so this derives it the
  /// same way a receiver would confirm a signer's identity: sign a probe digest and recover the
  /// signing key from the resulting `(r, s, v)`, using only BarnardCoreSigning's public surface
  /// (`signRecoverable` + `recoverPublicKey`).
  ///
  /// Public because any real caller assembling `authorityKeysHex` for a given
  /// `signingPrivateKeyHex` needs this too -- it is not test-only.
  public static func compressedPublicKey(fromPrivateKey privateKey: [UInt8]) -> [UInt8]? {
    guard privateKey.count == 32 else { return nil }
    let probeDigest = BarnardCoreCrypto.sha256(Array("venue-envelope-producer:pubkey-probe:v1".utf8))
    let probeSignature = BarnardCoreSigning.signRecoverable(privateKey: privateKey, messageHash32: probeDigest)
    return BarnardCoreSigning.recoverPublicKey(recoveryId: probeSignature.v, r: probeSignature.r, s: probeSignature.s, messageHash32: probeDigest)
  }

  /// Hex convenience over `compressedPublicKey(fromPrivateKey:)`.
  public static func derivePublicKeyHex(fromPrivateKeyHex privateKeyHex: String) -> String? {
    guard let privateKey = hex(privateKeyHex), let publicKey = compressedPublicKey(fromPrivateKey: privateKey) else { return nil }
    return hexString(publicKey)
  }
}

private func hex(_ s: String) -> [UInt8]? {
  guard s.count % 2 == 0 else { return nil }
  var out: [UInt8] = []
  out.reserveCapacity(s.count / 2)
  var index = s.startIndex
  while index < s.endIndex {
    let next = s.index(index, offsetBy: 2)
    guard let byte = UInt8(s[index..<next], radix: 16) else { return nil }
    out.append(byte)
    index = next
  }
  return out
}

private func hexString(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

private func optionalMap<T>(_ values: [String], _ transform: (String) -> [T]?) -> [[T]]? {
  var out: [[T]] = []
  out.reserveCapacity(values.count)
  for value in values {
    guard let mapped = transform(value) else { return nil }
    out.append(mapped)
  }
  return out
}
