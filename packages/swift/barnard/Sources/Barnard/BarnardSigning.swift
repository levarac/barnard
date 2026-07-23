// Use of this source code is governed by a BSD-style license.

#if canImport(BarnardCore)
import BarnardCore
#endif
import Foundation

/// `Data`-based compatibility adapters for signing math in `BarnardCore`.
enum BarnardSigning {
  static let signingKeyInfo = BarnardCoreSigning.signingKeyInfo
  static let rpidProofDomainTag = BarnardCoreSigning.rpidProofDomainTag
  static let keyBindingDomainTag = BarnardCoreSigning.keyBindingDomainTag

  struct SigningKeyPair {
    let privateKey: Secp256k1.UInt256
    let publicKeyCompressed: Data
  }

  struct RecoverableSignature {
    let r: Data
    let s: Data
    let v: Int
  }

  struct RpidOwnershipProof {
    let rpi: Data
    let enin: UInt64
    let eventIdHash: Data
    let signingPublicKey: Data
    let sig: RecoverableSignature
  }

  static func deriveSigningKeyPair(
    deviceSecret: Data,
    eventCode: String
  ) -> SigningKeyPair {
    let keyPair = BarnardCoreSigning.deriveSigningKeyPair(
      deviceSecret: Array(deviceSecret),
      eventCode: eventCode
    )
    return SigningKeyPair(
      privateKey: Secp256k1.UInt256(bytes: keyPair.privateKey),
      publicKeyCompressed: Data(keyPair.publicKeyCompressed)
    )
  }

  static func signRecoverable(
    privateKey: Secp256k1.UInt256,
    messageHash32: Data
  ) -> RecoverableSignature {
    adapt(BarnardCoreSigning.signRecoverable(
      privateKey: privateKey.bytes,
      messageHash32: Array(messageHash32)
    ))
  }

  static func recoverPublicKey(
    recId: Int,
    r: Secp256k1.UInt256,
    s: Secp256k1.UInt256,
    messageHash32: Data
  ) -> Data? {
    BarnardCoreSigning.recoverPublicKey(
      recoveryId: recId,
      r: r.bytes,
      s: s.bytes,
      messageHash32: Array(messageHash32)
    ).map { Data($0) }
  }

  static func buildRpidProofMessage(
    eventIdHash: Data,
    enin: UInt64,
    rpi: Data,
    challenge: Data?
  ) -> Data {
    Data(BarnardCoreSigning.buildRpidProofMessage(
      eventIdHash: Array(eventIdHash),
      enin: enin,
      rpi: Array(rpi),
      challenge: challenge.map(Array.init)
    ))
  }

  static func buildKeyBindingMessage(eventCodeHash: Data, displayId: Data) -> Data {
    Data(BarnardCoreSigning.buildKeyBindingMessage(
      eventCodeHash: Array(eventCodeHash),
      displayId: Array(displayId)
    ))
  }

  static func proveRpidOwnership(
    deviceSecret: Data,
    eventCode: String,
    eventIdHash: Data,
    enin: UInt64,
    challenge: Data?
  ) -> RpidOwnershipProof {
    let proof = BarnardCoreSigning.proveRpidOwnership(
      deviceSecret: Array(deviceSecret),
      eventCode: eventCode,
      eventIdHash: Array(eventIdHash),
      enin: enin,
      challenge: challenge.map(Array.init)
    )
    return RpidOwnershipProof(
      rpi: Data(proof.rpi),
      enin: proof.enin,
      eventIdHash: Data(proof.eventIdHash),
      signingPublicKey: Data(proof.signingPublicKey),
      sig: adapt(proof.signature)
    )
  }

  static func signKeyBinding(
    deviceSecret: Data,
    eventCode: String,
    eventCodeHash: Data,
    displayId: Data
  ) -> RecoverableSignature {
    adapt(BarnardCoreSigning.signKeyBinding(
      deviceSecret: Array(deviceSecret),
      eventCode: eventCode,
      eventCodeHash: Array(eventCodeHash),
      displayId: Array(displayId)
    ))
  }

  private static func adapt(
    _ signature: BarnardCoreRecoverableSignature
  ) -> RecoverableSignature {
    RecoverableSignature(
      r: Data(signature.r),
      s: Data(signature.s),
      v: signature.v
    )
  }
}
