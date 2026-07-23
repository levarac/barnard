// Use of this source code is governed by a BSD-style license.

import CryptoKit
import XCTest
@testable import Barnard

final class BarnardSigningTests: XCTestCase {
  func testDeriveSigningKeyPairIsDeterministic() {
    let secret = Data(repeating: 0x21, count: 32)
    let pair1 = BarnardSigning.deriveSigningKeyPair(deviceSecret: secret, eventCode: "EVT1")
    let pair2 = BarnardSigning.deriveSigningKeyPair(deviceSecret: secret, eventCode: "EVT1")
    XCTAssertEqual(pair1.publicKeyCompressed, pair2.publicKeyCompressed)
    XCTAssertEqual(pair1.privateKey.data, pair2.privateKey.data)
    XCTAssertEqual(pair1.publicKeyCompressed.count, 33)
  }

  func testDeriveSigningKeyPairDiffersFromTekChain() {
    // barnard#65: "barnard-sign" HKDF info must not be cross-computable
    // from the TEK chain ("barnard-tek" / "EN-RPIK").
    let secret = Data(repeating: 0x22, count: 32)
    let signingKeyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: secret, eventCode: "EVT1")
    let tek = BarnardCrypto.deriveTekForEvent(deviceSecret: secret, eventCode: "EVT1")
    XCTAssertNotEqual(signingKeyPair.privateKey.data, tek)
  }

  func testSignRecoverableRoundTripsThroughRecoverPublicKey() {
    let secret = Data(repeating: 0x23, count: 32)
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: secret, eventCode: "EVT1")
    let messageHash = Data(SHA256.hash(data: Data("hello barnard".utf8)))

    let sig = BarnardSigning.signRecoverable(privateKey: keyPair.privateKey, messageHash32: messageHash)
    let recovered = BarnardSigning.recoverPublicKey(
      recId: sig.v,
      r: Secp256k1.UInt256(data: sig.r),
      s: Secp256k1.UInt256(data: sig.s),
      messageHash32: messageHash
    )

    XCTAssertEqual(recovered, keyPair.publicKeyCompressed)
  }

  func testSignRecoverableProducesLowSSignatures() {
    let secret = Data(repeating: 0x24, count: 32)
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: secret, eventCode: "EVT1")
    let messageHash = Data(SHA256.hash(data: Data("canonical low-s check".utf8)))

    let sig = BarnardSigning.signRecoverable(privateKey: keyPair.privateKey, messageHash32: messageHash)
    let s = Secp256k1.UInt256(data: sig.s)
    let halfOrder = Secp256k1.N.shiftedRight1()
    XCTAssertFalse(s > halfOrder, "signature must be normalized to the lower half of the curve order")
  }

  func testProveRpidOwnershipEmbedsMatchingRpiAndVerifies() {
    let secret = Data(repeating: 0x25, count: 32)
    let eventIdHash = Data(SHA256.hash(data: Data("event-id".utf8)))

    let proof = BarnardSigning.proveRpidOwnership(
      deviceSecret: secret,
      eventCode: "EVT1",
      eventIdHash: eventIdHash,
      enin: 12345,
      challenge: nil
    )

    // The proof's RPI must match independently-derived TEK/RPIK/RPI for the
    // same (deviceSecret, eventCode, enin).
    let tek = BarnardCrypto.deriveTekForEvent(deviceSecret: secret, eventCode: "EVT1")
    let rpik = BarnardCrypto.deriveRpik(from: tek)
    let expectedRpi = BarnardCrypto.generateRpi(rpik: rpik, enin: UInt32(truncatingIfNeeded: UInt64(12345)))
    XCTAssertEqual(proof.rpi, expectedRpi)

    let message = BarnardSigning.buildRpidProofMessage(
      eventIdHash: eventIdHash,
      enin: 12345,
      rpi: proof.rpi,
      challenge: nil
    )
    let messageHash = Data(SHA256.hash(data: message))
    let recovered = BarnardSigning.recoverPublicKey(
      recId: proof.sig.v,
      r: Secp256k1.UInt256(data: proof.sig.r),
      s: Secp256k1.UInt256(data: proof.sig.s),
      messageHash32: messageHash
    )
    XCTAssertEqual(recovered, proof.signingPublicKey)
  }

  func testSignKeyBindingVerifiesAgainstSigningPublicKey() {
    let secret = Data(repeating: 0x26, count: 32)
    let eventCodeHash = BarnardCrypto.computeEventCodeHash("EVT1")
    let displayId = Data(repeating: 0xAA, count: 4)

    let sig = BarnardSigning.signKeyBinding(
      deviceSecret: secret,
      eventCode: "EVT1",
      eventCodeHash: eventCodeHash,
      displayId: displayId
    )
    let keyPair = BarnardSigning.deriveSigningKeyPair(deviceSecret: secret, eventCode: "EVT1")

    let message = BarnardSigning.buildKeyBindingMessage(eventCodeHash: eventCodeHash, displayId: displayId)
    let messageHash = Data(SHA256.hash(data: message))
    let recovered = BarnardSigning.recoverPublicKey(
      recId: sig.v,
      r: Secp256k1.UInt256(data: sig.r),
      s: Secp256k1.UInt256(data: sig.s),
      messageHash32: messageHash
    )
    XCTAssertEqual(recovered, keyPair.publicKeyCompressed)
  }

  // MARK: - BarnardIdentity (public, Flutter-free API)

  func testBarnardIdentitySignAndProveRoundTrip() {
    UserDefaults.standard.removeObject(forKey: "barnard.rpidSeed")
    let identity = BarnardIdentity()

    let publicKey = identity.signingPublicKey(eventCode: "EVT1")
    XCTAssertEqual(publicKey.count, 33)

    let sig = identity.sign(eventCode: "EVT1", bytes: Data("payload".utf8))
    XCTAssertEqual(sig.r.count, 32)
    XCTAssertEqual(sig.s.count, 32)

    let eventIdHash = Data(SHA256.hash(data: Data("event".utf8)))
    let proof = identity.proveRpidOwnership(eventCode: "EVT1", enin: 100, eventIdHash: eventIdHash)
    XCTAssertEqual(proof.signingPublicKey, publicKey)
    XCTAssertEqual(proof.rpi.count, 16)
  }
}
