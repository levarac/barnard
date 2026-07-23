// Use of this source code is governed by a BSD-style license.

public struct BarnardCoreSigningKeyPair {
  public let privateKey: [UInt8]
  public let publicKeyCompressed: [UInt8]
}

public struct BarnardCoreRecoverableSignature {
  public let r: [UInt8]
  public let s: [UInt8]
  public let v: Int
}

public struct BarnardCoreRpidOwnershipProof {
  public let rpi: [UInt8]
  public let enin: UInt64
  public let eventIdHash: [UInt8]
  public let signingPublicKey: [UInt8]
  public let signature: BarnardCoreRecoverableSignature
}

public enum BarnardCoreSigning {
  public static let signingKeyInfo = "barnard-sign"
  public static let rpidProofDomainTag = "barnard-rpid-proof:v1"
  public static let keyBindingDomainTag = "barnard-key-binding:v1"

  public static func deriveSigningKeyPair(
    deviceSecret: [UInt8],
    eventCode: String
  ) -> BarnardCoreSigningKeyPair {
    var seed = BarnardCorePrimitives.hkdfSha256(
      inputKeyMaterial: deviceSecret + Array(eventCode.utf8),
      info: Array(signingKeyInfo.utf8),
      outputByteCount: 32
    )
    var privateKey = BarnardCoreSecp256k1.Field.reduceOnce(
      BarnardCoreSecp256k1.UInt256(bytes: seed),
      BarnardCoreSecp256k1.curveOrder
    )
    while privateKey.isZero {
      seed = BarnardCorePrimitives.sha256(seed)
      privateKey = BarnardCoreSecp256k1.Field.reduceOnce(
        BarnardCoreSecp256k1.UInt256(bytes: seed),
        BarnardCoreSecp256k1.curveOrder
      )
    }
    let publicPoint = BarnardCoreSecp256k1.multiply(
      privateKey,
      BarnardCoreSecp256k1.generator
    )
    return BarnardCoreSigningKeyPair(
      privateKey: privateKey.bytes,
      publicKeyCompressed: BarnardCoreSecp256k1.compress(publicPoint)
    )
  }

  public static func signRecoverable(
    privateKey: [UInt8],
    messageHash32: [UInt8]
  ) -> BarnardCoreRecoverableSignature {
    precondition(privateKey.count == 32, "privateKey must be 32 bytes")
    precondition(messageHash32.count == 32, "messageHash must be 32 bytes")

    let privateScalar = BarnardCoreSecp256k1.UInt256(bytes: privateKey)
    let messageScalar = BarnardCoreSecp256k1.Field.reduceOnce(
      BarnardCoreSecp256k1.UInt256(bytes: messageHash32),
      BarnardCoreSecp256k1.curveOrder
    )
    let expectedPublicKey = BarnardCoreSecp256k1.compress(
      BarnardCoreSecp256k1.multiply(privateScalar, BarnardCoreSecp256k1.generator)
    )

    var r = BarnardCoreSecp256k1.UInt256.zero
    var s = BarnardCoreSecp256k1.UInt256.zero
    while true {
      let nonce = deterministicNonce(
        privateKey: privateScalar,
        messageHash32: messageHash32
      )
      let noncePoint = BarnardCoreSecp256k1.multiply(
        nonce,
        BarnardCoreSecp256k1.generator
      )
      guard let nonceX = noncePoint.x else {
        continue
      }
      r = BarnardCoreSecp256k1.Field.reduceOnce(
        nonceX,
        BarnardCoreSecp256k1.curveOrder
      )
      if r.isZero {
        continue
      }
      let nonceInverse = BarnardCoreSecp256k1.Field.inverseMod(
        nonce,
        BarnardCoreSecp256k1.curveOrder
      )
      s = BarnardCoreSecp256k1.Field.multiplyMod(
        nonceInverse,
        BarnardCoreSecp256k1.Field.addMod(
          messageScalar,
          BarnardCoreSecp256k1.Field.multiplyMod(
            privateScalar,
            r,
            BarnardCoreSecp256k1.curveOrder
          ),
          BarnardCoreSecp256k1.curveOrder
        ),
        BarnardCoreSecp256k1.curveOrder
      )
      if s.isZero {
        continue
      }
      break
    }

    let halfOrder = BarnardCoreSecp256k1.curveOrder.shiftedRight1()
    if s > halfOrder {
      s = BarnardCoreSecp256k1.curveOrder.subtracting(s)
    }

    var recoveryId = -1
    for candidate in 0..<4 {
      if recoverPublicKey(
        recoveryId: candidate,
        r: r.bytes,
        s: s.bytes,
        messageHash32: messageHash32
      ) == expectedPublicKey {
        recoveryId = candidate
        break
      }
    }
    precondition(recoveryId != -1, "could not determine recovery id")

    return BarnardCoreRecoverableSignature(
      r: r.bytes,
      s: s.bytes,
      v: recoveryId
    )
  }

  public static func recoverPublicKey(
    recoveryId: Int,
    r: [UInt8],
    s: [UInt8],
    messageHash32: [UInt8]
  ) -> [UInt8]? {
    guard recoveryId / 2 == 0, r.count == 32, s.count == 32, messageHash32.count == 32 else {
      return nil
    }
    let rScalar = BarnardCoreSecp256k1.UInt256(bytes: r)
    let sScalar = BarnardCoreSecp256k1.UInt256(bytes: s)
    if rScalar >= BarnardCoreSecp256k1.fieldPrime {
      return nil
    }
    guard let rPoint = BarnardCoreSecp256k1.decompress(
      x: rScalar,
      yIsOdd: (recoveryId & 1) == 1
    ) else {
      return nil
    }

    let messageScalar = BarnardCoreSecp256k1.Field.reduceOnce(
      BarnardCoreSecp256k1.UInt256(bytes: messageHash32),
      BarnardCoreSecp256k1.curveOrder
    )
    let negativeMessage = BarnardCoreSecp256k1.curveOrder.subtracting(messageScalar)
    let rInverse = BarnardCoreSecp256k1.Field.inverseMod(
      rScalar,
      BarnardCoreSecp256k1.curveOrder
    )
    let signatureFactor = BarnardCoreSecp256k1.Field.multiplyMod(
      rInverse,
      sScalar,
      BarnardCoreSecp256k1.curveOrder
    )
    let messageFactor = BarnardCoreSecp256k1.Field.multiplyMod(
      rInverse,
      negativeMessage,
      BarnardCoreSecp256k1.curveOrder
    )
    let generatorTerm = BarnardCoreSecp256k1.multiply(
      messageFactor,
      BarnardCoreSecp256k1.generator
    )
    let signatureTerm = BarnardCoreSecp256k1.multiply(signatureFactor, rPoint)
    let publicPoint = BarnardCoreSecp256k1.add(generatorTerm, signatureTerm)
    if publicPoint.isInfinity {
      return nil
    }
    return BarnardCoreSecp256k1.compress(publicPoint)
  }

  public static func buildRpidProofMessage(
    eventIdHash: [UInt8],
    enin: UInt64,
    rpi: [UInt8],
    challenge: [UInt8]?
  ) -> [UInt8] {
    precondition(eventIdHash.count == 32, "eventIdHash must be 32 bytes")
    precondition(rpi.count == 16, "rpi must be 16 bytes")
    let challengeBytes = challenge ?? []
    precondition(challengeBytes.count <= 0xffff, "challenge too long")

    var message = Array(rpidProofDomainTag.utf8)
    message += eventIdHash
    for shift in stride(from: 56, through: 0, by: -8) {
      message.append(UInt8((enin >> UInt64(shift)) & 0xff))
    }
    message += rpi
    let challengeCount = UInt16(challengeBytes.count)
    message.append(UInt8((challengeCount >> 8) & 0xff))
    message.append(UInt8(challengeCount & 0xff))
    message += challengeBytes
    return message
  }

  public static func buildKeyBindingMessage(
    eventCodeHash: [UInt8],
    displayId: [UInt8]
  ) -> [UInt8] {
    Array(keyBindingDomainTag.utf8) + eventCodeHash + displayId
  }

  public static func proveRpidOwnership(
    deviceSecret: [UInt8],
    eventCode: String,
    eventIdHash: [UInt8],
    enin: UInt64,
    challenge: [UInt8]?
  ) -> BarnardCoreRpidOwnershipProof {
    let tek = BarnardCoreCrypto.deriveTekForEvent(
      deviceSecret: deviceSecret,
      eventCode: eventCode
    )
    let rpik = BarnardCoreCrypto.deriveRpik(from: tek)
    let rpi = BarnardCoreCrypto.generateRpi(
      rpik: rpik,
      enin: UInt32(truncatingIfNeeded: enin)
    )
    let message = buildRpidProofMessage(
      eventIdHash: eventIdHash,
      enin: enin,
      rpi: rpi,
      challenge: challenge
    )
    let keyPair = deriveSigningKeyPair(
      deviceSecret: deviceSecret,
      eventCode: eventCode
    )
    let signature = signRecoverable(
      privateKey: keyPair.privateKey,
      messageHash32: BarnardCorePrimitives.sha256(message)
    )
    return BarnardCoreRpidOwnershipProof(
      rpi: rpi,
      enin: enin,
      eventIdHash: eventIdHash,
      signingPublicKey: keyPair.publicKeyCompressed,
      signature: signature
    )
  }

  public static func signKeyBinding(
    deviceSecret: [UInt8],
    eventCode: String,
    eventCodeHash: [UInt8],
    displayId: [UInt8]
  ) -> BarnardCoreRecoverableSignature {
    let message = buildKeyBindingMessage(
      eventCodeHash: eventCodeHash,
      displayId: displayId
    )
    let keyPair = deriveSigningKeyPair(
      deviceSecret: deviceSecret,
      eventCode: eventCode
    )
    return signRecoverable(
      privateKey: keyPair.privateKey,
      messageHash32: BarnardCorePrimitives.sha256(message)
    )
  }

  private static func deterministicNonce(
    privateKey: BarnardCoreSecp256k1.UInt256,
    messageHash32: [UInt8]
  ) -> BarnardCoreSecp256k1.UInt256 {
    let privateKeyBytes = privateKey.bytes
    let reducedMessage = BarnardCoreSecp256k1.Field.reduceOnce(
      BarnardCoreSecp256k1.UInt256(bytes: messageHash32),
      BarnardCoreSecp256k1.curveOrder
    ).bytes
    var value = [UInt8](repeating: 0x01, count: 32)
    var key = [UInt8](repeating: 0x00, count: 32)

    key = BarnardCorePrimitives.hmacSha256(
      key: key,
      message: value + [0x00] + privateKeyBytes + reducedMessage
    )
    value = BarnardCorePrimitives.hmacSha256(key: key, message: value)
    key = BarnardCorePrimitives.hmacSha256(
      key: key,
      message: value + [0x01] + privateKeyBytes + reducedMessage
    )
    value = BarnardCorePrimitives.hmacSha256(key: key, message: value)

    while true {
      value = BarnardCorePrimitives.hmacSha256(key: key, message: value)
      let candidate = BarnardCoreSecp256k1.UInt256(bytes: value)
      if !candidate.isZero && candidate < BarnardCoreSecp256k1.curveOrder {
        return candidate
      }
      key = BarnardCorePrimitives.hmacSha256(
        key: key,
        message: value + [0x00]
      )
      value = BarnardCorePrimitives.hmacSha256(key: key, message: value)
    }
  }
}
