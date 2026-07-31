// Use of this source code is governed by a BSD-style license.

public enum BarnardCoreWalletSignatureClassification: Int32 {
  case invalid = 0
  case validEoaShape = 1
  case smartWalletUnsupported = 2
}

public enum BarnardCoreWalletBindingVerification: Int32 {
  case invalid = 0
  case valid = 1
  case smartWalletUnsupported = 2
}

public enum BarnardCoreWalletVerifierVerdict: Equatable {
  case valid(verifiedAtUnixSeconds: Int64)
  case invalid(verifiedAtUnixSeconds: Int64)
  case unverified
}

/// Host-defined smart-wallet verification port.
///
/// Contract signature validity can change with contract state. Implementations
/// therefore attach their observation time to every valid or invalid verdict.
/// BarnardCore intentionally provides no RPC implementation.
public protocol BarnardCoreWalletVerifier {
  func verify(
    address: [UInt8],
    digest: [UInt8],
    signature: [UInt8]
  ) -> BarnardCoreWalletVerifierVerdict
}

public extension BarnardCoreSigning {
  static func buildAccountBindingText(
    domain: String,
    walletAddress: [UInt8],
    ownerPublicKey: [UInt8],
    chainId: UInt64,
    nonce: [UInt8],
    issuedAt: String
  ) -> String? {
    guard
      isCanonicalDomain(domain),
      walletAddress.count == 20,
      isValidCompressedPublicKey(ownerPublicKey),
      nonce.count == 16,
      isCanonicalIssuedAt(issuedAt)
    else {
      return nil
    }

    return [
      "\(domain) wants to bind this wallet to a Levarac owner key.",
      "",
      "This signature authorizes no transaction and moves no assets.",
      "",
      "Domain-Tag: \(accountBindingDomainTag)",
      "Wallet: 0x\(lowercaseHex(walletAddress))",
      "Owner-Key: 0x\(lowercaseHex(ownerPublicKey))",
      "Chain-ID: eip155:\(chainId)",
      "Scope: global",
      "Nonce: 0x\(lowercaseHex(nonce))",
      "Issued-At: \(issuedAt)",
    ].joined(separator: "\n")
  }

  static func buildAccountUnbindingText(
    domain: String,
    walletAddress: [UInt8],
    ownerPublicKey: [UInt8],
    chainId: UInt64,
    nonce: [UInt8],
    issuedAt: String
  ) -> String? {
    guard
      isCanonicalDomain(domain),
      walletAddress.count == 20,
      isValidCompressedPublicKey(ownerPublicKey),
      nonce.count == 16,
      isCanonicalIssuedAt(issuedAt)
    else {
      return nil
    }

    return [
      "\(domain) wants to revoke this wallet's binding to a Levarac owner key.",
      "",
      "This signature REVOKES a wallet binding and authorizes no transaction.",
      "",
      "Domain-Tag: \(accountUnbindingDomainTag)",
      "Wallet: 0x\(lowercaseHex(walletAddress))",
      "Owner-Key: 0x\(lowercaseHex(ownerPublicKey))",
      "Chain-ID: eip155:\(chainId)",
      "Scope: global",
      "Nonce: 0x\(lowercaseHex(nonce))",
      "Issued-At: \(issuedAt)",
    ].joined(separator: "\n")
  }

  static func buildSelfProofMessage(
    eventIdHash: [UInt8],
    eventSigningPublicKey: [UInt8],
    eninStart: UInt64,
    eninEnd: UInt64,
    ownerPublicKey: [UInt8]
  ) -> [UInt8]? {
    guard
      eventIdHash.count == 32,
      isValidCompressedPublicKey(eventSigningPublicKey),
      eninStart <= eninEnd,
      isValidCompressedPublicKey(ownerPublicKey)
    else {
      return nil
    }

    return Array(selfProofDomainTag.utf8)
      + eventIdHash
      + eventSigningPublicKey
      + uint64BigEndian(eninStart)
      + uint64BigEndian(eninEnd)
      + ownerPublicKey
  }

  static func signSelfProof(
    ownerPrivateKey: [UInt8],
    eventIdHash: [UInt8],
    eventSigningPublicKey: [UInt8],
    eninStart: UInt64,
    eninEnd: UInt64,
    ownerPublicKey: [UInt8]
  ) -> BarnardCoreRecoverableSignature? {
    guard
      publicKey(forPrivateKey: ownerPrivateKey) == ownerPublicKey,
      let message = buildSelfProofMessage(
        eventIdHash: eventIdHash,
        eventSigningPublicKey: eventSigningPublicKey,
        eninStart: eninStart,
        eninEnd: eninEnd,
        ownerPublicKey: ownerPublicKey
      )
    else {
      return nil
    }
    return signRecoverable(
      privateKey: ownerPrivateKey,
      messageHash32: BarnardCorePrimitives.sha256(message)
    )
  }

  static func verifySelfProof(
    eventIdHash: [UInt8],
    eventSigningPublicKey: [UInt8],
    eninStart: UInt64,
    eninEnd: UInt64,
    ownerPublicKey: [UInt8],
    signature: BarnardCoreRecoverableSignature
  ) -> Bool {
    guard
      let message = buildSelfProofMessage(
        eventIdHash: eventIdHash,
        eventSigningPublicKey: eventSigningPublicKey,
        eninStart: eninStart,
        eninEnd: eninEnd,
        ownerPublicKey: ownerPublicKey
      )
    else {
      return false
    }
    return verifyNativeSignature(
      signature,
      message: message,
      expectedPublicKey: ownerPublicKey
    )
  }

  static func buildWalletAcknowledgementMessage(
    walletAddress: [UInt8],
    walletSignature: [UInt8]
  ) -> [UInt8]? {
    guard walletAddress.count == 20, !walletSignature.isEmpty else {
      return nil
    }
    return Array(walletAcknowledgementDomainTag.utf8)
      + walletAddress
      + BarnardCorePrimitives.sha256(walletSignature)
  }

  static func signWalletAcknowledgement(
    ownerPrivateKey: [UInt8],
    walletAddress: [UInt8],
    walletSignature: [UInt8]
  ) -> BarnardCoreRecoverableSignature? {
    guard
      isValidPrivateKey(ownerPrivateKey),
      let message = buildWalletAcknowledgementMessage(
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    else {
      return nil
    }
    return signRecoverable(
      privateKey: ownerPrivateKey,
      messageHash32: BarnardCorePrimitives.sha256(message)
    )
  }

  static func verifyWalletAcknowledgement(
    ownerPublicKey: [UInt8],
    walletAddress: [UInt8],
    walletSignature: [UInt8],
    signature: BarnardCoreRecoverableSignature
  ) -> Bool {
    guard
      isValidCompressedPublicKey(ownerPublicKey),
      let message = buildWalletAcknowledgementMessage(
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    else {
      return false
    }
    return verifyNativeSignature(
      signature,
      message: message,
      expectedPublicKey: ownerPublicKey
    )
  }

  static func buildAccountRotationMessage(
    previousOwnerPublicKey: [UInt8],
    successorOwnerPublicKey: [UInt8]
  ) -> [UInt8]? {
    guard
      isValidCompressedPublicKey(previousOwnerPublicKey),
      isValidCompressedPublicKey(successorOwnerPublicKey),
      previousOwnerPublicKey != successorOwnerPublicKey
    else {
      return nil
    }
    return Array(accountRotationDomainTag.utf8)
      + previousOwnerPublicKey
      + successorOwnerPublicKey
  }

  static func signAccountRotation(
    previousOwnerPrivateKey: [UInt8],
    previousOwnerPublicKey: [UInt8],
    successorOwnerPublicKey: [UInt8]
  ) -> BarnardCoreRecoverableSignature? {
    guard
      publicKey(forPrivateKey: previousOwnerPrivateKey) == previousOwnerPublicKey,
      let message = buildAccountRotationMessage(
        previousOwnerPublicKey: previousOwnerPublicKey,
        successorOwnerPublicKey: successorOwnerPublicKey
      )
    else {
      return nil
    }
    return signRecoverable(
      privateKey: previousOwnerPrivateKey,
      messageHash32: BarnardCorePrimitives.sha256(message)
    )
  }

  static func verifyAccountRotation(
    previousOwnerPublicKey: [UInt8],
    successorOwnerPublicKey: [UInt8],
    signature: BarnardCoreRecoverableSignature
  ) -> Bool {
    guard
      let message = buildAccountRotationMessage(
        previousOwnerPublicKey: previousOwnerPublicKey,
        successorOwnerPublicKey: successorOwnerPublicKey
      )
    else {
      return false
    }
    return verifyNativeSignature(
      signature,
      message: message,
      expectedPublicKey: previousOwnerPublicKey
    )
  }

  static func buildAccountUnbindingMessage(
    ownerPublicKey: [UInt8],
    walletAddress: [UInt8],
    walletSignature: [UInt8]
  ) -> [UInt8]? {
    guard
      isValidCompressedPublicKey(ownerPublicKey),
      walletAddress.count == 20,
      !walletSignature.isEmpty
    else {
      return nil
    }
    return Array(accountUnbindingDomainTag.utf8)
      + ownerPublicKey
      + walletAddress
      + BarnardCorePrimitives.sha256(walletSignature)
  }

  static func signAccountUnbinding(
    ownerPrivateKey: [UInt8],
    ownerPublicKey: [UInt8],
    walletAddress: [UInt8],
    walletSignature: [UInt8]
  ) -> BarnardCoreRecoverableSignature? {
    guard
      publicKey(forPrivateKey: ownerPrivateKey) == ownerPublicKey,
      let message = buildAccountUnbindingMessage(
        ownerPublicKey: ownerPublicKey,
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    else {
      return nil
    }
    return signRecoverable(
      privateKey: ownerPrivateKey,
      messageHash32: BarnardCorePrimitives.sha256(message)
    )
  }

  static func verifyAccountUnbinding(
    ownerPublicKey: [UInt8],
    walletAddress: [UInt8],
    walletSignature: [UInt8],
    signature: BarnardCoreRecoverableSignature
  ) -> Bool {
    guard
      let message = buildAccountUnbindingMessage(
        ownerPublicKey: ownerPublicKey,
        walletAddress: walletAddress,
        walletSignature: walletSignature
      ),
      let recoveredPublicKey = strictRecoveredPublicKey(
        signature,
        messageHash32: BarnardCorePrimitives.sha256(message)
      )
    else {
      return false
    }
    return recoveredPublicKey == ownerPublicKey
  }

  static func verifyAccountUnbinding(
    text: String,
    walletSignature: [UInt8],
    expectedWalletAddress: [UInt8],
    expectedOwnerPublicKey: [UInt8]
  ) -> BarnardCoreWalletBindingVerification {
    guard
      expectedWalletAddress.count == 20,
      isValidCompressedPublicKey(expectedOwnerPublicKey),
      isCanonicalAccountUnbindingText(
        text,
        expectedWalletAddress: expectedWalletAddress,
        expectedOwnerPublicKey: expectedOwnerPublicKey
      )
    else {
      return .invalid
    }
    switch classifyWalletSignature(walletSignature) {
    case .invalid:
      return .invalid
    case .smartWalletUnsupported:
      return .smartWalletUnsupported
    case .validEoaShape:
      break
    }
    guard
      let recoveryId = normalizedEthereumRecoveryId(walletSignature[64]),
      let recoveredPublicKey = strictRecoveredPublicKey(
        BarnardCoreRecoverableSignature(
          r: Array(walletSignature[0..<32]),
          s: Array(walletSignature[32..<64]),
          v: recoveryId
        ),
        messageHash32: computeEip191Digest(text: text)
      ),
      ethereumAddress(publicKeyCompressed: recoveredPublicKey)
        == expectedWalletAddress
    else {
      return .invalid
    }
    return .valid
  }

  static func classifyWalletSignature(
    _ signature: [UInt8]
  ) -> BarnardCoreWalletSignatureClassification {
    let erc6492Magic = Array(
      repeating: [UInt8(0x64), UInt8(0x92)],
      count: 16
    )
      .flatMap { $0 }
    if signature.count >= erc6492Magic.count,
      signature.suffix(erc6492Magic.count).elementsEqual(erc6492Magic)
    {
      return .smartWalletUnsupported
    }
    return signature.count == 65 ? .validEoaShape : .invalid
  }

  static func verifyWalletBinding(
    text: String,
    walletSignature: [UInt8],
    expectedWalletAddress: [UInt8],
    expectedOwnerPublicKey: [UInt8],
    acknowledgement: BarnardCoreRecoverableSignature
  ) -> BarnardCoreWalletBindingVerification {
    guard
      expectedWalletAddress.count == 20,
      isValidCompressedPublicKey(expectedOwnerPublicKey),
      isCanonicalAccountBindingText(
        text,
        expectedWalletAddress: expectedWalletAddress,
        expectedOwnerPublicKey: expectedOwnerPublicKey
      )
    else {
      return .invalid
    }
    switch classifyWalletSignature(walletSignature) {
    case .invalid:
      return .invalid
    case .smartWalletUnsupported:
      return .smartWalletUnsupported
    case .validEoaShape:
      break
    }
    guard
      let recoveryId = normalizedEthereumRecoveryId(walletSignature[64]),
      let recoveredPublicKey = strictRecoveredPublicKey(
        BarnardCoreRecoverableSignature(
          r: Array(walletSignature[0..<32]),
          s: Array(walletSignature[32..<64]),
          v: recoveryId
        ),
        messageHash32: computeEip191Digest(text: text)
      ),
      ethereumAddress(publicKeyCompressed: recoveredPublicKey)
        == expectedWalletAddress,
      verifyWalletAcknowledgement(
        ownerPublicKey: expectedOwnerPublicKey,
        walletAddress: expectedWalletAddress,
        walletSignature: walletSignature,
        signature: acknowledgement
      )
    else {
      return .invalid
    }
    return .valid
  }

  private static func isCanonicalAccountBindingText(
    _ text: String,
    expectedWalletAddress: [UInt8],
    expectedOwnerPublicKey: [UInt8]
  ) -> Bool {
    guard !text.contains("\r"), !text.hasSuffix("\n") else {
      return false
    }
    let lines = text.split(
      separator: "\n",
      omittingEmptySubsequences: false
    ).map(String.init)
    guard
      lines.count == 11,
      lines[1].isEmpty,
      lines[2] == "This signature authorizes no transaction and moves no assets.",
      lines[3].isEmpty,
      lines[4] == "Domain-Tag: \(accountBindingDomainTag)",
      lines[5] == "Wallet: 0x\(lowercaseHex(expectedWalletAddress))",
      lines[6] == "Owner-Key: 0x\(lowercaseHex(expectedOwnerPublicKey))",
      lines[8] == "Scope: global"
    else {
      return false
    }

    let headerSuffix = " wants to bind this wallet to a Levarac owner key."
    guard lines[0].hasSuffix(headerSuffix) else {
      return false
    }
    let domain = String(lines[0].dropLast(headerSuffix.count))

    let chainPrefix = "Chain-ID: eip155:"
    guard lines[7].hasPrefix(chainPrefix) else {
      return false
    }
    let chainIdText = String(lines[7].dropFirst(chainPrefix.count))
    guard
      !chainIdText.isEmpty,
      chainIdText.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
      (chainIdText == "0" || !chainIdText.hasPrefix("0")),
      let chainId = UInt64(chainIdText)
    else {
      return false
    }

    let noncePrefix = "Nonce: 0x"
    guard
      lines[9].hasPrefix(noncePrefix),
      let nonce = decodeLowercaseHex(
        String(lines[9].dropFirst(noncePrefix.count))
      ),
      nonce.count == 16
    else {
      return false
    }

    let issuedAtPrefix = "Issued-At: "
    guard lines[10].hasPrefix(issuedAtPrefix) else {
      return false
    }
    let issuedAt = String(lines[10].dropFirst(issuedAtPrefix.count))

    guard let reconstructed = buildAccountBindingText(
      domain: domain,
      walletAddress: expectedWalletAddress,
      ownerPublicKey: expectedOwnerPublicKey,
      chainId: chainId,
      nonce: nonce,
      issuedAt: issuedAt
    ) else {
      return false
    }
    return reconstructed.utf8.elementsEqual(text.utf8)
  }

  private static func isCanonicalAccountUnbindingText(
    _ text: String,
    expectedWalletAddress: [UInt8],
    expectedOwnerPublicKey: [UInt8]
  ) -> Bool {
    guard !text.contains("\r"), !text.hasSuffix("\n") else {
      return false
    }
    let lines = text.split(
      separator: "\n",
      omittingEmptySubsequences: false
    ).map(String.init)
    guard
      lines.count == 11,
      lines[1].isEmpty,
      lines[2]
        == "This signature REVOKES a wallet binding and authorizes no transaction.",
      lines[3].isEmpty,
      lines[4] == "Domain-Tag: \(accountUnbindingDomainTag)",
      lines[5] == "Wallet: 0x\(lowercaseHex(expectedWalletAddress))",
      lines[6] == "Owner-Key: 0x\(lowercaseHex(expectedOwnerPublicKey))",
      lines[8] == "Scope: global"
    else {
      return false
    }

    let headerSuffix =
      " wants to revoke this wallet's binding to a Levarac owner key."
    guard lines[0].hasSuffix(headerSuffix) else {
      return false
    }
    let domain = String(lines[0].dropLast(headerSuffix.count))

    let chainPrefix = "Chain-ID: eip155:"
    guard lines[7].hasPrefix(chainPrefix) else {
      return false
    }
    let chainIdText = String(lines[7].dropFirst(chainPrefix.count))
    guard
      !chainIdText.isEmpty,
      chainIdText.utf8.allSatisfy({ (0x30...0x39).contains($0) }),
      (chainIdText == "0" || !chainIdText.hasPrefix("0")),
      let chainId = UInt64(chainIdText)
    else {
      return false
    }

    let noncePrefix = "Nonce: 0x"
    guard
      lines[9].hasPrefix(noncePrefix),
      let nonce = decodeLowercaseHex(
        String(lines[9].dropFirst(noncePrefix.count))
      ),
      nonce.count == 16
    else {
      return false
    }

    let issuedAtPrefix = "Issued-At: "
    guard lines[10].hasPrefix(issuedAtPrefix) else {
      return false
    }
    let issuedAt = String(lines[10].dropFirst(issuedAtPrefix.count))

    guard let reconstructed = buildAccountUnbindingText(
      domain: domain,
      walletAddress: expectedWalletAddress,
      ownerPublicKey: expectedOwnerPublicKey,
      chainId: chainId,
      nonce: nonce,
      issuedAt: issuedAt
    ) else {
      return false
    }
    return reconstructed.utf8.elementsEqual(text.utf8)
  }

  private static func verifyNativeSignature(
    _ signature: BarnardCoreRecoverableSignature,
    message: [UInt8],
    expectedPublicKey: [UInt8]
  ) -> Bool {
    strictRecoveredPublicKey(
      signature,
      messageHash32: BarnardCorePrimitives.sha256(message)
    ) == expectedPublicKey
  }

  private static func strictRecoveredPublicKey(
    _ signature: BarnardCoreRecoverableSignature,
    messageHash32: [UInt8]
  ) -> [UInt8]? {
    guard
      signature.r.count == 32,
      signature.s.count == 32,
      messageHash32.count == 32,
      signature.v == 0 || signature.v == 1
    else {
      return nil
    }

    let r = BarnardCoreSecp256k1.UInt256(bytes: signature.r)
    let s = BarnardCoreSecp256k1.UInt256(bytes: signature.s)
    guard
      !r.isZero,
      r < BarnardCoreSecp256k1.curveOrder,
      !s.isZero,
      s < BarnardCoreSecp256k1.curveOrder,
      s <= BarnardCoreSecp256k1.curveOrder.shiftedRight1()
    else {
      return nil
    }

    return recoverPublicKey(
      recoveryId: signature.v,
      r: signature.r,
      s: signature.s,
      messageHash32: messageHash32
    )
  }

  private static func normalizedEthereumRecoveryId(_ v: UInt8) -> Int? {
    switch v {
    case 0, 1:
      return Int(v)
    case 27, 28:
      return Int(v - 27)
    default:
      return nil
    }
  }

  private static func isValidPrivateKey(_ privateKey: [UInt8]) -> Bool {
    guard privateKey.count == 32 else {
      return false
    }
    let scalar = BarnardCoreSecp256k1.UInt256(bytes: privateKey)
    return !scalar.isZero && scalar < BarnardCoreSecp256k1.curveOrder
  }

  private static func publicKey(forPrivateKey privateKey: [UInt8]) -> [UInt8]? {
    guard isValidPrivateKey(privateKey) else {
      return nil
    }
    let point = BarnardCoreSecp256k1.multiply(
      BarnardCoreSecp256k1.UInt256(bytes: privateKey),
      BarnardCoreSecp256k1.generator
    )
    return BarnardCoreSecp256k1.compress(point)
  }

  private static func isValidCompressedPublicKey(_ publicKey: [UInt8]) -> Bool {
    serializeUncompressedPublicKey(publicKey) != nil
  }

  private static func uint64BigEndian(_ value: UInt64) -> [UInt8] {
    stride(from: 56, through: 0, by: -8).map {
      UInt8((value >> UInt64($0)) & 0xff)
    }
  }

  private static func lowercaseHex(_ bytes: [UInt8]) -> String {
    bytes.map {
      let value = String($0, radix: 16)
      return value.count == 1 ? "0" + value : value
    }.joined()
  }

  private static func decodeLowercaseHex(_ value: String) -> [UInt8]? {
    let bytes = Array(value.utf8)
    guard bytes.count.isMultiple(of: 2) else {
      return nil
    }
    var output: [UInt8] = []
    output.reserveCapacity(bytes.count / 2)
    for index in stride(from: 0, to: bytes.count, by: 2) {
      func nibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39:
          return byte - 0x30
        case 0x61...0x66:
          return byte - 0x61 + 10
        default:
          return nil
        }
      }
      guard let high = nibble(bytes[index]), let low = nibble(bytes[index + 1])
      else {
        return nil
      }
      output.append((high << 4) | low)
    }
    return output
  }

  private static func isCanonicalDomain(_ domain: String) -> Bool {
    let bytes = Array(domain.utf8)
    guard
      !bytes.isEmpty,
      isLowercaseAsciiLetterOrDigit(bytes[0])
    else {
      return false
    }

    var colonIndex: Int?
    for (index, byte) in bytes.enumerated() {
      if colonIndex != nil {
        if !(0x30...0x39).contains(byte) {
          return false
        }
        continue
      }
      switch byte {
      case 0x61...0x7a, 0x30...0x39, 0x2d, 0x2e:
        break
      case 0x3a:
        if index == 0 {
          return false
        }
        colonIndex = index
      default:
        return false
      }
    }

    let hostEnd = colonIndex ?? bytes.count
    guard
      hostEnd > 0,
      isLowercaseAsciiLetterOrDigit(bytes[hostEnd - 1])
    else {
      return false
    }
    guard let colonIndex else {
      return true
    }

    let portBytes = bytes.dropFirst(colonIndex + 1)
    guard
      !portBytes.isEmpty,
      portBytes.count <= 5,
      portBytes.allSatisfy({ (0x30...0x39).contains($0) }),
      (portBytes.count == 1 || portBytes.first != 0x30),
      let port = UInt32(String(decoding: portBytes, as: UTF8.self)),
      port <= 65_535
    else {
      return false
    }
    return true
  }

  private static func isLowercaseAsciiLetterOrDigit(_ byte: UInt8) -> Bool {
    (0x61...0x7a).contains(byte) || (0x30...0x39).contains(byte)
  }

  private static func isCanonicalIssuedAt(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    guard
      bytes.count == 20,
      bytes[4] == 0x2d,
      bytes[7] == 0x2d,
      bytes[10] == 0x54,
      bytes[13] == 0x3a,
      bytes[16] == 0x3a,
      bytes[19] == 0x5a
    else {
      return false
    }
    let digitPositions = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
    guard digitPositions.allSatisfy({
      (0x30...0x39).contains(bytes[$0])
    }) else {
      return false
    }

    func decimal(_ first: Int, _ second: Int) -> Int {
      Int(bytes[first] - 0x30) * 10 + Int(bytes[second] - 0x30)
    }
    let year = decimal(0, 1) * 100 + decimal(2, 3)
    let month = decimal(5, 6)
    let day = decimal(8, 9)
    let hour = decimal(11, 12)
    let minute = decimal(14, 15)
    let second = decimal(17, 18)
    guard
      (1...12).contains(month),
      (0...23).contains(hour),
      (0...59).contains(minute),
      (0...59).contains(second)
    else {
      return false
    }

    var daysInMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    let isLeapYear = year.isMultiple(of: 4)
      && (!year.isMultiple(of: 100) || year.isMultiple(of: 400))
    if isLeapYear {
      daysInMonth[1] = 29
    }
    return (1...daysInMonth[month - 1]).contains(day)
  }
}
