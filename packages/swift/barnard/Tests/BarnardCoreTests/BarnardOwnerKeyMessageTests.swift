// Use of this source code is governed by a BSD-style license.

import XCTest
@testable import BarnardCore

final class BarnardOwnerKeyMessageTests: XCTestCase {
  private let scalarOne = [UInt8](repeating: 0, count: 31) + [1]
  private let scalarTwo = [UInt8](repeating: 0, count: 31) + [2]
  private let generatorCompressed = bytes(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  )

  func testCanonicalBindingTextMatchesPinnedBytesAndDigest() throws {
    let text = try XCTUnwrap(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org",
        walletAddress: bytes("14791697260e4c9a71f18484c9f997b308e59325"),
        ownerPublicKey: bytes(
          "03879beac8b548009124867a99a358aeb34ff42f957f868bbc83339568b16d9c67"
        ),
        chainId: 1,
        nonce: (0x00...0x0f).map(UInt8.init),
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )

    XCTAssertEqual(
      text,
      """
      beid.levarac.org wants to bind this wallet to a Levarac owner key.

      This signature authorizes no transaction and moves no assets.

      Domain-Tag: barnard-account-binding:v1
      Wallet: 0x14791697260e4c9a71f18484c9f997b308e59325
      Owner-Key: 0x03879beac8b548009124867a99a358aeb34ff42f957f868bbc83339568b16d9c67
      Chain-ID: eip155:1
      Scope: global
      Nonce: 0x000102030405060708090a0b0c0d0e0f
      Issued-At: 2026-07-30T09:00:00Z
      """
    )
    XCTAssertEqual(Array(text.utf8).count, 407)
    XCTAssertEqual(
      hex(BarnardCoreSigning.computeEip191Digest(text: text)),
      "1aad6c43694a0e64bf3994959907b7392a590a1e7139bc9f52a86dc71709dc44"
    )
    XCTAssertFalse(text.hasSuffix("\n"))

    XCTAssertNil(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "BEID.levarac.org",
        walletAddress: [UInt8](repeating: 0, count: 20),
        ownerPublicKey: generatorCompressed,
        chainId: 1,
        nonce: [UInt8](repeating: 0, count: 16),
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )
    XCTAssertNil(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org",
        walletAddress: [UInt8](repeating: 0, count: 20),
        ownerPublicKey: generatorCompressed,
        chainId: 1,
        nonce: [UInt8](repeating: 0, count: 15),
        issuedAt: "2026-07-30T09:00:00+09:00"
      )
    )
    XCTAssertNil(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org:00080",
        walletAddress: [UInt8](repeating: 0, count: 20),
        ownerPublicKey: generatorCompressed,
        chainId: 1,
        nonce: [UInt8](repeating: 0, count: 16),
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )
    XCTAssertNil(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org:65536",
        walletAddress: [UInt8](repeating: 0, count: 20),
        ownerPublicKey: generatorCompressed,
        chainId: 1,
        nonce: [UInt8](repeating: 0, count: 16),
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )
    XCTAssertNil(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org",
        walletAddress: [UInt8](repeating: 0, count: 20),
        ownerPublicKey: generatorCompressed,
        chainId: 1,
        nonce: [UInt8](repeating: 0, count: 16),
        issuedAt: "2026-02-29T09:00:00Z"
      )
    )
    XCTAssertNotNil(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org:65535",
        walletAddress: [UInt8](repeating: 0, count: 20),
        ownerPublicKey: generatorCompressed,
        chainId: UInt64.max,
        nonce: [UInt8](repeating: 0, count: 16),
        issuedAt: "2024-02-29T09:00:00Z"
      )
    )
  }

  func testSelfProofBuilderSignerAndVerifier() throws {
    let eventHash = (0x00...0x1f).map(UInt8.init)
    let eventPublicKey = compressedPublicKey(privateKey: scalarTwo)
    let message = try XCTUnwrap(
      BarnardCoreSigning.buildSelfProofMessage(
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 0x0102_0304_0506_0708,
        eninEnd: 0x1112_1314_1516_1718,
        ownerPublicKey: generatorCompressed
      )
    )

    XCTAssertEqual(message.count, 135)
    XCTAssertEqual(
      Array(message.prefix(21)),
      Array("barnard-self-proof:v1".utf8)
    )
    XCTAssertEqual(Array(message[21..<53]), eventHash)
    XCTAssertEqual(Array(message[53..<86]), eventPublicKey)
    XCTAssertEqual(
      Array(message[86..<102]),
      bytes("01020304050607081112131415161718")
    )
    XCTAssertEqual(Array(message[102..<135]), generatorCompressed)
    XCTAssertNil(
      BarnardCoreSigning.buildSelfProofMessage(
        eventIdHash: Array(eventHash.dropLast()),
        eventSigningPublicKey: eventPublicKey,
        eninStart: 12,
        eninEnd: 34,
        ownerPublicKey: generatorCompressed
      )
    )

    let signature = try XCTUnwrap(
      BarnardCoreSigning.signSelfProof(
        ownerPrivateKey: scalarOne,
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 12,
        eninEnd: 34,
        ownerPublicKey: generatorCompressed
      )
    )
    XCTAssertTrue(
      BarnardCoreSigning.verifySelfProof(
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 12,
        eninEnd: 34,
        ownerPublicKey: generatorCompressed,
        signature: signature
      )
    )
    XCTAssertFalse(
      BarnardCoreSigning.verifySelfProof(
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 12,
        eninEnd: 35,
        ownerPublicKey: generatorCompressed,
        signature: signature
      )
    )
    XCTAssertFalse(
      BarnardCoreSigning.verifySelfProof(
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 12,
        eninEnd: 34,
        ownerPublicKey: generatorCompressed,
        signature: BarnardCoreRecoverableSignature(
          r: [UInt8](repeating: 0, count: 32),
          s: signature.s,
          v: signature.v
        )
      )
    )
    XCTAssertFalse(
      BarnardCoreSigning.verifySelfProof(
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 12,
        eninEnd: 34,
        ownerPublicKey: generatorCompressed,
        signature: BarnardCoreRecoverableSignature(
          r: signature.r,
          s: signature.s,
          v: 2
        )
      )
    )
    XCTAssertFalse(
      BarnardCoreSigning.verifySelfProof(
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 35,
        eninEnd: 12,
        ownerPublicKey: generatorCompressed,
        signature: signature
      )
    )

    let highS = BarnardCoreSecp256k1.curveOrder.subtracting(
      BarnardCoreSecp256k1.UInt256(bytes: signature.s)
    ).bytes
    XCTAssertFalse(
      BarnardCoreSigning.verifySelfProof(
        eventIdHash: eventHash,
        eventSigningPublicKey: eventPublicKey,
        eninStart: 12,
        eninEnd: 34,
        ownerPublicKey: generatorCompressed,
        signature: BarnardCoreRecoverableSignature(
          r: signature.r,
          s: highS,
          v: signature.v ^ 1
        )
      )
    )
  }

  func testWalletAcknowledgementBuilderSignerAndVerifier() throws {
    let walletAddress = (0x20...0x33).map(UInt8.init)
    let walletSignature = (0x40...0x80).map(UInt8.init)
    let message = try XCTUnwrap(
      BarnardCoreSigning.buildWalletAcknowledgementMessage(
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    )

    XCTAssertEqual(message.count, 73)
    XCTAssertEqual(
      Array(message.prefix(21)),
      Array("barnard-wallet-ack:v1".utf8)
    )
    XCTAssertEqual(Array(message[21..<41]), walletAddress)
    XCTAssertEqual(
      Array(message[41..<73]),
      BarnardCoreCrypto.sha256(walletSignature)
    )
    XCTAssertNil(
      BarnardCoreSigning.buildWalletAcknowledgementMessage(
        walletAddress: Array(walletAddress.dropLast()),
        walletSignature: walletSignature
      )
    )

    let signature = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: scalarOne,
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    )
    XCTAssertTrue(
      BarnardCoreSigning.verifyWalletAcknowledgement(
        ownerPublicKey: generatorCompressed,
        walletAddress: walletAddress,
        walletSignature: walletSignature,
        signature: signature
      )
    )
    XCTAssertFalse(
      BarnardCoreSigning.verifyWalletAcknowledgement(
        ownerPublicKey: generatorCompressed,
        walletAddress: Array(repeating: 0, count: 20),
        walletSignature: walletSignature,
        signature: signature
      )
    )
  }

  func testRotationBuilderSignerAndVerifier() throws {
    let successorPublicKey = compressedPublicKey(privateKey: scalarTwo)
    let message = try XCTUnwrap(
      BarnardCoreSigning.buildAccountRotationMessage(
        previousOwnerPublicKey: generatorCompressed,
        successorOwnerPublicKey: successorPublicKey
      )
    )
    XCTAssertEqual(message.count, 93)
    XCTAssertEqual(
      Array(message.prefix(27)),
      Array("barnard-account-rotation:v1".utf8)
    )
    XCTAssertEqual(Array(message[27..<60]), generatorCompressed)
    XCTAssertEqual(Array(message[60..<93]), successorPublicKey)
    XCTAssertNil(
      BarnardCoreSigning.buildAccountRotationMessage(
        previousOwnerPublicKey: generatorCompressed,
        successorOwnerPublicKey: generatorCompressed
      )
    )

    let signature = try XCTUnwrap(
      BarnardCoreSigning.signAccountRotation(
        previousOwnerPrivateKey: scalarOne,
        previousOwnerPublicKey: generatorCompressed,
        successorOwnerPublicKey: successorPublicKey
      )
    )
    XCTAssertTrue(
      BarnardCoreSigning.verifyAccountRotation(
        previousOwnerPublicKey: generatorCompressed,
        successorOwnerPublicKey: successorPublicKey,
        signature: signature
      )
    )
    XCTAssertFalse(
      BarnardCoreSigning.verifyAccountRotation(
        previousOwnerPublicKey: successorPublicKey,
        successorOwnerPublicKey: generatorCompressed,
        signature: signature
      )
    )
  }

  func testUnbindingBuilderAndBothSignerKinds() throws {
    let walletPrivateKey = scalarTwo
    let walletPublicKey = compressedPublicKey(privateKey: walletPrivateKey)
    let walletAddress = try XCTUnwrap(
      BarnardCoreSigning.ethereumAddress(publicKeyCompressed: walletPublicKey)
    )
    let walletSignature = (0x40...0x80).map(UInt8.init)
    let message = try XCTUnwrap(
      BarnardCoreSigning.buildAccountUnbindingMessage(
        ownerPublicKey: generatorCompressed,
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    )

    XCTAssertEqual(message.count, 113)
    XCTAssertEqual(
      Array(message.prefix(28)),
      Array("barnard-account-unbinding:v1".utf8)
    )
    XCTAssertEqual(Array(message[28..<61]), generatorCompressed)
    XCTAssertEqual(Array(message[61..<81]), walletAddress)
    XCTAssertEqual(
      Array(message[81..<113]),
      BarnardCoreCrypto.sha256(walletSignature)
    )
    XCTAssertNil(
      BarnardCoreSigning.buildAccountUnbindingMessage(
        ownerPublicKey: generatorCompressed,
        walletAddress: Array(walletAddress.dropLast()),
        walletSignature: walletSignature
      )
    )

    let ownerSignature = try XCTUnwrap(
      BarnardCoreSigning.signAccountUnbinding(
        signerPrivateKey: scalarOne,
        ownerPublicKey: generatorCompressed,
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    )
    XCTAssertTrue(
      BarnardCoreSigning.verifyAccountUnbinding(
        signer: .owner,
        ownerPublicKey: generatorCompressed,
        walletAddress: walletAddress,
        walletSignature: walletSignature,
        signature: ownerSignature
      )
    )
    XCTAssertFalse(
      BarnardCoreSigning.verifyAccountUnbinding(
        signer: .wallet,
        ownerPublicKey: generatorCompressed,
        walletAddress: walletAddress,
        walletSignature: walletSignature,
        signature: ownerSignature
      )
    )

    let walletSigner = try XCTUnwrap(
      BarnardCoreSigning.signAccountUnbinding(
        signerPrivateKey: walletPrivateKey,
        ownerPublicKey: generatorCompressed,
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    )
    XCTAssertTrue(
      BarnardCoreSigning.verifyAccountUnbinding(
        signer: .wallet,
        ownerPublicKey: generatorCompressed,
        walletAddress: walletAddress,
        walletSignature: walletSignature,
        signature: walletSigner
      )
    )
  }

  func testWalletBindingRejectsNonGlobalScopeWithMatchingSignatures() throws {
    let ownerPrivateKey = scalarTwo
    let ownerPublicKey = compressedPublicKey(privateKey: ownerPrivateKey)
    let walletAddress = try XCTUnwrap(
      BarnardCoreSigning.ethereumAddress(
        publicKeyCompressed: generatorCompressed
      )
    )
    let canonicalText = try XCTUnwrap(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org",
        walletAddress: walletAddress,
        ownerPublicKey: ownerPublicKey,
        chainId: 1,
        nonce: (0x00...0x0f).map(UInt8.init),
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )
    let alteredScopeText = canonicalText.replacingOccurrences(
      of: "Scope: global",
      with: "Scope: event"
    )
    let alteredScopeEip191Signature = BarnardCoreSigning.signRecoverable(
      privateKey: scalarOne,
      messageHash32: BarnardCoreSigning.computeEip191Digest(
        text: alteredScopeText
      )
    )
    let alteredScopeWalletSignature =
      alteredScopeEip191Signature.r
      + alteredScopeEip191Signature.s
      + [UInt8(alteredScopeEip191Signature.v + 27)]
    let alteredScopeAcknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: alteredScopeWalletSignature
      )
    )

    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: alteredScopeText,
        walletSignature: alteredScopeWalletSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: alteredScopeAcknowledgement
      ),
      .invalid
    )
  }

  func testWalletClassificationAndEoaBindingVerification() throws {
    let magic = bytes(
      "6492649264926492649264926492649264926492649264926492649264926492"
    )
    XCTAssertEqual(
      BarnardCoreSigning.classifyWalletSignature([UInt8](repeating: 0, count: 65)),
      .validEoaShape
    )
    XCTAssertEqual(
      BarnardCoreSigning.classifyWalletSignature([0xaa] + magic),
      .smartWalletUnsupported
    )
    XCTAssertEqual(
      BarnardCoreSigning.classifyWalletSignature(
        [UInt8](repeating: 0xaa, count: 33) + magic
      ),
      .smartWalletUnsupported
    )
    XCTAssertEqual(
      BarnardCoreSigning.classifyWalletSignature([]),
      .invalid
    )

    let ownerPrivateKey = scalarTwo
    let ownerPublicKey = compressedPublicKey(privateKey: ownerPrivateKey)
    let walletAddress = try XCTUnwrap(
      BarnardCoreSigning.ethereumAddress(
        publicKeyCompressed: generatorCompressed
      )
    )
    let nonce = (0x00...0x0f).map(UInt8.init)
    let text = try XCTUnwrap(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org",
        walletAddress: walletAddress,
        ownerPublicKey: ownerPublicKey,
        chainId: 1,
        nonce: nonce,
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )
    let eip191Signature = BarnardCoreSigning.signRecoverable(
      privateKey: scalarOne,
      messageHash32: BarnardCoreSigning.computeEip191Digest(text: text)
    )
    let walletSignature =
      eip191Signature.r
      + eip191Signature.s
      + [UInt8(eip191Signature.v + 27)]
    let acknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: walletSignature
      )
    )

    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: walletSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: acknowledgement
      ),
      .valid
    )

    var nonCanonicalLines = text.split(
      separator: "\n",
      omittingEmptySubsequences: false
    ).map(String.init)
    nonCanonicalLines[6] =
      "Owner-\u{212a}ey: " + nonCanonicalLines[6].dropFirst("Owner-Key: ".count)
    let unicodeEquivalentLabelText = nonCanonicalLines.joined(separator: "\n")
    XCTAssertNotEqual(
      Array(unicodeEquivalentLabelText.utf8),
      Array(text.utf8)
    )
    let unicodeEquivalentSignature = BarnardCoreSigning.signRecoverable(
      privateKey: scalarOne,
      messageHash32: BarnardCoreSigning.computeEip191Digest(
        text: unicodeEquivalentLabelText
      )
    )
    let unicodeEquivalentWalletSignature =
      unicodeEquivalentSignature.r
      + unicodeEquivalentSignature.s
      + [UInt8(unicodeEquivalentSignature.v + 27)]
    let unicodeEquivalentAcknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: unicodeEquivalentWalletSignature
      )
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: unicodeEquivalentLabelText,
        walletSignature: unicodeEquivalentWalletSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: unicodeEquivalentAcknowledgement
      ),
      .invalid
    )

    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: walletSignature,
        expectedWalletAddress: [UInt8](repeating: 0, count: 20),
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: acknowledgement
      ),
      .invalid
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: "Hello World",
        walletSignature: walletSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: acknowledgement
      ),
      .invalid
    )
    let textNamingAnotherOwner = try XCTUnwrap(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org",
        walletAddress: walletAddress,
        ownerPublicKey: generatorCompressed,
        chainId: 1,
        nonce: nonce,
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )
    let anotherOwnerEip191Signature = BarnardCoreSigning.signRecoverable(
      privateKey: scalarOne,
      messageHash32: BarnardCoreSigning.computeEip191Digest(
        text: textNamingAnotherOwner
      )
    )
    let anotherOwnerWalletSignature =
      anotherOwnerEip191Signature.r
      + anotherOwnerEip191Signature.s
      + [UInt8(anotherOwnerEip191Signature.v + 27)]
    let anotherOwnerAcknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: anotherOwnerWalletSignature
      )
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: textNamingAnotherOwner,
        walletSignature: anotherOwnerWalletSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: anotherOwnerAcknowledgement
      ),
      .invalid
    )
    let textNamingAnotherWallet = try XCTUnwrap(
      BarnardCoreSigning.buildAccountBindingText(
        domain: "beid.levarac.org",
        walletAddress: [UInt8](repeating: 0, count: 20),
        ownerPublicKey: ownerPublicKey,
        chainId: 1,
        nonce: nonce,
        issuedAt: "2026-07-30T09:00:00Z"
      )
    )
    let anotherWalletEip191Signature = BarnardCoreSigning.signRecoverable(
      privateKey: scalarOne,
      messageHash32: BarnardCoreSigning.computeEip191Digest(
        text: textNamingAnotherWallet
      )
    )
    let anotherWalletSignature =
      anotherWalletEip191Signature.r
      + anotherWalletEip191Signature.s
      + [UInt8(anotherWalletEip191Signature.v + 27)]
    let anotherWalletAcknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: anotherWalletSignature
      )
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: textNamingAnotherWallet,
        walletSignature: anotherWalletSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: anotherWalletAcknowledgement
      ),
      .invalid
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: Array(walletSignature.dropLast()),
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: acknowledgement
      ),
      .invalid
    )

    var invalidVSignature = walletSignature
    invalidVSignature[64] = 2
    let invalidVAcknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: invalidVSignature
      )
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: invalidVSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: invalidVAcknowledgement
      ),
      .invalid
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: walletSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: BarnardCoreRecoverableSignature(
          r: [UInt8](repeating: 0, count: 32),
          s: acknowledgement.s,
          v: acknowledgement.v
        )
      ),
      .invalid
    )

    var rawVSignature = walletSignature
    rawVSignature[64] = UInt8(eip191Signature.v)
    let rawVAcknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: rawVSignature
      )
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: rawVSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: rawVAcknowledgement
      ),
      .valid
    )

    var highSSignature = walletSignature
    let highS = BarnardCoreSecp256k1.curveOrder.subtracting(
      BarnardCoreSecp256k1.UInt256(bytes: eip191Signature.s)
    ).bytes
    highSSignature.replaceSubrange(
      32..<64,
      with: highS
    )
    highSSignature[64] = UInt8((eip191Signature.v ^ 1) + 27)
    let highSAcknowledgement = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: ownerPrivateKey,
        walletAddress: walletAddress,
        walletSignature: highSSignature
      )
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: highSSignature,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: highSAcknowledgement
      ),
      .invalid
    )
    XCTAssertEqual(
      BarnardCoreSigning.verifyWalletBinding(
        text: text,
        walletSignature: [0xaa] + magic,
        expectedWalletAddress: walletAddress,
        expectedOwnerPublicKey: ownerPublicKey,
        acknowledgement: acknowledgement
      ),
      .smartWalletUnsupported
    )
  }

  func testWalletVerifierPortCarriesObservationTime() {
    let verifier: any BarnardCoreWalletVerifier = FixedWalletVerifier()
    XCTAssertEqual(
      verifier.verify(
        address: [UInt8](repeating: 0, count: 20),
        digest: [UInt8](repeating: 0, count: 32),
        signature: [1, 2, 3]
      ),
      .valid(verifiedAtUnixSeconds: 1_753_863_200)
    )
  }

  private func compressedPublicKey(privateKey: [UInt8]) -> [UInt8] {
    BarnardCoreSecp256k1.compress(
      BarnardCoreSecp256k1.multiply(
        BarnardCoreSecp256k1.UInt256(bytes: privateKey),
        BarnardCoreSecp256k1.generator
      )
    )
  }
}

private struct FixedWalletVerifier: BarnardCoreWalletVerifier {
  func verify(
    address: [UInt8],
    digest: [UInt8],
    signature: [UInt8]
  ) -> BarnardCoreWalletVerifierVerdict {
    .valid(verifiedAtUnixSeconds: 1_753_863_200)
  }
}

private func bytes(_ hex: String) -> [UInt8] {
  stride(from: 0, to: hex.count, by: 2).map { offset in
    let start = hex.index(hex.startIndex, offsetBy: offset)
    let end = hex.index(start, offsetBy: 2)
    return UInt8(hex[start..<end], radix: 16)!
  }
}

private func hex(_ bytes: [UInt8]) -> String {
  bytes.map {
    let value = String($0, radix: 16)
    return value.count == 1 ? "0" + value : value
  }.joined()
}
