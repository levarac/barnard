// Use of this source code is governed by a BSD-style license.

import Foundation
import XCTest
@testable import BarnardCore

/// Loads `test-vectors/owner-key-v1.txt` — golden values computed from the
/// Swift `BarnardCore` reference implementation — and asserts BarnardCore's
/// own owner-key primitives reproduce them byte-for-byte.
///
/// The same file is consumed by the Kotlin test suite in
/// `packages/android/barnard`. A divergence between the two
/// implementations therefore fails both suites instead of neither. See
/// `test-vectors/README.md` for the file format and
/// `specs/133-android-owner-key/spec.md` for why this exists.
final class BarnardOwnerKeyConformanceVectorTests: XCTestCase {
  func testOwnerKeyPrimitivesMatchSharedConformanceVectors() throws {
    let vectors = try loadVectors()

    let zeroPair = BarnardCoreSigning.deriveOwnerKeyPair(
      accountSecret: try vectors.bytes("owner_zero_account_secret")
    )
    XCTAssertEqual(hex(zeroPair.privateKey), try vectors.string("owner_zero_private_key"))
    XCTAssertEqual(
      hex(zeroPair.publicKeyCompressed),
      try vectors.string("owner_zero_public_key")
    )

    let seqPair = BarnardCoreSigning.deriveOwnerKeyPair(
      accountSecret: try vectors.bytes("owner_seq_account_secret")
    )
    XCTAssertEqual(hex(seqPair.privateKey), try vectors.string("owner_seq_private_key"))
    XCTAssertEqual(
      hex(seqPair.publicKeyCompressed),
      try vectors.string("owner_seq_public_key")
    )

    let bindingText = try XCTUnwrap(
      BarnardCoreSigning.buildAccountBindingText(
        domain: try vectors.string("binding_domain"),
        walletAddress: try vectors.bytes("binding_wallet_address"),
        ownerPublicKey: try vectors.bytes("binding_owner_public_key"),
        chainId: try vectors.uint64("binding_chain_id"),
        nonce: try vectors.bytes("binding_nonce"),
        issuedAt: try vectors.string("binding_issued_at")
      )
    )
    XCTAssertEqual(bindingText, try vectors.string("binding_expected_text"))

    let selfProofOwnerPrivateKey = try vectors.bytes("selfproof_owner_private_key")
    let selfProofOwnerPublicKey = try vectors.bytes("selfproof_owner_public_key")
    let selfProofEventIdHash = try vectors.bytes("selfproof_event_id_hash")
    let selfProofEventSigningPublicKey = try vectors.bytes(
      "selfproof_event_signing_public_key"
    )
    let selfProofEninStart = try vectors.uint64("selfproof_enin_start")
    let selfProofEninEnd = try vectors.uint64("selfproof_enin_end")

    let selfProofMessage = try XCTUnwrap(
      BarnardCoreSigning.buildSelfProofMessage(
        eventIdHash: selfProofEventIdHash,
        eventSigningPublicKey: selfProofEventSigningPublicKey,
        eninStart: selfProofEninStart,
        eninEnd: selfProofEninEnd,
        ownerPublicKey: selfProofOwnerPublicKey
      )
    )
    XCTAssertEqual(hex(selfProofMessage), try vectors.string("selfproof_expected_message"))

    let selfProofSignature = try XCTUnwrap(
      BarnardCoreSigning.signSelfProof(
        ownerPrivateKey: selfProofOwnerPrivateKey,
        eventIdHash: selfProofEventIdHash,
        eventSigningPublicKey: selfProofEventSigningPublicKey,
        eninStart: selfProofEninStart,
        eninEnd: selfProofEninEnd,
        ownerPublicKey: selfProofOwnerPublicKey
      )
    )
    XCTAssertEqual(hex(selfProofSignature.r), try vectors.string("selfproof_expected_sig_r"))
    XCTAssertEqual(hex(selfProofSignature.s), try vectors.string("selfproof_expected_sig_s"))
    XCTAssertEqual(selfProofSignature.v, try vectors.int("selfproof_expected_sig_v"))
    XCTAssertTrue(
      BarnardCoreSigning.verifySelfProof(
        eventIdHash: selfProofEventIdHash,
        eventSigningPublicKey: selfProofEventSigningPublicKey,
        eninStart: selfProofEninStart,
        eninEnd: selfProofEninEnd,
        ownerPublicKey: selfProofOwnerPublicKey,
        signature: selfProofSignature
      )
    )

    let walletAckOwnerPrivateKey = try vectors.bytes("walletack_owner_private_key")
    let walletAckOwnerPublicKey = try vectors.bytes("walletack_owner_public_key")
    let walletAckWalletAddress = try vectors.bytes("walletack_wallet_address")
    let walletAckWalletSignature = try vectors.bytes("walletack_wallet_signature")

    let walletAckMessage = try XCTUnwrap(
      BarnardCoreSigning.buildWalletAcknowledgementMessage(
        walletAddress: walletAckWalletAddress,
        walletSignature: walletAckWalletSignature
      )
    )
    XCTAssertEqual(hex(walletAckMessage), try vectors.string("walletack_expected_message"))

    let walletAckSignature = try XCTUnwrap(
      BarnardCoreSigning.signWalletAcknowledgement(
        ownerPrivateKey: walletAckOwnerPrivateKey,
        walletAddress: walletAckWalletAddress,
        walletSignature: walletAckWalletSignature
      )
    )
    XCTAssertEqual(hex(walletAckSignature.r), try vectors.string("walletack_expected_sig_r"))
    XCTAssertEqual(hex(walletAckSignature.s), try vectors.string("walletack_expected_sig_s"))
    XCTAssertEqual(walletAckSignature.v, try vectors.int("walletack_expected_sig_v"))
    XCTAssertTrue(
      BarnardCoreSigning.verifyWalletAcknowledgement(
        ownerPublicKey: walletAckOwnerPublicKey,
        walletAddress: walletAckWalletAddress,
        walletSignature: walletAckWalletSignature,
        signature: walletAckSignature
      )
    )
  }

  func testECDSAProfilePositiveVector() throws {
    let vectors = try loadVectors(named: "secp256k1-ecdsa-v1.txt")
    let signature = BarnardCoreSigning.signRecoverable(
      privateKey: try vectors.bytes("private_key_valid"),
      messageHash32: try vectors.bytes("message_hash")
    )
    XCTAssertEqual(hex(signature.r), try vectors.string("expected_r"))
    XCTAssertEqual(hex(signature.s), try vectors.string("expected_s"))
    XCTAssertEqual(signature.v, try vectors.int("expected_v"))
    XCTAssertEqual(
      BarnardCoreSigning.recoverPublicKey(
        recoveryId: signature.v,
        r: signature.r,
        s: signature.s,
        messageHash32: try vectors.bytes("message_hash")
      ),
      try vectors.bytes("public_key_compressed")
    )
  }

  func testECDSAProfileRejectsPrivateKeyBoundariesAndOffCurveKey() throws {
    let vectors = try loadVectors(named: "secp256k1-ecdsa-v1.txt")
    for key in ["private_key_zero", "private_key_n", "private_key_n_plus_one"] {
      XCTAssertNil(
        BarnardCoreSigning.signWalletAcknowledgement(
          ownerPrivateKey: try vectors.bytes(key),
          walletAddress: [UInt8](repeating: 0, count: 20),
          walletSignature: [1]
        ),
        key
      )
    }
    XCTAssertNil(
      BarnardCoreSigning.buildSelfProofMessage(
        eventIdHash: [UInt8](repeating: 0, count: 32),
        eventSigningPublicKey: try vectors.bytes("off_curve_public_key"),
        eninStart: 0,
        eninEnd: 0,
        ownerPublicKey: try vectors.bytes("public_key_compressed")
      )
    )
  }

  func testECDSAProfileRejectsMalformedCompactComponents() throws {
    let vectors = try loadVectors(named: "secp256k1-ecdsa-v1.txt")
    let hash = try vectors.bytes("message_hash")
    let r = try vectors.bytes("expected_r")
    let s = try vectors.bytes("expected_s")
    for malformedR in ["malformed_r_short", "malformed_r_long"] {
      XCTAssertNil(BarnardCoreSigning.recoverPublicKey(
        recoveryId: try vectors.int("expected_v"), r: try vectors.bytes(malformedR),
        s: s, messageHash32: hash), malformedR)
    }
    for malformedS in ["malformed_s_short", "malformed_s_long"] {
      XCTAssertNil(BarnardCoreSigning.recoverPublicKey(
        recoveryId: try vectors.int("expected_v"), r: r,
        s: try vectors.bytes(malformedS), messageHash32: hash), malformedS)
    }
  }

  func testECDSAProfileRejectsHighSAndOutOfRangeRecoveryId() throws {
    let vectors = try loadVectors(named: "secp256k1-ecdsa-v1.txt")
    let hash = try vectors.bytes("message_hash")
    let r = try vectors.bytes("expected_r")
    XCTAssertNil(BarnardCoreSigning.recoverPublicKey(
      recoveryId: try vectors.int("high_s_recovery_v"), r: r,
      s: try vectors.bytes("high_s"), messageHash32: hash))
    XCTAssertNil(BarnardCoreSigning.recoverPublicKey(
      recoveryId: try vectors.int("out_of_range_recovery_id"), r: r,
      s: try vectors.bytes("expected_s"), messageHash32: hash))
    // The pure-Swift path (selected when CSecp256k1 is unavailable, i.e. the
    // mirrored Flutter build) must apply the same rejections.
    XCTAssertNil(BarnardCoreSigning.pureSwiftRecoverPublicKey(
      recoveryId: try vectors.int("high_s_recovery_v"), r: r,
      s: try vectors.bytes("high_s"), messageHash32: hash))
    XCTAssertNil(BarnardCoreSigning.pureSwiftRecoverPublicKey(
      recoveryId: try vectors.int("out_of_range_recovery_id"), r: r,
      s: try vectors.bytes("expected_s"), messageHash32: hash))
    XCTAssertNotNil(BarnardCoreSigning.pureSwiftRecoverPublicKey(
      recoveryId: try vectors.int("expected_v"), r: r,
      s: try vectors.bytes("expected_s"), messageHash32: hash))
    // A negative recovery id must be rejected by both paths (only 0 and 1 are valid).
    XCTAssertNil(BarnardCoreSigning.recoverPublicKey(
      recoveryId: -1, r: r, s: try vectors.bytes("expected_s"), messageHash32: hash))
    XCTAssertNil(BarnardCoreSigning.pureSwiftRecoverPublicKey(
      recoveryId: -1, r: r, s: try vectors.bytes("expected_s"), messageHash32: hash))
  }

  /// Profile clauses 2, 4, 6, 7, and 8 require byte-identical compressed keys and
  /// RFC 6979/no-extra-entropy, low-S compact recoverable signatures.
  func testLibsecp256k1AndPureSwiftBackendsAreByteIdentical() throws {
    let vectors = try loadVectors(named: "secp256k1-ecdsa-v1.txt")
    var pairs: [([UInt8], [UInt8])] = [(
      try vectors.bytes("private_key_valid"), try vectors.bytes("message_hash")
    )]
    let ownerVectors = try loadVectors()
    pairs.append((
      try ownerVectors.bytes("selfproof_owner_private_key"),
      BarnardCorePrimitives.sha256(try ownerVectors.bytes("selfproof_expected_message"))
    ))
    pairs.append((
      try ownerVectors.bytes("walletack_owner_private_key"),
      BarnardCorePrimitives.sha256(try ownerVectors.bytes("walletack_expected_message"))
    ))
    let fixedKey = try vectors.bytes("private_key_valid")
    pairs.append((fixedKey, [UInt8](repeating: 0xff, count: 32)))
    pairs.append((fixedKey, try decodeRequiredHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")))
    var state = [UInt8](repeating: 0x42, count: 32)
    // 200 pairs measured about 700 seconds under -O on an iOS Simulator.
    for index in 0..<24 {
      state = BarnardCorePrimitives.sha256(state + [UInt8(index & 0xff)])
      var key = BarnardCorePrimitives.sha256([0x6b] + state)
      while !BarnardCoreLibsecp256k1Backend.validatePrivateKey(key) {
        key = BarnardCorePrimitives.sha256(key)
      }
      pairs.append((key, BarnardCorePrimitives.sha256([0x68] + state)))
    }
    for (key, hash) in pairs {
      let pure = BarnardCoreSigning.pureSwiftSignRecoverable(privateKey: key, messageHash32: hash)
      let native = BarnardCoreSigning.signRecoverable(privateKey: key, messageHash32: hash)
      XCTAssertEqual(native.r, pure.r); XCTAssertEqual(native.s, pure.s); XCTAssertEqual(native.v, pure.v)
      let purePublicKey = BarnardCoreSecp256k1.compress(BarnardCoreSecp256k1.multiply(
        BarnardCoreSecp256k1.UInt256(bytes: key), BarnardCoreSecp256k1.generator))
      XCTAssertEqual(BarnardCoreLibsecp256k1Backend.compressedPublicKey(privateKey: key), purePublicKey)
    }
  }

  private func decodeRequiredHex(_ value: String) throws -> [UInt8] {
    guard let bytes = decodeHex(value) else { throw VectorError.malformedHex(value) }
    return bytes
  }

  // MARK: - Vector file loading

  private struct VectorFile {
    let values: [String: String]

    func string(_ key: String, line: UInt = #line) throws -> String {
      guard let value = values[key] else {
        XCTFail("Missing vector key '\(key)'", line: line)
        throw VectorError.missingKey(key)
      }
      return value
    }

    func bytes(_ key: String, line: UInt = #line) throws -> [UInt8] {
      let hexString = try string(key, line: line)
      guard let decoded = decodeHex(hexString) else {
        XCTFail("Malformed hex for vector key '\(key)'", line: line)
        throw VectorError.malformedHex(key)
      }
      return decoded
    }

    func uint64(_ key: String, line: UInt = #line) throws -> UInt64 {
      let value = try string(key, line: line)
      guard let parsed = UInt64(value) else {
        XCTFail("Malformed unsigned integer for vector key '\(key)'", line: line)
        throw VectorError.malformedInteger(key)
      }
      return parsed
    }

    func int(_ key: String, line: UInt = #line) throws -> Int {
      let value = try string(key, line: line)
      guard let parsed = Int(value) else {
        XCTFail("Malformed integer for vector key '\(key)'", line: line)
        throw VectorError.malformedInteger(key)
      }
      return parsed
    }
  }

  private enum VectorError: Error {
    case missingKey(String)
    case malformedHex(String)
    case malformedInteger(String)
    case malformedFile(String)
    case directoryNotFound
  }

  private func loadVectors(named fileName: String = "owner-key-v1.txt") throws -> VectorFile {
    let vectorsDirectory = try findTestVectorsDirectory()
    let fileURL = vectorsDirectory.appendingPathComponent(fileName)
    let contents = try String(contentsOf: fileURL, encoding: .utf8)
    return VectorFile(values: try parseVectorFile(contents))
  }

  /// Walks upward from this test file's own compile-time path until it
  /// finds a sibling directory literally named `test-vectors`. Bounded so a
  /// missing directory fails clearly instead of looping forever.
  private func findTestVectorsDirectory(maxLevels: Int = 20) throws -> URL {
    var candidateDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0..<maxLevels {
      let testVectorsCandidate = candidateDirectory.appendingPathComponent(
        "test-vectors",
        isDirectory: true
      )
      var isDirectory: ObjCBool = false
      if FileManager.default.fileExists(
        atPath: testVectorsCandidate.path,
        isDirectory: &isDirectory
      ), isDirectory.boolValue {
        return testVectorsCandidate
      }
      let parent = candidateDirectory.deletingLastPathComponent()
      if parent.path == candidateDirectory.path {
        break
      }
      candidateDirectory = parent
    }
    XCTFail(
      "Could not find a 'test-vectors' directory walking up \(maxLevels) levels from "
        + #filePath
    )
    throw VectorError.directoryNotFound
  }

  private func parseVectorFile(_ contents: String) throws -> [String: String] {
    var values: [String: String] = [:]
    for rawLine in contents.split(separator: "\n", omittingEmptySubsequences: false) {
      let line = String(rawLine)
      if line.isEmpty || line.hasPrefix("#") {
        continue
      }
      guard let equalsIndex = line.firstIndex(of: "=") else {
        XCTFail("Malformed vector line (no '='): \(line)")
        throw VectorError.malformedFile(line)
      }
      let key = String(line[line.startIndex..<equalsIndex])
      guard isValidKey(key) else {
        XCTFail("Malformed vector key: \(key)")
        throw VectorError.malformedFile(line)
      }
      let rawValue = String(line[line.index(after: equalsIndex)...])
      values[key] = try decodeValue(rawValue)
    }
    return values
  }

  private func isValidKey(_ key: String) -> Bool {
    !key.isEmpty
      && key.utf8.allSatisfy {
        (0x41...0x5a).contains($0) || (0x61...0x7a).contains($0) || (0x30...0x39).contains($0)
          || $0 == 0x5f
      }
  }

  private func decodeValue(_ value: String) throws -> String {
    var result = ""
    var iterator = value.makeIterator()
    while let character = iterator.next() {
      guard character == "\\" else {
        result.append(character)
        continue
      }
      guard let next = iterator.next() else {
        throw VectorError.malformedFile(value)
      }
      switch next {
      case "n":
        result.append("\n")
      case "\\":
        result.append("\\")
      default:
        throw VectorError.malformedFile(value)
      }
    }
    return result
  }

  private func hex(_ input: [UInt8]) -> String {
    input.map {
      let value = String($0, radix: 16)
      return value.count == 1 ? "0" + value : value
    }.joined()
  }
}

private func decodeHex(_ hex: String) -> [UInt8]? {
  guard hex.count.isMultiple(of: 2) else {
    return nil
  }
  var result: [UInt8] = []
  result.reserveCapacity(hex.count / 2)
  var index = hex.startIndex
  while index < hex.endIndex {
    let next = hex.index(index, offsetBy: 2)
    guard let byte = UInt8(hex[index..<next], radix: 16) else {
      return nil
    }
    result.append(byte)
    index = next
  }
  return result
}
