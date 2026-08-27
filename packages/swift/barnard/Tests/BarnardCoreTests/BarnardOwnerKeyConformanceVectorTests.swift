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

  private func loadVectors() throws -> VectorFile {
    let vectorsDirectory = try findTestVectorsDirectory()
    let fileURL = vectorsDirectory.appendingPathComponent("owner-key-v1.txt")
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
