// Use of this source code is governed by a BSD-style license.

import Foundation
import XCTest
@testable import Barnard
import BarnardCore

final class BarnardB005DisplayNameNormalizerTests: XCTestCase {
  private let normalizer = BarnardB005NativeDisplayNameNormalizer()

  func testAcceptsAlreadyNFCString() {
    // A plain ASCII string, and a precomposed Latin string, are both already NFC.
    XCTAssertTrue(normalizer.isNormalizedNFC("Barnard Core Split"))
    XCTAssertTrue(normalizer.isNormalizedNFC("caf\u{00e9}")) // "café" with precomposed é (U+00E9)
  }

  func testRejectsDecomposedHangulJamo() {
    // U+1100 U+1161 (decomposed Hangul jamo) normalizes under NFC to the single precomposed
    // syllable U+AC00. The decomposed form itself is not NFC and MUST be rejected.
    let decomposed = "\u{1100}\u{1161}"
    XCTAssertFalse(normalizer.isNormalizedNFC(decomposed))
  }

  func testRejectsDecomposedLatinWithCombiningAcute() {
    // "e" + combining acute (U+0301) normalizes under NFC to precomposed é (U+00E9).
    let decomposed = "e\u{0301}"
    XCTAssertFalse(normalizer.isNormalizedNFC(decomposed))
  }

  func testInvalidUTF8BytesAreRejectedByVerifyBeforeReachingNormalizer() throws {
    // Invalid UTF-8 never reaches the normalizer: BarnardB005EnvelopeV2.verify's strictDisplayName
    // rejects it during decoding. This exercises that end-to-end path with the native normalizer
    // wired in, confirming the two layers compose correctly.
    let v = try Self.loadVectors()
    var container = hex(v["v1_container"]!)
    let nameStart = 136
    container[nameStart] = 0xff // invalid UTF-8 lead byte, same length as the original name
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: normalizer))
  }

  func testEndToEndVerifyVectorOneThroughNativeNormalizer() throws {
    let v = try Self.loadVectors()
    let container = hex(v["v1_container"]!)
    let verified = BarnardB005EnvelopeV2.verify(container: container, currentEnin: 6_000_000, nameValidator: normalizer)
    XCTAssertNotNil(verified)
    XCTAssertEqual(verified?.receiverState, .RADIO_SELF_VERIFIED)
  }

  private static func loadVectors() throws -> [String: String] {
    var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0..<20 {
      let candidate = directory.appendingPathComponent("test-vectors/b005-envelope-v2.txt")
      if FileManager.default.fileExists(atPath: candidate.path) {
        let text = try String(contentsOf: candidate, encoding: .utf8)
        return Dictionary(uniqueKeysWithValues: text.split(separator: "\n").compactMap { line in
          let s = line.trimmingCharacters(in: .whitespaces)
          guard !s.isEmpty, !s.hasPrefix("#"), let i = s.firstIndex(of: "=") else { return nil }
          return (String(s[..<i]), String(s[s.index(after: i)...]))
        })
      }
      directory.deleteLastPathComponent()
    }
    throw NSError(domain: "BarnardB005DisplayNameNormalizerTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "repo root not found"])
  }

  private func hex(_ s: String) -> [UInt8] {
    var bytes: [UInt8] = []
    var index = s.startIndex
    while index < s.endIndex {
      let next = s.index(index, offsetBy: 2)
      bytes.append(UInt8(s[index..<next], radix: 16)!)
      index = next
    }
    return bytes
  }
}
