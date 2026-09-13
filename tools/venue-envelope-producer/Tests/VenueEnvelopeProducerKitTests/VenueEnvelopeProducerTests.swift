// Use of this source code is governed by a BSD-style license.

import Barnard
import BarnardCore
import XCTest
@testable import VenueEnvelopeProducerKit

/// Fixture identity for this test file only -- distinct byte patterns from
/// `test-vectors/b005-envelope-v2.txt` so nobody mistakes this for the same event.
private enum Fixture {
  static let registrarHex = String(repeating: "a1", count: 20)
  static let anchorOperatorHex = String(repeating: "a2", count: 20)
  static let nonceHex = String(repeating: "a3", count: 32)
  /// Private key = 1. A trivial but valid scalar (`0 < 1 < curveOrder`), same convention as
  /// `BarnardOwnerKeyMessageTests.scalarOne` -- live-signed here, not a precomputed vector.
  static let signingPrivateKeyHex = String(repeating: "00", count: 31) + "01"
  static let authorityPublicKeyHex = VenueEnvelopeProducer.derivePublicKeyHex(fromPrivateKeyHex: signingPrivateKeyHex)!

  static func input(joinMode: UInt8 = 0, relayHopCount: UInt8 = 0) -> VenueEnvelopeProducerInput {
    VenueEnvelopeProducerInput(
      registrarHex: registrarHex,
      anchorOperatorHex: anchorOperatorHex,
      nonceHex: nonceHex,
      authorityKeysHex: [authorityPublicKeyHex],
      signingPrivateKeyHex: signingPrivateKeyHex,
      joinMode: joinMode,
      eninSeconds: 300,
      validFromEnin: 6_000_000,
      validThroughEnin: 6_000_010,
      relayExpiresAtEnin: 6_000_004,
      eventCodeHashHex: joinMode == 0 ? nil : String(repeating: "5a", count: 8),
      eventDisplayName: "Venue Test Event",
      relayHopCount: relayHopCount
    )
  }
}

final class VenueEnvelopeProducerTests: XCTestCase {

  func testDriverProducesRawSignedEnvelopeAndNotBLEContainer() throws {
    let descriptor = try JSONEncoder().encode(Fixture.descriptor())
    let frame = Fixture.frame(descriptor: descriptor)
    guard case .success(let output) = VenueEnvelopeProducerDriver.produceSignedEnvelope(from: frame) else {
      return XCTFail("driver refused valid frame")
    }
    XCTAssertEqual(output.eventId.count, 32)
    XCTAssertGreaterThanOrEqual(output.signedEnvelope.count, 199)
    XCTAssertEqual(output.container.count, output.signedEnvelope.count + 4)
    XCTAssertNotEqual(output.container, output.signedEnvelope)
    let json = VenueEnvelopeProducerDriver.outputJSON(output)
    XCTAssertTrue(json.hasPrefix("{\"kind\":\"SIGNED_ENVELOPE_V1\""))
    XCTAssertTrue(json.contains("\"signedEnvelopeHex\":\"" + hexString(output.signedEnvelope) + "\""))
    XCTAssertFalse(json.contains(hexString(output.container)))
  }

  func testDriverRefusesWrongAuthorityDescriptor() throws {
    var descriptor = Fixture.descriptor()
    descriptor = VenueEnvelopeProducerDescriptor(registrarHex: descriptor.registrarHex, anchorOperatorHex: descriptor.anchorOperatorHex, nonceHex: descriptor.nonceHex, authorityKeysHex: [String(repeating: "02", count: 33)], joinMode: descriptor.joinMode, eninSeconds: descriptor.eninSeconds, validFromEnin: descriptor.validFromEnin, validThroughEnin: descriptor.validThroughEnin, relayExpiresAtEnin: descriptor.relayExpiresAtEnin, eventCodeHashHex: descriptor.eventCodeHashHex, eventDisplayName: descriptor.eventDisplayName, relayHopCount: descriptor.relayHopCount)
    XCTAssertEqualFailure(VenueEnvelopeProducerDriver.produceSignedEnvelope(from: Fixture.frame(descriptor: try JSONEncoder().encode(descriptor))), "invalid descriptor")
  }

  func testDriverRefusesTruncatedBadKeyAndTrailingEOF() throws {
    let descriptor = try JSONEncoder().encode(Fixture.descriptor())
    let frame = Fixture.frame(descriptor: descriptor)
    XCTAssertEqualFailure(VenueEnvelopeProducerDriver.produceSignedEnvelope(from: Array(frame.dropLast())), "descriptor frame is truncated")
    XCTAssertEqualFailure(VenueEnvelopeProducerDriver.produceSignedEnvelope(from: frame + [0]), "input has trailing bytes after the private key")
    XCTAssertEqualFailure(VenueEnvelopeProducerDriver.produceSignedEnvelope(from: Array(frame.prefix(frame.count - 32)) + [1]), "descriptor frame is truncated")
    let badKeyFrame = Array(frame.dropLast(32)) + [UInt8](repeating: 0, count: 32)
    XCTAssertEqualFailure(VenueEnvelopeProducerDriver.produceSignedEnvelope(from: badKeyFrame), "invalid descriptor")
  }

  // MARK: - 1. Real Swift verifier accepts the produced container

  func testRealSwiftVerifierAcceptsProducedContainerAndRecoversTheSigningKey() throws {
    guard case .success(let output) = VenueEnvelopeProducer.produce(Fixture.input()) else {
      return XCTFail("produce refused")
    }
    let verified = BarnardB005EnvelopeV2.verify(
      container: output.container,
      currentEnin: 6_000_001,
      nameValidator: BarnardB005NativeDisplayNameNormalizer(),
      recoverer: BarnardB005NativeRecoverer()
    )
    guard let verified else { return XCTFail("real Swift verifier rejected the produced container") }
    XCTAssertEqual(verified.receiverState, .RADIO_SELF_VERIFIED)
    XCTAssertEqual(verified.eventId, output.eventId)
    XCTAssertEqual(verified.eventDisplayName, "Venue Test Event")

    // "the recovered key is the authority key you signed with": verify() itself does not surface
    // the recovered pubkey, so recover independently over the same (r, s, v, digest) via
    // BarnardCoreSigning's public recovery function and compare to the known authority key.
    let signedEnvelope = verified.signedEnvelope
    let signature = Array(signedEnvelope.suffix(65))
    let tbs = Array(signedEnvelope.dropLast(65))
    let digest = BarnardCoreCrypto.sha256(Array("barnard-b005-event-info:v1".utf8) + tbs)
    let recovered = BarnardCoreSigning.recoverPublicKey(recoveryId: Int(signature[64]), r: Array(signature[0..<32]), s: Array(signature[32..<64]), messageHash32: digest)
    XCTAssertEqual(recovered.map(hexString), Fixture.authorityPublicKeyHex)
  }

  // MARK: - 3. Negative controls, each failing for its own reason

  func testFlippedSignatureByteFailsVerification() throws {
    guard case .success(let output) = VenueEnvelopeProducer.produce(Fixture.input()) else {
      return XCTFail("produce refused")
    }
    var mutated = output.container
    mutated[mutated.count - 1] ^= 1 // last byte of the trailing 65-byte signature
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: mutated, currentEnin: 6_000_001, nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: BarnardB005NativeRecoverer()))
  }

  func testForeignEventIdFailsRegistryAgreement() throws {
    guard case .success(let output) = VenueEnvelopeProducer.produce(Fixture.input()) else {
      return XCTFail("produce refused")
    }
    let verified = BarnardB005EnvelopeV2.verify(container: output.container, currentEnin: 6_000_001, nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: BarnardB005NativeRecoverer())
    guard let verified else { return XCTFail("produced container did not verify") }
    let keySetDigest = BarnardB005EnvelopeV2.keySetDigest([hex(Fixture.authorityPublicKeyHex)])!
    let foreignDefinition = BarnardEventDefinitionV1(
      eventId: [UInt8](repeating: 0xff, count: 32), // deliberately not this envelope's eventId
      keySetDigest: keySetDigest,
      joinMode: 0,
      eventCodeHash: verified.eventCodeHash,
      validFromUnixSeconds: 0,
      validUntilUnixSeconds: 300 * 6_000_020
    )
    let agreement = BarnardB005EnvelopeV2.registryAgreement(verified, definition: foreignDefinition)
    guard case .mismatched(let fields) = agreement else { return XCTFail("expected a mismatch") }
    XCTAssertTrue(fields.contains(.EVENT_ID))
  }

  func testStructurallyMalformedContainerFailsValidateStructure() throws {
    guard case .success(let output) = VenueEnvelopeProducer.produce(Fixture.input()) else {
      return XCTFail("produce refused")
    }
    let truncated = Array(output.container.dropLast(10)) // now disagrees with its own length header
    XCTAssertEqual(BarnardB005EnvelopeV2.validateStructure(container: truncated), .envelopeLength)
  }

  // MARK: - 4. The r || s || v assembly is pinned

  func testSignatureAssemblyOrderIsPinned() throws {
    guard case .success(let output) = VenueEnvelopeProducer.produce(Fixture.input()) else {
      return XCTFail("produce refused")
    }
    let signature = Array(output.container.suffix(65))
    let r = Array(signature[0..<32]), s = Array(signature[32..<64]), v = signature[64]
    // A real B005 v2 recovery byte is 0 or 1 (low-S normalized), never the Ethereum `v + 27`
    // convention the EIP-191 signing paths elsewhere in this SDK use.
    XCTAssertLessThanOrEqual(v, 1)
    // Swapping r and s (the other plausible-looking ordering bug) must break verification --
    // this is what "pinned" means: a test that fails if the byte order changes.
    let swapped = s + r + [v]
    let unsigned = try XCTUnwrap(BarnardB005EnvelopeV2.encodeUnsignedEnvelope(Fixture.encodeOnlyFields(), nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: BarnardB005NativeRecoverer()).successValue)
    guard case .success(let swappedSigned) = BarnardB005EnvelopeV2.assembleSignedEnvelope(toBeSigned: unsigned.toBeSigned, signature: swapped) else {
      return XCTFail("assembleSignedEnvelope refused a 65-byte signature")
    }
    let swappedContainer = BarnardB005EnvelopeV2.encodeContainer(relayHopCount: 0, signedEnvelope: swappedSigned)!
    XCTAssertNil(BarnardB005EnvelopeV2.verify(container: swappedContainer, currentEnin: 6_000_001, nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: BarnardB005NativeRecoverer()), "swapping r and s must not still verify")
  }

  // MARK: - Cross-language fixture (Kotlin side: BarnardVenueEnvelopeProducerFixtureTest)

  /// Writes the shared fixture `test-vectors/venue-envelope-producer-fixture.txt` that the Kotlin
  /// test in `packages/android/barnard` reads. This is a checked-in snapshot, not something
  /// generated at Kotlin test time (Kotlin's test module has no Swift toolchain to invoke): this
  /// test unconditionally overwrites the fixture rather than comparing against it, so someone
  /// changing this tool's producer or the shared encoder must run `swift test` here and commit
  /// the result. CI (`native-sdk.yml`'s `venue-envelope-producer` job) enforces that the commit
  /// actually happened, via a `git diff --exit-code` step after this test runs -- see that job
  /// for why the check has to live there rather than in this test itself.
  func testWriteCrossLanguageFixture() throws {
    guard case .success(let output) = VenueEnvelopeProducer.produce(Fixture.input()) else {
      return XCTFail("produce refused")
    }
    XCTAssertNotNil(BarnardB005EnvelopeV2.verify(container: output.container, currentEnin: 6_000_001, nameValidator: BarnardB005NativeDisplayNameNormalizer(), recoverer: BarnardB005NativeRecoverer()), "refusing to write a fixture the Swift verifier itself rejects")

    let contents = """
    # Cross-language acceptance fixture for tools/venue-envelope-producer.
    # Generated by VenueEnvelopeProducerTests.testWriteCrossLanguageFixture (Swift, real signing
    # key + real BarnardCoreSigning.signRecoverable, NOT a hand-written vector). Read by
    # BarnardVenueEnvelopeProducerFixtureTest.kt in packages/android/barnard, whose only
    # assertion is that Kotlin's BarnardB005EnvelopeV2.verify accepts these same bytes.
    container_hex=\(hexString(output.container))
    current_enin=6000001
    """ + "\n"
    let url = try Self.repoRoot().appendingPathComponent("test-vectors/venue-envelope-producer-fixture.txt")
    try contents.write(to: url, atomically: true, encoding: .utf8)
  }

  private static func repoRoot() throws -> URL {
    var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    for _ in 0..<20 {
      if FileManager.default.fileExists(atPath: directory.appendingPathComponent("test-vectors").path) {
        return directory
      }
      directory.deleteLastPathComponent()
    }
    throw NSError(domain: "VenueEnvelopeProducerTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "could not find repo root (test-vectors/)"])
  }
}

private extension Fixture {
  static func descriptor() -> VenueEnvelopeProducerDescriptor {
    VenueEnvelopeProducerDescriptor(registrarHex: registrarHex, anchorOperatorHex: anchorOperatorHex, nonceHex: nonceHex, authorityKeysHex: [authorityPublicKeyHex], joinMode: 0, eninSeconds: 300, validFromEnin: 6_000_000, validThroughEnin: 6_000_010, relayExpiresAtEnin: 6_000_004, eventCodeHashHex: nil, eventDisplayName: "Venue Test Event", relayHopCount: 0)
  }

  static func frame(descriptor: Data) -> [UInt8] {
    let length = descriptor.count
    return [UInt8((length >> 24) & 0xff), UInt8((length >> 16) & 0xff), UInt8((length >> 8) & 0xff), UInt8(length & 0xff)] + Array(descriptor) + hex(signingPrivateKeyHex)
  }

  /// The same fields `input()` produces, but as `BarnardB005EnvelopeFields` directly, for a test
  /// that needs to re-run `encodeUnsignedEnvelope` itself rather than through `produce`.
  static func encodeOnlyFields() -> BarnardB005EnvelopeFields {
    let key = hex(authorityPublicKeyHex)
    let eventId = BarnardB005EnvelopeV2.computeEventId(registrar: hex(registrarHex), anchorOperator: hex(anchorOperatorHex), nonce: hex(nonceHex), keySetDigest: BarnardB005EnvelopeV2.keySetDigest([key])!)!
    return BarnardB005EnvelopeFields(
      registrar: hex(registrarHex), anchorOperator: hex(anchorOperatorHex), nonce: hex(nonceHex),
      authorityKeys: [key], joinMode: 0, eninSeconds: 300,
      validFromEnin: 6_000_000, validThroughEnin: 6_000_010, relayExpiresAtEnin: 6_000_004,
      eventCodeHash: BarnardB005EnvelopeV2.openEventCodeHash(eventId: eventId)!,
      eventDisplayName: "Venue Test Event"
    )
  }
}

private extension XCTestCase {
  func XCTAssertEqualFailure<T>(_ result: Result<T, VenueEnvelopeProducerDriverError>, _ prefix: String, file: StaticString = #filePath, line: UInt = #line) {
    guard case .failure(let error) = result else { return XCTFail("expected driver failure", file: file, line: line) }
    XCTAssertTrue(error.description.hasPrefix(prefix), "unexpected error: \(error)", file: file, line: line)
  }
}

private func hex(_ s: String) -> [UInt8] { stride(from: 0, to: s.count, by: 2).map { UInt8(s.dropFirst($0).prefix(2), radix: 16)! } }
private func hexString(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

private extension Result {
  var successValue: Success? { if case .success(let value) = self { return value }; return nil }
}
