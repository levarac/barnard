// Use of this source code is governed by a BSD-style license.

import Foundation
import XCTest
@testable import Barnard

/// barnard#124: the per-event signing key pair is cached, so these tests
/// guard the properties that make caching safe rather than the speedup.
///
/// The cache is exercised with a counting stand-in for the real derivation
/// where the assertion is about cache behavior, and with the real derivation
/// where the assertion is about key material.
final class BarnardSigningKeyCacheTests: XCTestCase {
  private func stubKeyPair(_ marker: UInt8) -> BarnardSigning.SigningKeyPair {
    BarnardSigning.SigningKeyPair(
      privateKey: Secp256k1.UInt256(data: Data(repeating: marker, count: 32)),
      publicKeyCompressed: Data(repeating: marker, count: 33)
    )
  }

  func testSameInputsReuseTheDerivation() {
    let cache = BarnardSigningKeyCache()
    let secret = Data(repeating: 0x31, count: 32)
    var derivations = 0

    let first = cache.keyPair(deviceSecret: secret, eventCode: "EVT1") { _, _ in
      derivations += 1
      return stubKeyPair(0x01)
    }
    let second = cache.keyPair(deviceSecret: secret, eventCode: "EVT1") { _, _ in
      derivations += 1
      return stubKeyPair(0x02)
    }

    XCTAssertEqual(derivations, 1, "second lookup with identical inputs must not derive again")
    XCTAssertEqual(first.publicKeyCompressed, second.publicKeyCompressed)
  }

  /// The regression test for the catastrophic form of this bug: a cache
  /// keyed on `eventCode` alone would sign with another device's identity.
  func testDifferentDeviceSecretWithSameEventCodeDoesNotReuseTheEntry() {
    let cache = BarnardSigningKeyCache()
    var derivations = 0
    let derive: (Data, String) -> BarnardSigning.SigningKeyPair = { _, _ in
      derivations += 1
      return self.stubKeyPair(UInt8(derivations))
    }

    let first = cache.keyPair(
      deviceSecret: Data(repeating: 0x41, count: 32),
      eventCode: "EVT1",
      derive: derive
    )
    let second = cache.keyPair(
      deviceSecret: Data(repeating: 0x42, count: 32),
      eventCode: "EVT1",
      derive: derive
    )

    XCTAssertEqual(derivations, 2, "a different device secret must miss the cache")
    XCTAssertNotEqual(first.publicKeyCompressed, second.publicKeyCompressed)
  }

  /// The same property proved against the real derivation: the key pair
  /// handed back after the secret changes is the one that secret derives.
  func testDifferentDeviceSecretYieldsTheKeyPairOfThatSecret() {
    let cache = BarnardSigningKeyCache()
    let firstSecret = Data(repeating: 0x43, count: 32)
    let secondSecret = Data(repeating: 0x44, count: 32)
    let derive = BarnardSigning.deriveSigningKeyPair(deviceSecret:eventCode:)

    let first = cache.keyPair(deviceSecret: firstSecret, eventCode: "EVT1", derive: derive)
    let second = cache.keyPair(deviceSecret: secondSecret, eventCode: "EVT1", derive: derive)

    XCTAssertNotEqual(first.publicKeyCompressed, second.publicKeyCompressed)
    XCTAssertEqual(
      first.publicKeyCompressed,
      BarnardSigning.deriveSigningKeyPair(deviceSecret: firstSecret, eventCode: "EVT1")
        .publicKeyCompressed
    )
    XCTAssertEqual(
      second.publicKeyCompressed,
      BarnardSigning.deriveSigningKeyPair(deviceSecret: secondSecret, eventCode: "EVT1")
        .publicKeyCompressed
    )
  }

  func testDifferentEventCodeWithSameDeviceSecretDoesNotReuseTheEntry() {
    let cache = BarnardSigningKeyCache()
    let secret = Data(repeating: 0x45, count: 32)
    var derivations = 0
    let derive: (Data, String) -> BarnardSigning.SigningKeyPair = { _, _ in
      derivations += 1
      return self.stubKeyPair(UInt8(derivations))
    }

    let first = cache.keyPair(deviceSecret: secret, eventCode: "EVT1", derive: derive)
    let second = cache.keyPair(deviceSecret: secret, eventCode: "EVT2", derive: derive)

    XCTAssertEqual(derivations, 2, "a different event code must miss the cache")
    XCTAssertNotEqual(first.publicKeyCompressed, second.publicKeyCompressed)
  }

  /// Only one entry is retained, so at most one derived private key is
  /// resident and returning to earlier inputs re-derives.
  func testCacheHoldsASingleEntry() {
    let cache = BarnardSigningKeyCache()
    let secret = Data(repeating: 0x46, count: 32)
    var derivations = 0
    let derive: (Data, String) -> BarnardSigning.SigningKeyPair = { _, _ in
      derivations += 1
      return self.stubKeyPair(UInt8(derivations))
    }

    _ = cache.keyPair(deviceSecret: secret, eventCode: "EVT1", derive: derive)
    _ = cache.keyPair(deviceSecret: secret, eventCode: "EVT2", derive: derive)
    _ = cache.keyPair(deviceSecret: secret, eventCode: "EVT1", derive: derive)

    XCTAssertEqual(derivations, 3)
  }

  func testClearForcesRederivation() {
    let cache = BarnardSigningKeyCache()
    let secret = Data(repeating: 0x47, count: 32)
    var derivations = 0
    let derive: (Data, String) -> BarnardSigning.SigningKeyPair = { _, _ in
      derivations += 1
      return self.stubKeyPair(UInt8(derivations))
    }

    _ = cache.keyPair(deviceSecret: secret, eventCode: "EVT1", derive: derive)
    cache.clear()
    _ = cache.keyPair(deviceSecret: secret, eventCode: "EVT1", derive: derive)

    XCTAssertEqual(derivations, 2)
  }

  /// The fingerprint covers both inputs, and covers them unambiguously: a
  /// byte moved across the secret/event-code boundary changes it.
  func testFingerprintSeparatesTheInputs() {
    let a = BarnardSigningKeyCache.fingerprint(
      deviceSecret: Data([0x01, 0x02]),
      eventCode: "34"
    )
    let b = BarnardSigningKeyCache.fingerprint(
      deviceSecret: Data([0x01, 0x02, 0x33]),
      eventCode: "4"
    )
    let c = BarnardSigningKeyCache.fingerprint(
      deviceSecret: Data([0x01, 0x02]),
      eventCode: "34"
    )

    XCTAssertNotEqual(a, b)
    XCTAssertEqual(a, c, "the fingerprint must be stable for identical inputs")
    XCTAssertEqual(a.count, 32)
  }

  /// The device secret must not be recoverable from what the cache keeps.
  func testFingerprintDoesNotContainTheDeviceSecret() {
    let secret = Data((0..<32).map { UInt8($0 &+ 0x50) })
    let fingerprint = BarnardSigningKeyCache.fingerprint(deviceSecret: secret, eventCode: "EVT1")

    XCTAssertFalse(
      fingerprint.range(of: secret) != nil,
      "the fingerprint must not embed the device secret"
    )
    XCTAssertNotEqual(fingerprint, secret)
  }

  /// A warm cache under concurrent lookups serves one entry consistently and
  /// does not derive again. (A cold cache may derive more than once by
  /// design — the lock is not held across the derivation — so the warm case
  /// is what carries an exact count.)
  func testConcurrentLookupsOnAWarmCacheAreConsistent() {
    let cache = BarnardSigningKeyCache()
    let secret = Data(repeating: 0x48, count: 32)
    let expected = stubKeyPair(0x99)
    let derivations = BarnardTestCounter()

    _ = cache.keyPair(deviceSecret: secret, eventCode: "EVT1") { _, _ in
      derivations.increment()
      return expected
    }

    let results = BarnardTestResultBox()
    DispatchQueue.concurrentPerform(iterations: 64) { _ in
      let pair = cache.keyPair(deviceSecret: secret, eventCode: "EVT1") { _, _ in
        derivations.increment()
        return self.stubKeyPair(0x11)
      }
      results.record(pair.publicKeyCompressed)
    }

    XCTAssertEqual(derivations.value, 1, "a warm cache must not re-derive under concurrent lookups")
    XCTAssertEqual(results.distinctValues, [expected.publicKeyCompressed])
  }

  /// Concurrent lookups that contend on the single entry must each get the
  /// key pair for the inputs they passed.
  ///
  /// Every iteration uses a different (deviceSecret, eventCode), and the
  /// derivation is a pure function of its arguments that yields a distinct
  /// key pair per input pair, so a lookup that returned another iteration's
  /// entry — including one assembled from a fingerprint and a key pair read
  /// at different moments — produces a value this test can tell apart. The
  /// expected value is computed from the loop index rather than from the
  /// cache's own fingerprint, so a fault in that fingerprint cannot cancel
  /// out against the expectation.
  func testConcurrentLookupsReturnTheKeyPairForTheirOwnInputs() {
    let cache = BarnardSigningKeyCache()
    let iterations = 64
    let mismatches = BarnardTestCounter()

    DispatchQueue.concurrentPerform(iterations: iterations) { index in
      let secretMarker = UInt8(index)
      let eventMarker = UInt8(iterations - 1 - index)
      let deviceSecret = Data(repeating: secretMarker, count: 32)
      let eventCode = "EVT-\(eventMarker)"

      let pair = cache.keyPair(deviceSecret: deviceSecret, eventCode: eventCode) { secret, code in
        Self.stubKeyPair(
          secretMarker: secret.first ?? 0,
          eventMarker: UInt8(code.dropFirst(4)) ?? 0
        )
      }

      let expected = Self.stubKeyPair(secretMarker: secretMarker, eventMarker: eventMarker)
      if pair.publicKeyCompressed != expected.publicKeyCompressed
        || pair.privateKey.data != expected.privateKey.data
      {
        mismatches.increment()
      }
    }

    XCTAssertEqual(
      mismatches.value,
      0,
      "every concurrent lookup must return the key pair derived from its own inputs"
    )
  }

  /// Deterministic stand-in for a derivation, distinguishable by both inputs.
  private static func stubKeyPair(
    secretMarker: UInt8,
    eventMarker: UInt8
  ) -> BarnardSigning.SigningKeyPair {
    var publicKey = Data([secretMarker, eventMarker])
    publicKey.append(Data(repeating: secretMarker ^ eventMarker, count: 31))
    var privateKey = Data([eventMarker, secretMarker])
    privateKey.append(Data(repeating: secretMarker &+ eventMarker, count: 30))
    return BarnardSigning.SigningKeyPair(
      privateKey: Secp256k1.UInt256(data: privateKey),
      publicKeyCompressed: publicKey
    )
  }
}

/// Minimal thread-safe helpers for the concurrency tests above.
private final class BarnardTestCounter {
  private let lock = NSLock()
  private var count = 0

  func increment() {
    lock.lock()
    count += 1
    lock.unlock()
  }

  var value: Int {
    lock.lock()
    defer { lock.unlock() }
    return count
  }
}

private final class BarnardTestResultBox {
  private let lock = NSLock()
  private var values: Set<Data> = []

  func record(_ value: Data) {
    lock.lock()
    values.insert(value)
    lock.unlock()
  }

  var distinctValues: Set<Data> {
    lock.lock()
    defer { lock.unlock() }
    return values
  }
}
