// Use of this source code is governed by a BSD-style license.

import Dispatch
import Foundation
import XCTest
@testable import BarnardCore

final class BarnardCoreTests: XCTestCase {
  func testSha256MatchesPublishedVector() {
    XCTAssertEqual(
      hex(BarnardCoreCrypto.sha256(Array("abc".utf8))),
      "ba7816bf8f01cfea414140de5dae2223"
        + "b00361a396177a9cb410ff61f20015ad"
    )
  }

  func testRpidChainMatchesPreSplitVector() {
    let secret = (0..<32).map(UInt8.init)
    let tek = BarnardCoreCrypto.deriveTekForEvent(
      deviceSecret: secret,
      eventCode: "CORE-SPLIT-80"
    )
    let rpik = BarnardCoreCrypto.deriveRpik(from: tek)
    let rpi = BarnardCoreCrypto.generateRpi(rpik: rpik, enin: 123_456)

    XCTAssertEqual(hex(tek), "51c9263c4fbfc28fb28a76ab0d5d83d6")
    XCTAssertEqual(hex(rpik), "9c20d41985cc258c21e11f10f764b954")
    XCTAssertEqual(hex(rpi), "be601a7b45035ec4c85f8e203679d5ae")
  }

  func testInjectedStorageAndRandomSourceCreateThenReuseKey() {
    let storage = MemoryKeyStorage()
    let random = FixedRandomSource(bytes: [UInt8](repeating: 0x5a, count: 32))

    let first = BarnardCoreKeyManager.loadOrCreate(
      key: "device-secret",
      minimumByteCount: 32,
      generatedByteCount: 32,
      storage: storage,
      randomSource: random
    )
    let second = BarnardCoreKeyManager.loadOrCreate(
      key: "device-secret",
      minimumByteCount: 32,
      generatedByteCount: 32,
      storage: storage,
      randomSource: FixedRandomSource(bytes: [UInt8](repeating: 0xff, count: 32))
    )

    XCTAssertEqual(first, [UInt8](repeating: 0x5a, count: 32))
    XCTAssertEqual(second, first)
  }

  func testConcurrentColdLoadsAgreeWithStoredSecret() {
    let attempts = 8
    let secrets = [
      [UInt8](repeating: 0x11, count: 32),
      [UInt8](repeating: 0x22, count: 32),
    ]

    for attempt in 0..<attempts {
      let storage = DelayedKeyStorage(readDelay: 0.05)
      let results = ConcurrentByteValues()

      DispatchQueue.concurrentPerform(iterations: 2) { index in
        let loaded = BarnardCoreKeyManager.loadOrCreate(
          key: "device-secret-\(attempt)",
          minimumByteCount: 32,
          generatedByteCount: 32,
          storage: storage,
          randomSource: FixedRandomSource(bytes: secrets[index])
        )
        results.append(loaded)
      }

      let loadedValues = results.snapshot
      XCTAssertEqual(loadedValues.count, 2)
      XCTAssertEqual(
        loadedValues[0],
        loadedValues[1],
        "concurrent cold loads must return the same device secret (attempt \(attempt))"
      )
      XCTAssertEqual(
        loadedValues[0],
        storage.storedBytes(forKey: "device-secret-\(attempt)"),
        "concurrent cold loads must return the value that was persisted (attempt \(attempt))"
      )
    }
  }

  func testInjectedClockProducesExpectedPayload() {
    let tek = BarnardCoreCrypto.deriveTekForEvent(
      deviceSecret: (0..<32).map(UInt8.init),
      eventCode: "CORE-SPLIT-80"
    )
    let payload = BarnardCoreCrypto.currentPayload(
      tek: tek,
      clock: FixedClock(unixSeconds: 123_456 * 300)
    )

    XCTAssertEqual(hex(payload), "01be601a7b45035ec4c85f8e203679d5ae")
  }

  func testEninAndPolicyRemainScalarOnly() {
    XCTAssertEqual(
      BarnardCoreCrypto.calculateEnin(unixSeconds: 1_700_000_123),
      5_666_667
    )
    XCTAssertTrue(BarnardCoreV2Policy.shouldServeGattDisplayId(eventCode: "event"))
    XCTAssertFalse(BarnardCoreV2Policy.shouldServeGattDisplayId(eventCode: nil))
    XCTAssertTrue(
      BarnardCoreV2Policy.shouldEmitRssiUpdate(
        cachedPeerEnin: 10,
        currentEnin: 10
      )
    )
    XCTAssertFalse(
      BarnardCoreV2Policy.shouldEmitRssiUpdate(
        cachedPeerEnin: 10,
        currentEnin: 11
      )
    )
  }

  private func hex(_ bytes: [UInt8]) -> String {
    bytes.map {
      let value = String($0, radix: 16)
      return value.count == 1 ? "0" + value : value
    }.joined()
  }
}

private final class MemoryKeyStorage: BarnardCoreKeyStorage {
  private var values: [String: [UInt8]] = [:]

  func bytes(forKey key: String) -> [UInt8]? {
    values[key]
  }

  func setBytes(_ bytes: [UInt8], forKey key: String) {
    values[key] = bytes
  }
}

private final class DelayedKeyStorage: BarnardCoreKeyStorage {
  private let lock = NSLock()
  private let readDelay: TimeInterval
  private var values: [String: [UInt8]] = [:]

  init(readDelay: TimeInterval) {
    self.readDelay = readDelay
  }

  func bytes(forKey key: String) -> [UInt8]? {
    Thread.sleep(forTimeInterval: readDelay)
    lock.lock()
    defer { lock.unlock() }
    return values[key]
  }

  func setBytes(_ bytes: [UInt8], forKey key: String) {
    lock.lock()
    values[key] = bytes
    lock.unlock()
  }

  func storedBytes(forKey key: String) -> [UInt8]? {
    lock.lock()
    defer { lock.unlock() }
    return values[key]
  }
}

private final class ConcurrentByteValues {
  private let lock = NSLock()
  private var values: [[UInt8]] = []

  func append(_ value: [UInt8]) {
    lock.lock()
    values.append(value)
    lock.unlock()
  }

  var snapshot: [[UInt8]] {
    lock.lock()
    defer { lock.unlock() }
    return values
  }
}

private struct FixedRandomSource: BarnardCoreRandomSource {
  let bytes: [UInt8]

  func randomBytes(count: Int) -> [UInt8] {
    Array(bytes.prefix(count))
  }
}

private struct FixedClock: BarnardCoreClock {
  let unixSeconds: Int64

  func currentUnixSeconds() -> Int64 {
    unixSeconds
  }
}
