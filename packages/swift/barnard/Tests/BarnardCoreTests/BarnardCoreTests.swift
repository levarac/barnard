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
    let secrets = [
      [UInt8](repeating: 0x11, count: 32),
      [UInt8](repeating: 0x22, count: 32),
    ]
    let key = "device-secret-rendezvous"
    let storage = RendezvousKeyStorage(readTimeout: 1.0)
    let results = ConcurrentByteValues()

    // The storage blocks the first read until the second read has arrived.
    // The timeout is intentional: a correct implementation serializes the
    // calls, so the second read cannot rendezvous until the first transaction
    // has completed. An unfixed implementation reaches both reads together,
    // making the race deterministic without relying on sleeps or repetition.
    let completed = DispatchGroup()
    for index in secrets.indices {
      completed.enter()
      DispatchQueue.global().async {
        defer { completed.leave() }
        let loaded = BarnardCoreKeyManager.loadOrCreate(
          key: key,
          minimumByteCount: 32,
          generatedByteCount: 32,
          storage: storage,
          randomSource: FixedRandomSource(bytes: secrets[index])
        )
        results.append(loaded)
      }
    }

    guard completed.wait(timeout: .now() + 3) == .success else {
      XCTFail("concurrent cold loads did not complete before the timeout")
      return
    }

    let loadedValues = results.snapshot
    XCTAssertEqual(loadedValues.count, 2)
    XCTAssertEqual(
      loadedValues[0],
      loadedValues[1],
      "concurrent cold loads must return the same device secret"
    )
    XCTAssertEqual(
      loadedValues[0],
      storage.storedBytes(forKey: key),
      "concurrent cold loads must return the value that was persisted"
    )
  }

  func testReentrantStorageCallbackDoesNotDeadlock() {
    let storage = ReentrantKeyStorage()
    let completed = DispatchGroup()
    completed.enter()

    DispatchQueue.global().async {
      defer { completed.leave() }
      _ = BarnardCoreKeyManager.loadOrCreate(
        key: "outer-device-secret",
        minimumByteCount: 32,
        generatedByteCount: 32,
        storage: storage,
        randomSource: FixedRandomSource(bytes: [UInt8](repeating: 0x11, count: 32))
      )
    }

    guard completed.wait(timeout: .now() + 3) == .success else {
      XCTFail("re-entrant storage callback did not complete before the timeout")
      return
    }
    XCTAssertEqual(storage.nestedCallCount, 1)
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

private final class RendezvousKeyStorage: BarnardCoreKeyStorage {
  private let condition = NSCondition()
  private let readTimeout: TimeInterval
  private var readCount = 0
  private var values: [String: [UInt8]] = [:]

  init(readTimeout: TimeInterval) {
    self.readTimeout = readTimeout
  }

  func bytes(forKey key: String) -> [UInt8]? {
    condition.lock()
    readCount += 1
    if readCount == 2 {
      condition.broadcast()
    } else {
      let deadline = Date(timeIntervalSinceNow: readTimeout)
      while readCount < 2 && condition.wait(until: deadline) {}
    }
    let value = values[key]
    condition.unlock()
    return value
  }

  func setBytes(_ bytes: [UInt8], forKey key: String) {
    condition.lock()
    values[key] = bytes
    condition.unlock()
  }

  func storedBytes(forKey key: String) -> [UInt8]? {
    condition.lock()
    let value = values[key]
    condition.unlock()
    return value
  }
}

private final class ReentrantKeyStorage: BarnardCoreKeyStorage {
  private var values: [String: [UInt8]] = [:]
  private(set) var nestedCallCount = 0

  func bytes(forKey key: String) -> [UInt8]? {
    if nestedCallCount == 0 {
      nestedCallCount = 1
      _ = BarnardCoreKeyManager.loadOrCreate(
        key: "nested-device-secret",
        minimumByteCount: 32,
        generatedByteCount: 32,
        storage: self,
        randomSource: FixedRandomSource(bytes: [UInt8](repeating: 0x22, count: 32))
      )
    }
    return values[key]
  }

  func setBytes(_ bytes: [UInt8], forKey key: String) {
    values[key] = bytes
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
