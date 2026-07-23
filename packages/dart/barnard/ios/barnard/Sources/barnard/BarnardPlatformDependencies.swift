// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

#if canImport(BarnardCore)
import BarnardCore
#endif
import Foundation
import Security

struct BarnardSystemRandomSource: BarnardCoreRandomSource {
  func randomBytes(count: Int) -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return bytes
  }
}

struct BarnardUserDefaultsKeyStorage: BarnardCoreKeyStorage {
  let defaults: UserDefaults

  init(defaults: UserDefaults = .standard) {
    self.defaults = defaults
  }

  func bytes(forKey key: String) -> [UInt8]? {
    defaults.data(forKey: key).map(Array.init)
  }

  func setBytes(_ bytes: [UInt8], forKey key: String) {
    defaults.set(Data(bytes), forKey: key)
  }
}

struct BarnardSystemClock: BarnardCoreClock {
  func currentUnixSeconds() -> Int64 {
    Int64(Date().timeIntervalSince1970)
  }
}

struct BarnardFixedClock: BarnardCoreClock {
  let unixSeconds: Int64

  func currentUnixSeconds() -> Int64 {
    unixSeconds
  }
}
