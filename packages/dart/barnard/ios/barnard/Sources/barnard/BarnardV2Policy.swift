// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

#if canImport(BarnardCore)
import BarnardCore
#endif

enum BarnardV2Policy {
  static func shouldServeGattDisplayId(eventCode: String?) -> Bool {
    BarnardCoreV2Policy.shouldServeGattDisplayId(eventCode: eventCode)
  }

  struct KnownPeerWindow {
    let enin: UInt32

    func matches(_ currentEnin: UInt32) -> Bool {
      BarnardCoreV2Policy.shouldEmitRssiUpdate(
        cachedPeerEnin: enin,
        currentEnin: currentEnin
      )
    }
  }

  static func shouldEmitRssiUpdate(
    cachedPeerEnin: UInt32,
    currentEnin: UInt32
  ) -> Bool {
    BarnardCoreV2Policy.shouldEmitRssiUpdate(
      cachedPeerEnin: cachedPeerEnin,
      currentEnin: currentEnin
    )
  }
}
