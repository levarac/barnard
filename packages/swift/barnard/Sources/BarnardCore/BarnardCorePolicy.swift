// Use of this source code is governed by a BSD-style license.

public enum BarnardCoreV2Policy {
  public static func shouldServeGattDisplayId(eventCode: String?) -> Bool {
    guard let eventCode, !eventCode.isEmpty else {
      return false
    }
    return true
  }

  public static func shouldEmitRssiUpdate(
    cachedPeerEnin: UInt32,
    currentEnin: UInt32
  ) -> Bool {
    cachedPeerEnin == currentEnin
  }
}
