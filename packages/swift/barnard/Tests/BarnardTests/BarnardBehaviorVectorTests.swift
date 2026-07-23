// Use of this source code is governed by a BSD-style license.

import CryptoKit
import XCTest
@testable import Barnard

/// Golden behavior captured before the BarnardCore split for issue #80.
///
/// The fixed inputs deliberately cover every deterministic surface moved by
/// the refactor: RPID derivation, ENIN calculation, signing, and v2 policy.
final class BarnardBehaviorVectorTests: XCTestCase {
  func testBehaviorVectorsMatchPreSplitImplementation() {
    let deviceSecret = Data((0..<32).map(UInt8.init))
    let eventCode = "CORE-SPLIT-80"
    let enin: UInt32 = 123_456
    let unixSeconds = 1_700_000_123

    let eventTek = BarnardCrypto.deriveTekForEvent(
      deviceSecret: deviceSecret,
      eventCode: eventCode
    )
    let anonymousTek = BarnardCrypto.deriveTekForAnonymous(deviceSecret: deviceSecret)
    let rpik = BarnardCrypto.deriveRpik(from: eventTek)
    let rpi = BarnardCrypto.generateRpi(rpik: rpik, enin: enin)
    let signingKeyPair = BarnardSigning.deriveSigningKeyPair(
      deviceSecret: deviceSecret,
      eventCode: eventCode
    )
    let messageHash = Data(SHA256.hash(data: Data("issue-80-signing".utf8)))
    let signature = BarnardSigning.signRecoverable(
      privateKey: signingKeyPair.privateKey,
      messageHash32: messageHash
    )

    let beaconChain = BarnardCrypto.BeaconChainConfig(
      chainId: "vector",
      genesisUnixSeconds: 1_600_000_000,
      slotSeconds: 12
    )
    let fixedEnin = BarnardCrypto.calculateEnin(
      for: Date(timeIntervalSince1970: TimeInterval(unixSeconds)),
      mode: .fixedLength,
      eninSeconds: 300
    )
    let beaconEnin = BarnardCrypto.calculateEnin(
      for: Date(timeIntervalSince1970: TimeInterval(unixSeconds)),
      mode: .beaconSlot,
      beaconChain: beaconChain
    )
    let stableEnin = BarnardCrypto.stableReadEnin(
      startedAt: Date(timeIntervalSince1970: 899),
      completedAt: Date(timeIntervalSince1970: 899),
      eninSeconds: 300
    )
    let crossedEnin = BarnardCrypto.stableReadEnin(
      startedAt: Date(timeIntervalSince1970: 899),
      completedAt: Date(timeIntervalSince1970: 900),
      eninSeconds: 300
    )

    var payload = Data([1])
    payload.append(rpi)

    let vectors: [String: String] = [
      "anonymous_tek": anonymousTek.hexString,
      "beacon_enin": String(beaconEnin),
      "display_id": BarnardCrypto.displayId4(from: eventTek).hexString,
      "event_code_hash": BarnardCrypto.computeEventCodeHash(eventCode).hexString,
      "event_tek": eventTek.hexString,
      "fixed_enin": String(fixedEnin),
      "payload": payload.hexString,
      "policy_display_empty": String(BarnardV2Policy.shouldServeGattDisplayId(eventCode: "")),
      "policy_display_joined": String(BarnardV2Policy.shouldServeGattDisplayId(eventCode: eventCode)),
      "policy_rssi_rotated": String(
        BarnardV2Policy.shouldEmitRssiUpdate(cachedPeerEnin: enin, currentEnin: enin + 1)
      ),
      "policy_rssi_same": String(
        BarnardV2Policy.shouldEmitRssiUpdate(cachedPeerEnin: enin, currentEnin: enin)
      ),
      "rpi": rpi.hexString,
      "rpik": rpik.hexString,
      "signing_private_key": signingKeyPair.privateKey.data.hexString,
      "signing_public_key": signingKeyPair.publicKeyCompressed.hexString,
      "signing_r": signature.r.hexString,
      "signing_s": signature.s.hexString,
      "signing_v": String(signature.v),
      "stable_enin": stableEnin.map(String.init) ?? "nil",
      "crossed_enin": crossedEnin.map(String.init) ?? "nil",
    ]

    let actual = vectors.keys.sorted().map { "\($0)=\(vectors[$0]!)" }.joined(separator: "\n")
    let expected = """
      anonymous_tek=1fc47c788289a03f2fbc8382f80b060c
      beacon_enin=8333343
      crossed_enin=nil
      display_id=c0fab611
      event_code_hash=0b9f14789f13968f
      event_tek=51c9263c4fbfc28fb28a76ab0d5d83d6
      fixed_enin=5666667
      payload=01be601a7b45035ec4c85f8e203679d5ae
      policy_display_empty=false
      policy_display_joined=true
      policy_rssi_rotated=false
      policy_rssi_same=true
      rpi=be601a7b45035ec4c85f8e203679d5ae
      rpik=9c20d41985cc258c21e11f10f764b954
      signing_private_key=054e89de8696ef821cd60963bf0d2980ce1392241a1606ed3bed32983448f404
      signing_public_key=036548e454f2b65bf3dc9676d64f8f22517caf0a07af7f33e0710fda7b8efd9e0c
      signing_r=e7df5948c76c2c0c3397dcdbf72fed1cf87e5d2379cb0831e4d2f1f2b3f262f5
      signing_s=51760b12ac9be31472f61ca68574e7d1c950ca68504d7dd37bff1bba97e3e7d8
      signing_v=0
      stable_enin=2
      """
    XCTAssertEqual(actual, expected)
  }
}
