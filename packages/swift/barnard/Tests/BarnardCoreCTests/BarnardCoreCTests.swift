// Use of this source code is governed by a BSD-style license.

import Foundation
import XCTest
import BarnardCore
@testable import BarnardCoreC

/// Replays the issue #80 golden behavior vector (BarnardBehaviorVectorTests)
/// exclusively through the exported C ABI entry points, so any drift between
/// the C surface and BarnardCore fails byte-identically here.
final class BarnardCoreCTests: XCTestCase {
  private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
  }

  func testCAbiReproducesIssue80GoldenVector() {
    let deviceSecret = (0..<32).map(UInt8.init)
    let eventCode = Array("CORE-SPLIT-80".utf8)
    let enin: UInt32 = 123_456

    var eventTek = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(
      barnard_core_derive_tek_for_event(
        deviceSecret, 32, eventCode, Int32(eventCode.count), &eventTek
      ),
      0
    )
    XCTAssertEqual(hex(eventTek), "51c9263c4fbfc28fb28a76ab0d5d83d6")

    var anonymousTek = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_derive_tek_for_anonymous(deviceSecret, 32, &anonymousTek), 0)
    XCTAssertEqual(hex(anonymousTek), "1fc47c788289a03f2fbc8382f80b060c")

    var rpik = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_derive_rpik(eventTek, &rpik), 0)
    XCTAssertEqual(hex(rpik), "9c20d41985cc258c21e11f10f764b954")

    var rpi = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_generate_rpi(rpik, enin, &rpi), 0)
    XCTAssertEqual(hex(rpi), "be601a7b45035ec4c85f8e203679d5ae")
    XCTAssertEqual(hex([1] + rpi), "01be601a7b45035ec4c85f8e203679d5ae")

    var displayId = [UInt8](repeating: 0, count: 4)
    XCTAssertEqual(barnard_core_display_id4(eventTek, &displayId), 0)
    XCTAssertEqual(hex(displayId), "c0fab611")

    var eventCodeHash = [UInt8](repeating: 0, count: 8)
    XCTAssertEqual(
      barnard_core_compute_event_code_hash(eventCode, Int32(eventCode.count), &eventCodeHash),
      0
    )
    XCTAssertEqual(hex(eventCodeHash), "0b9f14789f13968f")

    XCTAssertEqual(
      barnard_core_calculate_enin(1_700_000_123, 0, 300, 0, 0),
      5_666_667
    )
    XCTAssertEqual(
      barnard_core_calculate_enin(1_700_000_123, 1, 300, 1_600_000_000, 12),
      8_333_343
    )

    var stableEnin: UInt32 = 0
    XCTAssertEqual(barnard_core_stable_read_enin(899, 899, 0, 300, 0, 0, &stableEnin), 1)
    XCTAssertEqual(stableEnin, 2)
    XCTAssertEqual(barnard_core_stable_read_enin(899, 900, 0, 300, 0, 0, &stableEnin), 0)

    XCTAssertEqual(barnard_core_should_serve_gatt_display_id(eventCode, 0), 0)
    XCTAssertEqual(
      barnard_core_should_serve_gatt_display_id(eventCode, Int32(eventCode.count)),
      1
    )
    XCTAssertEqual(barnard_core_should_emit_rssi_update(enin, enin + 1), 0)
    XCTAssertEqual(barnard_core_should_emit_rssi_update(enin, enin), 1)

    var privateKey = [UInt8](repeating: 0, count: 32)
    var publicKey = [UInt8](repeating: 0, count: 33)
    XCTAssertEqual(
      barnard_core_derive_signing_keypair(
        deviceSecret, 32, eventCode, Int32(eventCode.count), &privateKey, &publicKey
      ),
      0
    )
    XCTAssertEqual(
      hex(privateKey),
      "054e89de8696ef821cd60963bf0d2980ce1392241a1606ed3bed32983448f404"
    )
    XCTAssertEqual(
      hex(publicKey),
      "036548e454f2b65bf3dc9676d64f8f22517caf0a07af7f33e0710fda7b8efd9e0c"
    )

    let message = Array("issue-80-signing".utf8)
    var messageHash = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(barnard_core_sha256(message, Int32(message.count), &messageHash), 0)

    var r = [UInt8](repeating: 0, count: 32)
    var s = [UInt8](repeating: 0, count: 32)
    var v: Int32 = -1
    XCTAssertEqual(barnard_core_sign_recoverable(privateKey, messageHash, &r, &s, &v), 0)
    XCTAssertEqual(hex(r), "e7df5948c76c2c0c3397dcdbf72fed1cf87e5d2379cb0831e4d2f1f2b3f262f5")
    XCTAssertEqual(hex(s), "51760b12ac9be31472f61ca68574e7d1c950ca68504d7dd37bff1bba97e3e7d8")
    XCTAssertEqual(v, 0)
  }

  func testOutOfDomainTimestampsDoNotTrap() {
    // calculate_enin has no error channel: out-of-domain saturates.
    XCTAssertEqual(barnard_core_calculate_enin(-400, 0, 300, 0, 0), 0)
    XCTAssertEqual(barnard_core_calculate_enin(.max, 0, 300, 0, 0), .max)
    XCTAssertEqual(barnard_core_calculate_enin(.max, 1, 300, 0, 1), .max)
    XCTAssertEqual(barnard_core_calculate_enin(-400, 1, 300, 0, 12), 0)
    XCTAssertEqual(barnard_core_calculate_enin(.min, 1, 300, 1, 12), 0)

    // stable_read_enin has an error channel: out-of-domain is rejected.
    var enin: UInt32 = 0
    XCTAssertEqual(barnard_core_stable_read_enin(-1, 899, 0, 300, 0, 0, &enin), -1)
    XCTAssertEqual(barnard_core_stable_read_enin(899, .max, 0, 300, 0, 0, &enin), -1)
    XCTAssertEqual(barnard_core_stable_read_enin(-1, -1, 1, 300, 0, 12, &enin), 1)
    XCTAssertEqual(enin, 0)
    XCTAssertEqual(barnard_core_stable_read_enin(.min, .min, 1, 300, 1, 12, &enin), 1)
    XCTAssertEqual(enin, 0)
  }

  func testCAbiEninUsesCoreNonTrappingDomainGuard() {
    let cases: [(Int64, Int32, Int64, Int64, Int64, UInt32)] = [
      (1_700_000_123, 0, 300, 0, 0, 5_666_667),
      (-1, 0, 300, 0, 0, 0),
      (.max, 0, 300, 0, 0, .max),
      (-400, 1, 300, 0, 12, 0),
      (.max, 1, 300, 0, 1, .max),
    ]

    for (unixSeconds, mode, eninSeconds, genesis, slot, expectedCValue) in cases {
      let coreMode: BarnardCoreEninMode = mode == 1 ? .beaconSlot : .fixedLength
      let coreValue = BarnardCoreCrypto.calculateEninIfRepresentable(
        unixSeconds: unixSeconds,
        mode: coreMode,
        eninSeconds: eninSeconds,
        beaconChain: BarnardCoreBeaconChain(
          chainId: "c-abi-test",
          genesisUnixSeconds: genesis,
          slotSeconds: slot
        )
      )
      XCTAssertEqual(
        barnard_core_calculate_enin(unixSeconds, mode, eninSeconds, genesis, slot),
        coreValue ?? expectedCValue
      )
    }
  }

  func testUtf8InputsRejectMalformedSequences() {
    let malformed: [UInt8] = [0xc3, 0x28]
    let secret = [UInt8](repeating: 0, count: 32)
    var output = [UInt8](repeating: 0, count: 33)
    var privateKey = [UInt8](repeating: 0, count: 32)

    XCTAssertEqual(
      barnard_core_derive_tek_for_event(secret, 32, malformed, Int32(malformed.count), &output),
      -1
    )
    XCTAssertEqual(
      barnard_core_compute_event_code_hash(malformed, Int32(malformed.count), &output),
      -1
    )
    XCTAssertEqual(
      barnard_core_derive_signing_keypair(
        secret, 32, malformed, Int32(malformed.count), &privateKey, &output
      ),
      -1
    )
    XCTAssertEqual(barnard_core_should_serve_gatt_display_id(malformed, Int32(malformed.count)), 0)
    XCTAssertEqual(
      barnard_core_eip191_digest(malformed, Int32(malformed.count), &output),
      -1
    )
    let walletAddress = [UInt8](repeating: 0, count: 20)
    let publicKey = [UInt8](repeating: 0, count: 33)
    let scalar = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(
      barnard_core_verify_wallet_binding(
        malformed,
        Int32(malformed.count),
        [],
        0,
        walletAddress,
        publicKey,
        scalar,
        scalar,
        0
      ),
      -1
    )
  }

  func testOwnerKeyCAbiMatchesGoldenVectorsAndVerifiesProofs() {
    let accountSecret = [UInt8](repeating: 0, count: 32)
    var ownerPrivateKey = [UInt8](repeating: 0, count: 32)
    var ownerPublicKey = [UInt8](repeating: 0, count: 33)
    XCTAssertEqual(
      barnard_core_derive_owner_keypair(
        accountSecret,
        &ownerPrivateKey,
        &ownerPublicKey
      ),
      0
    )
    XCTAssertEqual(
      hex(ownerPrivateKey),
      "46cbfd04992339fab4937354a6f24c115a238f4bd133a8c43b18162ab986bf27"
    )
    XCTAssertEqual(
      hex(ownerPublicKey),
      "03351e5165d083f53425fc4a51e7228d53e88eb2899bcb6a83368a8aafaa1de5f4"
    )

    let abc = Array("abc".utf8)
    var digest = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(barnard_core_keccak256(abc, Int32(abc.count), &digest), 0)
    XCTAssertEqual(
      hex(digest),
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )

    let personalMessage = Array("Hello World".utf8)
    XCTAssertEqual(
      barnard_core_eip191_digest(
        personalMessage,
        Int32(personalMessage.count),
        &digest
      ),
      0
    )
    XCTAssertEqual(
      hex(digest),
      "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
    )

    let eventHash = (0x00...0x1f).map(UInt8.init)
    let eventPublicKey = decodeHex(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d"
        + "959f2815b16f81798"
    )
    var selfProofMessage = [UInt8](repeating: 0, count: 135)
    XCTAssertEqual(
      barnard_core_build_self_proof_message(
        eventHash,
        eventPublicKey,
        12,
        34,
        ownerPublicKey,
        &selfProofMessage
      ),
      0
    )
    XCTAssertEqual(
      Array(selfProofMessage.prefix(21)),
      Array("barnard-self-proof:v1".utf8)
    )
    XCTAssertEqual(Array(selfProofMessage[53..<86]), eventPublicKey)
    XCTAssertEqual(Array(selfProofMessage[102..<135]), ownerPublicKey)

    var selfProofHash = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(
      barnard_core_sha256(
        selfProofMessage,
        Int32(selfProofMessage.count),
        &selfProofHash
      ),
      0
    )
    var selfProofR = [UInt8](repeating: 0, count: 32)
    var selfProofS = [UInt8](repeating: 0, count: 32)
    var selfProofV: Int32 = -1
    XCTAssertEqual(
      barnard_core_sign_recoverable(
        ownerPrivateKey,
        selfProofHash,
        &selfProofR,
        &selfProofS,
        &selfProofV
      ),
      0
    )
    XCTAssertEqual(
      barnard_core_verify_self_proof(
        eventHash,
        eventPublicKey,
        12,
        34,
        ownerPublicKey,
        selfProofR,
        selfProofS,
        selfProofV
      ),
      1
    )
    XCTAssertEqual(
      barnard_core_verify_self_proof(
        eventHash,
        eventPublicKey,
        12,
        35,
        ownerPublicKey,
        selfProofR,
        selfProofS,
        selfProofV
      ),
      0
    )

    let walletPrivateKey = [UInt8](repeating: 0, count: 31) + [1]
    let walletAddress = decodeHex("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    let bindingText = Array(
      """
      beid.levarac.org wants to bind this wallet to a Levarac owner key.

      This signature authorizes no transaction and moves no assets.

      Domain-Tag: barnard-account-binding:v1
      Wallet: 0x\(hex(walletAddress))
      Owner-Key: 0x\(hex(ownerPublicKey))
      Chain-ID: eip155:1
      Scope: global
      Nonce: 0x000102030405060708090a0b0c0d0e0f
      Issued-At: 2026-07-30T09:00:00Z
      """.utf8
    )
    var bindingDigest = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(
      barnard_core_eip191_digest(
        bindingText,
        Int32(bindingText.count),
        &bindingDigest
      ),
      0
    )
    var walletR = [UInt8](repeating: 0, count: 32)
    var walletS = [UInt8](repeating: 0, count: 32)
    var walletV: Int32 = -1
    XCTAssertEqual(
      barnard_core_sign_recoverable(
        walletPrivateKey,
        bindingDigest,
        &walletR,
        &walletS,
        &walletV
      ),
      0
    )
    let walletSignature = walletR + walletS + [UInt8(walletV + 27)]
    var walletSignatureHash = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(
      barnard_core_sha256(
        walletSignature,
        Int32(walletSignature.count),
        &walletSignatureHash
      ),
      0
    )
    let acknowledgementMessage =
      Array("barnard-wallet-ack:v1".utf8)
      + walletAddress
      + walletSignatureHash
    var acknowledgementHash = [UInt8](repeating: 0, count: 32)
    XCTAssertEqual(
      barnard_core_sha256(
        acknowledgementMessage,
        Int32(acknowledgementMessage.count),
        &acknowledgementHash
      ),
      0
    )
    var acknowledgementR = [UInt8](repeating: 0, count: 32)
    var acknowledgementS = [UInt8](repeating: 0, count: 32)
    var acknowledgementV: Int32 = -1
    XCTAssertEqual(
      barnard_core_sign_recoverable(
        ownerPrivateKey,
        acknowledgementHash,
        &acknowledgementR,
        &acknowledgementS,
        &acknowledgementV
      ),
      0
    )
    XCTAssertEqual(
      barnard_core_verify_wallet_binding(
        bindingText,
        Int32(bindingText.count),
        walletSignature,
        Int32(walletSignature.count),
        walletAddress,
        ownerPublicKey,
        acknowledgementR,
        acknowledgementS,
        acknowledgementV
      ),
      1
    )
    XCTAssertEqual(
      barnard_core_verify_wallet_binding(
        personalMessage,
        Int32(personalMessage.count),
        walletSignature,
        Int32(walletSignature.count),
        walletAddress,
        ownerPublicKey,
        acknowledgementR,
        acknowledgementS,
        acknowledgementV
      ),
      0
    )

    let erc6492Magic = decodeHex(
      "6492649264926492649264926492649264926492649264926492649264926492"
    )
    XCTAssertEqual(
      barnard_core_classify_wallet_signature(
        walletSignature,
        Int32(walletSignature.count)
      ),
      1
    )
    XCTAssertEqual(
      barnard_core_classify_wallet_signature(
        erc6492Magic,
        Int32(erc6492Magic.count)
      ),
      2
    )
    XCTAssertEqual(barnard_core_classify_wallet_signature(nil, 0), 0)
  }

  func testInvalidArgumentsAreRejected() {
    var out = [UInt8](repeating: 0, count: 16)
    XCTAssertEqual(barnard_core_derive_tek_for_event(nil, 32, nil, 0, &out), -1)
    XCTAssertEqual(barnard_core_derive_tek_for_anonymous(nil, 1, &out), -1)
    XCTAssertEqual(barnard_core_derive_rpik(nil, &out), -1)
    XCTAssertEqual(barnard_core_sha256(nil, 4, &out), -1)
    XCTAssertEqual(barnard_core_stable_read_enin(0, 0, 0, 300, 0, 0, nil), -1)
    XCTAssertEqual(barnard_core_should_serve_gatt_display_id(nil, 5), 0)
    XCTAssertEqual(barnard_core_derive_owner_keypair(nil, nil, nil), -1)
    XCTAssertEqual(barnard_core_keccak256(nil, 1, nil), -1)
    XCTAssertEqual(barnard_core_eip191_digest(nil, 1, nil), -1)
    XCTAssertEqual(
      barnard_core_build_self_proof_message(nil, nil, 0, 0, nil, nil),
      -1
    )
    XCTAssertEqual(
      barnard_core_verify_self_proof(
        nil,
        nil,
        0,
        0,
        nil,
        nil,
        nil,
        0
      ),
      -1
    )
    XCTAssertEqual(barnard_core_classify_wallet_signature(nil, 1), -1)
  }

  private func decodeHex(_ value: String) -> [UInt8] {
    stride(from: 0, to: value.count, by: 2).map { offset in
      let start = value.index(value.startIndex, offsetBy: offset)
      let end = value.index(start, offsetBy: 2)
      return UInt8(value[start..<end], radix: 16)!
    }
  }
}
