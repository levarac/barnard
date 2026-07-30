// Use of this source code is governed by a BSD-style license.

import XCTest
@testable import BarnardCore

final class BarnardOwnerKeyPrimitiveTests: XCTestCase {
  func testDeriveOwnerKeyPairMatchesCrossImplementationVectors() {
    let zeroPair = BarnardCoreSigning.deriveOwnerKeyPair(
      accountSecret: [UInt8](repeating: 0, count: 32)
    )
    XCTAssertEqual(
      hex(zeroPair.privateKey),
      "46cbfd04992339fab4937354a6f24c115a238f4bd133a8c43b18162ab986bf27"
    )
    XCTAssertEqual(
      hex(zeroPair.publicKeyCompressed),
      "03351e5165d083f53425fc4a51e7228d53e88eb2899bcb6a83368a8aafaa1de5f4"
    )

    let sequentialPair = BarnardCoreSigning.deriveOwnerKeyPair(
      accountSecret: (0..<32).map(UInt8.init)
    )
    XCTAssertEqual(
      hex(sequentialPair.privateKey),
      "3cfd4805b144d962c1cddccdf8452f02bfe022a867f550b0eb5ed8b2512ec758"
    )
    XCTAssertEqual(
      hex(sequentialPair.publicKeyCompressed),
      "03879beac8b548009124867a99a358aeb34ff42f957f868bbc83339568b16d9c67"
    )
  }

  func testKeccak256MatchesEthereumVectorsIncludingRateBoundaries() {
    XCTAssertEqual(
      hex(BarnardCoreCrypto.keccak256([])),
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    )
    XCTAssertEqual(
      hex(BarnardCoreCrypto.keccak256(Array("abc".utf8))),
      "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )
    XCTAssertEqual(
      hex(BarnardCoreCrypto.keccak256((0..<135).map { UInt8($0 & 0xff) })),
      "cbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62"
    )
    XCTAssertEqual(
      hex(BarnardCoreCrypto.keccak256((0..<136).map { UInt8($0 & 0xff) })),
      "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e"
    )
    XCTAssertEqual(
      hex(BarnardCoreCrypto.keccak256((0..<137).map { UInt8($0 & 0xff) })),
      "ac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db"
    )
  }

  func testUncompressedSec1SerializationAndEthereumAddressUseXYOnly() {
    let generatorCompressed = bytes(
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    let uncompressed = BarnardCoreSigning.serializeUncompressedPublicKey(
      generatorCompressed
    )

    XCTAssertEqual(
      hex(uncompressed ?? []),
      "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )
    XCTAssertEqual(
      hex(BarnardCoreSigning.ethereumAddress(publicKeyCompressed: generatorCompressed) ?? []),
      "7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    )
    XCTAssertNil(
      BarnardCoreSigning.serializeUncompressedPublicKey(
        [0x04] + [UInt8](repeating: 0, count: 32)
      )
    )
    XCTAssertNil(
      BarnardCoreSigning.serializeUncompressedPublicKey(
        [0x02] + [UInt8](repeating: 0xff, count: 32)
      )
    )
  }

  func testEip191DigestUsesUtf8ByteLength() {
    XCTAssertEqual(
      hex(BarnardCoreSigning.computeEip191Digest(text: "")),
      "5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad"
    )
    XCTAssertEqual(
      hex(BarnardCoreSigning.computeEip191Digest(text: "Hello World")),
      "a1de988600a42c4b4ab089b619297c17d53cffae5d5120d82d8a92d0bb3b78f2"
    )
    XCTAssertEqual(
      hex(BarnardCoreSigning.computeEip191Digest(text: "é")),
      "ba8cc708d7c0ceccba0ed21ddc61b53a0db963cffb45659d761ff24f520f0a99"
    )
  }

  func testEthersPersonalSignVectorRecoversExpectedAddress() {
    let digest = BarnardCoreSigning.computeEip191Digest(text: "Hello World")
    let recovered = BarnardCoreSigning.recoverPublicKey(
      recoveryId: 0,
      r: bytes(
        "a617d0558818c7a479d5063987981b59d6e619332ef52249be8243572ef10868"
      ),
      s: bytes(
        "07e381afe644d9bb56b213f6e08374c893db308ac1a5ae2bf8b33bcddcb0f76a"
      ),
      messageHash32: digest
    )

    XCTAssertEqual(
      hex(recovered ?? []),
      "035163ad559bf4672c2cb557e073c8de4edc4a92a8fb39634b30ca7005fbcb1f6c"
    )
    XCTAssertEqual(
      hex(
        BarnardCoreSigning.ethereumAddress(
          publicKeyCompressed: recovered ?? []
        ) ?? []
      ),
      "0a489345f9e9bc5254e18dd14fa7ecfdb2ce5f21"
    )
  }

  private func hex(_ input: [UInt8]) -> String {
    input.map {
      let value = String($0, radix: 16)
      return value.count == 1 ? "0" + value : value
    }.joined()
  }

  private func bytes(_ hex: String) -> [UInt8] {
    stride(from: 0, to: hex.count, by: 2).map { offset in
      let start = hex.index(hex.startIndex, offsetBy: offset)
      let end = hex.index(start, offsetBy: 2)
      return UInt8(hex[start..<end], radix: 16)!
    }
  }
}
