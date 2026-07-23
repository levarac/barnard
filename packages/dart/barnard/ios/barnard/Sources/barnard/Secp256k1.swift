// Use of this source code is governed by a BSD-style license.

import Foundation

/// Compatibility representation retained inside the Apple-facing module.
/// Curve arithmetic lives in `BarnardCore`; this type only adapts byte arrays
/// to the existing `Data`-based test and signing boundary.
enum Secp256k1 {
  struct UInt256: Comparable {
    let bytes: [UInt8]

    init(data: Data) {
      self.init(bytes: Array(data))
    }

    init(bytes input: [UInt8]) {
      if input.count > 32 {
        bytes = Array(input.suffix(32))
      } else if input.count < 32 {
        bytes = [UInt8](repeating: 0, count: 32 - input.count) + input
      } else {
        bytes = input
      }
    }

    init?(hex: String) {
      guard hex.count <= 64 else {
        return nil
      }
      var padded = hex
      while padded.count < 64 {
        padded = "0" + padded
      }
      var output: [UInt8] = []
      output.reserveCapacity(32)
      var index = padded.startIndex
      while index < padded.endIndex {
        let next = padded.index(index, offsetBy: 2)
        guard let byte = UInt8(padded[index..<next], radix: 16) else {
          return nil
        }
        output.append(byte)
        index = next
      }
      bytes = output
    }

    var data: Data {
      Data(bytes)
    }

    static func < (lhs: UInt256, rhs: UInt256) -> Bool {
      for index in 0..<32 where lhs.bytes[index] != rhs.bytes[index] {
        return lhs.bytes[index] < rhs.bytes[index]
      }
      return false
    }

    func shiftedRight1() -> UInt256 {
      var output = [UInt8](repeating: 0, count: 32)
      var carry: UInt8 = 0
      for index in 0..<32 {
        output[index] = (bytes[index] >> 1) | carry
        carry = (bytes[index] & 1) << 7
      }
      return UInt256(bytes: output)
    }
  }

  static let N =
    UInt256(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!
}
