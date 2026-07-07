// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import Foundation

/// Minimal secp256k1 field/point arithmetic and a fixed-width 256-bit
/// integer, used by `BarnardSigning` (barnard#65) for recoverable
/// ("ecrecover"-able) ECDSA. iOS has no system-provided secp256k1 curve
/// (CryptoKit covers P-256/384/521 and Curve25519 only).
enum Secp256k1 {
  /// Fixed-width 256-bit unsigned integer for secp256k1 field/scalar
  /// arithmetic. Stored as 4 big-endian `UInt64` limbs (`limbs.0` most
  /// significant).
  struct UInt256: Comparable {
    var limbs: (UInt64, UInt64, UInt64, UInt64)

    static func == (lhs: UInt256, rhs: UInt256) -> Bool {
      lhs.limbs == rhs.limbs
    }

    static let zero = UInt256(limbs: (0, 0, 0, 0))
    static let one = UInt256(limbs: (0, 0, 0, 1))

    init(limbs: (UInt64, UInt64, UInt64, UInt64)) {
      self.limbs = limbs
    }

    init?(hex: String) {
      var h = hex
      if h.count > 64 { return nil }
      while h.count < 64 { h = "0" + h }
      var parts: [UInt64] = []
      var idx = h.startIndex
      for _ in 0..<4 {
        let next = h.index(idx, offsetBy: 16)
        guard let v = UInt64(h[idx..<next], radix: 16) else { return nil }
        parts.append(v)
        idx = next
      }
      self.limbs = (parts[0], parts[1], parts[2], parts[3])
    }

    /// Interprets `data` as a big-endian integer, truncating/left-padding
    /// to 32 bytes if the input isn't exactly 32 bytes.
    init(data: Data) {
      var bytes = [UInt8](data)
      if bytes.count > 32 {
        bytes = Array(bytes.suffix(32))
      } else if bytes.count < 32 {
        bytes = [UInt8](repeating: 0, count: 32 - bytes.count) + bytes
      }
      func limb(_ range: Range<Int>) -> UInt64 {
        var v: UInt64 = 0
        for i in range { v = (v << 8) | UInt64(bytes[i]) }
        return v
      }
      self.limbs = (limb(0..<8), limb(8..<16), limb(16..<24), limb(24..<32))
    }

    /// Big-endian 32-byte encoding.
    var data: Data {
      var out = [UInt8](repeating: 0, count: 32)
      let parts = [limbs.0, limbs.1, limbs.2, limbs.3]
      for (i, part) in parts.enumerated() {
        for j in 0..<8 {
          out[i * 8 + j] = UInt8((part >> (56 - 8 * j)) & 0xff)
        }
      }
      return Data(out)
    }

    static func < (lhs: UInt256, rhs: UInt256) -> Bool {
      if lhs.limbs.0 != rhs.limbs.0 { return lhs.limbs.0 < rhs.limbs.0 }
      if lhs.limbs.1 != rhs.limbs.1 { return lhs.limbs.1 < rhs.limbs.1 }
      if lhs.limbs.2 != rhs.limbs.2 { return lhs.limbs.2 < rhs.limbs.2 }
      return lhs.limbs.3 < rhs.limbs.3
    }

    var isZero: Bool { self == .zero }

    @inline(__always)
    func testBit(_ n: Int) -> Bool {
      let bitIndex = n % 64
      switch n / 64 {
      case 0: return (limbs.3 >> bitIndex) & 1 == 1
      case 1: return (limbs.2 >> bitIndex) & 1 == 1
      case 2: return (limbs.1 >> bitIndex) & 1 == 1
      default: return (limbs.0 >> bitIndex) & 1 == 1
      }
    }

    /// Adds `x + y + carryIn`, returning `(result, carryOut)`.
    @inline(__always)
    private static func addLimb(_ x: UInt64, _ y: UInt64, _ carryIn: UInt64) -> (UInt64, UInt64) {
      let (s1, o1) = x.addingReportingOverflow(y)
      let (s2, o2) = s1.addingReportingOverflow(carryIn)
      return (s2, (o1 ? 1 : 0) &+ (o2 ? 1 : 0))
    }

    /// Unsigned add with carry-out (across all 4 limbs), ripple-carry from
    /// the least-significant limb (`limbs.3`). Operates directly on the
    /// tuple fields (no array allocation) since this is the innermost loop
    /// of `Field.mulMod`/`powMod`, called millions of times per signature.
    @inline(__always)
    func addingWithCarry(_ other: UInt256) -> (UInt256, Bool) {
      let (r3, c3) = UInt256.addLimb(limbs.3, other.limbs.3, 0)
      let (r2, c2) = UInt256.addLimb(limbs.2, other.limbs.2, c3)
      let (r1, c1) = UInt256.addLimb(limbs.1, other.limbs.1, c2)
      let (r0, c0) = UInt256.addLimb(limbs.0, other.limbs.0, c1)
      return (UInt256(limbs: (r0, r1, r2, r3)), c0 != 0)
    }

    /// Subtracts `x - y - borrowIn`, returning `(result, borrowOut)`.
    @inline(__always)
    private static func subLimb(_ x: UInt64, _ y: UInt64, _ borrowIn: UInt64) -> (UInt64, UInt64) {
      let (d1, b1) = x.subtractingReportingOverflow(y)
      let (d2, b2) = d1.subtractingReportingOverflow(borrowIn)
      return (d2, (b1 ? 1 : 0) &+ (b2 ? 1 : 0))
    }

    /// Unsigned subtract assuming `self >= other` (across all 4 limbs).
    @inline(__always)
    func subtracting(_ other: UInt256) -> UInt256 {
      let (d3, b3) = UInt256.subLimb(limbs.3, other.limbs.3, 0)
      let (d2, b2) = UInt256.subLimb(limbs.2, other.limbs.2, b3)
      let (d1, b1) = UInt256.subLimb(limbs.1, other.limbs.1, b2)
      let (d0, _) = UInt256.subLimb(limbs.0, other.limbs.0, b1)
      return UInt256(limbs: (d0, d1, d2, d3))
    }

    @inline(__always)
    func shiftedRight1() -> UInt256 {
      let c1 = limbs.0 & 1
      let c2 = limbs.1 & 1
      let c3 = limbs.2 & 1
      return UInt256(
        limbs: (
          limbs.0 >> 1,
          (limbs.1 >> 1) | (c1 << 63),
          (limbs.2 >> 1) | (c2 << 63),
          (limbs.3 >> 1) | (c3 << 63)
        )
      )
    }
  }

  /// Field/scalar arithmetic mod an arbitrary 256-bit modulus `m` (either
  /// the field prime `P` or the curve order `N`). Reduced with modular
  /// addition/doubling only (no full-width multiply+reduce): every
  /// 256-bit input here is already `< 2 * m` (`m` is within ~2^129 of
  /// 2^256 for both `P` and `N`), so a single conditional subtraction
  /// reduces it.
  enum Field {
    static func reduceOnce(_ a: UInt256, _ m: UInt256) -> UInt256 {
      a >= m ? a.subtracting(m) : a
    }

    static func addMod(_ a: UInt256, _ b: UInt256, _ m: UInt256) -> UInt256 {
      let (sum, carry) = a.addingWithCarry(b)
      if carry || sum >= m { return sum.subtracting(m) }
      return sum
    }

    static func subMod(_ a: UInt256, _ b: UInt256, _ m: UInt256) -> UInt256 {
      if a >= b { return a.subtracting(b) }
      return m.subtracting(b.subtracting(a))
    }

    /// Modular multiplication via double-and-add (avoids a full 512-bit
    /// multiply + reduction step).
    static func mulMod(_ a: UInt256, _ b: UInt256, _ m: UInt256) -> UInt256 {
      var result = UInt256.zero
      let addend = reduceOnce(a, m)
      for i in stride(from: 255, through: 0, by: -1) {
        result = addMod(result, result, m)
        if b.testBit(i) {
          result = addMod(result, addend, m)
        }
      }
      return result
    }

    static func powMod(_ base: UInt256, _ exponent: UInt256, _ m: UInt256) -> UInt256 {
      var result = UInt256.one
      let b = reduceOnce(base, m)
      for i in stride(from: 255, through: 0, by: -1) {
        result = mulMod(result, result, m)
        if exponent.testBit(i) {
          result = mulMod(result, b, m)
        }
      }
      return result
    }

    /// Modular inverse via Fermat's little theorem (`m` must be prime):
    /// `a^-1 = a^(m-2) mod m`.
    static func invMod(_ a: UInt256, _ m: UInt256) -> UInt256 {
      let mMinus2 = m.subtracting(UInt256(limbs: (0, 0, 0, 2)))
      return powMod(a, mMinus2, m)
    }
  }

  static let P = UInt256(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")!
  static let N = UInt256(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!
  static let Gx = UInt256(hex: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")!
  static let Gy = UInt256(hex: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")!

  struct Point: Equatable {
    var x: UInt256?
    var y: UInt256?
    static let infinity = Point(x: nil, y: nil)
    var isInfinity: Bool { x == nil || y == nil }
  }

  static let G = Point(x: Gx, y: Gy)

  static func pointDouble(_ p: Point) -> Point {
    guard let x = p.x, let y = p.y, !y.isZero else { return .infinity }
    let num = Field.mulMod(UInt256(limbs: (0, 0, 0, 3)), Field.mulMod(x, x, P), P)
    let den = Field.invMod(Field.mulMod(UInt256(limbs: (0, 0, 0, 2)), y, P), P)
    let slope = Field.mulMod(num, den, P)
    let x3 = Field.subMod(Field.subMod(Field.mulMod(slope, slope, P), x, P), x, P)
    let y3 = Field.subMod(Field.mulMod(slope, Field.subMod(x, x3, P), P), y, P)
    return Point(x: x3, y: y3)
  }

  static func pointAdd(_ p1: Point, _ p2: Point) -> Point {
    if p1.isInfinity { return p2 }
    if p2.isInfinity { return p1 }
    guard let x1 = p1.x, let y1 = p1.y, let x2 = p2.x, let y2 = p2.y else { return .infinity }
    if x1 == x2 {
      if Field.addMod(y1, y2, P).isZero { return .infinity }
      return pointDouble(p1)
    }
    let slope = Field.mulMod(Field.subMod(y2, y1, P), Field.invMod(Field.subMod(x2, x1, P), P), P)
    let x3 = Field.subMod(Field.subMod(Field.mulMod(slope, slope, P), x1, P), x2, P)
    let y3 = Field.subMod(Field.mulMod(slope, Field.subMod(x1, x3, P), P), y1, P)
    return Point(x: x3, y: y3)
  }

  static func scalarMult(_ k: UInt256, _ point: Point) -> Point {
    var result = Point.infinity
    let addend = point
    for i in stride(from: 255, through: 0, by: -1) {
      result = pointDouble(result)
      if k.testBit(i) {
        result = pointAdd(result, addend)
      }
    }
    return result
  }

  /// SEC1-compressed encoding (33 bytes: 0x02/0x03 prefix + 32-byte X).
  static func compress(_ point: Point) -> Data {
    guard let x = point.x, let y = point.y else { return Data() }
    let prefix: UInt8 = y.testBit(0) ? 0x03 : 0x02
    return Data([prefix]) + x.data
  }

  /// Decompress a point from its X coordinate and Y parity bit. Returns
  /// nil if X is not on the curve.
  static func decompress(x: UInt256, yIsOdd: Bool) -> Point? {
    let x3 = Field.mulMod(Field.mulMod(x, x, P), x, P)
    let rhs = Field.addMod(x3, UInt256(limbs: (0, 0, 0, 7)), P)
    // secp256k1's P is congruent to 3 mod 4, so sqrt(a) = a^((P+1)/4) mod P.
    let sqrtExponent = P.addingWithCarry(UInt256.one).0.shiftedRight1().shiftedRight1()
    var y = Field.powMod(rhs, sqrtExponent, P)
    if Field.mulMod(y, y, P) != rhs { return nil }
    if y.testBit(0) != yIsOdd {
      y = P.subtracting(y)
    }
    return Point(x: x, y: y)
  }
}
