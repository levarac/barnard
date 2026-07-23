// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

enum BarnardCoreSecp256k1 {
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
      var value = hex
      if value.count > 64 {
        return nil
      }
      while value.count < 64 {
        value = "0" + value
      }
      var parts: [UInt64] = []
      var index = value.startIndex
      for _ in 0..<4 {
        let next = value.index(index, offsetBy: 16)
        guard let part = UInt64(value[index..<next], radix: 16) else {
          return nil
        }
        parts.append(part)
        index = next
      }
      limbs = (parts[0], parts[1], parts[2], parts[3])
    }

    init(bytes input: [UInt8]) {
      var bytes = input
      if bytes.count > 32 {
        bytes = Array(bytes.suffix(32))
      } else if bytes.count < 32 {
        bytes = [UInt8](repeating: 0, count: 32 - bytes.count) + bytes
      }
      func limb(_ range: Range<Int>) -> UInt64 {
        var value: UInt64 = 0
        for index in range {
          value = (value << 8) | UInt64(bytes[index])
        }
        return value
      }
      limbs = (limb(0..<8), limb(8..<16), limb(16..<24), limb(24..<32))
    }

    var bytes: [UInt8] {
      var output = [UInt8](repeating: 0, count: 32)
      let parts = [limbs.0, limbs.1, limbs.2, limbs.3]
      for (index, part) in parts.enumerated() {
        for byteIndex in 0..<8 {
          output[index * 8 + byteIndex] =
            UInt8((part >> UInt64(56 - 8 * byteIndex)) & 0xff)
        }
      }
      return output
    }

    static func < (lhs: UInt256, rhs: UInt256) -> Bool {
      if lhs.limbs.0 != rhs.limbs.0 {
        return lhs.limbs.0 < rhs.limbs.0
      }
      if lhs.limbs.1 != rhs.limbs.1 {
        return lhs.limbs.1 < rhs.limbs.1
      }
      if lhs.limbs.2 != rhs.limbs.2 {
        return lhs.limbs.2 < rhs.limbs.2
      }
      return lhs.limbs.3 < rhs.limbs.3
    }

    var isZero: Bool {
      self == .zero
    }

    @inline(__always)
    func testBit(_ index: Int) -> Bool {
      let bitIndex = index % 64
      switch index / 64 {
      case 0: return (limbs.3 >> UInt64(bitIndex)) & 1 == 1
      case 1: return (limbs.2 >> UInt64(bitIndex)) & 1 == 1
      case 2: return (limbs.1 >> UInt64(bitIndex)) & 1 == 1
      default: return (limbs.0 >> UInt64(bitIndex)) & 1 == 1
      }
    }

    @inline(__always)
    private static func addLimb(
      _ lhs: UInt64,
      _ rhs: UInt64,
      _ carryIn: UInt64
    ) -> (UInt64, UInt64) {
      let (first, firstOverflow) = lhs.addingReportingOverflow(rhs)
      let (second, secondOverflow) = first.addingReportingOverflow(carryIn)
      return (second, (firstOverflow ? 1 : 0) &+ (secondOverflow ? 1 : 0))
    }

    @inline(__always)
    func addingWithCarry(_ other: UInt256) -> (UInt256, Bool) {
      let (result3, carry3) = UInt256.addLimb(limbs.3, other.limbs.3, 0)
      let (result2, carry2) = UInt256.addLimb(limbs.2, other.limbs.2, carry3)
      let (result1, carry1) = UInt256.addLimb(limbs.1, other.limbs.1, carry2)
      let (result0, carry0) = UInt256.addLimb(limbs.0, other.limbs.0, carry1)
      return (UInt256(limbs: (result0, result1, result2, result3)), carry0 != 0)
    }

    @inline(__always)
    private static func subtractLimb(
      _ lhs: UInt64,
      _ rhs: UInt64,
      _ borrowIn: UInt64
    ) -> (UInt64, UInt64) {
      let (first, firstBorrow) = lhs.subtractingReportingOverflow(rhs)
      let (second, secondBorrow) = first.subtractingReportingOverflow(borrowIn)
      return (second, (firstBorrow ? 1 : 0) &+ (secondBorrow ? 1 : 0))
    }

    @inline(__always)
    func subtracting(_ other: UInt256) -> UInt256 {
      let (result3, borrow3) = UInt256.subtractLimb(limbs.3, other.limbs.3, 0)
      let (result2, borrow2) = UInt256.subtractLimb(limbs.2, other.limbs.2, borrow3)
      let (result1, borrow1) = UInt256.subtractLimb(limbs.1, other.limbs.1, borrow2)
      let (result0, _) = UInt256.subtractLimb(limbs.0, other.limbs.0, borrow1)
      return UInt256(limbs: (result0, result1, result2, result3))
    }

    @inline(__always)
    func shiftedRight1() -> UInt256 {
      let carry1 = limbs.0 & 1
      let carry2 = limbs.1 & 1
      let carry3 = limbs.2 & 1
      return UInt256(
        limbs: (
          limbs.0 >> 1,
          (limbs.1 >> 1) | (carry1 << 63),
          (limbs.2 >> 1) | (carry2 << 63),
          (limbs.3 >> 1) | (carry3 << 63)
        )
      )
    }
  }

  enum Field {
    static func reduceOnce(_ value: UInt256, _ modulus: UInt256) -> UInt256 {
      value >= modulus ? value.subtracting(modulus) : value
    }

    static func addMod(_ lhs: UInt256, _ rhs: UInt256, _ modulus: UInt256) -> UInt256 {
      let (sum, carry) = lhs.addingWithCarry(rhs)
      if carry || sum >= modulus {
        return sum.subtracting(modulus)
      }
      return sum
    }

    static func subtractMod(_ lhs: UInt256, _ rhs: UInt256, _ modulus: UInt256) -> UInt256 {
      if lhs >= rhs {
        return lhs.subtracting(rhs)
      }
      return modulus.subtracting(rhs.subtracting(lhs))
    }

    static func multiplyMod(_ lhs: UInt256, _ rhs: UInt256, _ modulus: UInt256) -> UInt256 {
      var result = UInt256.zero
      let addend = reduceOnce(lhs, modulus)
      for index in stride(from: 255, through: 0, by: -1) {
        result = addMod(result, result, modulus)
        if rhs.testBit(index) {
          result = addMod(result, addend, modulus)
        }
      }
      return result
    }

    static func powerMod(_ base: UInt256, _ exponent: UInt256, _ modulus: UInt256) -> UInt256 {
      var result = UInt256.one
      let reducedBase = reduceOnce(base, modulus)
      for index in stride(from: 255, through: 0, by: -1) {
        result = multiplyMod(result, result, modulus)
        if exponent.testBit(index) {
          result = multiplyMod(result, reducedBase, modulus)
        }
      }
      return result
    }

    static func inverseMod(_ value: UInt256, _ modulus: UInt256) -> UInt256 {
      let modulusMinusTwo = modulus.subtracting(UInt256(limbs: (0, 0, 0, 2)))
      return powerMod(value, modulusMinusTwo, modulus)
    }
  }

  static let fieldPrime =
    UInt256(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")!
  static let curveOrder =
    UInt256(hex: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")!
  static let generatorX =
    UInt256(hex: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")!
  static let generatorY =
    UInt256(hex: "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")!

  struct Point: Equatable {
    var x: UInt256?
    var y: UInt256?

    static let infinity = Point(x: nil, y: nil)

    var isInfinity: Bool {
      x == nil || y == nil
    }
  }

  static let generator = Point(x: generatorX, y: generatorY)

  static func double(_ point: Point) -> Point {
    guard let x = point.x, let y = point.y, !y.isZero else {
      return .infinity
    }
    let numerator = Field.multiplyMod(
      UInt256(limbs: (0, 0, 0, 3)),
      Field.multiplyMod(x, x, fieldPrime),
      fieldPrime
    )
    let denominator = Field.inverseMod(
      Field.multiplyMod(UInt256(limbs: (0, 0, 0, 2)), y, fieldPrime),
      fieldPrime
    )
    let slope = Field.multiplyMod(numerator, denominator, fieldPrime)
    let x3 = Field.subtractMod(
      Field.subtractMod(Field.multiplyMod(slope, slope, fieldPrime), x, fieldPrime),
      x,
      fieldPrime
    )
    let y3 = Field.subtractMod(
      Field.multiplyMod(slope, Field.subtractMod(x, x3, fieldPrime), fieldPrime),
      y,
      fieldPrime
    )
    return Point(x: x3, y: y3)
  }

  static func add(_ lhs: Point, _ rhs: Point) -> Point {
    if lhs.isInfinity {
      return rhs
    }
    if rhs.isInfinity {
      return lhs
    }
    guard let x1 = lhs.x, let y1 = lhs.y, let x2 = rhs.x, let y2 = rhs.y else {
      return .infinity
    }
    if x1 == x2 {
      if Field.addMod(y1, y2, fieldPrime).isZero {
        return .infinity
      }
      return double(lhs)
    }
    let slope = Field.multiplyMod(
      Field.subtractMod(y2, y1, fieldPrime),
      Field.inverseMod(Field.subtractMod(x2, x1, fieldPrime), fieldPrime),
      fieldPrime
    )
    let x3 = Field.subtractMod(
      Field.subtractMod(Field.multiplyMod(slope, slope, fieldPrime), x1, fieldPrime),
      x2,
      fieldPrime
    )
    let y3 = Field.subtractMod(
      Field.multiplyMod(slope, Field.subtractMod(x1, x3, fieldPrime), fieldPrime),
      y1,
      fieldPrime
    )
    return Point(x: x3, y: y3)
  }

  static func multiply(_ scalar: UInt256, _ point: Point) -> Point {
    var result = Point.infinity
    for index in stride(from: 255, through: 0, by: -1) {
      result = double(result)
      if scalar.testBit(index) {
        result = add(result, point)
      }
    }
    return result
  }

  static func compress(_ point: Point) -> [UInt8] {
    guard let x = point.x, let y = point.y else {
      return []
    }
    return [y.testBit(0) ? 0x03 : 0x02] + x.bytes
  }

  static func decompress(x: UInt256, yIsOdd: Bool) -> Point? {
    let xCubed = Field.multiplyMod(
      Field.multiplyMod(x, x, fieldPrime),
      x,
      fieldPrime
    )
    let rightSide = Field.addMod(
      xCubed,
      UInt256(limbs: (0, 0, 0, 7)),
      fieldPrime
    )
    let squareRootExponent = fieldPrime.addingWithCarry(UInt256.one).0
      .shiftedRight1()
      .shiftedRight1()
    var y = Field.powerMod(rightSide, squareRootExponent, fieldPrime)
    if Field.multiplyMod(y, y, fieldPrime) != rightSide {
      return nil
    }
    if y.testBit(0) != yIsOdd {
      y = fieldPrime.subtracting(y)
    }
    return Point(x: x, y: y)
  }
}
