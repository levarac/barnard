// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

enum BarnardCorePrimitives {
  static func sha256(_ input: [UInt8]) -> [UInt8] {
    let constants: [UInt32] = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]
    var state: [UInt32] = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    var message = input
    let bitCount = UInt64(message.count) &* 8
    message.append(0x80)
    while message.count % 64 != 56 {
      message.append(0)
    }
    for shift in stride(from: 56, through: 0, by: -8) {
      message.append(UInt8((bitCount >> UInt64(shift)) & 0xff))
    }

    for offset in stride(from: 0, to: message.count, by: 64) {
      var words = [UInt32](repeating: 0, count: 64)
      for index in 0..<16 {
        let start = offset + index * 4
        words[index] =
          UInt32(message[start]) << 24
          | UInt32(message[start + 1]) << 16
          | UInt32(message[start + 2]) << 8
          | UInt32(message[start + 3])
      }
      for index in 16..<64 {
        let x = words[index - 15]
        let y = words[index - 2]
        let s0 = rotateRight(x, by: 7) ^ rotateRight(x, by: 18) ^ (x >> 3)
        let s1 = rotateRight(y, by: 17) ^ rotateRight(y, by: 19) ^ (y >> 10)
        words[index] = words[index - 16] &+ s0 &+ words[index - 7] &+ s1
      }

      var a = state[0]
      var b = state[1]
      var c = state[2]
      var d = state[3]
      var e = state[4]
      var f = state[5]
      var g = state[6]
      var h = state[7]

      for index in 0..<64 {
        let sum1 = rotateRight(e, by: 6) ^ rotateRight(e, by: 11) ^ rotateRight(e, by: 25)
        let choice = (e & f) ^ ((~e) & g)
        let temp1 = h &+ sum1 &+ choice &+ constants[index] &+ words[index]
        let sum0 = rotateRight(a, by: 2) ^ rotateRight(a, by: 13) ^ rotateRight(a, by: 22)
        let majority = (a & b) ^ (a & c) ^ (b & c)
        let temp2 = sum0 &+ majority

        h = g
        g = f
        f = e
        e = d &+ temp1
        d = c
        c = b
        b = a
        a = temp1 &+ temp2
      }

      state[0] = state[0] &+ a
      state[1] = state[1] &+ b
      state[2] = state[2] &+ c
      state[3] = state[3] &+ d
      state[4] = state[4] &+ e
      state[5] = state[5] &+ f
      state[6] = state[6] &+ g
      state[7] = state[7] &+ h
    }

    var output: [UInt8] = []
    output.reserveCapacity(32)
    for word in state {
      output.append(UInt8((word >> 24) & 0xff))
      output.append(UInt8((word >> 16) & 0xff))
      output.append(UInt8((word >> 8) & 0xff))
      output.append(UInt8(word & 0xff))
    }
    return output
  }

  static func hmacSha256(key: [UInt8], message: [UInt8]) -> [UInt8] {
    var normalizedKey = key.count > 64 ? sha256(key) : key
    if normalizedKey.count < 64 {
      normalizedKey += [UInt8](repeating: 0, count: 64 - normalizedKey.count)
    }
    let innerPad = normalizedKey.map { $0 ^ 0x36 }
    let outerPad = normalizedKey.map { $0 ^ 0x5c }
    return sha256(outerPad + sha256(innerPad + message))
  }

  static func hkdfSha256(
    inputKeyMaterial: [UInt8],
    info: [UInt8],
    outputByteCount: Int,
    salt: [UInt8] = []
  ) -> [UInt8] {
    precondition(outputByteCount >= 0 && outputByteCount <= 255 * 32)
    let effectiveSalt = salt.isEmpty ? [UInt8](repeating: 0, count: 32) : salt
    let pseudorandomKey = hmacSha256(key: effectiveSalt, message: inputKeyMaterial)
    var output: [UInt8] = []
    var previous: [UInt8] = []
    var counter: UInt8 = 1
    while output.count < outputByteCount {
      previous = hmacSha256(
        key: pseudorandomKey,
        message: previous + info + [counter]
      )
      output += previous
      counter &+= 1
    }
    return Array(output.prefix(outputByteCount))
  }

  static func aes128EcbEncrypt(key: [UInt8], plaintext: [UInt8]) -> [UInt8] {
    guard key.count == 16, plaintext.count == 16 else {
      return [UInt8](repeating: 0, count: 16)
    }
    let roundKeys = expandAes128Key(key)
    var state = plaintext
    addRoundKey(&state, roundKeys, offset: 0)
    for round in 1..<10 {
      subBytes(&state)
      shiftRows(&state)
      mixColumns(&state)
      addRoundKey(&state, roundKeys, offset: round * 16)
    }
    subBytes(&state)
    shiftRows(&state)
    addRoundKey(&state, roundKeys, offset: 160)
    return state
  }

  private static func rotateRight(_ value: UInt32, by count: UInt32) -> UInt32 {
    (value >> count) | (value << (32 - count))
  }

  private static let aesSBox: [UInt8] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ]

  private static func expandAes128Key(_ key: [UInt8]) -> [UInt8] {
    let roundConstants: [UInt8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
    var expanded = key + [UInt8](repeating: 0, count: 160)
    var generated = 16
    var round = 0
    var temporary = [UInt8](repeating: 0, count: 4)
    while generated < 176 {
      for index in 0..<4 {
        temporary[index] = expanded[generated - 4 + index]
      }
      if generated % 16 == 0 {
        let first = temporary.removeFirst()
        temporary.append(first)
        temporary = temporary.map { aesSBox[Int($0)] }
        temporary[0] ^= roundConstants[round]
        round += 1
      }
      for index in 0..<4 {
        expanded[generated] = expanded[generated - 16] ^ temporary[index]
        generated += 1
      }
    }
    return expanded
  }

  private static func addRoundKey(_ state: inout [UInt8], _ roundKeys: [UInt8], offset: Int) {
    for index in 0..<16 {
      state[index] ^= roundKeys[offset + index]
    }
  }

  private static func subBytes(_ state: inout [UInt8]) {
    for index in 0..<16 {
      state[index] = aesSBox[Int(state[index])]
    }
  }

  private static func shiftRows(_ state: inout [UInt8]) {
    let copy = state
    state[1] = copy[5]
    state[5] = copy[9]
    state[9] = copy[13]
    state[13] = copy[1]
    state[2] = copy[10]
    state[6] = copy[14]
    state[10] = copy[2]
    state[14] = copy[6]
    state[3] = copy[15]
    state[7] = copy[3]
    state[11] = copy[7]
    state[15] = copy[11]
  }

  private static func mixColumns(_ state: inout [UInt8]) {
    for column in 0..<4 {
      let offset = column * 4
      let a0 = state[offset]
      let a1 = state[offset + 1]
      let a2 = state[offset + 2]
      let a3 = state[offset + 3]
      state[offset] = multiplyBy2(a0) ^ multiplyBy3(a1) ^ a2 ^ a3
      state[offset + 1] = a0 ^ multiplyBy2(a1) ^ multiplyBy3(a2) ^ a3
      state[offset + 2] = a0 ^ a1 ^ multiplyBy2(a2) ^ multiplyBy3(a3)
      state[offset + 3] = multiplyBy3(a0) ^ a1 ^ a2 ^ multiplyBy2(a3)
    }
  }

  private static func multiplyBy2(_ value: UInt8) -> UInt8 {
    (value << 1) ^ ((value & 0x80) == 0 ? 0 : 0x1b)
  }

  private static func multiplyBy3(_ value: UInt8) -> UInt8 {
    multiplyBy2(value) ^ value
  }
}
