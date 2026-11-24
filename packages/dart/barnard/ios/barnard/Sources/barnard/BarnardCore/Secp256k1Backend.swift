// Use of this source code is governed by a BSD-style license.

// Compiled only when the manifest links the vendored libsecp256k1 target
// (Apple platforms); Linux hosts build the pure-Swift backend instead.
#if BARNARD_LIBSECP256K1
import CSecp256k1

/// The deliberately small cryptographic boundary required by the Barnard ECDSA profile.
/// Point arithmetic and libsecp256k1 representation details never cross this boundary.
protocol BarnardCoreSecp256k1Backend {
  static func validatePrivateKey(_ candidate: [UInt8]) -> Bool
  static func normalizedPrivateKey(_ candidate: [UInt8]) -> [UInt8]?
  static func compressedPublicKey(privateKey: [UInt8]) -> [UInt8]?
  static func signRecoverable(privateKey: [UInt8], hash32: [UInt8]) -> BarnardCoreRecoverableSignature?
  static func recoverPublicKey(signature: BarnardCoreRecoverableSignature, hash32: [UInt8]) -> [UInt8]?
}

enum BarnardCoreLibsecp256k1Backend: BarnardCoreSecp256k1Backend {
  private static let order = bytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
  private static let halfOrder = bytes("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
  private static let contextInitialized: Void = {
    var generator = SystemRandomNumberGenerator()
    var seed = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    let initialized = seed.withUnsafeMutableBufferPointer {
      barnard_secp256k1_context_create($0.baseAddress)
    }
    precondition(initialized == 1, "libsecp256k1 context randomization failed")
  }()

  private static func requireContext() { _ = contextInitialized }

  static func normalizedPrivateKey(_ candidate: [UInt8]) -> [UInt8]? {
    guard candidate.count == 32 else { return nil }
    var normalized = candidate
    if !candidate.lexicographicallyPrecedes(order) {
      var borrow = 0
      for index in stride(from: 31, through: 0, by: -1) {
        let difference = Int(candidate[index]) - Int(order[index]) - borrow
        normalized[index] = UInt8(truncatingIfNeeded: difference)
        borrow = difference < 0 ? 1 : 0
      }
    }
    return validatePrivateKey(normalized) ? normalized : nil
  }

  static func validatePrivateKey(_ candidate: [UInt8]) -> Bool {
    requireContext()
    guard candidate.count == 32 else { return false }
    var key = candidate
    let valid = key.withUnsafeMutableBufferPointer {
      barnard_secp256k1_seckey_verify($0.baseAddress) == 1
    }
    return valid
  }

  static func compressedPublicKey(privateKey: [UInt8]) -> [UInt8]? {
    requireContext()
    guard validatePrivateKey(privateKey) else { return nil }
    var key = privateKey, output = [UInt8](repeating: 0, count: 33)
    let ok = key.withUnsafeMutableBufferPointer { keyPointer in
      output.withUnsafeMutableBufferPointer { outputPointer in
        barnard_secp256k1_pubkey_create(keyPointer.baseAddress, outputPointer.baseAddress)
      }
    }
    return ok == 1 ? output : nil
  }

  static func signRecoverable(privateKey: [UInt8], hash32: [UInt8]) -> BarnardCoreRecoverableSignature? {
    requireContext()
    guard validatePrivateKey(privateKey), hash32.count == 32 else { return nil }
    var key = privateKey, hash = hash32, compact = [UInt8](repeating: 0, count: 64), recoveryId: Int32 = -1
    let ok = key.withUnsafeMutableBufferPointer { kp in hash.withUnsafeMutableBufferPointer { hp in
      compact.withUnsafeMutableBufferPointer { sp in barnard_secp256k1_sign_recoverable(kp.baseAddress, hp.baseAddress, sp.baseAddress, &recoveryId) }
    }}
    // Profile clause 8 permits only recovery ids 0 and 1.
    guard ok == 1, recoveryId == 0 || recoveryId == 1 else { return nil }
    return BarnardCoreRecoverableSignature(r: Array(compact[..<32]), s: Array(compact[32...]), v: Int(recoveryId))
  }

  static func recoverPublicKey(signature: BarnardCoreRecoverableSignature, hash32: [UInt8]) -> [UInt8]? {
    requireContext()
    // Profile clauses 6–8 require canonical 32-byte, low-S components and v in {0,1}.
    guard signature.r.count == 32, signature.s.count == 32, hash32.count == 32,
          signature.v == 0 || signature.v == 1,
          signature.r.contains(where: { $0 != 0 }), signature.r.lexicographicallyPrecedes(order),
          signature.s.contains(where: { $0 != 0 }), !halfOrder.lexicographicallyPrecedes(signature.s)
    else { return nil }
    var compact = signature.r + signature.s, hash = hash32, output = [UInt8](repeating: 0, count: 33)
    let ok = compact.withUnsafeMutableBufferPointer { sp in hash.withUnsafeMutableBufferPointer { hp in
      output.withUnsafeMutableBufferPointer { op in barnard_secp256k1_recover(sp.baseAddress, hp.baseAddress, Int32(signature.v), op.baseAddress) }
    }}
    return ok == 1 ? output : nil
  }

  static func expandedPublicKey(_ compressed: [UInt8]) -> [UInt8]? {
    requireContext()
    guard compressed.count == 33 else { return nil }
    var input = compressed, output = [UInt8](repeating: 0, count: 65)
    let ok = input.withUnsafeMutableBufferPointer { ip in output.withUnsafeMutableBufferPointer { op in
      barnard_secp256k1_pubkey_expand(ip.baseAddress, op.baseAddress)
    }}
    return ok == 1 ? output : nil
  }

  private static func bytes(_ hex: String) -> [UInt8] {
    stride(from: 0, to: hex.count, by: 2).map { i in
      let start = hex.index(hex.startIndex, offsetBy: i)
      return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
    }
  }
}
#endif
