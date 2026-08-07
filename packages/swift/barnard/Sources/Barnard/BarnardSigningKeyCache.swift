// Use of this source code is governed by a BSD-style license.

import Foundation

/// Single-entry cache for the per-event signing key pair derived from
/// `(deviceSecret, eventCode)` (barnard#124).
///
/// Derivation is deterministic in those two inputs but costs one secp256k1
/// scalar multiplication, which dominates repeated signing in unoptimized
/// builds. Caching it is safe only if the cache can never hand back a key
/// pair derived from different inputs, so this type — not its caller — owns
/// the cache key:
///
/// - The entry is identified by a fingerprint over **both** inputs, computed
///   here from the arguments actually used for the derivation. That an entry
///   cannot be addressed by `eventCode` alone is structural: no API exposes
///   such a lookup. Beyond that, returning a key pair derived from different
///   inputs would require a SHA-256 collision on the fingerprint — infeasible
///   under standard assumptions, which is the assumption this cache rests on
///   rather than an impossibility.
/// - The fingerprint is a one-way hash. The device secret itself is never
///   stored by this type.
/// - The cache retains at most **one entry**, replaced by any lookup with
///   different inputs, so a rotated or reset device secret misses on its next
///   use. That bounds what the cache holds, not how many derived private keys
///   exist: derivation deliberately runs outside the lock, so concurrent cold
///   misses each hold their own derived key pair for the duration of their
///   call, and every caller holds the pair it was handed.
///
/// Eviction is driven by that next lookup, not by the rotation: what a
/// rotated secret changes immediately is what the cache *returns*, not what
/// it still *holds*. The key pair derived from the previous secret stays
/// resident until a lookup with different inputs overwrites it, or until
/// `clear()` is called, or for the life of the instance if no further
/// lookup happens. Both overwrite and `clear()` drop this type's reference;
/// neither erases key material, and nothing here zeroizes released storage.
final class BarnardSigningKeyCache {
  /// Domain separation for the fingerprint. Local to this cache; never
  /// serialized, stored, or sent on the wire.
  private static let fingerprintDomainTag = "barnard-signing-key-cache:v1"

  private let lock = NSLock()
  private var cachedFingerprint: Data?
  private var cachedKeyPair: BarnardSigning.SigningKeyPair?

  /// Returns the signing key pair for `(deviceSecret, eventCode)`, deriving
  /// it with `derive` only when the cached entry was built from different
  /// inputs.
  ///
  /// `derive` is called with the lock released: it is the expensive
  /// operation this cache exists to avoid, and holding a lock across it
  /// would serialize concurrent signers on it. Two threads racing on a cold
  /// cache may therefore both derive. That is benign — derivation is a pure
  /// function of its inputs, so both compute the same key pair, and the
  /// fingerprint is stored together with the key pair it belongs to, so the
  /// loser of the race can only cause a redundant miss later, never a hit on
  /// a mismatched entry.
  func keyPair(
    deviceSecret: Data,
    eventCode: String,
    derive: (Data, String) -> BarnardSigning.SigningKeyPair
  ) -> BarnardSigning.SigningKeyPair {
    let wanted = Self.fingerprint(deviceSecret: deviceSecret, eventCode: eventCode)
    let hit = synchronized { () -> BarnardSigning.SigningKeyPair? in
      guard let cachedFingerprint = self.cachedFingerprint, cachedFingerprint == wanted else {
        return nil
      }
      return self.cachedKeyPair
    }
    if let hit {
      return hit
    }

    let derived = derive(deviceSecret, eventCode)
    synchronized {
      self.cachedFingerprint = wanted
      self.cachedKeyPair = derived
    }
    return derived
  }

  /// Drops this type's reference to the cached key pair ahead of the natural
  /// eviction on the next lookup with different inputs, so the next lookup
  /// derives again.
  ///
  /// This is not erasure: the storage is not zeroized, and copies already
  /// returned to callers or being derived concurrently are untouched.
  func clear() {
    synchronized {
      self.cachedFingerprint = nil
      self.cachedKeyPair = nil
    }
  }

  /// One-way identifier for the derivation inputs.
  ///
  /// The device secret is length-prefixed so that no other
  /// `(deviceSecret, eventCode)` pair can produce the same preimage by
  /// shifting bytes across the boundary.
  static func fingerprint(deviceSecret: Data, eventCode: String) -> Data {
    var preimage = Data(fingerprintDomainTag.utf8)
    preimage.append(contentsOf: withUnsafeBytes(of: UInt32(deviceSecret.count).bigEndian, Array.init))
    preimage.append(deviceSecret)
    preimage.append(Data(eventCode.utf8))
    return BarnardCrypto.sha256(preimage)
  }

  private func synchronized<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}
