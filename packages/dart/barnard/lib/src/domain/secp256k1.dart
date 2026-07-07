// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

/// Minimal secp256k1 ECDSA support with recoverable ("ecrecover"-able)
/// signatures, built on the secp256k1 curve parameters already shipped by
/// `package:pointycastle`.
///
/// This does not implement a generic secp256k1/ECDSA library — only the
/// operations barnard#65 needs: derive a keypair from 32 bytes of key
/// material, produce a recoverable signature (r, s, v), and recover the
/// public key from a signature (used by tests to prove the signature is
/// genuinely ecrecover-compatible).
library;

import "dart:typed_data";

import "package:pointycastle/export.dart";

import "crypto.dart";

final ECDomainParameters _params = ECCurve_secp256k1();

BigInt get _curveOrder => _params.n;

BigInt _bytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (final byte in bytes) {
    result = (result << 8) | BigInt.from(byte);
  }
  return result;
}

Uint8List _bigIntToBytes(BigInt value, int length) {
  final result = Uint8List(length);
  BigInt v = value;
  for (int i = length - 1; i >= 0; i--) {
    result[i] = (v & BigInt.from(0xff)).toInt();
    v = v >> 8;
  }
  return result;
}

/// A secp256k1 keypair: the raw scalar private key and its SEC1-compressed
/// (33-byte) public key.
class Secp256k1KeyPair {
  const Secp256k1KeyPair({required this.privateKey, required this.publicKeyCompressed});

  /// The private scalar, in `[1, n-1]`. Callers must never let this leave
  /// the boundary that derived it.
  final BigInt privateKey;

  /// SEC1-compressed public key point (33 bytes: 0x02/0x03 prefix + 32-byte X).
  final Uint8List publicKeyCompressed;
}

/// A recoverable ECDSA signature: `(r, s, v)` where `v` is the recovery id
/// (`0` or `1`) needed to recover the public key from `(r, s)` alone
/// (i.e. "ecrecover"-compatible).
class RecoverableSignature {
  const RecoverableSignature({required this.r, required this.s, required this.v});

  /// 32-byte big-endian `r`.
  final Uint8List r;

  /// 32-byte big-endian `s`, normalized to the lower half of the curve
  /// order (canonical / "low-S" form).
  final Uint8List s;

  /// Recovery id: `0` or `1`.
  final int v;
}

/// Derive a secp256k1 keypair from 32 bytes of key material (e.g. HKDF
/// output). The scalar is reduced mod the curve order; on the
/// astronomically unlikely event it reduces to zero, it is re-hashed with
/// SHA-256 and retried so derivation always succeeds deterministically.
Secp256k1KeyPair secp256k1KeyPairFromSeed(Uint8List seed32) {
  if (seed32.length != 32) {
    throw ArgumentError("seed must be 32 bytes, got ${seed32.length}");
  }

  Uint8List candidate = seed32;
  BigInt d = _bytesToBigInt(candidate) % _curveOrder;
  while (d == BigInt.zero) {
    candidate = sha256(candidate);
    d = _bytesToBigInt(candidate) % _curveOrder;
  }

  final ECPoint? q = (_params.G * d);
  if (q == null) {
    throw StateError("secp256k1KeyPairFromSeed: failed to derive public key point");
  }

  return Secp256k1KeyPair(
    privateKey: d,
    publicKeyCompressed: Uint8List.fromList(q.getEncoded(true)),
  );
}

/// Sign a 32-byte message hash with [privateKey], returning a recoverable
/// signature. Uses RFC 6979 deterministic `k` (HMAC-SHA256) so signing is
/// deterministic and never depends on a system RNG, and normalizes `s` to
/// the lower half of the curve order (canonical form) with the matching
/// recovery id flip.
RecoverableSignature signRecoverable(BigInt privateKey, Uint8List messageHash32) {
  if (messageHash32.length != 32) {
    throw ArgumentError("messageHash must be 32 bytes, got ${messageHash32.length}");
  }

  final key = ECPrivateKey(privateKey, _params);
  final signer = ECDSASigner(null, HMac(SHA256Digest(), 64))
    ..init(true, PrivateKeyParameter<ECPrivateKey>(key));

  ECSignature sig = signer.generateSignature(messageHash32) as ECSignature;

  final halfOrder = _curveOrder >> 1;
  BigInt s = sig.s;
  if (s > halfOrder) {
    s = _curveOrder - s;
  }

  final ECPoint? q = (_params.G * privateKey);
  if (q == null) {
    throw StateError("signRecoverable: failed to derive public key point");
  }
  final expectedPub = Uint8List.fromList(q.getEncoded(true));

  int? recoveryId;
  for (int id = 0; id < 4; id++) {
    final candidate = _recoverPublicKey(id, sig.r, s, messageHash32);
    if (candidate != null && _bytesEqual(candidate, expectedPub)) {
      recoveryId = id;
      break;
    }
  }
  if (recoveryId == null) {
    throw StateError("signRecoverable: could not determine recovery id");
  }

  return RecoverableSignature(
    r: _bigIntToBytes(sig.r, 32),
    s: _bigIntToBytes(s, 32),
    v: recoveryId,
  );
}

/// Recover the SEC1-compressed public key from a [RecoverableSignature]
/// and the 32-byte message hash that was signed. Returns null if the
/// signature/recovery id is invalid.
Uint8List? recoverPublicKey(RecoverableSignature signature, Uint8List messageHash32) {
  final r = _bytesToBigInt(signature.r);
  final s = _bytesToBigInt(signature.s);
  return _recoverPublicKey(signature.v, r, s, messageHash32);
}

Uint8List? _recoverPublicKey(int recId, BigInt r, BigInt s, Uint8List messageHash32) {
  final curve = _params.curve;
  final n = _curveOrder;
  final prime = _fieldPrime;
  final i = BigInt.from(recId ~/ 2);
  final x = r + (i * n);
  if (x >= prime) return null;

  ECPoint rPoint;
  try {
    rPoint = curve.decompressPoint(recId & 1, x);
  } catch (_) {
    return null;
  }

  final nTimesR = rPoint * n;
  if (nTimesR == null || !nTimesR.isInfinity) return null;

  final e = _bytesToBigInt(messageHash32);
  final eNeg = (-e) % n;
  final rInv = r.modInverse(n);
  final srInv = (rInv * s) % n;
  final eInvrInv = (rInv * eNeg) % n;

  final ECPoint? term1 = _params.G * eInvrInv;
  final ECPoint? term2 = rPoint * srInv;
  if (term1 == null || term2 == null) return null;
  final point = term1 + term2;
  if (point == null || point.isInfinity) return null;
  return Uint8List.fromList(point.getEncoded(true));
}

/// secp256k1's field prime `p`. pointycastle's `ECCurve` does not expose
/// `p` directly, so this module (hard-coded to secp256k1) uses the
/// well-known curve constant.
final BigInt _fieldPrime = BigInt.parse(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
  radix: 16,
);

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
