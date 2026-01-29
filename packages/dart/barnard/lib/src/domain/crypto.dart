// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

/// GAEN v1.2-compatible cryptographic utilities for Resolvable ID.
///
/// This library implements the key derivation and RPI generation algorithms
/// specified in the Google/Apple Exposure Notification Cryptography Spec v1.2.
///
/// Key derivation chain:
/// ```
/// DeviceSecret (32 bytes)
///      |
///      +-- Anonymous Mode: TEK = HKDF(DeviceSecret, "barnard-tek-anonymous", 16)
///      |
///      +-- Event Mode: TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)
///                           |
///                           v
///                      RPIK = HKDF(TEK, "EN-RPIK", 16)
///                           |
///                           v
///                      RPI = AES128-ECB(RPIK, PaddedData)
/// ```
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// HKDF-SHA256 key derivation function (RFC 5869).
///
/// - [ikm]: Input keying material
/// - [info]: Context and application-specific info
/// - [length]: Output length in bytes
/// - [salt]: Optional salt (defaults to 32 zero bytes)
Uint8List hkdfSha256({
  required Uint8List ikm,
  required Uint8List info,
  required int length,
  Uint8List? salt,
}) {
  final actualSalt = salt ?? Uint8List(32);

  // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
  final extractHmac = HMac(SHA256Digest(), 64)..init(KeyParameter(actualSalt));
  final prk = Uint8List(32);
  extractHmac.update(ikm, 0, ikm.length);
  extractHmac.doFinal(prk, 0);

  // HKDF-Expand
  final hashLen = 32;
  final n = (length + hashLen - 1) ~/ hashLen;
  final okm = Uint8List(length);
  var t = Uint8List(0);
  var pos = 0;

  for (var i = 1; i <= n; i++) {
    final expandHmac = HMac(SHA256Digest(), 64)..init(KeyParameter(prk));

    // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
    expandHmac.update(t, 0, t.length);
    expandHmac.update(info, 0, info.length);
    expandHmac.update(Uint8List.fromList([i]), 0, 1);

    t = Uint8List(32);
    expandHmac.doFinal(t, 0);

    final copyLen = min(hashLen, length - pos);
    okm.setRange(pos, pos + copyLen, t);
    pos += copyLen;
  }

  return okm;
}

/// AES-128-ECB encryption of a single 16-byte block.
///
/// Used for RPI generation as specified in GAEN.
Uint8List aes128EcbEncrypt(Uint8List key, Uint8List plaintext) {
  if (key.length != 16) {
    throw ArgumentError('Key must be 16 bytes');
  }
  if (plaintext.length != 16) {
    throw ArgumentError('Plaintext must be 16 bytes');
  }

  final cipher = BlockCipher('AES/ECB')..init(true, KeyParameter(key));
  final output = Uint8List(16);
  cipher.processBlock(plaintext, 0, output, 0);
  return output;
}

/// SHA-256 hash.
Uint8List sha256(Uint8List data) {
  final digest = SHA256Digest();
  return digest.process(data);
}

/// Derive TEK from DeviceSecret and optional EventCode.
///
/// - Anonymous Mode (eventCode == null): Returns `HKDF(DeviceSecret, "barnard-tek-anonymous", 16)`.
/// - Event Mode: Returns `HKDF(DeviceSecret || EventCode, "barnard-tek", 16)`.
Uint8List deriveTek(Uint8List deviceSecret, [String? eventCode]) {
  if (eventCode == null) {
    // Anonymous Mode: deterministic TEK
    return hkdfSha256(
      ikm: deviceSecret,
      info: Uint8List.fromList(utf8.encode('barnard-tek-anonymous')),
      length: 16,
    );
  }

  // Event Mode: deterministic TEK
  final eventCodeBytes = utf8.encode(eventCode);
  final combined = Uint8List(deviceSecret.length + eventCodeBytes.length);
  combined.setRange(0, deviceSecret.length, deviceSecret);
  combined.setRange(deviceSecret.length, combined.length, eventCodeBytes);

  return hkdfSha256(
    ikm: combined,
    info: Uint8List.fromList(utf8.encode('barnard-tek')),
    length: 16,
  );
}

/// Derive RPIK (Rolling Proximity Identifier Key) from TEK.
///
/// `RPIK = HKDF(TEK, "EN-RPIK", 16)`
Uint8List deriveRpik(Uint8List tek) {
  if (tek.length != 16) {
    throw ArgumentError('TEK must be 16 bytes');
  }

  return hkdfSha256(
    ikm: tek,
    info: Uint8List.fromList(utf8.encode('EN-RPIK')),
    length: 16,
  );
}

/// Generate RPI (Rolling Proximity Identifier) from RPIK and ENIN.
///
/// `RPI = AES128-ECB(RPIK, PaddedData)`
///
/// Where PaddedData = "EN-RPI" (6 bytes) + 0x000000000000 (6 bytes) + ENIN (4 bytes big-endian)
Uint8List generateRpi(Uint8List rpik, int enin) {
  if (rpik.length != 16) {
    throw ArgumentError('RPIK must be 16 bytes');
  }

  // Build PaddedData: "EN-RPI" + 6 zero bytes + ENIN (4 bytes big-endian)
  final paddedData = Uint8List(16);

  // "EN-RPI" (6 bytes)
  final prefix = utf8.encode('EN-RPI');
  paddedData.setRange(0, 6, prefix);

  // 6 zero bytes (already initialized to 0)

  // ENIN as 4 bytes big-endian at offset 12
  final eninBytes = ByteData(4)..setUint32(0, enin, Endian.big);
  paddedData.setRange(12, 16, eninBytes.buffer.asUint8List());

  return aes128EcbEncrypt(rpik, paddedData);
}

/// Calculate ENIN (EN Interval Number) for a given timestamp.
///
/// `ENIN = floor(unix_timestamp_seconds / 600)`
///
/// Each ENIN represents a 10-minute interval.
int calculateEnin(DateTime timestamp) {
  return timestamp.millisecondsSinceEpoch ~/ 1000 ~/ 600;
}

/// Calculate EventCodeHash from EventCode.
///
/// `EventCodeHash = SHA256(EventCode)[0:8]`
Uint8List calculateEventCodeHash(String eventCode) {
  final hash = sha256(Uint8List.fromList(utf8.encode(eventCode)));
  return hash.sublist(0, 8);
}

/// Attempt to resolve an RPI to a known TEK.
///
/// Searches within a time window around [currentEnin] (default ±1 hour).
///
/// Returns the matching TEK if found, null otherwise.
Uint8List? resolveRpi({
  required Uint8List rpi,
  required List<Uint8List> knownTeks,
  required int currentEnin,
  int windowSize = 8, // ±6 past + 1 current + 1 future
}) {
  if (rpi.length != 16) return null;

  for (final tek in knownTeks) {
    if (tek.length != 16) continue;

    final rpik = deriveRpik(tek);

    // Search window: 6 intervals past + current + 1 future
    for (var offset = -6; offset <= 1; offset++) {
      final enin = currentEnin + offset;
      final candidate = generateRpi(rpik, enin);

      if (_bytesEqual(candidate, rpi)) {
        return tek;
      }
    }
  }

  return null;
}

/// Get displayId from TEK (first 3 bytes as lowercase hex).
String tekToDisplayId(Uint8List tek) {
  if (tek.length < 3) {
    throw ArgumentError('TEK must be at least 3 bytes');
  }
  return tek
      .sublist(0, 3)
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
}

/// Compare two byte lists for equality.
bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Generate cryptographically secure random bytes.
Uint8List generateSecureRandomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}

/// Utility class providing static methods for Barnard cryptographic operations.
///
/// This class wraps the standalone crypto functions for convenient usage.
abstract class BarnardCrypto {
  /// Derive TEK for Event Mode from DeviceSecret and EventCode.
  ///
  /// `TEK = HKDF(DeviceSecret || EventCode, "barnard-tek", 16)`
  static Uint8List deriveTekForEvent(Uint8List deviceSecret, String eventCode) {
    return deriveTek(deviceSecret, eventCode);
  }

  /// Derive TEK for Anonymous Mode from DeviceSecret.
  static Uint8List deriveTekForAnonymous(Uint8List deviceSecret) {
    return deriveTek(deviceSecret, null);
  }

  /// Compute EventCodeHash from EventCode.
  ///
  /// `EventCodeHash = SHA256(EventCode)[0:8]`
  static Uint8List computeEventCodeHash(String eventCode) {
    return calculateEventCodeHash(eventCode);
  }

  /// Derive RPIK from TEK.
  ///
  /// `RPIK = HKDF(TEK, "EN-RPIK", 16)`
  static Uint8List deriveRpikFromTek(Uint8List tek) {
    return deriveRpik(tek);
  }

  /// Generate RPI from RPIK and ENIN.
  ///
  /// `RPI = AES128-ECB(RPIK, PaddedData)`
  static Uint8List generateRpiFromRpik(Uint8List rpik, int enin) {
    return generateRpi(rpik, enin);
  }

  /// Calculate current ENIN.
  static int currentEnin() {
    return calculateEnin(DateTime.now());
  }

  /// Attempt to resolve an RPI to a known TEK.
  static Uint8List? tryResolveRpi({
    required Uint8List rpi,
    required List<Uint8List> knownTeks,
    int? enin,
  }) {
    return resolveRpi(
      rpi: rpi,
      knownTeks: knownTeks,
      currentEnin: enin ?? currentEnin(),
    );
  }

  /// Get displayId from TEK (first 3 bytes as lowercase hex).
  static String displayIdFromTek(Uint8List tek) {
    return tekToDisplayId(tek);
  }
}
