// Use of this source code is governed by a BSD-style license.

/// Lowercase-hex encoding helpers.
///
/// v2 uses hex strings (not base64) at the Dart/method-channel boundary for
/// byte-valued fields like RPID, displayId, and TEK.
library;

import "dart:typed_data";

/// Encode [bytes] as a lowercase hex string.
///
/// Always lowercase, no `0x` prefix, single-nibble bytes zero-padded.
String bytesToHex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write((b & 0xff).toRadixString(16).padLeft(2, "0"));
  }
  return sb.toString();
}

/// Decode a hex string into bytes.
///
/// Accepts both upper- and lowercase input. Throws [FormatException] for
/// odd length or non-hex characters.
Uint8List hexToBytes(String hex) {
  if (hex.length.isOdd) {
    throw FormatException("hex string has odd length: ${hex.length}", hex);
  }
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final hi = _hexNibble(hex.codeUnitAt(i * 2));
    final lo = _hexNibble(hex.codeUnitAt(i * 2 + 1));
    out[i] = (hi << 4) | lo;
  }
  return out;
}

int _hexNibble(int code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x61 + 10; // a-f
  if (code >= 0x41 && code <= 0x46) return code - 0x41 + 10; // A-F
  throw FormatException("invalid hex character: ${String.fromCharCode(code)}");
}
