// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import "dart:math";
import "dart:typed_data";

import "package:barnard/src/domain/hex.dart";
import "package:flutter_test/flutter_test.dart";

void main() {
  group("bytesToHex", () {
    test("returns empty string for empty input", () {
      expect(bytesToHex(Uint8List(0)), equals(""));
    });

    test("encodes a simple byte sequence as lowercase hex", () {
      final bytes = Uint8List.fromList([0, 1, 15, 16, 255]);
      expect(bytesToHex(bytes), equals("00010f10ff"));
    });

    test("always emits lowercase output", () {
      final bytes = Uint8List.fromList([0xab, 0xcd, 0xef]);
      expect(bytesToHex(bytes), equals("abcdef"));
    });

    test("pads single-nibble bytes with leading zero", () {
      final bytes = Uint8List.fromList([0x0a, 0x00, 0x0f]);
      expect(bytesToHex(bytes), equals("0a000f"));
    });
  });

  group("hexToBytes", () {
    test("decodes a simple two-char hex string", () {
      expect(hexToBytes("ab"), equals(Uint8List.fromList([0xab])));
    });

    test("decodes a longer hex string", () {
      expect(
        hexToBytes("00010f10ff"),
        equals(Uint8List.fromList([0, 1, 15, 16, 255])),
      );
    });

    test("accepts uppercase input", () {
      expect(hexToBytes("ABCDEF"), equals(Uint8List.fromList([0xab, 0xcd, 0xef])));
    });

    test("throws FormatException on odd length", () {
      expect(() => hexToBytes("abc"), throwsFormatException);
    });

    test("throws FormatException on non-hex character", () {
      expect(() => hexToBytes("az"), throwsFormatException);
    });

    test("handles empty string as empty byte list", () {
      expect(hexToBytes(""), equals(Uint8List(0)));
    });
  });

  group("round-trip", () {
    test("bytesToHex(hexToBytes(x)) == x for 100 random inputs", () {
      final rng = Random(42);
      for (var i = 0; i < 100; i++) {
        final len = rng.nextInt(64);
        final bytes = Uint8List.fromList(
          List.generate(len, (_) => rng.nextInt(256)),
        );
        final hex = bytesToHex(bytes);
        expect(hexToBytes(hex), equals(bytes));
      }
    });
  });
}
