import "dart:convert";
import "dart:typed_data";

import "package:barnard/barnard.dart";
import "package:test/test.dart";

void main() {
  group("GAEN-compatible key derivation", () {
    test("HKDF-SHA256 produces 16-byte output", () {
      final ikm = Uint8List.fromList(List.generate(32, (i) => i));
      final info = Uint8List.fromList(utf8.encode("test-info"));

      final result = hkdfSha256(ikm: ikm, info: info, length: 16);

      expect(result.length, equals(16));
    });

    test("HKDF-SHA256 is deterministic", () {
      final ikm = Uint8List.fromList(List.generate(32, (i) => i));
      final info = Uint8List.fromList(utf8.encode("test-info"));

      final result1 = hkdfSha256(ikm: ikm, info: info, length: 16);
      final result2 = hkdfSha256(ikm: ikm, info: info, length: 16);

      expect(result1, equals(result2));
    });

    test("AES-128-ECB encrypts 16-byte block", () {
      final key = Uint8List.fromList(List.generate(16, (i) => i));
      final plaintext = Uint8List.fromList(List.generate(16, (i) => 0xFF - i));

      final ciphertext = aes128EcbEncrypt(key, plaintext);

      expect(ciphertext.length, equals(16));
      expect(ciphertext, isNot(equals(plaintext)));
    });

    test("AES-128-ECB is deterministic", () {
      final key = Uint8List.fromList(List.generate(16, (i) => i));
      final plaintext = Uint8List.fromList(List.generate(16, (i) => 0xFF - i));

      final ciphertext1 = aes128EcbEncrypt(key, plaintext);
      final ciphertext2 = aes128EcbEncrypt(key, plaintext);

      expect(ciphertext1, equals(ciphertext2));
    });

    test("SHA-256 produces 32-byte output", () {
      final input = Uint8List.fromList(utf8.encode("TECH2026"));

      final hash = sha256(input);

      expect(hash.length, equals(32));
    });
  });

  group("TEK derivation", () {
    test("deriveTek produces 16-byte output", () {
      final deviceSecret = Uint8List.fromList(List.generate(32, (i) => i * 2));
      const eventCode = "TECH2026";

      final tek = deriveTek(deviceSecret, eventCode);

      expect(tek.length, equals(16));
    });

    test("deriveTek is deterministic for same inputs", () {
      final deviceSecret = Uint8List.fromList(List.generate(32, (i) => i * 2));
      const eventCode = "TECH2026";

      final tek1 = deriveTek(deviceSecret, eventCode);
      final tek2 = deriveTek(deviceSecret, eventCode);

      expect(tek1, equals(tek2));
    });

    test("deriveTek produces different output for different event codes", () {
      final deviceSecret = Uint8List.fromList(List.generate(32, (i) => i * 2));

      final tek1 = deriveTek(deviceSecret, "EVENT_A");
      final tek2 = deriveTek(deviceSecret, "EVENT_B");

      expect(tek1, isNot(equals(tek2)));
    });

    test(
      "deriveTek produces different output for different device secrets",
      () {
        final deviceSecret1 = Uint8List.fromList(List.generate(32, (i) => i));
        final deviceSecret2 = Uint8List.fromList(
          List.generate(32, (i) => i + 1),
        );
        const eventCode = "TECH2026";

        final tek1 = deriveTek(deviceSecret1, eventCode);
        final tek2 = deriveTek(deviceSecret2, eventCode);

        expect(tek1, isNot(equals(tek2)));
      },
    );
  });

  group("RPIK derivation", () {
    test("deriveRpik produces 16-byte output", () {
      final tek = Uint8List.fromList(List.generate(16, (i) => i));

      final rpik = deriveRpik(tek);

      expect(rpik.length, equals(16));
    });

    test("deriveRpik is deterministic", () {
      final tek = Uint8List.fromList(List.generate(16, (i) => i));

      final rpik1 = deriveRpik(tek);
      final rpik2 = deriveRpik(tek);

      expect(rpik1, equals(rpik2));
    });

    test("deriveRpik produces different output for different TEKs", () {
      final tek1 = Uint8List.fromList(List.generate(16, (i) => i));
      final tek2 = Uint8List.fromList(List.generate(16, (i) => i + 1));

      final rpik1 = deriveRpik(tek1);
      final rpik2 = deriveRpik(tek2);

      expect(rpik1, isNot(equals(rpik2)));
    });

    test("deriveRpik throws for invalid TEK length", () {
      final invalidTek = Uint8List.fromList(List.generate(15, (i) => i));

      expect(() => deriveRpik(invalidTek), throwsArgumentError);
    });
  });

  group("RPI generation", () {
    test("generateRpi produces 16-byte output", () {
      final rpik = Uint8List.fromList(List.generate(16, (i) => i));
      const enin = 2948599; // Example ENIN

      final rpi = generateRpi(rpik, enin);

      expect(rpi.length, equals(16));
    });

    test("generateRpi is deterministic for same RPIK and ENIN", () {
      final rpik = Uint8List.fromList(List.generate(16, (i) => i));
      const enin = 2948599;

      final rpi1 = generateRpi(rpik, enin);
      final rpi2 = generateRpi(rpik, enin);

      expect(rpi1, equals(rpi2));
    });

    test("generateRpi produces different output for different ENINs", () {
      final rpik = Uint8List.fromList(List.generate(16, (i) => i));
      const enin1 = 2948599;
      const enin2 = 2948600;

      final rpi1 = generateRpi(rpik, enin1);
      final rpi2 = generateRpi(rpik, enin2);

      expect(rpi1, isNot(equals(rpi2)));
    });

    test("generateRpi throws for invalid RPIK length", () {
      final invalidRpik = Uint8List.fromList(List.generate(15, (i) => i));
      const enin = 2948599;

      expect(() => generateRpi(invalidRpik, enin), throwsArgumentError);
    });
  });

  group("ENIN calculation", () {
    test("calculateEnin defaults to a 120-second fixed-length window", () {
      // UNIX timestamp 1736947200 = 2026-01-15 12:00:00 UTC
      final timestamp = DateTime.fromMillisecondsSinceEpoch(
        1736947200 * 1000,
        isUtc: true,
      );

      final enin = calculateEnin(timestamp);

      // ENIN = 1736947200 / 120 = 14474560
      expect(enin, equals(14474560));
    });

    test("calculateEnin changes every 2 minutes by default", () {
      final timestamp1 = DateTime.fromMillisecondsSinceEpoch(
        1736947200 * 1000,
        isUtc: true,
      );
      final timestamp2 = DateTime.fromMillisecondsSinceEpoch(
        (1736947200 + 120) * 1000,
        isUtc: true,
      );

      final enin1 = calculateEnin(timestamp1);
      final enin2 = calculateEnin(timestamp2);

      expect(enin2, equals(enin1 + 1));
    });

    test("calculateEnin is stable within the default 2-minute window", () {
      final timestamp1 = DateTime.fromMillisecondsSinceEpoch(
        1736947200 * 1000,
        isUtc: true,
      );
      final timestamp2 = DateTime.fromMillisecondsSinceEpoch(
        (1736947200 + 119) * 1000,
        isUtc: true,
      );

      final enin1 = calculateEnin(timestamp1);
      final enin2 = calculateEnin(timestamp2);

      expect(enin1, equals(enin2));
    });

    test("calculateEnin supports fixed-length windows", () {
      final timestamp = DateTime.fromMillisecondsSinceEpoch(
        1736947224 * 1000,
        isUtc: true,
      );

      final enin = calculateEnin(
        timestamp,
        mode: EninMode.fixedLength,
        eninSeconds: 12,
      );

      expect(enin, equals(144745602));
    });

    test("calculateEnin clamps fixed-length windows to safe bounds", () {
      final timestamp = DateTime.fromMillisecondsSinceEpoch(
        3600 * 1000,
        isUtc: true,
      );

      expect(calculateEnin(timestamp, eninSeconds: 1), equals(300));
      expect(calculateEnin(timestamp, eninSeconds: 7200), equals(1));
    });

    test("calculateEnin supports Beacon Chain slot identity", () {
      final timestamp = DateTime.fromMillisecondsSinceEpoch(
        (BeaconChainConfig.ethereumMainnet.genesisUnixSeconds + 24) * 1000,
        isUtc: true,
      );

      final enin = calculateEnin(
        timestamp,
        mode: EninMode.beaconSlot,
        beaconChain: BeaconChainConfig.ethereumMainnet,
      );

      expect(enin, equals(2));
    });

    test(
      "calculateEnin clamps pre-genesis Beacon Chain timestamps to zero",
      () {
        final timestamp = DateTime.fromMillisecondsSinceEpoch(
          (BeaconChainConfig.ethereumMainnet.genesisUnixSeconds - 1) * 1000,
          isUtc: true,
        );

        final enin = calculateEnin(
          timestamp,
          mode: EninMode.beaconSlot,
          beaconChain: BeaconChainConfig.ethereumMainnet,
        );

        expect(enin, equals(0));
      },
    );
  });

  group("EventCodeHash calculation", () {
    test("calculateEventCodeHash produces 8-byte output", () {
      const eventCode = "TECH2026";

      final hash = calculateEventCodeHash(eventCode);

      expect(hash.length, equals(8));
    });

    test("calculateEventCodeHash is deterministic", () {
      const eventCode = "TECH2026";

      final hash1 = calculateEventCodeHash(eventCode);
      final hash2 = calculateEventCodeHash(eventCode);

      expect(hash1, equals(hash2));
    });

    test(
      "calculateEventCodeHash produces different output for different codes",
      () {
        const eventCode1 = "EVENT_A";
        const eventCode2 = "EVENT_B";

        final hash1 = calculateEventCodeHash(eventCode1);
        final hash2 = calculateEventCodeHash(eventCode2);

        expect(hash1, isNot(equals(hash2)));
      },
    );
  });

  group("v2 displayId derivation", () {
    test("displayIdFromTek returns 8 lowercase hex chars", () {
      final tek = Uint8List.fromList(List.generate(16, (i) => i));
      final displayId = displayIdFromTek(tek);
      expect(displayId.length, equals(8));
      expect(displayId, matches(RegExp(r"^[0-9a-f]{8}$")));
    });

    test("displayIdFromTek is deterministic for same TEK", () {
      final tek = Uint8List.fromList(List.generate(16, (i) => i + 7));
      expect(displayIdFromTek(tek), equals(displayIdFromTek(tek)));
    });

    test("displayIdFromTek differs for different TEKs", () {
      final tek1 = Uint8List.fromList(List.generate(16, (i) => i));
      final tek2 = Uint8List.fromList(List.generate(16, (i) => i + 1));
      expect(displayIdFromTek(tek1), isNot(equals(displayIdFromTek(tek2))));
    });

    test("known-answer: SHA256(0x00 * 16)[0:4] == 374708ff", () {
      // Fixed KAT: first 4 bytes of SHA-256 of 16 zero bytes
      final tek = Uint8List(16);
      expect(displayIdFromTek(tek), equals("374708ff"));
    });

    test("known-answer: SHA256(0x01..0x10)[0:4] == 5dfbabee", () {
      // TEK = 0x01 0x02 ... 0x10 (16 bytes)
      final tek = Uint8List.fromList(List.generate(16, (i) => i + 1));
      // Precomputed: SHA-256(0x0102...10)[0:4] = 5dfbabee
      expect(displayIdFromTek(tek), equals("5dfbabee"));
    });

    test("displayIdFromTek rejects non-16-byte TEK", () {
      expect(
        () => displayIdFromTek(Uint8List(15)),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => displayIdFromTek(Uint8List(17)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test("BarnardCrypto.computeDisplayId matches top-level function", () {
      final tek = Uint8List.fromList(List.generate(16, (i) => i * 3));
      expect(
        BarnardCrypto.computeDisplayId(tek),
        equals(displayIdFromTek(tek)),
      );
    });
  });

  group("End-to-end key derivation chain (v2)", () {
    test("full chain: DeviceSecret -> TEK -> RPIK -> RPI + v2 displayId", () {
      final deviceSecretA = Uint8List.fromList(List.generate(32, (i) => i * 3));
      const eventCode = "TECH2026";

      final tekA = deriveTek(deviceSecretA, eventCode);
      final rpikA = deriveRpik(tekA);
      const currentEnin = 2948599;
      final rpiA = generateRpi(rpikA, currentEnin);

      // v2: RPI resolution via peer-TEK lookup is removed. Instead, the
      // reporter publishes displayId = SHA256(TEK)[0:4] via GATT B003.
      expect(rpiA.length, equals(16));
      final displayId = displayIdFromTek(tekA);
      expect(displayId.length, equals(8));
      expect(displayId, matches(RegExp(r"^[0-9a-f]{8}$")));
    });

    test("different event codes produce unlinkable identities", () {
      final deviceSecret = Uint8List.fromList(List.generate(32, (i) => i));

      final tekEvent1 = deriveTek(deviceSecret, "EVENT_1");
      final tekEvent2 = deriveTek(deviceSecret, "EVENT_2");

      // TEKs differ
      expect(tekEvent1, isNot(equals(tekEvent2)));

      // displayIds differ
      expect(
        displayIdFromTek(tekEvent1),
        isNot(equals(displayIdFromTek(tekEvent2))),
      );

      // RPIs differ
      final rpikEvent1 = deriveRpik(tekEvent1);
      final rpikEvent2 = deriveRpik(tekEvent2);
      const enin = 2948599;
      final rpiEvent1 = generateRpi(rpikEvent1, enin);
      final rpiEvent2 = generateRpi(rpikEvent2, enin);
      expect(rpiEvent1, isNot(equals(rpiEvent2)));
    });
  });
}
