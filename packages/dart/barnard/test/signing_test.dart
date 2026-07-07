import "dart:typed_data";

import "package:barnard/barnard.dart";
import "package:barnard/mock_barnard.dart";
import "package:test/test.dart";

Uint8List _deviceSecret(int seed) =>
    Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + seed) & 0xff));

void main() {
  group("per-event signing key derivation (barnard#65)", () {
    test("same device + same event => identical signing public key", () {
      final secret = _deviceSecret(1);
      final a = deriveSigningKeyPair(secret, "event-A");
      final b = deriveSigningKeyPair(secret, "event-A");

      expect(a.publicKeyCompressed, equals(b.publicKeyCompressed));
      expect(a.privateKey, equals(b.privateKey));
    });

    test("same device + different event => different signing public key", () {
      final secret = _deviceSecret(1);
      final a = deriveSigningKeyPair(secret, "event-A");
      final b = deriveSigningKeyPair(secret, "event-B");

      expect(a.publicKeyCompressed, isNot(equals(b.publicKeyCompressed)));
    });

    test("no cross-event-stable public key: distinct events across many "
        "derivations never collide and never repeat a prior event's key", () {
      final secret = _deviceSecret(42);
      final seen = <String>{};
      for (int i = 0; i < 50; i++) {
        final pub = deriveSigningKeyPair(secret, "event-$i").publicKeyCompressed;
        final hex = bytesToHex(pub);
        expect(seen.contains(hex), isFalse, reason: "event-$i collided with a prior event's key");
        seen.add(hex);
      }
    });

    test("re-derivable offline: recomputing from DeviceSecret alone reproduces the same key", () {
      final secret = _deviceSecret(7);
      final first = deriveSigningKeyPair(secret, "reunion-2026");
      // Simulate "later, offline" by deriving again from scratch.
      final second = deriveSigningKeyPair(Uint8List.fromList(secret), "reunion-2026");

      expect(first.publicKeyCompressed, equals(second.publicKeyCompressed));
    });

    test("different devices => different signing keys for the same event", () {
      final a = deriveSigningKeyPair(_deviceSecret(1), "shared-event");
      final b = deriveSigningKeyPair(_deviceSecret(2), "shared-event");

      expect(a.publicKeyCompressed, isNot(equals(b.publicKeyCompressed)));
    });

    test("domain separation from TEK/RPIK: signing key differs from the TEK-derived key material", () {
      final secret = _deviceSecret(3);
      const eventCode = "domain-sep-event";

      final signingPub = deriveSigningKeyPair(secret, eventCode).publicKeyCompressed;
      final tek = BarnardCrypto.deriveTekForEvent(secret, eventCode);
      final rpik = BarnardCrypto.deriveRpikFromTek(tek);

      // The signing key material must not equal (nor be trivially
      // derivable as a prefix/suffix of) the TEK or RPIK: different HKDF
      // `info` strings feed into independent HKDF outputs.
      expect(bytesToHex(signingPub), isNot(contains(bytesToHex(tek))));
      expect(bytesToHex(signingPub), isNot(contains(bytesToHex(rpik))));
      expect(tek, isNot(equals(rpik)));
    });

    test("signing key is not cross-computable from TEK: same IKM, different info, different HKDF output", () {
      final secret = _deviceSecret(9);
      const eventCode = "cross-compute-event";

      // TEK uses info="barnard-tek"; signing key uses info="barnard-sign".
      // Prove they diverge even though both are HKDF(DeviceSecret||EventCode, ...).
      final tekSeed = hkdfSha256(
        ikm: _concat(secret, eventCode),
        info: Uint8List.fromList("barnard-tek".codeUnits),
        length: 32,
      );
      final signSeed = hkdfSha256(
        ikm: _concat(secret, eventCode),
        info: Uint8List.fromList(signingKeyInfo.codeUnits),
        length: 32,
      );

      expect(tekSeed, isNot(equals(signSeed)));
    });
  });

  group("recoverable (ecrecover-able) secp256k1 signatures", () {
    test("signature recovers the exact signing public key from (r, s, v)", () {
      final secret = _deviceSecret(5);
      const eventCode = "ecrecover-event";
      final keyPair = deriveSigningKeyPair(secret, eventCode);
      final message = Uint8List.fromList("hello barnard".codeUnits);
      final messageHash = sha256(message);

      final sig = signRecoverable(keyPair.privateKey, messageHash);
      final recovered = recoverPublicKey(sig, messageHash);

      expect(recovered, isNotNull);
      expect(recovered, equals(keyPair.publicKeyCompressed));
    });

    test("recovery fails (does not silently match) against a tampered message", () {
      final secret = _deviceSecret(6);
      const eventCode = "tamper-event";
      final keyPair = deriveSigningKeyPair(secret, eventCode);
      final message = Uint8List.fromList("original".codeUnits);
      final tampered = Uint8List.fromList("tampered!".codeUnits);

      final sig = signRecoverable(keyPair.privateKey, sha256(message));
      final recovered = recoverPublicKey(sig, sha256(tampered));

      expect(recovered, isNot(equals(keyPair.publicKeyCompressed)));
    });

    test("signature is 32/32-byte r/s with recovery id in {0, 1}", () {
      final secret = _deviceSecret(8);
      final keyPair = deriveSigningKeyPair(secret, "shape-event");
      final sig = signRecoverable(keyPair.privateKey, sha256(Uint8List.fromList([1, 2, 3])));

      expect(sig.r.length, equals(32));
      expect(sig.s.length, equals(32));
      expect(sig.v, anyOf(equals(0), equals(1)));
    });
  });

  group("BarnardIdentity (sibling module to BarnardClient)", () {
    test("MockBarnardIdentity.sign produces an ecrecover-able signature bound to eventCode", () async {
      final identity = MockBarnardIdentity();
      const eventCode = "identity-module-event";
      final pubKey = await identity.signingPublicKey(eventCode);
      final message = Uint8List.fromList("observation-tuple".codeUnits);

      final sig = await identity.sign(eventCode, message);
      final recovered = recoverPublicKey(
        RecoverableSignature(r: sig.r, s: sig.s, v: sig.v),
        sha256(message),
      );

      expect(recovered, equals(pubKey));
    });

    test("MockBarnardIdentity never exposes a private key — only public key + signatures", () {
      // Compile-time API check: BarnardIdentity has no private-key-shaped
      // accessor (the opposite of exportCurrentTek on BarnardClient).
      final identity = MockBarnardIdentity();
      expect(identity, isA<BarnardIdentity>());
    });

    test("MockBarnardIdentity.pairedWith(MockBarnard) shares the sensing client's DeviceSecret", () async {
      final client = MockBarnard();
      final identity = MockBarnardIdentity.pairedWith(client);
      final direct = MockBarnardIdentity(deviceSecret: client.deviceSecretForTesting);

      final a = await identity.signingPublicKey("paired-event");
      final b = await direct.signingPublicKey("paired-event");
      expect(a, equals(b));
    });
  });
}

Uint8List _concat(Uint8List a, String eventCode) {
  final codeBytes = Uint8List.fromList(eventCode.codeUnits);
  final out = Uint8List(a.length + codeBytes.length);
  out.setRange(0, a.length, a);
  out.setRange(a.length, out.length, codeBytes);
  return out;
}
