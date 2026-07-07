import "dart:typed_data";

import "package:barnard/barnard.dart";
import "package:barnard/mock_barnard.dart";
import "package:test/test.dart";

Uint8List _deviceSecret(int seed) =>
    Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + seed) & 0xff));

Uint8List _eventIdHash(int seed) => sha256(Uint8List.fromList(List<int>.generate(40, (i) => (i + seed) & 0xff)));

void main() {
  group("proveRpidOwnership (barnard#63)", () {
    test("proof is bound to (eventIdHash, enin): recoverable, verifiable, matches getCurrentRpi's RPI", () async {
      final secret = _deviceSecret(11);
      const eventCode = "rpid-proof-event";
      final identity = MockBarnardIdentity(deviceSecret: secret);
      final eventIdHash = _eventIdHash(1);

      final proof = await identity.proveRpidOwnership(
        eventCode: eventCode,
        enin: 2948599,
        eventIdHash: eventIdHash,
      );

      // The proof's rpi matches what BarnardClient.getCurrentRpi would
      // compute independently for the same TEK/enin.
      final tek = BarnardCrypto.deriveTekForEvent(secret, eventCode);
      final rpik = BarnardCrypto.deriveRpikFromTek(tek);
      final expectedRpi = BarnardCrypto.generateRpiFromRpik(rpik, 2948599);
      expect(proof.rpi, equals(expectedRpi));

      // The signature recovers to the disclosed signingPublicKey.
      final message = buildRpidProofMessage(eventIdHash: eventIdHash, enin: proof.enin, rpi: proof.rpi);
      final recovered = recoverPublicKey(
        RecoverableSignature(r: proof.sig.r, s: proof.sig.s, v: proof.sig.v),
        sha256(message),
      );
      expect(recovered, equals(proof.signingPublicKey));
      expect(proof.signingPublicKey, equals(await identity.signingPublicKey(eventCode)));
    });

    test("discloses neither TEK nor RPIK: proof bytes never contain the TEK/RPIK material", () async {
      final secret = _deviceSecret(12);
      const eventCode = "no-tek-leak-event";
      final identity = MockBarnardIdentity(deviceSecret: secret);
      final tek = BarnardCrypto.deriveTekForEvent(secret, eventCode);
      final rpik = BarnardCrypto.deriveRpikFromTek(tek);

      final proof = await identity.proveRpidOwnership(
        eventCode: eventCode,
        enin: 100,
        eventIdHash: _eventIdHash(2),
      );

      expect(proof.rpi, isNot(equals(tek)));
      expect(proof.rpi, isNot(equals(rpik)));
      expect(bytesToHex(proof.sig.r), isNot(contains(bytesToHex(tek))));
      expect(bytesToHex(proof.sig.s), isNot(contains(bytesToHex(tek))));
    });

    test("discloses no non-claimed RPI: proof for one enin does not reveal another enin's RPI", () async {
      final secret = _deviceSecret(13);
      const eventCode = "single-rpi-event";
      final identity = MockBarnardIdentity(deviceSecret: secret);

      final proofA = await identity.proveRpidOwnership(eventCode: eventCode, enin: 1, eventIdHash: _eventIdHash(3));

      final tek = BarnardCrypto.deriveTekForEvent(secret, eventCode);
      final rpik = BarnardCrypto.deriveRpikFromTek(tek);
      final otherEninRpi = BarnardCrypto.generateRpiFromRpik(rpik, 2);

      expect(proofA.rpi, isNot(equals(otherEninRpi)));
    });

    test("not replayable to another event: a proof's message differs by eventIdHash", () async {
      final secret = _deviceSecret(14);
      const eventCode = "replay-event";
      final identity = MockBarnardIdentity(deviceSecret: secret);

      final proofA = await identity.proveRpidOwnership(eventCode: eventCode, enin: 5, eventIdHash: _eventIdHash(4));
      final proofB = await identity.proveRpidOwnership(eventCode: eventCode, enin: 5, eventIdHash: _eventIdHash(5));

      // Same rpi/enin (same TEK), but the signed messages (and thus
      // signatures) differ because eventIdHash differs — a verifier who
      // checks eventIdHash rejects proofA's signature replayed against
      // proofB's claimed event.
      expect(proofA.rpi, equals(proofB.rpi));
      expect(proofA.sig.r, isNot(equals(proofB.sig.r)));

      final messageForB = buildRpidProofMessage(eventIdHash: proofB.eventIdHash, enin: proofA.enin, rpi: proofA.rpi);
      final recoveredWrong = recoverPublicKey(
        RecoverableSignature(r: proofA.sig.r, s: proofA.sig.s, v: proofA.sig.v),
        sha256(messageForB),
      );
      expect(recoveredWrong, isNot(equals(proofA.signingPublicKey)));
    });

    test("not replayable to another ENIN: a proof's message differs by enin", () async {
      final secret = _deviceSecret(15);
      const eventCode = "replay-enin-event";
      final identity = MockBarnardIdentity(deviceSecret: secret);
      final eventIdHash = _eventIdHash(6);

      final proofEnin5 = await identity.proveRpidOwnership(eventCode: eventCode, enin: 5, eventIdHash: eventIdHash);

      final messageForEnin6 = buildRpidProofMessage(eventIdHash: eventIdHash, enin: 6, rpi: proofEnin5.rpi);
      final recoveredWrong = recoverPublicKey(
        RecoverableSignature(r: proofEnin5.sig.r, s: proofEnin5.sig.s, v: proofEnin5.sig.v),
        sha256(messageForEnin6),
      );
      expect(recoveredWrong, isNot(equals(proofEnin5.signingPublicKey)));
    });

    test("challenge (verifier nonce) changes the signed message: non-replayable across challenges", () async {
      final secret = _deviceSecret(16);
      const eventCode = "challenge-event";
      final identity = MockBarnardIdentity(deviceSecret: secret);
      final eventIdHash = _eventIdHash(7);

      final proofNoChallenge = await identity.proveRpidOwnership(eventCode: eventCode, enin: 9, eventIdHash: eventIdHash);
      final proofWithChallenge = await identity.proveRpidOwnership(
        eventCode: eventCode,
        enin: 9,
        eventIdHash: eventIdHash,
        challenge: Uint8List.fromList([1, 2, 3, 4]),
      );

      expect(proofNoChallenge.sig.r, isNot(equals(proofWithChallenge.sig.r)));
    });
  });

  group("proveKeyBinding (barnard#63 acceptance criterion 3)", () {
    test("binding signature recovers to signingPublicKey for the same eventCode", () async {
      final secret = _deviceSecret(20);
      const eventCode = "binding-event";
      final identity = MockBarnardIdentity(deviceSecret: secret);

      final tek = BarnardCrypto.deriveTekForEvent(secret, eventCode);
      final displayId = displayIdFromTek(tek);
      final displayIdBytes = Uint8List.fromList(
        List<int>.generate(displayId.length ~/ 2, (i) => int.parse(displayId.substring(i * 2, i * 2 + 2), radix: 16)),
      );

      final sig = await identity.proveKeyBinding(eventCode: eventCode, displayId: displayIdBytes);

      final eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode);
      final message = buildKeyBindingMessage(eventCodeHash: eventCodeHash, displayId: displayIdBytes);
      final recovered = recoverPublicKey(RecoverableSignature(r: sig.r, s: sig.s, v: sig.v), sha256(message));

      expect(recovered, equals(await identity.signingPublicKey(eventCode)));
    });
  });
}
