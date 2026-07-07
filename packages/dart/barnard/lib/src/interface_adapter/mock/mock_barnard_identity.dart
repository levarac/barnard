// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import "dart:math";
import "dart:typed_data";

import "../../domain/crypto.dart";
import "../../domain/secp256k1.dart";
import "../../domain/signing.dart";
import "../../usecase/barnard_identity.dart";
import "mock_barnard.dart";

/// Mock/local implementation of [BarnardIdentity]. Computes the per-event
/// signing key entirely in Dart from a locally held `DeviceSecret` — no
/// platform channel involved.
class MockBarnardIdentity implements BarnardIdentity {
  MockBarnardIdentity({Uint8List? deviceSecret})
    : _deviceSecret = deviceSecret ?? _generateRandomBytes(32);

  /// Pair a [MockBarnardIdentity] with the same `DeviceSecret` as [client],
  /// so the signing identity and the sensing client are rooted in the same
  /// device secret (as they would be for a real device).
  factory MockBarnardIdentity.pairedWith(MockBarnard client) {
    return MockBarnardIdentity(deviceSecret: client.deviceSecretForTesting);
  }

  final Uint8List _deviceSecret;

  @override
  Future<Uint8List> signingPublicKey(String eventCode) async {
    return deriveSigningKeyPair(_deviceSecret, eventCode).publicKeyCompressed;
  }

  @override
  Future<BarnardSignature> sign(String eventCode, Uint8List bytes) async {
    final RecoverableSignature sig = signWithDeviceSecret(
      deviceSecret: _deviceSecret,
      eventCode: eventCode,
      message: bytes,
    );
    return BarnardSignature(r: sig.r, s: sig.s, v: sig.v);
  }

  @override
  Future<RpidOwnershipProof> proveRpidOwnership({
    required String eventCode,
    required int enin,
    required Uint8List eventIdHash,
    Uint8List? challenge,
  }) async {
    final tek = BarnardCrypto.deriveTekForEvent(_deviceSecret, eventCode);
    final rpik = BarnardCrypto.deriveRpikFromTek(tek);
    final rpi = BarnardCrypto.generateRpiFromRpik(rpik, enin);

    final sig = signRpidOwnershipProof(
      deviceSecret: _deviceSecret,
      eventCode: eventCode,
      eventIdHash: eventIdHash,
      enin: enin,
      rpi: rpi,
      challenge: challenge,
    );

    return RpidOwnershipProof(
      rpi: rpi,
      enin: enin,
      eventIdHash: eventIdHash,
      signingPublicKey: deriveSigningKeyPair(_deviceSecret, eventCode).publicKeyCompressed,
      sig: BarnardSignature(r: sig.r, s: sig.s, v: sig.v),
    );
  }

  @override
  Future<BarnardSignature> proveKeyBinding({
    required String eventCode,
    required Uint8List displayId,
  }) async {
    final eventCodeHash = BarnardCrypto.computeEventCodeHash(eventCode);
    final sig = signKeyBinding(
      deviceSecret: _deviceSecret,
      eventCode: eventCode,
      eventCodeHash: eventCodeHash,
      displayId: displayId,
    );
    return BarnardSignature(r: sig.r, s: sig.s, v: sig.v);
  }
}

Uint8List _generateRandomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List<int>.generate(length, (_) => random.nextInt(256)));
}
