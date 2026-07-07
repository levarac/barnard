// Copyright 2024-2026 The Greeting Inc. All rights reserved.
// Use of this source code is governed by a BSD-style license.

import "dart:math";
import "dart:typed_data";

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
}

Uint8List _generateRandomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List<int>.generate(length, (_) => random.nextInt(256)));
}
