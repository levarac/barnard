// Use of this source code is governed by a BSD-style license.

import "package:flutter/services.dart";

import "../../domain/hex.dart";
import "../../usecase/barnard_identity.dart";

/// Real-device implementation of [BarnardIdentity]. Delegates key
/// derivation and signing to native code (Kotlin/Swift) over a dedicated
/// `barnard/identity` method channel, separate from `barnard/methods`
/// (used by [BarnardBleClient]) — the private key is derived and used
/// natively and never crosses into Dart.
class BarnardBleIdentity implements BarnardIdentity {
  BarnardBleIdentity._();

  static const MethodChannel _methods = MethodChannel("barnard/identity");

  /// Create a [BarnardBleIdentity] bound to the same native `DeviceSecret`
  /// as the platform's `BarnardBleClient`.
  static Future<BarnardBleIdentity> create() async {
    return BarnardBleIdentity._();
  }

  @override
  Future<Uint8List> signingPublicKey(String eventCode) async {
    final String hex =
        (await _methods.invokeMethod<String>("signingPublicKey", {
          "eventCode": eventCode,
        })) ??
        "";
    final Uint8List bytes = hexToBytes(hex);
    if (bytes.length != 33) {
      throw StateError(
        "signingPublicKey: expected 33 bytes from native, got ${bytes.length}",
      );
    }
    return bytes;
  }

  @override
  Future<BarnardSignature> sign(String eventCode, Uint8List bytes) async {
    final Map<Object?, Object?> result =
        (await _methods.invokeMethod<Map<Object?, Object?>>("sign", {
          "eventCode": eventCode,
          "bytes": bytesToHex(bytes),
        })) ??
        const {};

    final Uint8List r = hexToBytes(result["r"] as String? ?? "");
    final Uint8List s = hexToBytes(result["s"] as String? ?? "");
    final int? v = result["v"] as int?;
    if (r.length != 32 || s.length != 32 || v == null) {
      throw StateError("sign: malformed signature from native ($result)");
    }
    return BarnardSignature(r: r, s: s, v: v);
  }

  @override
  Future<RpidOwnershipProof> proveRpidOwnership({
    required String eventCode,
    required int enin,
    required Uint8List eventIdHash,
    Uint8List? challenge,
  }) async {
    final Map<Object?, Object?> result =
        (await _methods.invokeMethod<Map<Object?, Object?>>("proveRpidOwnership", {
          "eventCode": eventCode,
          "enin": enin,
          "eventIdHash": bytesToHex(eventIdHash),
          "challenge": challenge != null ? bytesToHex(challenge) : null,
        })) ??
        const {};

    final Uint8List rpi = hexToBytes(result["rpi"] as String? ?? "");
    final Uint8List signingPublicKey = hexToBytes(result["signingPublicKey"] as String? ?? "");
    final Uint8List r = hexToBytes(result["r"] as String? ?? "");
    final Uint8List s = hexToBytes(result["s"] as String? ?? "");
    final int? v = result["v"] as int?;
    if (rpi.length != 16 || signingPublicKey.length != 33 || r.length != 32 || s.length != 32 || v == null) {
      throw StateError("proveRpidOwnership: malformed proof from native ($result)");
    }

    return RpidOwnershipProof(
      rpi: rpi,
      enin: enin,
      eventIdHash: eventIdHash,
      signingPublicKey: signingPublicKey,
      sig: BarnardSignature(r: r, s: s, v: v),
    );
  }

  @override
  Future<BarnardSignature> proveKeyBinding({
    required String eventCode,
    required Uint8List displayId,
  }) async {
    final Map<Object?, Object?> result =
        (await _methods.invokeMethod<Map<Object?, Object?>>("proveKeyBinding", {
          "eventCode": eventCode,
          "displayId": bytesToHex(displayId),
        })) ??
        const {};

    final Uint8List r = hexToBytes(result["r"] as String? ?? "");
    final Uint8List s = hexToBytes(result["s"] as String? ?? "");
    final int? v = result["v"] as int?;
    if (r.length != 32 || s.length != 32 || v == null) {
      throw StateError("proveKeyBinding: malformed signature from native ($result)");
    }
    return BarnardSignature(r: r, s: s, v: v);
  }
}
