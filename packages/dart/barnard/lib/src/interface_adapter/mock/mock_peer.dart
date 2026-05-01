import "dart:math";
import "dart:typed_data";

import "../../domain/transport.dart";

class MockPeer {
  MockPeer({
    required this.id,
    required this.seed,
    required this.transport,
  }) : _random = Random(seed);

  final int id;
  final int seed;
  final TransportKind transport;
  final Random _random;

  int _rssi = -60;

  /// A deterministic 16-byte "mock TEK" derived from [seed].
  ///
  /// This simulates what the peer's v2 GATT B003 read would yield as
  /// `displayId = SHA256(TEK)[0:4]`. It is not a real TEK.
  Uint8List get mockTek {
    final Random r = Random(seed ^ 0x7e7e7e7e);
    final Uint8List bytes = Uint8List(16);
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = r.nextInt(256);
    }
    return bytes;
  }

  /// Inner 16-byte RPI for the given [windowIndex].
  Uint8List rpidForWindow(int windowIndex) {
    final int combinedSeed = seed ^ windowIndex;
    final Random r = Random(combinedSeed);
    final Uint8List bytes = Uint8List(16);
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = r.nextInt(256);
    }
    return bytes;
  }

  /// 17-byte RPID wire form `[formatVersion(1) + RPI(16)]` for the given
  /// [windowIndex].
  Uint8List rpidPayloadForWindow(int windowIndex, {int formatVersion = 1}) {
    final Uint8List rpi = rpidForWindow(windowIndex);
    final Uint8List out = Uint8List(17);
    out[0] = formatVersion & 0xff;
    out.setRange(1, 17, rpi);
    return out;
  }

  int nextRssi() {
    final int delta = _random.nextInt(7) - 3; // [-3..+3]
    _rssi = (_rssi + delta).clamp(-95, -25);
    return _rssi;
  }
}
