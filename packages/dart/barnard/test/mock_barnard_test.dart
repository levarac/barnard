import "dart:async";

import "package:barnard/barnard.dart";
import "package:barnard/mock_barnard.dart";
import "package:test/test.dart";

void main() {
  test("myResolvedDisplayId returns 6-character hex string", () {
    final BarnardClient barnard = MockBarnard();

    final String? displayId = barnard.myResolvedDisplayId;

    expect(displayId, isNotNull);
    expect(displayId!.length, equals(6));
    expect(RegExp(r"^[0-9a-f]{6}$").hasMatch(displayId), isTrue);
  });

  test("myResolvedDisplayId changes after joinEvent", () async {
    final BarnardClient barnard = MockBarnard();

    final String? initialId = barnard.myResolvedDisplayId;
    await barnard.joinEvent("TEST-EVENT-001");
    final String? afterJoinId = barnard.myResolvedDisplayId;

    expect(initialId, isNotNull);
    expect(afterJoinId, isNotNull);
    expect(afterJoinId, isNot(equals(initialId)));
  });

  test("mock emits DetectionEvent and stores RSSI samples", () async {
    final BarnardClient barnard = MockBarnard(simulatedPeerCount: 10, tickMs: 100);

    final List<DetectionEvent> detections = <DetectionEvent>[];
    final StreamSubscription sub = barnard.events.listen((BarnardEvent e) {
      if (e is DetectionEvent) detections.add(e);
    });

    await barnard.startScan();
    await Future<void>.delayed(const Duration(milliseconds: 600));
    await barnard.stopScan();

    expect(detections.isNotEmpty, isTrue);
    final List<RssiSample> samples = barnard.getRssiSamples(limit: 50);
    expect(samples.isNotEmpty, isTrue);

    await barnard.dispose();
    await sub.cancel();
  });
}
