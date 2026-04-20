import "dart:async";
import "dart:typed_data";

import "package:barnard/barnard.dart";
import "package:barnard/mock_barnard.dart";
import "package:test/test.dart";

void main() {
  group("v2 public API", () {
    test("myDisplayId is 8 lowercase hex chars", () {
      final BarnardClient barnard = MockBarnard();
      final String displayId = barnard.myDisplayId;
      expect(displayId, matches(RegExp(r"^[0-9a-f]{8}$")));
    });

    test("myDisplayId changes after joinEvent", () async {
      final BarnardClient barnard = MockBarnard();
      final String initial = barnard.myDisplayId;
      await barnard.joinEvent("TEST-EVENT-001");
      final String afterJoin = barnard.myDisplayId;
      expect(afterJoin, isNot(equals(initial)));
    });

    test("myDisplayId reverts after leaveEvent", () async {
      final BarnardClient barnard = MockBarnard();
      final String initial = barnard.myDisplayId;
      await barnard.joinEvent("TEST-EVENT-001");
      await barnard.leaveEvent();
      expect(barnard.myDisplayId, equals(initial));
    });

    test("currentEnin returns a positive int close to wall clock", () {
      final BarnardClient barnard = MockBarnard();
      final int expected =
          DateTime.now().millisecondsSinceEpoch ~/ 1000 ~/ 600;
      expect(barnard.currentEnin, isPositive);
      expect((barnard.currentEnin - expected).abs(), lessThanOrEqualTo(1));
    });

    test("getCurrentRpi returns 16 bytes (inner RPI)", () async {
      final BarnardClient barnard = MockBarnard();
      final Uint8List rpi = await barnard.getCurrentRpi();
      expect(rpi.length, equals(16));
    });

    test("exportCurrentTek returns a 16-byte TEK", () async {
      final BarnardClient barnard = MockBarnard();
      final Uint8List tek = await barnard.exportCurrentTek();
      expect(tek.length, equals(16));
    });

    test("exportCurrentTek changes after joinEvent / leaveEvent", () async {
      final BarnardClient barnard = MockBarnard();
      final Uint8List before = await barnard.exportCurrentTek();
      await barnard.joinEvent("TEST-EVENT-002");
      final Uint8List inside = await barnard.exportCurrentTek();
      expect(inside, isNot(equals(before)));
      await barnard.leaveEvent();
      final Uint8List after = await barnard.exportCurrentTek();
      expect(after, equals(before));
    });

    test("exportCurrentTek returns a defensive copy", () async {
      final BarnardClient barnard = MockBarnard();
      final Uint8List first = await barnard.exportCurrentTek();
      first[0] ^= 0xff;
      final Uint8List second = await barnard.exportCurrentTek();
      expect(second[0], isNot(equals(first[0])));
    });

    test("exportCurrentTek throws after dispose", () async {
      final BarnardClient barnard = MockBarnard();
      await barnard.dispose();
      expect(() => barnard.exportCurrentTek(), throwsStateError);
    });
  });

  group("detection stream", () {
    test("mock emits v2 DetectionEvent with required fields", () async {
      final BarnardClient barnard = MockBarnard(
        simulatedPeerCount: 10,
        tickMs: 100,
        overrides: const MockBarnardOverrides(b003FailureRate: 0.0),
      );

      final List<DetectionEvent> detections = <DetectionEvent>[];
      final StreamSubscription sub = barnard.events.listen((BarnardEvent e) {
        if (e is DetectionEvent) detections.add(e);
      });

      await barnard.startScan();
      await Future<void>.delayed(const Duration(milliseconds: 600));
      await barnard.stopScan();

      expect(detections, isNotEmpty);
      for (final DetectionEvent d in detections) {
        expect(d.rpid.length, equals(17),
            reason: "rpid wire form is [version(1) + RPI(16)]");
        expect(d.reporterRpid.length, equals(17));
        expect(d.enin, isPositive);
        // With b003FailureRate = 0, detectedDisplayId is always present.
        expect(d.detectedDisplayId, isNotNull);
        expect(d.detectedDisplayId!, matches(RegExp(r"^[0-9a-f]{8}$")));
      }

      final List<RssiSample> samples = barnard.getRssiSamples(limit: 50);
      expect(samples, isNotEmpty);

      await barnard.dispose();
      await sub.cancel();
    });

    test("mock simulates B003 failure: detectedDisplayId can be null",
        () async {
      final BarnardClient barnard = MockBarnard(
        simulatedPeerCount: 5,
        tickMs: 50,
        overrides: const MockBarnardOverrides(b003FailureRate: 1.0),
      );

      final List<DetectionEvent> detections = <DetectionEvent>[];
      final StreamSubscription sub = barnard.events.listen((BarnardEvent e) {
        if (e is DetectionEvent) detections.add(e);
      });

      await barnard.startScan();
      await Future<void>.delayed(const Duration(milliseconds: 400));
      await barnard.stopScan();

      expect(detections, isNotEmpty);
      for (final DetectionEvent d in detections) {
        expect(d.detectedDisplayId, isNull);
      }

      await barnard.dispose();
      await sub.cancel();
    });
  });
}
