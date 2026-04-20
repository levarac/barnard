import "dart:async";

import "package:barnard/barnard.dart";
import "package:barnard/mock_barnard.dart";

Future<void> main() async {
  final BarnardClient barnard = MockBarnard(simulatedPeerCount: 50);

  print("v2 API demo");
  print("  myDisplayId: ${barnard.myDisplayId}");
  print("  currentEnin: ${barnard.currentEnin}");

  final tek = await barnard.exportCurrentTek();
  print("  exportCurrentTek: ${tek.length} bytes (hex: ${bytesToHex(tek)})");

  final rpi = await barnard.getCurrentRpi();
  print("  getCurrentRpi:    ${rpi.length} bytes (hex: ${bytesToHex(rpi)})");

  int detectionCount = 0;
  int b003FailureCount = 0;
  final StreamSubscription sub = barnard.events.listen((BarnardEvent e) {
    if (e is DetectionEvent) {
      detectionCount += 1;
      if (e.detectedDisplayId == null) {
        b003FailureCount += 1;
      }
    }
  });

  await barnard.startAuto();
  await Future<void>.delayed(const Duration(seconds: 3));
  await barnard.stopAuto();

  await sub.cancel();
  await barnard.dispose();

  print(
    "stream summary: detections=$detectionCount b003FailureNullDisplayId=$b003FailureCount",
  );
}
