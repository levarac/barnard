import "dart:io";

import "package:test/test.dart";

void main() {
  group("iOS GATT watchdog source invariants", () {
    for (final _SwiftSource source in <_SwiftSource>[
      _SwiftSource(
        name: "Flutter iOS",
        path: "ios/barnard/Sources/barnard/BarnardBleController.swift",
      ),
      _SwiftSource(
        name: "React Native iOS",
        path: "../../react-native/barnard/ios/BarnardBleController.swift",
      ),
    ]) {
      test("${source.name} keeps watchdog active until connection release", () {
        final String text = File(source.path).readAsStringSync();

        final String didConnect = _sliceBetween(
          text,
          "func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral)",
          "func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral",
        );
        expect(didConnect, isNot(contains("cancelConnectWatchdog()")));

        final String finishConnection = _sliceBetween(
          text,
          "private func finishConnection(_ peripheral: CBPeripheral)",
          source.finishConnectionEndMarker,
        );
        expect(finishConnection, isNot(contains("cancelConnectWatchdog()")));

        final String didFailToConnect = _sliceBetween(
          text,
          "func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral",
          "func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral",
        );
        expect(didFailToConnect, contains("cancelConnectWatchdog()"));

        final String didDisconnect = _sliceBetween(
          text,
          "func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral",
          "// MARK: - CBPeripheralDelegate",
        );
        expect(didDisconnect, contains("cancelConnectWatchdog()"));
      });
    }
  });
}

String _sliceBetween(String text, String start, String end) {
  final int startIndex = text.indexOf(start);
  expect(startIndex, isNonNegative, reason: "missing start marker: $start");
  final int endIndex = text.indexOf(end, startIndex + start.length);
  expect(endIndex, isNonNegative, reason: "missing end marker: $end");
  return text.substring(startIndex, endIndex);
}

class _SwiftSource {
  const _SwiftSource({
    required this.name,
    required this.path,
  });

  final String name;
  final String path;

  String get finishConnectionEndMarker {
    if (name == "React Native iOS") {
      return "private func characteristicName";
    }
    return "// MARK: - Event Emission";
  }
}
