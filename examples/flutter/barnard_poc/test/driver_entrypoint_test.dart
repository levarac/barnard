import "package:flutter/widgets.dart";
import "package:flutter_test/flutter_test.dart";
import "package:barnard_poc/main.dart";

void main() {
  test("exposes stable keys for Flutter Driver smoke checks", () {
    expect(barnardPermissionStripKey, isA<ValueKey<String>>());
    expect(barnardAllowBluetoothButtonKey, isA<ValueKey<String>>());
    expect(barnardStartAutoButtonKey, isA<ValueKey<String>>());
    expect(barnardControlMenuButtonKey, isA<ValueKey<String>>());
  });
}
