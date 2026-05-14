import "package:barnard/barnard.dart";
import "package:flutter/widgets.dart";
import "package:flutter_test/flutter_test.dart";
import "package:barnard_poc/main.dart";

BarnardPermissionStatus _statusFromMap(Map<Object?, Object?> overrides) {
  final Map<Object?, Object?> base = <Object?, Object?>{
    "platform": "ios",
    "permissions": <Object?, Object?>{"ios.bluetooth": "granted"},
    "requiredPermissions": <Object?>["ios.bluetooth"],
    "missingPermissions": <Object?>[],
    "requestablePermissions": <Object?>[],
    "blockedPermissions": <Object?>[],
    "canScan": true,
    "canAdvertise": true,
    ...overrides,
  };
  return BarnardPermissionStatus.fromMap(base);
}

void main() {
  test("smoke", () {
    expect(true, isTrue);
  });

  group("shouldJoinEventForInput", () {
    test("joins when no event has been selected yet", () {
      expect(shouldJoinEventForInput(null, "BND"), isTrue);
    });

    test(
      "does not join again when the trimmed input matches current event",
      () {
        expect(shouldJoinEventForInput("BND", " BND "), isFalse);
      },
    );

    test("rejoins when the user changed the event code", () {
      expect(shouldJoinEventForInput("BND", "BND2"), isTrue);
    });

    test("does not join for empty input", () {
      expect(shouldJoinEventForInput("BND", " "), isFalse);
    });
  });

  group("scanResolutionFromDebugName", () {
    test("marks gatt_read_display_id as resolved", () {
      expect(
        scanResolutionFromDebugName("gatt_read_display_id"),
        ScanResolutionState.resolved,
      );
    });

    test("marks b004 mismatch as rejected", () {
      expect(
        scanResolutionFromDebugName("gatt_b004_mismatch"),
        ScanResolutionState.rejected,
      );
    });

    test("marks terminal gatt failures as failed", () {
      expect(
        scanResolutionFromDebugName("gatt_resolution_failed"),
        ScanResolutionState.failed,
      );
      expect(
        scanResolutionFromDebugName("connect_timeout"),
        ScanResolutionState.failed,
      );
    });

    test("leaves ordinary scan events awaiting gatt", () {
      expect(
        scanResolutionFromDebugName("ble_discovery_result"),
        ScanResolutionState.awaitingGatt,
      );
    });
  });

  group("scanResolutionForDebugEvent", () {
    test("marks recoverable gatt resolution failures as retrying", () {
      expect(
        scanResolutionForDebugEvent("gatt_resolution_failed", <String, Object?>{
          "recoverable": true,
        }),
        ScanResolutionState.retrying,
      );
    });

    test("keeps non-recoverable gatt resolution failures as failed", () {
      expect(
        scanResolutionForDebugEvent("gatt_resolution_failed", <String, Object?>{
          "recoverable": false,
        }),
        ScanResolutionState.failed,
      );
    });
  });

  group("isDebugPeerLocalName", () {
    test("accepts debug peer local names", () {
      expect(isDebugPeerLocalName("BND-D6A7"), isTrue);
    });

    test("rejects production or malformed local names", () {
      expect(isDebugPeerLocalName("BNRD"), isFalse);
      expect(isDebugPeerLocalName("BND-d6a7"), isFalse);
      expect(isDebugPeerLocalName(null), isFalse);
    });
  });

  group("shouldRefreshPermissionsForLifecycle", () {
    test("refreshes permissions when returning to the app", () {
      expect(
        shouldRefreshPermissionsForLifecycle(AppLifecycleState.resumed),
        isTrue,
      );
    });

    test(
      "does not refresh permissions while the app is leaving foreground",
      () {
        expect(
          shouldRefreshPermissionsForLifecycle(AppLifecycleState.inactive),
          isFalse,
        );
        expect(
          shouldRefreshPermissionsForLifecycle(AppLifecycleState.paused),
          isFalse,
        );
        expect(
          shouldRefreshPermissionsForLifecycle(AppLifecycleState.detached),
          isFalse,
        );
      },
    );
  });

  group("canStartBleFromStatus", () {
    test("null status (initial check still pending) blocks Start", () {
      expect(canStartBleFromStatus(null), isFalse);
    });

    test("returns true when permissions granted and BLE is available", () {
      expect(canStartBleFromStatus(_statusFromMap(<Object?, Object?>{})), isTrue);
    });

    test(
      "returns false on iOS Simulator where authorization is granted but "
      "BLE capability is not (issue #57)",
      () {
        final BarnardPermissionStatus simulatorStatus = _statusFromMap(
          <Object?, Object?>{"canScan": false, "canAdvertise": false},
        );
        expect(simulatorStatus.allGranted, isTrue);
        expect(canStartBleFromStatus(simulatorStatus), isFalse);
        expect(canStartScanFromStatus(simulatorStatus), isFalse);
        expect(canStartAdvertiseFromStatus(simulatorStatus), isFalse);
      },
    );

    test("scan-capable advertise-incapable device blocks Auto only", () {
      // Some Android devices support BLE scan but not advertise (no multi-
      // advertisement support / null bluetoothLeAdvertiser). The user can
      // still scan, so individual Scan-only should remain enabled.
      final BarnardPermissionStatus partial = _statusFromMap(
        <Object?, Object?>{"canAdvertise": false},
      );
      expect(canStartBleFromStatus(partial), isFalse);
      expect(canStartScanFromStatus(partial), isTrue);
      expect(canStartAdvertiseFromStatus(partial), isFalse);
    });

    test("permission missing blocks Start regardless of capability", () {
      final BarnardPermissionStatus missing = _statusFromMap(<Object?, Object?>{
        "permissions": <Object?, Object?>{"ios.bluetooth": "notDetermined"},
        "missingPermissions": <Object?>["ios.bluetooth"],
        "requestablePermissions": <Object?>["ios.bluetooth"],
      });
      expect(canStartBleFromStatus(missing), isFalse);
      expect(canStartScanFromStatus(missing), isFalse);
      expect(canStartAdvertiseFromStatus(missing), isFalse);
    });
  });

  group("blePermissionStripStateFor", () {
    test("null → checking", () {
      expect(blePermissionStripStateFor(null), BlePermissionStripState.checking);
    });

    test("blocked permission → blocked", () {
      final BarnardPermissionStatus blocked = _statusFromMap(<Object?, Object?>{
        "permissions": <Object?, Object?>{"ios.bluetooth": "denied"},
        "missingPermissions": <Object?>["ios.bluetooth"],
        "blockedPermissions": <Object?>["ios.bluetooth"],
        "canScan": false,
        "canAdvertise": false,
      });
      expect(
        blePermissionStripStateFor(blocked),
        BlePermissionStripState.blocked,
      );
    });

    test("missing permission → missing", () {
      final BarnardPermissionStatus missing = _statusFromMap(<Object?, Object?>{
        "permissions": <Object?, Object?>{"ios.bluetooth": "notDetermined"},
        "missingPermissions": <Object?>["ios.bluetooth"],
        "requestablePermissions": <Object?>["ios.bluetooth"],
        "canScan": false,
        "canAdvertise": false,
      });
      expect(
        blePermissionStripStateFor(missing),
        BlePermissionStripState.missing,
      );
    });

    test("granted but no BLE capability → unsupported (issue #57)", () {
      final BarnardPermissionStatus simulator = _statusFromMap(
        <Object?, Object?>{"canScan": false, "canAdvertise": false},
      );
      expect(
        blePermissionStripStateFor(simulator),
        BlePermissionStripState.unsupported,
      );
      expect(
        blePermissionStripLabel(simulator),
        "Bluetooth: Not available on this device",
      );
    });

    test("granted and capable → ready", () {
      expect(
        blePermissionStripStateFor(_statusFromMap(<Object?, Object?>{})),
        BlePermissionStripState.ready,
      );
    });
  });
}
