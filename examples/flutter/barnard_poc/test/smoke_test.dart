import "package:flutter/widgets.dart";
import "package:flutter_test/flutter_test.dart";
import "package:barnard_poc/main.dart";

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
}
