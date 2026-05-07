# barnard

Barnard SDK for Flutter/Dart.

This package provides:
- Public API surface (types + interfaces)
- `MockBarnard` for early integration (no hardware)
- Real BLE Transport for Flutter (GATT-first RPID read)

The real BLE Transport implements **Scan / Advertise** with **GATT-first** RPID delivery:
- Advertise is used for discovery (service UUID).
- The receiver (Central) connects and reads a 17-byte payload from a readable characteristic:
  - `[formatVersion:uint8][rpid:16 bytes]`

## Requirements

- Flutter 3.41.0 or newer
- Dart 3.11.0 or newer
- iOS 14.0 or newer
- Android API 24 or newer for the Flutter plugin package

Swift Package Manager support in Flutter depends on the Flutter 3.41 toolchain.

## Installation

Add Barnard to your Flutter app.

For a local checkout:

```yaml
dependencies:
  barnard:
    path: ../path/to/barnard/packages/dart/barnard
```

For a Git dependency:

```yaml
dependencies:
  barnard:
    git:
      url: https://github.com/thegreeting/barnard.git
      path: packages/dart/barnard
```

Then fetch dependencies:

```bash
flutter pub get
```

Import the BLE Transport when you want real device Scan / Advertise:

```dart
import "package:barnard/barnard_ble.dart";
```

Import the domain API when you only need shared types or the mock implementation:

```dart
import "package:barnard/barnard.dart";
import "package:barnard/mock_barnard.dart";
```

## Platform Setup

### iOS

Add Bluetooth usage-description strings to the host app `ios/Runner/Info.plist`:

```xml
<key>NSBluetoothAlwaysUsageDescription</key>
<string>This app uses Bluetooth to detect nearby devices.</string>
<key>NSBluetoothPeripheralUsageDescription</key>
<string>This app uses Bluetooth to advertise to nearby devices.</string>
```

Barnard does not initialize CoreBluetooth during plugin registration. The iOS Bluetooth permission dialog can only be triggered by an explicit app action such as `requestPermissions()`, `startScan()`, `startAdvertise()`, or `startAuto()`.

Barnard is foreground-only. iOS simulators do not support the BLE flows used by this Transport, so use physical devices for Scan / Advertise testing.

### Android

Barnard's Android library manifest is merged into the host app, so apps do not need to copy BLE permissions into their own manifest for the default foreground BLE Transport. The package declares:

```xml
<!-- BLE permissions for Android 12+ -->
<uses-permission android:name="android.permission.BLUETOOTH_SCAN"
    android:usesPermissionFlags="neverForLocation" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.BLUETOOTH_ADVERTISE" />

<!-- Legacy permissions for Android 11 and below -->
<uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" android:maxSdkVersion="28" />

<uses-feature android:name="android.hardware.bluetooth_le" android:required="false" />
```

The `neverForLocation` flag on `BLUETOOTH_SCAN` means Android 12+ BLE Scan does not require location permission. This flag is scoped to the Bluetooth Scan permission and does not prevent the host app from requesting `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION` for GPS, maps, geofencing, or other non-BLE location features. Android 11 and below still require legacy location permission for BLE Scan discovery.

If the host app uses BLE Scan results themselves to infer physical location, do not use Barnard's default `neverForLocation` declaration. Android may filter some BLE beacons when this flag is present. Override the merged permission in the app manifest:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">
    <uses-permission
        android:name="android.permission.BLUETOOTH_SCAN"
        tools:remove="android:usesPermissionFlags" />
</manifest>
```

## Usage

Create a client, request permissions at an app-controlled point, subscribe to events, and start Scan + Advertise:

```dart
import "dart:async";

import "package:barnard/barnard.dart";
import "package:barnard/barnard_ble.dart";

final client = await BarnardBleClient.create();

final BarnardPermissionStatus permissions = await client.requestPermissions();
if (!permissions.allGranted) {
  // Show app-specific guidance before starting BLE.
  return;
}

final StreamSubscription<BarnardEvent> eventsSub = client.events.listen((
  BarnardEvent event,
) {
  switch (event) {
    case DetectionEvent():
      print("Detected ${event.detectedDisplayId} rssi=${event.rssi}");
    case RssiUpdateEvent():
      print("RSSI update rssi=${event.rssi}");
    case ConstraintEvent():
      print("Constraint ${event.code}: ${event.message}");
    case ErrorEvent():
      print("Error ${event.code}: ${event.message}");
    default:
      break;
  }
});

await client.joinEvent("EXAMPLE_EVENT");
await client.startAuto();

// Later:
await client.stopAuto();
await eventsSub.cancel();
await client.dispose();
```

Use `startScan()` or `startAdvertise()` instead of `startAuto()` when the app wants to control the Central and Peripheral roles independently.

### Permission API

Use `getPermissionStatus()` when you want to inspect current permissions without showing an OS dialog:

```dart
final status = await client.getPermissionStatus();
if (!status.allGranted) {
  final requested = await client.requestPermissions();
  if (!requested.allGranted) return;
}
```

On iOS, `requestPermissions()` creates the CoreBluetooth managers and lets the system show the Bluetooth dialog if authorization is still undetermined. On Android, it requests the runtime permissions required for the current API level.

### Event Shape

Barnard v2 emits byte-valued fields as lowercase hex strings at the native bridge boundary and as `Uint8List` in Dart events.

Important fields:
- `DetectionEvent.rpid`: 17-byte wire form `[formatVersion(1) + RPI(16)]`
- `DetectionEvent.reporterRpid`: this device's 17-byte RPID at the observation timestamp
- `DetectionEvent.detectedDisplayId`: 8-char lowercase hex `SHA256(peerTEK)[0:4]`, or `null` if the B003 GATT read failed
- `DetectionEvent.enin`: ENIN at the observation timestamp

The SDK never transmits TEK over BLE. `exportCurrentTek()` is an explicit host-app API for non-BLE egress.

## Example

Run the Flutter PoC app:

```bash
cd examples/flutter/barnard_poc
flutter pub get
flutter run
```

## Local Verification

Run Dart and Flutter tests:

```bash
flutter pub get
flutter test
```

Run the Android plugin unit tests, including `android/src/test/kotlin`:

```bash
cd android
flutter precache --android
./gradlew testDebugUnitTest
```

## Troubleshooting

- `permission_denied` constraint: call `requestPermissions()` from an app-controlled UX point and retry after the returned status has no `missingPermissions`.
- `bluetooth_off` or `bluetooth_not_ready`: ask the user to enable Bluetooth and retry.
- No iOS detections in simulator: use physical devices. CoreBluetooth Scan / Advertise is not available in the simulator.
- Android app does not show permission dialogs: confirm the app is using the Barnard plugin package and did not remove merged permissions with manifest tools rules.
- Cross-platform discovery is foreground-only. iOS background advertising may move Service UUIDs to the overflow area, making devices hard to discover.

## Scan Filter

The SDK uses a Service UUID filter (`0000B001-0000-1000-8000-00805F9B34FB`) for efficient scanning. This reduces battery consumption and filters out non-Barnard devices at the system level.

## Channels

- MethodChannel: `barnard/methods`
- EventChannel: `barnard/events`
- EventChannel: `barnard/debugEvents`
