# barnard

React Native plugin for Barnard SDK - BLE Scan/Advertise + GATT-based RPID detection.

## Features

- BLE Central role (Scan)
- BLE Peripheral role (Advertise + GATT server)
- GATT-based v2 RPID exchange
- iOS support via CoreBluetooth
- Android support via platform BLE APIs
- TypeScript API

## Installation

```bash
npm install barnard
# or
yarn add barnard
```

Minimum platform versions:
- React Native 0.71+
- iOS 14.0+
- Android API 21+

### iOS Setup

1. Install CocoaPods dependencies:

```bash
cd ios && pod install
```

2. Add Bluetooth permissions to `Info.plist`:

```xml
<key>NSBluetoothAlwaysUsageDescription</key>
<string>This app uses Bluetooth to detect nearby devices</string>
<key>NSBluetoothPeripheralUsageDescription</key>
<string>This app uses Bluetooth to advertise to nearby devices</string>
```

Barnard does not initialize CoreBluetooth when the native module is registered. The iOS Bluetooth permission dialog can only be triggered by an explicit app action such as `requestPermissions()`, `startScan()`, `startAdvertise()`, or `startAuto()`.

Barnard does not require iOS Local Network permission. If a debug run shows a "Find Devices on Local Networks" dialog, that is from development tooling such as Metro, not Barnard BLE registration.

### Android Setup

The plugin automatically adds the required BLE and legacy location declarations to `AndroidManifest.xml` through manifest merge. Use Barnard's permission API so the app controls when Android shows runtime permission dialogs:

```typescript
const status = await barnard.getPermissionStatus();
if (status.missingPermissions.length > 0) {
  if (status.blockedPermissions.length > 0) {
    await barnard.openAppSettings();
  } else {
    const requested = await barnard.requestPermissions();
    if (requested.blockedPermissions.length > 0) {
      await barnard.openAppSettings();
    }
  }
}
```

On Android 12+ Barnard requests Bluetooth runtime permissions and declares `BLUETOOTH_SCAN` with `neverForLocation`, so location permission is not required for BLE Scan. This flag is scoped to the Bluetooth Scan permission and does not prevent the host app from requesting `ACCESS_FINE_LOCATION` or `ACCESS_COARSE_LOCATION` for GPS, maps, geofencing, or other non-BLE location features. On Android 11 and below Barnard requests the legacy location permission required by Android BLE Scan.

If the user denies the Android 12+ Nearby devices request, Android may mark the Bluetooth permissions as blocked (`blockedPermissions` is non-empty) and will not show the dialog again. Use `openAppSettings()` and tell the user to enable **Nearby devices** for the app; Android Settings does not label this group as "Bluetooth".

After calling `openAppSettings()`, refresh `getPermissionStatus()` when the app returns to the foreground (for example when React Native `AppState` becomes `active`). Android does not notify Barnard directly when the user changes Nearby devices in Settings, so the host app should update its cached permission UI on foreground resume.

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

### Basic Example

```typescript
import { BarnardManager } from 'barnard';

const barnard = new BarnardManager();

const capabilities = await barnard.getCapabilities();
console.log('Supported transports:', capabilities.supportedTransports);

const permissions = await barnard.requestPermissions();
if (permissions.missingPermissions.length > 0) {
  // Show app-specific guidance before starting BLE.
  return;
}

const unsubscribe = barnard.onDetection((event) => {
  console.log('Detected:', event.detectedDisplayId);
  console.log('RSSI:', event.rssi);
  console.log('ENIN:', event.enin);
});

await barnard.joinEvent('EXAMPLE_EVENT');
await barnard.startAuto({
  scan: { allowDuplicates: true },
  advertise: { formatVersion: 1 },
});

// Later: cleanup
await barnard.stopAuto();
unsubscribe();
await barnard.dispose();
```

### Event Handling

The SDK emits several event types:

```typescript
// Detection events (RPID detections)
barnard.onDetection((event) => {
  console.log('Detected:', event.detectedDisplayId, event.rssi);
});

// High-rate RSSI updates for known peers
barnard.onRssiUpdate((event) => {
  console.log('RSSI:', event.rssi, event.enin);
});

// State changes (scanning/advertising status)
barnard.onStateChange((event) => {
  console.log('State:', event.state);
});

// Constraint events (permissions, Bluetooth disabled, etc.)
barnard.onConstraint((event) => {
  console.log('Constraint:', event.code, event.message);
});

// Error events
barnard.onError((event) => {
  console.log('Error:', event.code, event.message);
});

// Debug events (troubleshooting)
barnard.onDebug((event) => {
  console.log('Debug:', event.level, event.name, event.data);
});
```

### API Reference

#### `BarnardManager`

##### Methods

- **`getCapabilities()`**: Get platform capabilities
  - Returns: `Promise<BarnardCapabilities>`

- **`getState()`**: Get current state (scanning/advertising status)
  - Returns: `Promise<BarnardState>`

- **`getPermissionStatus()`**: Inspect platform BLE permissions without prompting
  - Returns: `Promise<BarnardPermissionStatus>`

- **`requestPermissions()`**: Request platform BLE permissions at an app-controlled moment
  - Returns: `Promise<BarnardPermissionStatus>`

- **`openAppSettings()`**: Open the host app's system settings page when permissions are blocked
  - Returns: `Promise<void>`

- **`getCurrentEventCode()`**: Get the joined event code, or `null`
  - Returns: `Promise<string | null>`

- **`getMyDisplayId()`**: Get this device's 8-char v2 displayId
  - Returns: `Promise<string>`

- **`getCurrentRpi()`**: Get the current 16-byte inner RPI as 32-char lowercase hex
  - Returns: `Promise<string>`

- **`getCurrentEnin()`**: Get the current ENIN
  - Returns: `Promise<number>`

- **`exportCurrentTek()`**: Explicitly export the current 16-byte TEK as 32-char lowercase hex
  - Returns: `Promise<string>`

- **`startScan(config?)`**: Start BLE scanning
  - Parameters: `ScanConfig` (optional)
  - Returns: `Promise<void>`

- **`stopScan()`**: Stop BLE scanning
  - Returns: `Promise<void>`

- **`startAdvertise(config?)`**: Start BLE advertising
  - Parameters: `AdvertiseConfig` (optional)
  - Returns: `Promise<void>`

- **`stopAdvertise()`**: Stop BLE advertising
  - Returns: `Promise<void>`

- **`startAuto(config?)`**: Start both scanning and advertising
  - Parameters: `AutoConfig` (optional)
  - Returns: `Promise<AutoStartResult>`

- **`stopAuto()`**: Stop both scanning and advertising
  - Returns: `Promise<void>`

- **`joinEvent(eventCode)`**: Join an event and derive event-scoped TEK/RPID/displayId values
  - Returns: `Promise<void>`

- **`leaveEvent()`**: Leave the current event and return to anonymous derivation
  - Returns: `Promise<void>`

- **`dispose()`**: Dispose of the manager and release resources
  - Returns: `Promise<void>`

##### Event Listeners

- **`onDetection(callback)`**: Subscribe to detection events
  - Returns: Unsubscribe function

- **`onRssiUpdate(callback)`**: Subscribe to high-rate RSSI update events for known peers
  - Returns: Unsubscribe function

- **`onStateChange(callback)`**: Subscribe to state change events
  - Returns: Unsubscribe function

- **`onConstraint(callback)`**: Subscribe to constraint violation events
  - Returns: Unsubscribe function

- **`onError(callback)`**: Subscribe to error events
  - Returns: Unsubscribe function

- **`onDebug(callback)`**: Subscribe to debug events
  - Returns: Unsubscribe function

### Type Definitions

```typescript
interface BarnardCapabilities {
  supportedTransports: TransportKind[];
  supportsConnectionlessRpid: boolean;
  supportsGattFallback: boolean;
  supportsBackground: boolean;
  supportsHighRateRssi: boolean;
}

type BarnardPermissionDecision =
  | 'granted'
  | 'denied'
  | 'notDetermined'
  | 'restricted'
  | 'unsupported'
  | 'unknown';

interface BarnardPermissionStatus {
  platform: string;
  permissions: Record<string, BarnardPermissionDecision>;
  requiredPermissions: string[];
  missingPermissions: string[];
  canScan: boolean;
  canAdvertise: boolean;
}

interface BarnardState {
  isScanning: boolean;
  isAdvertising: boolean;
  eventCode?: string | null;
}

interface DetectionEvent {
  type: 'detection';
  timestamp: string;
  transport: TransportKind;
  formatVersion: number;
  rpid: string;               // 34-char lowercase hex, [formatVersion + RPI]
  reporterRpid: string;       // 34-char lowercase hex for this device
  detectedDisplayId: string | null; // 8-char lowercase hex, or null
  enin: number;
  rssi: number;
  payloadRaw?: string | null; // 34-char lowercase hex when available
  debugLocalName?: string | null;
}

interface RssiUpdateEvent {
  type: 'rssi_update';
  timestamp: string;
  rpid: string;
  reporterRpid: string;
  enin: number;
  rssi: number;
  detectedDisplayId?: string | null;
}
```

## Security & Privacy

- **No device-unique persistent identifiers on-wire**: Barnard transmits rotating v2 RPID values, not device-unique persistent IDs.
- **TEK is not transmitted over BLE**: `exportCurrentTek()` is an explicit host-app egress API, not part of Scan / Advertise / GATT delivery.
- **GATT-based exchange**: Advertise is used for discovery; RPIDs are read through GATT characteristics.

## Troubleshooting

- `permission_denied` constraint: call `requestPermissions()` from an app-controlled UX point and retry after the returned status has no `missingPermissions`. If `blockedPermissions` is non-empty, open app settings instead of requesting again.
- `bluetooth_off` or `bluetooth_not_ready`: ask the user to enable Bluetooth and retry.
- No iOS detections in simulator: use physical devices. CoreBluetooth Scan / Advertise is not available in the simulator. On iOS Simulator `getPermissionStatus()` / `requestPermissions()` return `canScan: false` and `canAdvertise: false` even when authorization is granted, so host apps should branch on those capability flags rather than on `allGranted` alone.
- No Android detections in emulator or on BLE-less devices: Android Emulator does not virtualize BLE and some devices lack BLE / multi-advertisement hardware. `getPermissionStatus()` returns `canScan: false` / `canAdvertise: false` on these devices regardless of permission grants. As on iOS, branch on the capability flags rather than on `allGranted`.
- Android app does not show permission dialogs: confirm the package manifest is being merged and the app did not remove Barnard permissions with manifest tools rules.
- Cross-platform discovery is foreground-only. iOS background advertising may move Service UUIDs to the overflow area, making devices hard to discover.

## License

MIT

## Related

- [Barnard Spec](../../../specs/001-barnard-core-sdk/spec.md)
- [Flutter Implementation](../../dart/barnard)
