# barnard

React Native plugin for Barnard SDK - BLE Scan/Advertise + GATT-based RPID detection.

## Features

- ✅ BLE Central role (scanning for nearby devices)
- ✅ BLE Peripheral role (advertising + GATT server)
- ✅ GATT-based RPID exchange
- ✅ iOS support via CoreBluetooth
- ✅ Android support (API 21+)
- ✅ TypeScript API

## Installation

```bash
npm install barnard
# or
yarn add barnard
```

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

### Android Setup

The plugin automatically adds the required permissions to `AndroidManifest.xml`. You need to request permissions at runtime:

```typescript
import { PermissionsAndroid, Platform } from 'react-native';

async function requestBluetoothPermissions() {
  if (Platform.OS === 'android' && Platform.Version >= 31) {
    const granted = await PermissionsAndroid.requestMultiple([
      PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
      PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
      PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
    ]);
    return Object.values(granted).every(
      status => status === PermissionsAndroid.RESULTS.GRANTED
    );
  }
  return true;
}
```

## Usage

### Basic Example

```typescript
import { BarnardManager } from 'barnard';

// Create manager instance
const barnard = new BarnardManager();

// Check capabilities
const capabilities = await barnard.getCapabilities();
console.log('Supported transports:', capabilities.supportedTransports);

// Listen for detections
const unsubscribe = barnard.onDetection((event) => {
  console.log('Detected:', event.displayId);
  console.log('RSSI:', event.rssi);
  console.log('Transport:', event.transport);
});

// Start scanning and advertising
await barnard.startAuto({
  scan: { allowDuplicates: true },
  advertise: { formatVersion: 1 },
});

// Later: cleanup
unsubscribe();
await barnard.dispose();
```

### Event Handling

The SDK emits several event types:

```typescript
// Detection events (RPID detections)
barnard.onDetection((event) => {
  console.log('Detected:', event.displayId, event.rssi);
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

- **`dispose()`**: Dispose of the manager and release resources
  - Returns: `void`

##### Event Listeners

- **`onDetection(callback)`**: Subscribe to detection events
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

interface BarnardState {
  isScanning: boolean;
  isAdvertising: boolean;
}

interface DetectionEvent {
  type: 'detection';
  timestamp: string;
  transport: TransportKind;
  formatVersion: number;
  rpid: string;        // base64
  displayId: string;   // hex (first 4 bytes)
  rssi: number;
  payloadRaw?: string; // base64
}
```

## Security & Privacy

- **No device-unique persistent identifiers on-wire**: The RPID rotates every 600 seconds using HMAC-SHA256
- **Local seed storage**: A 32-byte random seed is generated and stored locally (UserDefaults on iOS, SharedPreferences on Android)
- **GATT-based exchange**: RPIDs are transmitted via GATT characteristic reads, not in advertisement data

## Minimum Requirements

- **React Native**: 0.71+
- **iOS**: 14.0+
- **Android**: API 21+ (Android 5.0+)

## License

MIT

## Related

- [Barnard Spec](../../specs/001-barnard-core-sdk/spec.md)
- [Flutter Implementation](../dart/barnard)
