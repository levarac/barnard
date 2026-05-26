# Barnard Demo - React Native Example

Example React Native application demonstrating the Barnard SDK for BLE-based proximity detection.

## Features

- BLE scanning for nearby devices
- BLE advertising as a peripheral
- GATT-based RPID detection
- Real-time detection feed
- Permission handling for iOS and Android

## Prerequisites

- Node.js 16+
- React Native development environment
- iOS: Xcode 14+ and CocoaPods
- Android: Android Studio and SDK

## Installation

1. Install dependencies:

```bash
npm install
# or
yarn install
```

2. iOS: Install CocoaPods

```bash
cd ios && pod install && cd ..
```

## Running

### iOS

```bash
npm run ios
# or
npx react-native run-ios
```

### Android

```bash
npm run android
# or
npx react-native run-android
```

## Usage

1. **Grant Permissions**: The app calls Barnard's permission API when it is ready to show Bluetooth permission dialogs
2. **Start All**: Tap "Start All" to begin scanning and advertising
3. **View Detections**: Nearby devices running the same app will appear in the detection list
4. **Individual Controls**: Use "Start Scan" and "Start Adv" for granular control

## Testing

To test proximity detection:

1. Install the app on two or more devices
2. Run the app on all devices
3. Tap "Start All" on each device
4. Devices should detect each other and display RPIDs in the detection list

## Notes

- **iOS**: Requires physical device (BLE not supported in simulator)
- **iOS Debug**: React Native / Flutter-style debug tooling can show the Local Network dialog for development server or VM Service discovery. That dialog is separate from Barnard's Bluetooth permission flow.
- **Android**: Requires physical device with BLE support
- **Background mode**: Not supported in this MVP version
- **Permissions**: Barnard supplies Android manifest declarations; grant the runtime permissions when prompted

## Troubleshooting

### iOS

- If pods fail to install, try `pod repo update` then `pod install`
- Ensure Bluetooth usage-description strings are set in Info.plist
- Physical device required (simulator doesn't support BLE)

### Android

- Ensure Android SDK is properly configured
- Check that Barnard runtime permissions are granted
- Try rebuilding if native modules don't link: `cd android && ./gradlew clean`

## Related

- [Barnard SDK](../../../packages/react-native/barnard)
- [Barnard Spec](../../../specs/001-barnard-core-sdk/spec.md)
