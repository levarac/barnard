# barnard_poc

Barnard Flutter PoC app (real BLE via GATT-first RPID read).

## Requirements

Use Flutter 3.47.8 stable (Dart 3.13.7), pinned in this directory and the repository root. The example requires Dart `^3.13.7` to exclude SDKs affected by [GHSA-frr6-h895-5pxp](https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp).

## Run

```bash
flutter pub get
flutter run
```

## Notes

- iOS requires `NSBluetoothAlwaysUsageDescription` (and typically `NSBluetoothPeripheralUsageDescription`) in `Info.plist`.
- Android BLE and legacy location manifest declarations are supplied by the Barnard plugin. The app calls Barnard's permission API for runtime prompts.
- `flutter run` debug sessions may show iOS's Local Network dialog for Flutter tooling / VM Service discovery. That dialog is separate from Barnard's Bluetooth permission flow and is not triggered by Barnard BLE registration.
