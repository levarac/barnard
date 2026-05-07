# barnard_poc

Barnard Flutter PoC app (real BLE via GATT-first RPID read).

## Run

```bash
flutter pub get
flutter run
```

## Notes

- iOS requires `NSBluetoothAlwaysUsageDescription` (and typically `NSBluetoothPeripheralUsageDescription`) in `Info.plist`.
- Android BLE and legacy location manifest declarations are supplied by the Barnard plugin. The app calls Barnard's permission API for runtime prompts.
