# Barnard

Barnard is a sensing foundation SDK.

It focuses on **Scan/Advertise** and delivering a stable event model (main + debug) for upper layers (e.g., Flutter / React Native), while keeping domain logic and server dependencies out of scope.

## Repository layout

- `specs/` — product and SDK specifications (source of intent)
- `schema/` — language-agnostic **JSON Schemas** (source of truth for event/config/capabilities shapes)
- `packages/`
  - `packages/dart/barnard/` — Flutter plugin package (public API + mock + real BLE Transport)
  - `packages/react-native/barnard/` — React Native package (TypeScript API + native BLE Transport)
- `examples/`
  - `examples/dart/barnard_demo/` — demo using the mock implementation
  - `examples/flutter/barnard_poc/` — Flutter PoC app (real BLE via GATT-first RPID read)
  - `examples/react-native/barnard_demo/` — React Native demo app
- `.github/workflows/` — CI (Flutter analyze/test, Android plugin unit tests, and demos)

## Package READMEs

Start with the package README for the platform you are integrating:

- [Flutter/Dart package](packages/dart/barnard/README.md)
- [React Native package](packages/react-native/barnard/README.md)

Those documents cover installation, iOS `Info.plist` setup, Android manifest merge behavior, runtime permission APIs, and minimal Scan / Advertise usage.

## Flutter quick start

From `packages/dart/barnard`:

```bash
flutter pub get
flutter test
```

Run the Flutter plugin Android unit tests:

```bash
cd packages/dart/barnard/android
flutter precache --android
./gradlew testDebugUnitTest
```

Run the demo:

```bash
cd examples/dart/barnard_demo
flutter pub get
dart run bin/main.dart
```

Run the Flutter PoC app:

```bash
cd examples/flutter/barnard_poc
flutter pub get
flutter run
```

## React Native quick start

From `packages/react-native/barnard`:

```bash
npm install
npm test
```

Run the React Native demo from `examples/react-native/barnard_demo` after installing its app dependencies and native platform dependencies.

## Principles

- Detection is based on **receiver-observed facts**: `rpid + rssi + timestamp`
- Cross-language consistency is driven by **JSON Schema** under `schema/barnard/v2`
- On-wire BLE payloads must not contain device-unique persistent identifiers
- Host apps control OS permission dialog timing through Barnard permission APIs
- Android uses `neverForLocation` for Barnard's default BLE Scan permission; host apps that use BLE Scan results themselves for physical location can override that merged declaration
