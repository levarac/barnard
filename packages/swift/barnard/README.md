# Barnard (Swift)

First-class Swift Package Manager library for native iOS apps to adopt the
Barnard protocol without a Flutter runtime dependency (barnard#56).

## Installation

Add as a Swift Package dependency (local path shown; publish via a Git tag
once this package is released):

```swift
dependencies: [
    .package(path: "../path/to/packages/swift/barnard")
]
```

Then depend on the `Barnard` product in your app target. The package also
publishes `BarnardCore` for deterministic RPID, ENIN, signing, and policy work
on non-Apple Swift targets. `BarnardCore` uses standard-library byte arrays and
integer Unix time; it does not expose Foundation types.

## Usage

```swift
import Barnard

let engine = BarnardEngine()
engine.onEvent = { event in
  switch event {
  case .detection(let d):
    print("detected rpid=\(d.rpid) rssi=\(d.rssi)")
  default:
    break
  }
}

engine.requestPermissions { status in
  guard status.canScan, status.canAdvertise else { return }
  engine.startAuto()
}
```

For per-event device signing identity (RPID ownership proofs, key binding),
use `BarnardIdentity` — see `Sources/Barnard/BarnardIdentity.swift`.

See `examples/ios-native` for a runnable minimal app.

## Relationship to the Flutter plugin

This package is the **canonical origin** for the shared Swift sources also
shipped inside `packages/dart/barnard/ios/barnard`. The Flutter plugin keeps a
referencing mirror copy because pub.dev packages must be self-contained:

- The platform adapters (`BarnardCrypto.swift`, `Secp256k1.swift`,
  `BarnardSigning.swift`, `BarnardRpidGenerator.swift`,
  `BarnardV2Policy.swift`, `BarnardPlatformDependencies.swift`, and
  `PrivacyInfo.xcprivacy`) are the native origins for byte-for-byte copies in
  the Flutter plugin.
- Every source under `Sources/BarnardCore` is likewise the native origin for
  the corresponding Flutter plugin copy under `Sources/barnard/BarnardCore`.
  `scripts/sync-mirrors.sh` regenerates both groups, and
  `scripts/check-swift-mirror.sh` fails CI if they drift.
- `BarnardEngine.swift` (Flutter-free port of `BarnardBleController`) and
  `BarnardIdentity.swift` (Flutter-free port of `BarnardIdentityController`)
  are native-only files, not mirrored sources. Their Flutter counterparts are
  woven into the method-channel API (`FlutterEventSink`, `FlutterMethodCall`)
  and cannot be copied verbatim. The native files expose the same behavior
  through a Swift-first public API (closures/return values instead of a
  method-channel dispatcher).

**Why keep a mirror copy instead of making the Flutter plugin depend on this
package**: the Flutter plugin ships via a CocoaPods podspec
(`packages/dart/barnard/ios/barnard.podspec`); making a CocoaPods pod depend
on a sibling local SwiftPM package is possible but nontrivial to wire up
safely, and this repo's CI/tooling here has no Flutter/CocoaPods toolchain
to validate that path end-to-end. Synchronizing the pure, dependency-free
sources from this native origin into the Flutter package, with a byte-identical
drift check, is lower-risk for this first slice. Follow-up: evaluate making
`packages/dart/barnard/ios` depend on this package directly once that path is
validated against a real Flutter build.
