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

This package is currently a **mirror**, not a move, of
`packages/dart/barnard/ios/barnard`:

- The platform adapters (`BarnardCrypto.swift`, `Secp256k1.swift`,
  `BarnardSigning.swift`, `BarnardRpidGenerator.swift`,
  `BarnardV2Policy.swift`, `BarnardPlatformDependencies.swift`, and
  `PrivacyInfo.xcprivacy`) are byte-for-byte copies of the Flutter plugin's
  Flutter-free sources.
- Every source under `Sources/BarnardCore` is also a byte-for-byte copy of the
  corresponding Flutter plugin source under `Sources/barnard/BarnardCore`.
  `scripts/check-swift-mirror.sh` (repo root) checks both groups and fails CI
  if they drift.
- `BarnardEngine.swift` (Flutter-free port of `BarnardBleController`) and
  `BarnardIdentity.swift` (Flutter-free port of `BarnardIdentityController`)
  are new files, not mirrors — the originals are woven into Flutter's
  method-channel API (`FlutterEventSink`, `FlutterMethodCall`) and cannot be
  copied verbatim. They re-implement the same behavior with a Swift-first
  public API (closures/return values instead of a method-channel
  dispatcher).

**Why mirror instead of making the Flutter plugin depend on this package**:
the Flutter plugin ships via a CocoaPods podspec
(`packages/dart/barnard/ios/barnard.podspec`); making a CocoaPods pod depend
on a sibling local SwiftPM package is possible but nontrivial to wire up
safely, and this repo's CI/tooling here has no Flutter/CocoaPods toolchain
to validate that path end-to-end. Mirroring the pure, dependency-free
sources with a byte-identical sync check is lower-risk for this first
slice. Follow-up: evaluate making `packages/dart/barnard/ios` depend on
this package directly (true move) once that path is validated against a
real Flutter build.
