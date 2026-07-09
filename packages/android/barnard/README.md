# Barnard (Android)

First-class Gradle library for native Android apps to adopt the Barnard
protocol without a Flutter or React Native runtime dependency (barnard#56).

## Installation

Add as a Gradle composite build (local path shown; publish to Maven once
this package is released):

```kotlin
// settings.gradle.kts
includeBuild("../path/to/packages/android/barnard") {
    dependencySubstitution {
        substitute(module("network.greeting.barnard:barnard")).using(project(":"))
    }
}
```

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("network.greeting.barnard:barnard:1.0-SNAPSHOT")
}
```

## Usage

```kotlin
import network.greeting.barnard.BarnardEngine
import network.greeting.barnard.BarnardEvent

val engine = BarnardEngine(applicationContext)
engine.setActivity(activity) // required for requestPermissions()
engine.onEvent = { event ->
    when (event) {
        is BarnardEvent.Detection -> println("detected rpid=${event.detection.rpid} rssi=${event.detection.rssi}")
        else -> Unit
    }
}

engine.requestPermissions { result ->
    when (result) {
        is BarnardPermissionResult.Granted -> {
            if (result.status.canScan && result.status.canAdvertise) {
                engine.startAuto()
            }
        }
        is BarnardPermissionResult.Failed -> {
            // result.error.code is one of E_NO_ACTIVITY, E_PERMISSION_REQUEST_IN_PROGRESS,
            // or E_DISPOSED (engine disposed before the platform replied).
        }
    }
}
```

Unlike iOS (where Bluetooth authorization state is pushed by
`CoreBluetooth`), Android's runtime-permission flow is `Activity`-driven:
forward the hosting `Activity`'s `onRequestPermissionsResult` into
`engine.onRequestPermissionsResult(...)` for `requestPermissions` to
resolve.

For per-event device signing identity (RPID ownership proofs, key
binding), use `BarnardIdentity` — see
`src/main/kotlin/network/greeting/barnard/BarnardIdentity.kt`.

See `examples/android-native` for a runnable minimal app.

## Relationship to the Flutter plugin

This package is currently a **mirror**, not a move, of
`packages/dart/barnard/android`:

- `BarnardCrypto.kt`, `BarnardSigning.kt`, `BarnardV2Policy.kt`, and
  `BarnardIso8601.kt` are byte-for-byte copies of the Flutter plugin's
  Flutter-free sources (pure JVM, no Android-framework or Flutter-embedding
  dependency). `scripts/check-android-mirror.sh` (repo root) fails CI if
  they drift.
- `BarnardEngine.kt` (Flutter-free port of `BarnardController`) and
  `BarnardIdentity.kt` (Flutter-free port of `BarnardIdentityController`)
  are new files, not mirrors — the originals are woven into Flutter's
  method-channel API (`MethodChannel`, `EventChannel`,
  `PluginRegistry.RequestPermissionsResultListener`) and cannot be copied
  verbatim. They re-implement the same behavior with a Kotlin-first public
  API (typed sealed events/callbacks instead of a method-channel
  dispatcher).

**Why mirror instead of making the Flutter plugin depend on this
package**: the Flutter plugin's Android module resolves its Flutter
embedding classpath dynamically from the Flutter SDK
(`packages/dart/barnard/android/build.gradle`); making it depend on a
sibling standalone Gradle library is possible but nontrivial to wire up
safely across Flutter's own Gradle plugin, and this repo's CI/tooling here
has no Flutter toolchain to validate that path end-to-end. Mirroring the
pure, dependency-free sources with a byte-identical sync check is
lower-risk for this first slice. Follow-up: evaluate making
`packages/dart/barnard/android` depend on this package directly (true
move) once that path is validated against a real Flutter build.
