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
        substitute(module("org.levarac.barnard:barnard")).using(project(":"))
    }
}
```

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("org.levarac.barnard:barnard:1.0-SNAPSHOT")
}
```

## Usage

```kotlin
import org.levarac.barnard.BarnardEngine
import org.levarac.barnard.BarnardEvent

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
`src/main/kotlin/org/levarac/barnard/BarnardIdentity.kt`.

See `examples/android-native` for a runnable minimal app.

## Relationship to the Flutter plugin

This package is the **canonical origin** for the shared Kotlin sources also
shipped inside `packages/dart/barnard/android`. The Flutter plugin keeps a
referencing mirror copy because pub.dev packages must be self-contained:

- `BarnardCrypto.kt`, `BarnardSigning.kt`, `BarnardV2Policy.kt`, and
  `BarnardIso8601.kt` are the native origins for byte-for-byte copies in the
  Flutter plugin (pure JVM, no Android-framework or Flutter-embedding
  dependency). `scripts/sync-mirrors.sh` regenerates the copies, and
  `scripts/check-android-mirror.sh` fails CI if they drift.
- `BarnardEngine.kt` (Flutter-free port of `BarnardController`) and
  `BarnardIdentity.kt` (Flutter-free port of `BarnardIdentityController`)
  are native-only files, not mirrored sources. Their Flutter counterparts are
  woven into the method-channel API (`MethodChannel`, `EventChannel`,
  `PluginRegistry.RequestPermissionsResultListener`) and cannot be copied
  verbatim. The native files expose the same behavior through a Kotlin-first
  public API (typed sealed events/callbacks instead of a method-channel
  dispatcher).

**Why keep a mirror copy instead of making the Flutter plugin depend on this
package**: the Flutter plugin's Android module resolves its Flutter
embedding classpath dynamically from the Flutter SDK
(`packages/dart/barnard/android/build.gradle`); making it depend on a
sibling standalone Gradle library is possible but nontrivial to wire up
safely across Flutter's own Gradle plugin, and this repo's CI/tooling here
has no Flutter toolchain to validate that path end-to-end. Synchronizing the
pure, dependency-free sources from this native origin into the Flutter
package, with a byte-identical drift check, is lower-risk for this first slice.
Follow-up: evaluate making `packages/dart/barnard/android` depend on this
package directly once that path is validated against a real Flutter build.
