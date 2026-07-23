# Issue #78 feasibility spike: Swift logic core on Android

## Verdict

**Do not replace the Kotlin logic core yet.** The official Swift 6.4 Android
toolchain can produce Android shared libraries, and an `@c` export works, but
the current Barnard Swift package is not cross-platform at the source boundary:
only `Secp256k1.swift` and `BarnardV2Policy.swift` compiled unchanged. The
crypto, RPID, signing, and identity files import Apple-only modules or mix
deterministic logic with Apple storage/randomness. The smallest Foundation-using
probe also needs about 62-67 MB of stripped native libraries per ABI (about
24-25 MB per ABI under a simple zip).

The cheapest next move is shared, schema-validated conformance vectors consumed
by both Swift and Kotlin tests, while Issue #72 continues to cover the
platform-native BLE shell on devices.

## 1. Toolchain and CI setup

I used the matching host/target snapshot published for the `release/6.4.x`
branch on 2026-07-17:

- Host: `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-17-a` for macOS.
- Target: `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-17-a_android`.
- Existing NDK: r28c (`28.2.13676358`), which satisfies the SDK script's
  minimum of NDK 27.
- All downloaded and extracted Swift files were kept under
  `spike/issue-78-swift-android-core/.toolchain/`. No toolchain or SDK file is
  committed.

Evidence:

```text
$ ax ...swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-17-a-osx.pkg --head
"content-length": "1957930046"

$ ax ...swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-17-a_android.artifactbundle.tar.gz --head
"content-length": "342612514"

$ stat -f '%N %z bytes' .toolchain/downloads/*
..._android.artifactbundle.tar.gz 342612514 bytes
...-osx.pkg 1957930046 bytes
```

The exact compressed download total was **2,300,542,560 bytes**. The complete
workspace-local `.toolchain` directory (downloads, extracted toolchain, Android
SDK, and caches) occupied **10 GB**. This excludes the pre-existing NDK, which
was not downloaded.

```text
$ shasum -a 256 .toolchain/downloads/*
97bf596f3057d3f0c17664432b097e32447d9babf14d6068a0f97c3f58aa9aa8  ...-osx.pkg
54a9c6b9491ea531cd3f5696f1071c2ca055cad89b89a2f408633b73f373c601  ..._android.artifactbundle.tar.gz

$ ax https://www.swift.org/api/v1/install/dev/6.4.x/android-sdk.json --body
[{"checksum":"54a9c6b9491ea531cd3f5696f1071c2ca055cad89b89a2f408633b73f373c601",
  "dir":"swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-17-a", ...}]
```

The host package signature was valid:

```text
$ pkgutil --check-signature ...-osx.pkg
Status: signed by a developer certificate issued by Apple for distribution
Developer ID Installer: Swift Open Source (V9AUD2URP3)
```

The extracted toolchain and SDK identify themselves as:

```text
$ .toolchain/.../usr/bin/swift --version
Apple Swift version 6.4-dev (LLVM 3704913b9103f85, Swift 9517428e7f4b63e)
Target: arm64-apple-macosx27.0.0
Build config: +assertions

$ .toolchain/.../usr/bin/swift sdk list --swift-sdks-path .toolchain/sdk
swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-17-a_android
```

The official NDK setup script succeeded without copying the NDK:

```text
$ ANDROID_NDK_HOME=.../ndk/28.2.13676358 \
    SWIFT_ANDROID_NDK_LINK=1 bash ./scripts/setup-android-sdk.sh
setup-android-sdk.sh: success: ndk-sysroot linked to Android NDK at
.../ndk/28.2.13676358/toolchains/llvm/prebuilt
```

### Full package result

The unchanged package was built with the snapshot `swift`, a workspace-local
scratch/cache/config/security path, the installed SDK path, API 28, and
`--disable-sandbox` (nested SwiftPM `sandbox-exec` is not permitted inside this
worker sandbox):

```text
$ swift build --package-path packages/swift/barnard \
    --scratch-path spike/issue-78-swift-android-core/.build/full-package \
    --swift-sdks-path spike/issue-78-swift-android-core/.toolchain/sdk \
    --swift-sdk aarch64-unknown-linux-android28 \
    --build-system native --disable-sandbox
Building for debugging...
error: emit-module command failed with exit code 1
packages/swift/barnard/Sources/Barnard/BarnardCrypto.swift:4:8:
error: no such module 'CommonCrypto'
4 | import CommonCrypto
```

Therefore the answer to “does `packages/swift/barnard`, including crypto,
cross-compile out of the box?” is **no**.

### CI runner story

The upstream `swiftlang/swift-android-examples` workflow currently demonstrates
both `ubuntu-latest` and `macos-latest`, JDK 25, NDK caching, a pinned matching
host/Android Swift pair, and Gradle builds for Android artifacts:

```text
$ ax https://raw.githubusercontent.com/swiftlang/swift-android-examples/main/.github/workflows/ci.yml --body
matrix:
  swift_version: ['6.3', 'nightly-6.3', 'nightly-main']
  ndk_version: ['r27d', 'r29', 'r30-beta2']
  os: ['ubuntu-latest', 'macos-latest']
...
- name: Set up JDK 25
...
- name: Cache Android Swift SDK artifact
...
- name: Cache Host Toolchain
  # Disabled because we are overflowing the 10GB GitHub cache limit
  if: false
```

For Barnard, a practical CI job can use Ubuntu or macOS, pin one exact
toolchain/SDK snapshot, cache the Android SDK and NDK, and build all three ABIs.
The host toolchain should be installed on each run or cached outside the normal
10 GB GitHub cache budget. A 6.4 development snapshot is not a stable production
pin.

## 2. Cross-compile and binding layer

### Source boundary measured

The committed probe contains byte-identical copies of two current Barnard
sources:

```text
$ cmp -s Sources/.../Secp256k1.swift \
    ../../packages/swift/barnard/Sources/Barnard/Secp256k1.swift
Secp256k1.swift: byte-identical

$ cmp -s Sources/.../BarnardV2Policy.swift \
    ../../packages/swift/barnard/Sources/Barnard/BarnardV2Policy.swift
BarnardV2Policy.swift: byte-identical
```

Both compiled into Android `.so` files for `aarch64`, `armv7`, and `x86_64`.
The other files need exclusion or source surgery:

| Existing source | Result | Reason |
|---|---|---|
| `Secp256k1.swift` | Compiled unchanged | Uses Foundation `Data`; available |
| `BarnardV2Policy.swift` | Compiled unchanged | Pure scalar/String policy |
| `BarnardCrypto.swift` | Excluded | `CommonCrypto` and `CryptoKit` unavailable; `SecRandomCopyBytes` is platform randomness mixed into the file |
| `BarnardSigning.swift` | Excluded | `CryptoKit` unavailable and proof methods depend on `BarnardCrypto` |
| `BarnardRpidGenerator.swift` | Excluded | `CryptoKit`/`Security` unavailable; `UserDefaults` storage is mixed with payload generation |
| `BarnardIdentity.swift` | Excluded | `CryptoKit` unavailable; device-secret persistence is mixed into the wrapper |
| `BarnardEngine.swift` | Excluded | `CoreBluetooth` and `UIKit`; explicitly outside the shared-core scope |

The import probes used the Android target/resource/sysroot directly:

```text
$ swiftc -typecheck Probes/ImportAvailability/<Module>.swift \
    -module-name ImportProbe \
    -target aarch64-unknown-linux-android28 \
    -resource-dir .../swift-resources/usr/lib/swift-aarch64 \
    -sdk .../ndk-sysroot
CommonCrypto: FAIL (1) — no such module 'CommonCrypto'
CoreBluetooth: FAIL (1) — no such module 'CoreBluetooth'
CryptoKit: FAIL (1) — no such module 'CryptoKit'
Foundation: PASS
Security: FAIL (1) — no such module 'Security'
UIKit: FAIL (1) — no such module 'UIKit'
```

The minimal package built successfully for all SDK-provided Android ABIs:

```text
$ swift build --product BarnardAndroidLogicProbe \
    --swift-sdk aarch64-unknown-linux-android28 -c release
Build of product 'BarnardAndroidLogicProbe' complete!

$ swift build ... --swift-sdk armv7-unknown-linux-android28 -c release
Build of product 'BarnardAndroidLogicProbe' complete!

$ swift build ... --swift-sdk x86_64-unknown-linux-android28 -c release
Build of product 'BarnardAndroidLogicProbe' complete!
```

### `@c` experiment

`CExports.swift` exports a scalar policy function:

```swift
@c(barnard_should_emit_rssi_update)
public func barnardShouldEmitRssiUpdate(
  _ cachedPeerEnin: UInt32,
  _ currentEnin: UInt32
) -> UInt8
```

The symbol exists for every ABI:

```text
$ llvm-nm -D <each .so> | rg barnard_should_emit_rssi_update
00000000000015bc T barnard_should_emit_rssi_update  # aarch64
000010ec T barnard_should_emit_rssi_update          # armv7
0000000000001650 T barnard_should_emit_rssi_update  # x86_64
```

The generated header contains a directly callable C shape:

```text
$ rg -n -C 3 barnard_should_emit .../BarnardAndroidLogicProbe-Swift.h
SWIFT_EXTERN uint8_t barnard_should_emit_rssi_update(
  uint32_t cachedPeerEnin, uint32_t currentEnin
) SWIFT_NOEXCEPT SWIFT_WARN_UNUSED_RESULT;
```

This proves a narrow C ABI is viable. It does **not** prove a complete JNI/Kotlin
wrapper, exception mapping, lifetime management, or debugging path.

### `swift-java` assessment

I did not run `JExtractSwiftPlugin` end to end because the actual shared core
does not compile yet. Current upstream documentation says:

```text
$ ax https://raw.githubusercontent.com/swiftlang/swift-java/main/README.md --body
supporting libraries ... are under active development and not yet published
to Maven Central
...
swift-java jextract --mode=jni ... including Android systems can be supported
...
There is no guarantee about API stability until the project reaches a 1.0 release.
```

The upstream Android example additionally requires JDK 25 to publish
`SwiftKitCore` to `mavenLocal` before Gradle can consume it. This worker has JDK
25.0.3, but publishing was not attempted because it was not needed to answer the
source/toolchain blocker and the task forbids writes outside the workspace.

The documented JNI feature table covers the useful deterministic API shapes:
classes/structs, global/member functions, enums, `Data`, `Date`, optional
parameters/returns, Strings, and primitive/unsigned integers. It also warns that
Java has no unsigned primitives. The logic-only `BarnardIdentity` surface is
therefore plausibly expressible after crypto/storage separation. The full
`BarnardEngine` surface contains platform types and callback/event shapes such
as escaping closures over user-defined types and `[String: Any]?`; it should
remain native rather than be forced through the bridge.

Conclusion: generated JNI can probably avoid a second **algorithm**
implementation, but today it adds non-trivial Gradle/plugin/runtime glue and
pre-1.0 tooling risk. The `@c` route is simpler for a few scalar/byte-buffer
functions but would require a manually maintained wrapper API.

## 3. Binary cost per ABI

The product `.so` itself is tiny:

```text
$ file <three release .so files>; stat -f '%z bytes' <files>
arm64-v8a:   37,544 bytes, ELF 64-bit ARM aarch64
armeabi-v7a: 34,464 bytes, ELF 32-bit ARM EABI5
x86_64:      35,240 bytes, ELF 64-bit x86-64
```

I recursively followed each ELF `DT_NEEDED` entry through the Swift Android SDK
and NDK, copied the closure, then used NDK `llvm-strip --strip-all` and zipped
each ABI directory. Android system libraries (`libc`, `libm`, `libdl`) were not
counted. The closure contains 18 files per ABI including the product and
`libc++_shared.so`.

| ABI | Product `.so` | Product + runtime, raw | Product + runtime, stripped | Simple zip |
|---|---:|---:|---:|---:|
| arm64-v8a | 37,544 B | 98,063,680 B | 65,663,840 B | 24,055,234 B |
| armeabi-v7a | 34,464 B | 90,160,480 B | 62,333,108 B | 24,237,536 B |
| x86_64 | 35,240 B | 96,080,888 B | 66,691,776 B | 24,656,466 B |
| all three | 107,248 B | 284,305,048 B | 194,688,724 B | 72,949,236 B (sum) |

Command output:

```text
arm64-v8a product=37544 runtime_plus_product_raw=98063680
  stripped=65663840 zip=24055234 libs=18
armeabi-v7a product=34464 runtime_plus_product_raw=90160480
  stripped=62333108 zip=24237536 libs=18
x86_64 product=35240 runtime_plus_product_raw=96080888
  stripped=66691776 zip=24656466 libs=18
```

An attempted statically linked dynamic library did not link:

```text
$ swift build ... --swift-sdk aarch64-unknown-linux-android28 \
    -c release --static-swift-stdlib
ld.lld: error: unable to find library -lCoreFoundation
ld.lld: error: unable to find library -l_FoundationCShims
ld.lld: error: unable to find library -l_FoundationCollections
```

These are uncompressed native-payload and simple-zip measurements, not an APK
download-size measurement. I did not assemble an AAR/APK. The probe excludes the
unported crypto/RPID/signing code, so the full core cannot be smaller than this
without reducing its Foundation/runtime dependency set.

## 4. Foundation subset

The deterministic sources use:

- `Data`: construction, append/concatenation, prefix/suffix, subrange
  replacement, unsafe-byte conversion, and byte mapping.
- `Date` and `timeIntervalSince1970`.
- String UTF-8 conversion and `String(format:)` for hex.
- `UserDefaults` in `BarnardRpidGenerator`/`BarnardIdentity`; this is storage,
  not deterministic logic.
- `withUnsafeBytes` and fixed-width integer endian conversions.

`FoundationProbe.swift` deliberately compiles `Data`, `Date`,
`String(format:)`, and `UserDefaults` in the Android product. The Android build
completed for all three ABIs, so these APIs are in this SDK's compilable
Foundation surface. Host tests also exercised the Data/Date path:

```text
$ swift test
Test cExportPolicyShape() passed
Test foundationDataAndDateShape() passed
Test secp256k1SourceIsLive() passed
Test run with 3 tests ... passed
```

I did not execute the Foundation probe on an Android device, so runtime behavior
of `UserDefaults` was not verified. `CryptoKit`, `CommonCrypto`, and `Security`
are separate Apple modules, not supported Foundation APIs; the import probe
above failed for each. Device-secret storage and secure randomness should be
injected from the platform shell even if a Foundation storage API compiles.

## 5. Kotlin contributor loop

The current upstream recommended layout is:

1. Swift package with a dynamic library and `JExtractSwiftPlugin`.
2. Gradle builds the Swift package once per ABI.
3. Generated Java/JNI sources plus the Swift runtime libraries and
   `libc++_shared.so` are packaged into an AAR.
4. Kotlin consumes that AAR and generated Java API.

The upstream example's command is:

```text
$ ./gradlew :hello-swift-java-hashing-lib:assembleRelease
# Builds arm64-v8a, armeabi-v7a, x86_64 and packages an AAR.
```

Today the setup also requires an exact Swift host/Android SDK pair, NDK 27+,
JDK 25 for locally publishing the not-yet-public `SwiftKitCore` Maven artifact,
and cache management for multi-gigabyte toolchains.

For Barnard, the shortest credible loop would be:

```text
edit shared Swift logic
  -> swift test on host
  -> Gradle task cross-builds 3 ABIs and runs jextract
  -> Kotlin unit/instrumentation tests
  -> Issue #72 two-device BLE test for the native shell
```

I verified the first two compilation layers (host tests and three Android ABI
builds). I did not verify Android Studio source stepping through JNI into Swift
or LLDB attachment. Treat cross-language debugging as an open contributor-risk,
not as solved.

## 6. Cheapest fallback: schema-driven conformance vectors

The repository already states the intended fallback:

```text
$ sed -n '1,20p' schema/README.md
Goals
- Keep Dart / Swift / Kotlin / JS implementations consistent without sharing code
- Enable conformance testing via shared test vectors

$ find schema -type f | rg -i 'vector|fixture|conformance'
# no output
```

Implement one versioned fixture contract, for example:

```text
schema/barnard/v2/conformance/
  logic-vector.schema.json
  vectors/
    crypto.json
    enin-boundaries.json
    signing.json
    policy.json
```

Each deterministic input/output row should cover:

- Device secret + event code -> TEK, RPIK, RPI, 17-byte payload,
  event-code hash, and display ID.
- Fixed-length ENIN clamps/boundaries and Beacon Slot genesis/boundaries.
- Stable-read same-window and boundary-crossing results.
- secp256k1 public key, RFC 6979 low-S `(r,s,v)`, ownership-proof bytes, and
  key-binding bytes.
- Known-peer cached/current ENIN policy outcomes, including the stale-RPID case
  behind Issues #75/#76.
- Invalid lengths and challenge bounds.

The fixture secret is test data only and must never become an on-wire field.
Swift XCTest and Kotlin/JUnit should load the same JSON files and assert every
byte. CI should validate the vectors against their JSON Schema, then run both
native suites. Issue #72 remains complementary: vectors contain deterministic
logic drift, while the bounded two-device harness contains BLE/permission/GATT
drift.

This removes algorithm drift at the test-contract boundary without adding a
Swift runtime, JNI/AAR tooling, or a third implementation. Re-evaluate a shared
Swift core after a stable 6.4 release, public/stable SwiftKit Maven artifacts,
an extracted storage/crypto abstraction, and a materially smaller measured
runtime payload.
