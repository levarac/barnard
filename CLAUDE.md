# CLAUDE.md

Project-specific guidance for Claude Code. See `AGENTS.md` for the spec-driven
workflow, commit conventions, and definition of done — this file only records
how to build and test the repository locally.

## Test commands

The commands below are the local equivalents of the CI jobs in
`.github/workflows/`. Run the surfaces your change touches; run all of them
before a release. Every command is relative to the repository root.

### Schema and privacy invariants (fast, no toolchain)

```
python3 scripts/check-schema-privacy-invariant.py --self-test
python3 scripts/check-wallet-binding-schema.py
./scripts/check-swift-mirror.sh
./scripts/check-android-mirror.sh
./scripts/check-swift-package-manifest-mirror.sh
```

### Swift — packages/swift/barnard (requires Xcode + an iOS Simulator)

`xcodebuild` needs a full Xcode, not the Command Line Tools. Check with
`xcode-select -p`; if it prints `/Library/Developer/CommandLineTools`, point it
at Xcode first (this needs sudo, so a human has to run it):

```
sudo xcode-select -s /Applications/Xcode.app
```

```
cd packages/swift/barnard
UDID=$(xcrun simctl list devices available iOS -j | \
  python3 -c "import json,sys; d=json.load(sys.stdin)['devices']; \
  runtimes=sorted([k for k in d if 'iOS' in k], reverse=True); \
  print([dev for rt in runtimes for dev in d[rt] if 'iPhone' in dev['name']][0]['udid'])")
xcodebuild -scheme Barnard-Package -destination "id=$UDID" SWIFT_OPTIMIZATION_LEVEL=-O test
```

`SWIFT_OPTIMIZATION_LEVEL=-O` is required, not optional: the default `-Onone`
build makes the BigInteger-based secp256k1 math roughly 9x slower and pushes
the suite against its timeout.

BarnardCore purity check (stdlib-only target must not pull in platform APIs).
This one works with the Command Line Tools toolchain alone:

```
cd packages/swift/barnard
swift build --target BarnardCore
swift build --target BarnardCoreC
grep -RnwE 'Foundation|FoundationEssentials|CryptoKit|CoreBluetooth|Security|UIKit|CommonCrypto|SecRandom|UserDefaults|Data|Date|CCCrypt' \
  Sources/BarnardCore Sources/BarnardCoreC && echo "FORBIDDEN DEPENDENCY" && exit 1
```

### Android — packages/android/barnard (requires JDK 17)

```
cd packages/android/barnard
./gradlew assembleDebug assembleRelease
./gradlew test
```

### Dart / Flutter — packages/dart/barnard (requires the Flutter stable channel)

```
cd packages/dart/barnard
flutter pub get
flutter analyze
flutter test

cd packages/dart/barnard/android
./gradlew testDebugUnitTest

cd examples/flutter/barnard_poc
flutter pub get
flutter analyze
flutter test
```

## Notes

- CI ignores markdown-only changes (`paths-ignore: '**/*.md'`), so a docs-only
  change does not exercise these suites.
- `swift-android.yml` (BarnardCore cross-compiled for `aarch64-android` with a
  pinned Swift 6.4 development snapshot) is CI-only; it is not reproduced here
  because it downloads a ~1.6 GB pinned toolchain.
