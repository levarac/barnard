# Mirror project-type reference checks

## Problem and scope

Byte-identical native/Dart mirrors can reference a project type that is absent
from the mirror target (issue #155). Detect this without a compiler or Flutter
SDK, using Python 3 and the existing Bash mirror checks.

No public shapes, schemas, Transport behavior, or on-wire payloads change. No
device-unique persistent identifiers are introduced. Scan / Advertise / Central /
Peripheral / GATT behavior is unchanged.

## Behavior

- `scripts/mirror-manifest.sh` remains the authoritative list of mirrored files.
- Inventory type declarations in native production sources: Swift `Sources`,
  and Android `src/main` Kotlin/Java files. Tests and examples are excluded.
- For each manifested Swift or Android source, compare identifier references to
  that inventory. A known project type must have a declaration somewhere in the
  corresponding Dart mirror target, including independently implemented files.
- Swift's Dart target includes its `BarnardCore` subdirectory. Kotlin and Java
  production sources are inventoried together. Existing React Native byte
  comparisons remain unchanged; this new invariant covers the Dart mirrors.
- Ignore comments. Retain identifiers inside strings as possible references,
  including interpolation, preferring a named false failure to a missed type.
  Strings cannot contribute declarations. Platform/stdlib/external identifiers
  absent from the native project inventory are not rejected.
- On a missing type, exit 1 and print the native referencing file, line, missing
  type name, declaration location(s), and mirror target. Missing manifest inputs
  also fail. An I/O or manifest error exits 2. Success prints checked file and
  declaration counts. There are no retries or network operations.
- Existing byte comparisons still run. Both Ubuntu mirror CI jobs run the new
  check via their existing scripts and execute the compiler-free fixtures.

## Heuristic limits

This is a spelling-based check, not proof that a mirror compiles. It recognizes
named Swift class/struct/enum/protocol/actor/typealias declarations and Kotlin/
Java class/interface/object/typealias/enum/record declarations, including nested
declarations. It cannot resolve qualified names, scopes, visibility, overloads,
generic substitutions, typealias expansion, extension members, generated types,
conditional compilation, target exclusions, or dependency/module availability.
Same-named declarations can hide an absent qualified type. Shadowed names,
inactive branches, strings, and cross-package names may cause false failures.
Only conventional ASCII identifiers are supported. A new declaration syntax or
different target layout requires updating this check and its fixtures.
Swift extended regex syntax is unsupported: a Swift source used for declaration
inventory or manifested references containing raw `#/` exits 2 before comment
erasure, including occurrences inside comments or strings, rather than risk
hiding declarations or references. Bare `/.../` regex literals are not parsed.

## Example and acceptance

The initial check of `origin/main` found two references to
`BarnardAdoptionProtocolError` with no mirror declaration. Extract its unchanged
public enum from the native census file into its own manifested source file.
It also found references to `BarnardCoreLibsecp256k1Backend` under
`#if BARNARD_LIBSECP256K1`; mirror the existing conditional backend file as well.
The Dart target does not enable that flag, so its pure Swift behavior is
unchanged. No type-name exemptions are needed.

If a manifested `Shared.kt` uses `NativeOnly`, declared only in native
`NativeOnly.kt`, byte comparison succeeds but the type check fails naming
`Shared.kt` and `NativeOnly`. Adding an independent declaration of `NativeOnly`
to the Dart target makes the type check pass. The same behavior applies to Swift.

Fixtures cover each language's missing type, a type declared in both trees,
manifested types, platform/stdlib types, comments, string interpolation,
declaration kinds, Java declarations, and missing mirrored files. The current
repository must pass both mirror checks; all Native SDK CI jobs must succeed on
the draft PR. Native compilation remains the responsibility of existing CI.
