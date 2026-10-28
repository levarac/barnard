# Swift package CI time budget

## Problem and goals

The Native SDK CI `swift-package` job serializes iOS Simulator and native macOS
validation. Run 40591916504 at `f38fae4` took 810 seconds: the test steps took
415 and 304 seconds, respectively. Each executed the same 197 XCTest methods,
but against a different platform. Preserve both executions and every existing
build, purity, manifest, and consumer check while keeping each job below ten
minutes. Changing production code, test inputs, assertions, runner types, or
repository settings is outside this change.

## Terminology and behavior

`swift-package-ios` validates the package graph and runs all three test targets
on iOS Simulator. `swift-package-macos` builds the stdlib-only targets, checks
their purity, runs the whole package on native macOS, checks the root/inner
manifests, and builds the scratch iOS Simulator consumer. Both use `macos-15`
and the existing commands and optimization settings.

The `swift-package` aggregate check waits for both jobs. It MUST run even when
a dependency fails or is skipped, and MUST succeed only when both dependencies
succeed. For example, a successful iOS run and a failed macOS build produce a
failed aggregate check. No retry, test-result cache, test selection, or parallel
test execution is added. Existing job timeouts are not increased.

## Why retain both test executions

The baseline logs contain 197 distinct methods on each platform, including
`testLibsecp256k1AndPureSwiftBackendsAreByteIdentical` (237.413 seconds on iOS,
81.894 seconds on macOS). The native macOS build took another 209.92 seconds.
The only test added on main between `67b97a5` and `f38fae4`, in `070609d`, took
0.003/0.005 seconds. The earlier run is a pull-request revision with one test
absent from main, so equal counts do not imply identical revision contents.

Deleting a platform execution would reduce platform coverage. The expensive
backend comparison already uses finite deterministic inputs (29 key/hash
pairs); reducing them would reduce the exercised cases. Its code did not
change in this interval. Existing adapter tests share persisted defaults, so
unrestricted parallel test execution is not appropriate. Separate platform
jobs remove the serialization without changing either corpus or assertions.

## Compatibility, security, and privacy

No public shape changes: schemas, APIs, examples, and Scan / Advertise /
Central / Peripheral / GATT / Transport behavior are unchanged. No device-unique
persistent identifiers are added to on-wire payloads. Test fixtures and mocks
remain unchanged and bounded. The existing `swift-package` check name remains
available as the aggregate; repository protection settings are unchanged.

## Validation

Compare the complete `(test target, suite, method)` inventory from both baseline
test steps with both PR jobs. Each platform MUST still execute all 197 baseline
methods, with no renames or removals. Record per-step build/test time and job
wall time from GitHub Actions logs and metadata. Both platform jobs and the
aggregate MUST be green and below 600 seconds, and every other Native SDK CI
job MUST remain green. Hosted runner performance can vary; a single passing
measurement does not establish a long-term percentile.
