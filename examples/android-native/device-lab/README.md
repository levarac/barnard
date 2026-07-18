# Native Android device-lab target

This target drives `examples/android-native` on two real Android devices and
exercises the Flutter-free `packages/android/barnard` library through
`BarnardEngine`.

It mirrors the existing Flutter device-lab rendezvous:

1. The Advertiser joins `EVENT_CODE`, starts Advertise, and reports its
   event-scoped `displayId`.
2. The Scanner joins the same event and starts Scan.
3. The run passes only when the Scanner receives a `Detection` or `RssiUpdate`
   carrying that exact `displayId`, and its instrumentation test exits cleanly.

## Run on the device-lab host

From the Barnard checkout:

```bash
cd examples/android-native
./device-lab/run_two_device_loop.sh
```

The defaults match the current emi lab:

- Advertiser: Galaxy S7 edge, adb serial `45732079`
- Scanner: Nexus 5X, adb serial `00b8316e85a2a456`
- Event code: `BND`
- Application ID: `network.greeting.barnard.example.native`

Override them with `ADV_SERIAL`, `SCAN_SERIAL`, `EVENT_CODE`, `HOLD_SECONDS`,
`SCAN_TIMEOUT_SECONDS`, or `OUTPUT_DIR`. The existing pull-based watcher can
invoke this repository-owned script after checking out the Barnard commit; the
watcher and its credentials remain outside this public repository.

The script builds the app and instrumentation APKs, installs clean copies,
grants the applicable Android runtime permissions, enables Location services
for the legacy Android Scanner, runs both roles, and force-stops both app
processes during cleanup. Filtered logs overwrite four fixed files under
`/tmp/barnard-android-native-device-lab` by default.

## What can run without two BLE devices

```bash
./gradlew :app:assembleDebug :app:assembleDebugAndroidTest
bash -n device-lab/run_two_device_loop.sh
shellcheck device-lab/run_two_device_loop.sh
```

Those checks prove that the native app, test APK, and host harness compile or
parse. They do **not** prove a BLE rendezvous. Only a run ending with
`RESULT=PASS ... transport=android-native` on the two real devices supplies
that evidence.

This harness changes no public schema or on-wire payload and adds no
device-unique persistent identifier on-wire. The iOS twin remains out of scope
until iOS devices join the lab.
