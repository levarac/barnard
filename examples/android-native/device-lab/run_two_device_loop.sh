#!/usr/bin/env bash
# Copyright 2024-2026 The Greeting Inc. All rights reserved.
# Use of this source code is governed by a BSD-style license.
#
# Native Android two-device rendezvous for the Barnard device lab (issue #72).
# It mirrors the Flutter loop's contract while exercising BarnardEngine:
# advertiser joins an event and reports its displayId; scanner joins the same
# event and must receive that displayId through the Scan -> Central GATT path.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ADB="${ADB:-adb}"
GRADLEW="${GRADLEW:-$APP_DIR/gradlew}"

ADV_SERIAL="${ADV_SERIAL:-45732079}"
SCAN_SERIAL="${SCAN_SERIAL:-00b8316e85a2a456}"
APP_ID="${APP_ID:-network.greeting.barnard.example.native}"
TEST_APP_ID="${TEST_APP_ID:-$APP_ID.test}"
RUNNER="${RUNNER:-androidx.test.runner.AndroidJUnitRunner}"
EVENT_CODE="${EVENT_CODE:-BND}"
HOLD_SECONDS="${HOLD_SECONDS:-450}"
SCAN_TIMEOUT_SECONDS="${SCAN_TIMEOUT_SECONDS:-60}"
PERMISSION_WAIT_SECONDS="${PERMISSION_WAIT_SECONDS:-30}"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp/barnard-android-native-device-lab}"

ADV_TEST_CLASS="network.greeting.barnard.example.devicelab.BarnardAdvertiserDeviceLabTest#advertisesAndHolds"
SCAN_TEST_CLASS="network.greeting.barnard.example.devicelab.BarnardScannerDeviceLabTest#discoversAdvertiserByDisplayId"
APP_APK="${APP_APK:-$APP_DIR/app/build/outputs/apk/debug/app-debug.apk}"
TEST_APK="${TEST_APK:-$APP_DIR/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk}"

ADV_INSTRUMENTATION_LOG="$OUTPUT_DIR/advertiser-instrumentation.log"
ADV_LOGCAT="$OUTPUT_DIR/advertiser-logcat.log"
SCAN_INSTRUMENTATION_LOG="$OUTPUT_DIR/scanner-instrumentation.log"
SCAN_LOGCAT="$OUTPUT_DIR/scanner-logcat.log"

ADV_PID=""
ADV_LOGCAT_PID=""
SCAN_LOGCAT_PID=""

fail() {
  echo "RESULT=ERROR $*"
  exit 2
}

validate_bounded_integer() {
  name="$1"
  value="$2"
  minimum="$3"
  maximum="$4"
  case "$value" in
    ''|*[!0-9]*) fail "$name must be an integer in $minimum..$maximum" ;;
  esac
  if [ "$value" -lt "$minimum" ] || [ "$value" -gt "$maximum" ]; then
    fail "$name must be in $minimum..$maximum (got $value)"
  fi
}

validate_bounded_integer HOLD_SECONDS "$HOLD_SECONDS" 1 900
validate_bounded_integer SCAN_TIMEOUT_SECONDS "$SCAN_TIMEOUT_SECONDS" 1 180
validate_bounded_integer PERMISSION_WAIT_SECONDS "$PERMISSION_WAIT_SECONDS" 0 60
[ "$ADV_SERIAL" != "$SCAN_SERIAL" ] || fail "ADV_SERIAL and SCAN_SERIAL must name different devices"
command -v "$ADB" >/dev/null 2>&1 || fail "adb is not available: $ADB"
[ -x "$GRADLEW" ] || fail "Gradle wrapper is not executable: $GRADLEW"

mkdir -p "$OUTPUT_DIR"
: > "$ADV_INSTRUMENTATION_LOG"
: > "$ADV_LOGCAT"
: > "$SCAN_INSTRUMENTATION_LOG"
: > "$SCAN_LOGCAT"

# shellcheck disable=SC2329  # Invoked indirectly by the trap below.
cleanup() {
  set +e
  [ -z "$ADV_PID" ] || kill "$ADV_PID" 2>/dev/null
  [ -z "$ADV_LOGCAT_PID" ] || kill "$ADV_LOGCAT_PID" 2>/dev/null
  [ -z "$SCAN_LOGCAT_PID" ] || kill "$SCAN_LOGCAT_PID" 2>/dev/null
  "$ADB" -s "$ADV_SERIAL" shell am force-stop "$APP_ID" >/dev/null 2>&1
  "$ADB" -s "$SCAN_SERIAL" shell am force-stop "$APP_ID" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

device_ready() {
  serial="$1"
  "$ADB" devices | awk -v target="$serial" '$1 == target && $2 == "device" { found = 1 } END { exit(found ? 0 : 1) }'
}

echo "[android-native] build app and instrumentation APKs"
"$GRADLEW" -p "$APP_DIR" :app:assembleDebug :app:assembleDebugAndroidTest
[ -f "$APP_APK" ] || fail "app APK missing after build: $APP_APK"
[ -f "$TEST_APK" ] || fail "test APK missing after build: $TEST_APK"

echo "[android-native] ensure both devices are connected"
"$ADB" reconnect >/dev/null 2>&1 || true
ready=false
for _ in $(seq 1 30); do
  if device_ready "$ADV_SERIAL" && device_ready "$SCAN_SERIAL"; then
    ready=true
    break
  fi
  "$ADB" reconnect >/dev/null 2>&1 || true
  sleep 2
done
[ "$ready" = true ] || fail "both Android devices are not ready over adb"

install_role() {
  serial="$1"
  role="$2"
  echo "[android-native] install clean APKs on $serial ($role)"
  "$ADB" -s "$serial" uninstall "$TEST_APP_ID" >/dev/null 2>&1 || true
  "$ADB" -s "$serial" uninstall "$APP_ID" >/dev/null 2>&1 || true
  "$ADB" -s "$serial" install -g "$APP_APK" >/dev/null
  "$ADB" -s "$serial" install -g -t "$TEST_APK" >/dev/null
  "$ADB" -s "$serial" shell svc bluetooth enable >/dev/null 2>&1 || true

  # Android 8 needs Location; Android 12+ needs the Bluetooth runtime group.
  # `install -g` grants applicable permissions, while these explicit grants
  # make the intent clear and harmlessly no-op on other API levels.
  for permission in \
    android.permission.ACCESS_FINE_LOCATION \
    android.permission.BLUETOOTH_SCAN \
    android.permission.BLUETOOTH_ADVERTISE \
    android.permission.BLUETOOTH_CONNECT; do
    "$ADB" -s "$serial" shell pm grant "$APP_ID" "$permission" >/dev/null 2>&1 || true
  done
}

install_role "$ADV_SERIAL" advertiser
install_role "$SCAN_SERIAL" scanner
"$ADB" -s "$SCAN_SERIAL" shell settings put secure location_mode 3 >/dev/null 2>&1 || true

"$ADB" -s "$ADV_SERIAL" logcat -c
"$ADB" -s "$SCAN_SERIAL" logcat -c
"$ADB" -s "$ADV_SERIAL" logcat -v time BarnardDeviceLab:I '*:S' > "$ADV_LOGCAT" 2>&1 &
ADV_LOGCAT_PID=$!
"$ADB" -s "$SCAN_SERIAL" logcat -v time BarnardDeviceLab:I '*:S' > "$SCAN_LOGCAT" 2>&1 &
SCAN_LOGCAT_PID=$!

echo "[android-native] start Advertise role on $ADV_SERIAL"
"$ADB" -s "$ADV_SERIAL" shell am instrument -w -r \
  -e class "$ADV_TEST_CLASS" \
  -e eventCode "$EVENT_CODE" \
  -e holdSeconds "$HOLD_SECONDS" \
  "$TEST_APP_ID/$RUNNER" > "$ADV_INSTRUMENTATION_LOG" 2>&1 &
ADV_PID=$!

display_id=""
advertising=false
for _ in $(seq 1 90); do
  display_id="$(sed -n 's/.*BARNARD_SELF_DISPLAY_ID=\([0-9a-f]\{8\}\).*/\1/p' "$ADV_LOGCAT" | head -1 || true)"
  if grep -q 'BARNARD_ADVERTISING=true' "$ADV_LOGCAT"; then
    advertising=true
  fi
  if [ -n "$display_id" ] && [ "$advertising" = true ]; then
    break
  fi
  if ! kill -0 "$ADV_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

if [ -z "$display_id" ] || [ "$advertising" != true ]; then
  echo "[android-native] Advertise role did not become ready"
  tail -n 40 "$ADV_INSTRUMENTATION_LOG" || true
  tail -n 40 "$ADV_LOGCAT" || true
  echo "RESULT=FAIL advertiser_ready=no"
  exit 1
fi
echo "[android-native] advertiser displayId=$display_id and advertising=true"

echo "[android-native] run Scan role on $SCAN_SERIAL expecting $display_id"
set +e
"$ADB" -s "$SCAN_SERIAL" shell am instrument -w -r \
  -e class "$SCAN_TEST_CLASS" \
  -e expectedDisplayId "$display_id" \
  -e eventCode "$EVENT_CODE" \
  -e scanTimeoutSeconds "$SCAN_TIMEOUT_SECONDS" \
  -e permissionWaitSeconds "$PERMISSION_WAIT_SECONDS" \
  "$TEST_APP_ID/$RUNNER" > "$SCAN_INSTRUMENTATION_LOG" 2>&1
scan_rc=$?
set -e

echo "[android-native] --- scanner markers ---"
grep -E 'BARNARD_SCAN_|BARNARD_PERM|BARNARD_EVT (detection|rssi_update|constraint|error)' "$SCAN_LOGCAT" | tail -n 40 || true
echo "[android-native] scanner adb exit_code=$scan_rc"

scan_found=false
if grep -q 'BARNARD_SCAN_FOUND=true' "$SCAN_LOGCAT"; then
  scan_found=true
fi
runner_ok=false
if [ "$scan_rc" -eq 0 ] && grep -q 'OK (1 test)' "$SCAN_INSTRUMENTATION_LOG"; then
  runner_ok=true
fi

if [ "$scan_found" = true ] && [ "$runner_ok" = true ]; then
  echo "RESULT=PASS advertiser=$display_id scanner_found=yes transport=android-native"
  exit 0
fi

tail -n 60 "$SCAN_INSTRUMENTATION_LOG" || true
tail -n 60 "$SCAN_LOGCAT" || true
echo "RESULT=FAIL advertiser=$display_id scanner_found=$scan_found runner_ok=$runner_ok"
exit 1
