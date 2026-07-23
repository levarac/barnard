/* Use of this source code is governed by a BSD-style license.
 *
 * C-host consumption proof for the BarnardCoreC shared library (issue #78).
 *
 * Loads libBarnardCoreC (.so on Linux/Android, .dylib on macOS) with dlopen,
 * resolves the exported C ABI symbols, and replays the issue #80 golden
 * behavior vector (BarnardBehaviorVectorTests). Exits 0 only if every value
 * matches byte-for-byte.
 *
 * Usage: barnard_core_c_host_proof <path-to-libBarnardCoreC>
 */

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int32_t (*derive_tek_for_event_fn)(
    const uint8_t *, int32_t, const uint8_t *, int32_t, uint8_t *);
typedef int32_t (*derive_tek_for_anonymous_fn)(const uint8_t *, int32_t, uint8_t *);
typedef int32_t (*derive_rpik_fn)(const uint8_t *, uint8_t *);
typedef int32_t (*generate_rpi_fn)(const uint8_t *, uint32_t, uint8_t *);
typedef uint32_t (*calculate_enin_fn)(int64_t, int32_t, int64_t, int64_t, int64_t);
typedef int32_t (*stable_read_enin_fn)(
    int64_t, int64_t, int32_t, int64_t, int64_t, int64_t, uint32_t *);
typedef int32_t (*event_code_hash_fn)(const uint8_t *, int32_t, uint8_t *);
typedef int32_t (*display_id4_fn)(const uint8_t *, uint8_t *);
typedef int32_t (*sha256_fn)(const uint8_t *, int32_t, uint8_t *);
typedef int32_t (*derive_signing_keypair_fn)(
    const uint8_t *, int32_t, const uint8_t *, int32_t, uint8_t *, uint8_t *);
typedef int32_t (*sign_recoverable_fn)(
    const uint8_t *, const uint8_t *, uint8_t *, uint8_t *, int32_t *);
typedef uint8_t (*should_emit_rssi_update_fn)(uint32_t, uint32_t);
typedef uint8_t (*should_serve_gatt_display_id_fn)(const uint8_t *, int32_t);

static int failures = 0;

static void expect_hex(const char *name, const uint8_t *bytes, size_t count,
                       const char *expected) {
  char actual[2 * 64 + 1];
  for (size_t i = 0; i < count; i++) {
    snprintf(actual + 2 * i, 3, "%02x", bytes[i]);
  }
  actual[2 * count] = '\0';
  int ok = strcmp(actual, expected) == 0;
  printf("%s=%s%s\n", name, actual, ok ? "" : " MISMATCH");
  if (!ok) {
    printf("  expected %s=%s\n", name, expected);
    failures++;
  }
}

static void expect_u32(const char *name, uint32_t actual, uint32_t expected) {
  int ok = actual == expected;
  printf("%s=%u%s\n", name, actual, ok ? "" : " MISMATCH");
  if (!ok) {
    printf("  expected %s=%u\n", name, expected);
    failures++;
  }
}

static void expect_i32(const char *name, int32_t actual, int32_t expected) {
  int ok = actual == expected;
  printf("%s=%d%s\n", name, actual, ok ? "" : " MISMATCH");
  if (!ok) {
    printf("  expected %s=%d\n", name, expected);
    failures++;
  }
}

static void *must_sym(void *handle, const char *name) {
  void *sym = dlsym(handle, name);
  if (!sym) {
    fprintf(stderr, "missing symbol %s: %s\n", name, dlerror());
    exit(2);
  }
  return sym;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path-to-libBarnardCoreC>\n", argv[0]);
    return 2;
  }
  void *handle = dlopen(argv[1], RTLD_NOW);
  if (!handle) {
    fprintf(stderr, "dlopen failed: %s\n", dlerror());
    return 2;
  }

  derive_tek_for_event_fn derive_tek_for_event =
      (derive_tek_for_event_fn)must_sym(handle, "barnard_core_derive_tek_for_event");
  derive_tek_for_anonymous_fn derive_tek_for_anonymous =
      (derive_tek_for_anonymous_fn)must_sym(handle, "barnard_core_derive_tek_for_anonymous");
  derive_rpik_fn derive_rpik = (derive_rpik_fn)must_sym(handle, "barnard_core_derive_rpik");
  generate_rpi_fn generate_rpi =
      (generate_rpi_fn)must_sym(handle, "barnard_core_generate_rpi");
  calculate_enin_fn calculate_enin =
      (calculate_enin_fn)must_sym(handle, "barnard_core_calculate_enin");
  stable_read_enin_fn stable_read_enin =
      (stable_read_enin_fn)must_sym(handle, "barnard_core_stable_read_enin");
  event_code_hash_fn event_code_hash =
      (event_code_hash_fn)must_sym(handle, "barnard_core_compute_event_code_hash");
  display_id4_fn display_id4 = (display_id4_fn)must_sym(handle, "barnard_core_display_id4");
  sha256_fn sha256 = (sha256_fn)must_sym(handle, "barnard_core_sha256");
  derive_signing_keypair_fn derive_signing_keypair =
      (derive_signing_keypair_fn)must_sym(handle, "barnard_core_derive_signing_keypair");
  sign_recoverable_fn sign_recoverable =
      (sign_recoverable_fn)must_sym(handle, "barnard_core_sign_recoverable");
  should_emit_rssi_update_fn should_emit_rssi_update =
      (should_emit_rssi_update_fn)must_sym(handle, "barnard_core_should_emit_rssi_update");
  should_serve_gatt_display_id_fn should_serve_gatt_display_id =
      (should_serve_gatt_display_id_fn)must_sym(
          handle, "barnard_core_should_serve_gatt_display_id");

  uint8_t device_secret[32];
  for (int i = 0; i < 32; i++) device_secret[i] = (uint8_t)i;
  const char *event_code = "CORE-SPLIT-80";
  int32_t event_code_len = (int32_t)strlen(event_code);
  const uint32_t enin = 123456u;

  uint8_t event_tek[16], anonymous_tek[16], rpik[16], rpi[16];
  uint8_t display_id[4], code_hash[8];

  if (derive_tek_for_event(device_secret, 32, (const uint8_t *)event_code,
                           event_code_len, event_tek) != 0 ||
      derive_tek_for_anonymous(device_secret, 32, anonymous_tek) != 0 ||
      derive_rpik(event_tek, rpik) != 0 || generate_rpi(rpik, enin, rpi) != 0 ||
      display_id4(event_tek, display_id) != 0 ||
      event_code_hash((const uint8_t *)event_code, event_code_len, code_hash) != 0) {
    fprintf(stderr, "a derivation call returned an error\n");
    return 2;
  }

  expect_hex("anonymous_tek", anonymous_tek, 16, "1fc47c788289a03f2fbc8382f80b060c");
  expect_u32("beacon_enin", calculate_enin(1700000123, 1, 300, 1600000000, 12), 8333343u);

  uint32_t stable = 0;
  expect_i32("crossed_enin_status", stable_read_enin(899, 900, 0, 300, 0, 0, &stable), 0);
  expect_hex("display_id", display_id, 4, "c0fab611");
  expect_hex("event_code_hash", code_hash, 8, "0b9f14789f13968f");
  expect_hex("event_tek", event_tek, 16, "51c9263c4fbfc28fb28a76ab0d5d83d6");
  expect_u32("fixed_enin", calculate_enin(1700000123, 0, 300, 0, 0), 5666667u);

  uint8_t payload[17];
  payload[0] = 1;
  memcpy(payload + 1, rpi, 16);
  expect_hex("payload", payload, 17, "01be601a7b45035ec4c85f8e203679d5ae");

  expect_i32("policy_display_empty",
             should_serve_gatt_display_id((const uint8_t *)event_code, 0), 0);
  expect_i32("policy_display_joined",
             should_serve_gatt_display_id((const uint8_t *)event_code, event_code_len), 1);
  expect_i32("policy_rssi_rotated", should_emit_rssi_update(enin, enin + 1), 0);
  expect_i32("policy_rssi_same", should_emit_rssi_update(enin, enin), 1);
  expect_hex("rpi", rpi, 16, "be601a7b45035ec4c85f8e203679d5ae");
  expect_hex("rpik", rpik, 16, "9c20d41985cc258c21e11f10f764b954");

  uint8_t private_key[32], public_key[33];
  if (derive_signing_keypair(device_secret, 32, (const uint8_t *)event_code,
                             event_code_len, private_key, public_key) != 0) {
    fprintf(stderr, "derive_signing_keypair returned an error\n");
    return 2;
  }
  expect_hex("signing_private_key", private_key, 32,
             "054e89de8696ef821cd60963bf0d2980ce1392241a1606ed3bed32983448f404");
  expect_hex("signing_public_key", public_key, 33,
             "036548e454f2b65bf3dc9676d64f8f22517caf0a07af7f33e0710fda7b8efd9e0c");

  const char *message = "issue-80-signing";
  uint8_t message_hash[32], r[32], s[32];
  int32_t v = -1;
  if (sha256((const uint8_t *)message, (int32_t)strlen(message), message_hash) != 0 ||
      sign_recoverable(private_key, message_hash, r, s, &v) != 0) {
    fprintf(stderr, "signing call returned an error\n");
    return 2;
  }
  expect_hex("signing_r", r, 32,
             "e7df5948c76c2c0c3397dcdbf72fed1cf87e5d2379cb0831e4d2f1f2b3f262f5");
  expect_hex("signing_s", s, 32,
             "51760b12ac9be31472f61ca68574e7d1c950ca68504d7dd37bff1bba97e3e7d8");
  expect_i32("signing_v", v, 0);

  stable = 0;
  expect_i32("stable_enin_status", stable_read_enin(899, 899, 0, 300, 0, 0, &stable), 1);
  expect_u32("stable_enin", stable, 2u);

  if (failures != 0) {
    printf("FAILED: %d mismatch(es)\n", failures);
    return 1;
  }
  printf("OK: C host reproduced the issue #80 golden vector via libBarnardCoreC\n");
  return 0;
}
