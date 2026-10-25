/* Use of this source code is governed by a BSD-style license. */
#ifndef BARNARD_CORE_C_SIGNING_H
#define BARNARD_CORE_C_SIGNING_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sign a 32-byte message hash with a 32-byte secp256k1 private key.
 * Returns 0 on success, or -1 for any null pointer or a private scalar
 * outside 1 <= k < N (including zero, N, and all-0xff bytes).
 * Callers provide readable 32-byte inputs, writable 32-byte r/s outputs,
 * and a writable int32_t recovery id. Invalid arguments do not write outputs.
 */
int32_t barnard_core_sign_recoverable(
    const uint8_t *private_key32, const uint8_t *message_hash32,
    uint8_t *out_r32, uint8_t *out_s32, int32_t *out_v);

#ifdef __cplusplus
}
#endif

#endif
