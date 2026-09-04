#ifndef BARNARD_SECP256K1_H
#define BARNARD_SECP256K1_H
#include <stdint.h>
int barnard_secp256k1_seckey_verify(const uint8_t key32[32]);
int barnard_secp256k1_pubkey_create(const uint8_t key32[32], uint8_t output33[33]);
int barnard_secp256k1_pubkey_expand(const uint8_t input33[33], uint8_t output65[65]);
int barnard_secp256k1_sign_recoverable(const uint8_t key32[32], const uint8_t hash32[32], uint8_t compact64[64], int *recovery_id);
int barnard_secp256k1_recover(const uint8_t compact64[64], const uint8_t hash32[32], int recovery_id, uint8_t output33[33]);
#endif
