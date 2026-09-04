#include "barnard_secp256k1.h"
#define ENABLE_MODULE_RECOVERY 1
#define ECMULT_WINDOW_SIZE 15
#define ECMULT_GEN_PREC_BITS 4
#include "vendor/src/secp256k1.c"
#include "vendor/src/modules/recovery/main_impl.h"
static secp256k1_context *barnard_global_context;
int barnard_secp256k1_context_create(const uint8_t seed32[32]) {
  if (barnard_global_context != NULL) return 1;
  barnard_global_context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  if (barnard_global_context == NULL) return 0;
  if (!secp256k1_context_randomize(barnard_global_context, seed32)) {
    secp256k1_context_destroy(barnard_global_context);
    barnard_global_context = NULL;
    return 0;
  }
  return 1;
}
__attribute__((destructor)) static void barnard_context_destroy(void) { if (barnard_global_context != NULL) secp256k1_context_destroy(barnard_global_context); }
static const secp256k1_context *barnard_context(void) { return barnard_global_context; }
int barnard_secp256k1_seckey_verify(const uint8_t key32[32]) { return secp256k1_ec_seckey_verify(barnard_context(), key32); }
int barnard_secp256k1_pubkey_create(const uint8_t key32[32], uint8_t output33[33]) { secp256k1_pubkey p; size_t n=33; return secp256k1_ec_pubkey_create(barnard_context(),&p,key32) && secp256k1_ec_pubkey_serialize(barnard_context(),output33,&n,&p,SECP256K1_EC_COMPRESSED) && n==33; }
int barnard_secp256k1_pubkey_expand(const uint8_t input33[33], uint8_t output65[65]) { secp256k1_pubkey p; size_t n=65; return secp256k1_ec_pubkey_parse(barnard_context(),&p,input33,33) && secp256k1_ec_pubkey_serialize(barnard_context(),output65,&n,&p,SECP256K1_EC_UNCOMPRESSED) && n==65; }
int barnard_secp256k1_sign_recoverable(const uint8_t key32[32], const uint8_t hash32[32], uint8_t compact64[64], int *recovery_id) { secp256k1_ecdsa_recoverable_signature s; return secp256k1_ecdsa_sign_recoverable(barnard_context(),&s,hash32,key32,secp256k1_nonce_function_rfc6979,NULL) && secp256k1_ecdsa_recoverable_signature_serialize_compact(barnard_context(),compact64,recovery_id,&s); }
int barnard_secp256k1_recover(const uint8_t compact64[64], const uint8_t hash32[32], int recovery_id, uint8_t output33[33]) { secp256k1_ecdsa_recoverable_signature s; secp256k1_pubkey p; size_t n=33; if(recovery_id<0||recovery_id>1)return 0; return secp256k1_ecdsa_recoverable_signature_parse_compact(barnard_context(),&s,compact64,recovery_id) && secp256k1_ecdsa_recover(barnard_context(),&p,&s,hash32) && secp256k1_ec_pubkey_serialize(barnard_context(),output33,&n,&p,SECP256K1_EC_COMPRESSED) && n==33; }
