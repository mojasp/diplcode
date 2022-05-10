#ifndef CRYPTOWRAPPER_HPP
#define CRYPTOWRAPPER_HPP 

#include <unistd.h>
#include <stdint.h>

#include "lcm.h"

#ifdef __cplusplus
extern "C" {
#endif

//return types
#define LCMCRYPTO_DECRYPTION_ERROR 1
#define LCMCRYPTO_ENCRYPTION_ERROR 2
#define LCMCRYPTO_INVALID_AUTH_TAG 3

#define LCMCRYPTO_TAGSIZE 16
#define LCMCRYPTO_IVSIZE  12

#define LCMCRYPTO_SESSION_NONCE_SIZE 6

#define LCMCRYPTO_DEBUG 1

#define CRYPTO_DBG(fmt, ...) \
    do { if (LCMCRYPTO_DEBUG) fprintf(stderr, "lcmcrypto: " fmt, __VA_ARGS__); } while (0) //formatted debug message while preserving possible compilation errors

typedef struct _lcm_security_ctx lcm_security_ctx; //opaque type used for interoperability with c code

lcm_security_ctx* lcm_create_security_ctx (lcm_security_parameters* params, size_t paramlen);

void lcm_destroy_security_ctx (lcm_security_ctx* ctx);

int lcm_encrypt_channelname(lcm_security_ctx* ctx, uint32_t seqno, char* ptext, size_t ptextsize, char* ctext, size_t ctextsize);
int lcm_encrypt_message(lcm_security_ctx* ctx, const char* channelname, uint32_t seqno, char* ptext, size_t ptextsize, char* ctext, size_t ctextsize);

int lcm_decrypt_channelname(lcm_security_ctx* ctx, uint16_t sender_id, uint32_t seqno, char* ctext, size_t ctextsize, char* ptext, size_t ptextsize);
int lcm_decrypt_message(lcm_security_ctx* ctx, const char* channelname, uint16_t sender_id, uint32_t seqno, char* ctext, size_t ctextsize, char* ptext, size_t ptextsize);


uint16_t get_sender_id_from_cryptoctx(lcm_security_ctx* ctx, const char* channelname);

#ifdef __cplusplus
}
#endif

#endif /* ifndef CRYPTOWRAPPER_HPP */
