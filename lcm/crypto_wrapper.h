#ifndef CRYPTOWRAPPER_HPP
#define CRYPTOWRAPPER_HPP 

#include <unistd.h>
#include <stdint.h>

#include "lcm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LCMCRYPTO_INVALID_AUTH_TAG 2
#define LCMCRYPTO_DECRYPTION_ERROR 1
#define LCMCRYPTO_ENCRYPTION_ERROR 3

#define LCMCRYPTO_TAGSIZE 16
#define LCMCRYPTO_IVSIZE  12

#define LCMCRYPTO_SESSION_NONCE_SIZE 6

typedef struct _lcm_security_ctx lcm_security_ctx; //opaque

lcm_security_ctx* create_security_ctx (lcm_security_parameters* params);

void destroy_security_ctx (lcm_security_ctx* ctx);

//returns 8 bytes
const uint8_t* get_salt();

//returns -1 and writes to stderr on failure
int encrypt(lcm_security_ctx* ctx, uint32_t seqno, char * ptext, size_t ptextsize, char * ctext, size_t ctextsize);

int decrypt(lcm_security_ctx* ctx, uint32_t seqno, char * ctext, size_t ctextsize, char * ptext, size_t ptextsize);

#ifdef __cplusplus
}
#endif

#endif /* ifndef CRYPTOWRAPPER_HPP */
