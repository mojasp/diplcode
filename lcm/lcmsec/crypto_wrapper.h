#ifndef CRYPTOWRAPPER_HPP
#define CRYPTOWRAPPER_HPP 

#include <stdint.h>

#include "lcm.h"

#ifdef __cplusplus
extern "C" {
#endif

//return types
#define LCMCRYPTO_DECRYPTION_ERROR -1
#define LCMCRYPTO_ENCRYPTION_ERROR -2
#define LCMCRYPTO_INVALID_AUTH_TAG -3

#define LCMCRYPTO_TAGSIZE 16
#define LCMCRYPTO_IVSIZE  12
#define LCMCRYPTO_SALTSIZE 2

#define CRYPTO_DBG(fmt, ...) \
    do { if (LCMSEC_DEBUG) fprintf(stderr, "lcmsec: " fmt, __VA_ARGS__); } while (0) //formatted debug message while preserving possible compilation errors

typedef struct _lcm_security_ctx lcm_security_ctx; //opaque type used for interoperability with c code

lcm_security_ctx* lcm_create_security_ctx (lcm_security_parameters* params);

void lcm_destroy_security_ctx (lcm_security_ctx* ctx);


/**
 * @brief performs keyexchange on all available channels
 *
 * @param ctx security context
 * @return 0 on success, 1 on error
 */
int lcm_crypto_perform_keyexchange(lcm_security_ctx* ctx);

int lcm_encrypt_channelname(lcm_security_ctx* ctx, uint32_t seqno, const char* ptext, size_t ptextsize, uint8_t** ctext);

//returns bytes written or error
//ctext is an output-parameter, the buffer is managed by the crypto module
int lcm_encrypt_message(lcm_security_ctx* ctx, const char* channelname, uint32_t seqno, const uint8_t * ptext, size_t ptextsize, uint8_t** ctext);

// Decrypt channelname until nullterminator is found. Results are written into ptext.
// A maximum size of LCM_MAX_CHANNEL_NAME_LENGTH+1 is implied.
// Returns: the strlength of the channelname or -1
//
// ctext_max_size is the total length of the payload. it is needed, in case the total message
// including channelname is both
//   * malformed (no nullterminator)
//   * its size (in total) is smaller than LCM_MAX_CHANNEL_NAME_LENGTH+1
// Otherwise we would decrypt past the buffer of the incoming message
int lcm_decrypt_channelname(lcm_security_ctx *ctx, uint16_t sender_id, uint32_t seqno, const char *ctext,
                            size_t ctextsize_max_size, uint8_t** ptext);

int lcm_decrypt_message(lcm_security_ctx* ctx, const char* channelname, uint16_t sender_id, uint32_t seqno, uint8_t* ctext, size_t ctextsize, uint8_t** rptext);


uint16_t get_sender_id_from_cryptoctx(lcm_security_ctx* ctx, const char* channelname);

#ifdef __cplusplus
}
#endif

#endif /* ifndef CRYPTOWRAPPER_HPP */
