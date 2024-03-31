#ifndef CRYPTOWRAPPER_HPP
#define CRYPTOWRAPPER_HPP 

#include "lcmsec.h"
#include <stdio.h>
#include <cstdlib>

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

lcm_security_ctx* lcm_create_security_ctx (lcm_security_parameters* params){
    fprintf(stderr, "LCM ERROR: lcm_create_security_ctx called even though LCM is compiled without LCMsec support");
    exit(EXIT_FAILURE);
}

void lcm_destroy_security_ctx (lcm_security_ctx* ctx){
    fprintf(stderr, "LCM ERROR: lcm_create_security_ctx called even though LCM is compiled without LCMsec support");
    exit(EXIT_FAILURE);

}

int lcm_encrypt_channelname(lcm_security_ctx* ctx, uint32_t seqno, const char* ptext, size_t ptextsize, uint8_t** ctext){
    fprintf(stderr, "LCM ERROR: lcm_encrypt_channelname called even though LCM is compiled without LCMsec support");
    exit(EXIT_FAILURE);
}

//returns bytes written or error
//ctext is an output-parameter, the buffer is managed by the crypto module
int lcm_encrypt_message(lcm_security_ctx* ctx, const char* channelname, uint32_t seqno, const uint8_t * ptext, size_t ptextsize, uint8_t** ctext){
    fprintf(stderr, "LCM ERROR: lcm_encrypt_message called even though LCM is compiled without LCMsec support");
    exit(EXIT_FAILURE);

}

// Decrypt channelname until nullterminator is found. Results are written into ptext.
// A maximum size of LCM_MAX_CHANNEL_NAME_LENGTH+1 is implied.
// Returns: the strlength of the channelname or -1
//
// ctext_max_size is the total length of the payload. it is needed, in case the total message
// including channelname is both
//   * malformed (no nullterminator)
//   * its size (in total) is smaller than LCM_MAX_CHANNEL_NAME_LENGTH+1
// Otherwise we would decrypt past the buffer of the incoming message
int lcm_decrypt_channelname(lcm_security_ctx *ctx, uint16_t sender_id, uint32_t seqno, const char *ctext
                            size_t ctextsize_max_size, uint8_t** ptext){
    fprintf(stderr, "LCM ERROR: lcm_decrypt_channelname called even though LCM is compiled without LCMsec support");
    exit(EXIT_FAILURE);

}

int lcm_decrypt_message(lcm_security_ctx* ctx, const char* channelname, uint16_t sender_id, uint32_t seqno, uint8_t* ctext, size_t ctextsize, uint8_t** rptext){
    fprintf(stderr, "LCM ERROR: lcm_decrypt_message called even though LCM is compiled without LCMsec support");
    exit(EXIT_FAILURE);
}


uint16_t get_sender_id_from_cryptoctx(lcm_security_ctx* ctx, const char* channelname){
    fprintf(stderr, "LCM ERROR: get_sender_id_from_cryptoctx called even though LCM is compiled without LCMsec support");
    exit(EXIT_FAILURE);

}

#ifdef __cplusplus
}
#endif

#endif /* ifndef CRYPTOWRAPPER_HPP */
