#ifndef CRYPTOWRAPPER_HPP
#define CRYPTOWRAPPER_HPP 

#include <unistd.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LCMCRYPTO_INVALID_AUTH_TAG 2
#define LCMCRYPTO_DECRYPTION_ERROR 1
#define LCMCRYPTO_ENCRYPTION_ERROR 3

#define LCMCRYPTO_TAGSIZE 16
#define LCMCRYPTO_IVSIZE  12


typedef struct {
    uint8_t data[12];
} IV;

//returns 8 bytes
uint64_t get_salt();

void create_IV(IV* iv, uint64_t salt, const uint32_t seqno);

//returns -1 and writes to stderr on failure
int encrypt(char * ptext, size_t ptextsize, const IV* iv, char * ctext, size_t ctextsize);

int decrypt(char * ctext, size_t ctextsize, const IV* iv, char * ptext, size_t ptextsize);

#ifdef __cplusplus
}
#endif

#endif /* ifndef CRYPTOWRAPPER_HPP */
