#ifndef CRYPTOWRAPPER_HPP
#define CRYPTOWRAPPER_HPP 

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LCMCRYPTO_INVALID_AUTH_TAG 2
#define LCMCRYPTO_DECRYPTION_ERROR 1
#define LCMCRYPTO_ENCRYPTION_ERROR 3

#define LCMCRYPTO_TAGSIZE 12


//returns -1 and writes to stderr on failure
int encrypt(char * ptext, size_t ptextsize, char * ctext, size_t ctextsize); 

int decrypt(char * ctext, size_t ctextsize, char * ptext, size_t ptextsize);

#ifdef __cplusplus
}
#endif

#endif /* ifndef CRYPTOWRAPPER_HPP */
