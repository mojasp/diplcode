#include "crypto_wrapper.h"
#include <udpm_util.h>
#include <assert.h>

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>

#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/base64.h>
#include <botan/cipher_mode.h>

class gcm_crypto_context {
    public:
        //96 bit IV are recommended for gcm (better performance) - for now, we use 64 bit salt and 32 bit nonce (LCM seqno)
        std::vector<uint8_t> salt[8];
        const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");;

        const int TAG_SIZE = LCMCRYPTO_TAGSIZE;

        gcm_crypto_context () {
            Botan::AutoSeeded_RNG rng;

            rng.random_vec(8);
        }
};

gcm_crypto_context crypto_ctx;

extern "C" uint64_t get_salt() {
return *(uint64_t*) crypto_ctx.salt;
}

extern "C" void create_IV(IV* iv, uint64_t salt, const uint32_t seqno) {
memcpy(iv->data, &salt, 8);
memcpy(iv->data+8, &seqno, 4);
}

void prettyprint_hex(uint8_t * data, size_t size, const char* msg_string) {
    std::string encoded = Botan::hex_encode(data, size);
    cout << msg_string << encoded << endl;
}
void prettyprint_base64(uint8_t * data, size_t size, const char* msg_string) {
    std::string encoded = Botan::base64_encode(data, size);
    cout << msg_string << encoded << endl;
}
extern "C" int encrypt(char * ptext, size_t ptextsize, const IV * iv, char * ctext, size_t ctextsize) {
    auto enc = Botan::Cipher_Mode::create("AES-128/GCM", Botan::ENCRYPTION);

    enc->set_key(crypto_ctx.key);

    enc->start(iv->data, sizeof(iv->data));
    Botan::secure_vector<uint8_t> ct(ptext, ptext + ptextsize);
    enc->finish(ct);
    printf("tagsize %i\n", enc->tag_size());
    assert(enc->tag_size() == LCMCRYPTO_TAGSIZE);
    //TODO: stupid implementation for now, take advantage of in-place encryption later
    memcpy(ctext, ct.data(), ct.size());

    std::cout << enc->name() << " with iv " << Botan::hex_encode(iv->data, sizeof(iv->data)) << " " << Botan::hex_encode(ct) << "\n";
    return 0;
}
extern "C" int decrypt(char * ctext, size_t ctextsize, const IV* iv, char * ptext, size_t ptextsize) {
    auto dec = Botan::Cipher_Mode::create("AES-128/GCM", Botan::DECRYPTION);
    dec->set_key(crypto_ctx.key);

    dec->start(iv->data, sizeof(iv->data));
    Botan::secure_vector<uint8_t> pt(ctext, ctext + ctextsize);
    dec->finish(pt);
    //TODO: stupid implementation for now, take advantage of in-place encryption later
    memcpy(ptext, pt.data(), pt.size());

    std::cout << dec->name() << " with iv " << Botan::hex_encode(iv->data, sizeof(iv->data)) << " " << Botan::hex_encode(pt) << "\n";
    return 0;
}
