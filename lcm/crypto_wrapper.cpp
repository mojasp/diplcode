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

/*
 * this should indeed be a cpp struct as opposed to a C struct since botan expects various c++ Datatypes for encryption. 
 * having this in c++ therefore saves some copies & maybe allocations
 */
class _lcm_security_ctx {
    public:
        std::string algorithm;

        std::vector<uint8_t> salt;
        uint16_t sender_id; 
        std::vector<uint8_t> key;
        const int TAG_SIZE = LCMCRYPTO_TAGSIZE;

        _lcm_security_ctx (lcm_security_parameters* params) :
            algorithm(params->algorithm),
            sender_id(params->sender_id)
        {
            salt = Botan::hex_decode(params->nonce);
            key = Botan::hex_decode(params->key);
        }


        Botan::secure_vector<uint8_t> create_IV( const uint32_t seqno) {
            Botan::secure_vector<uint8_t> result;

            result.resize(LCMCRYPTO_IVSIZE);
            assert(LCMCRYPTO_IVSIZE==12); //nessecary for hardcoded values in this function here
            assert(salt.size() == LCMCRYPTO_SESSION_NONCE_SIZE);

            auto data = &result[0];
            memcpy(data, &sender_id, 2);
            memcpy(data+2, &salt[0], salt.size());
            memcpy(data + 2 + salt.size(), &seqno, 4);
            return result; //RVO should elide copy
        }
};

extern "C" lcm_security_ctx* create_security_ctx (lcm_security_parameters *params){
    return new lcm_security_ctx(params);
}
extern "C" void destroy_security_ctx (lcm_security_ctx* ctx){delete ctx;}

void prettyprint_hex(uint8_t * data, size_t size, const char* msg_string) {
    std::string encoded = Botan::hex_encode(data, size);
    cout << msg_string << encoded << endl;
}
void prettyprint_base64(uint8_t * data, size_t size, const char* msg_string) {
    std::string encoded = Botan::base64_encode(data, size);
    cout << msg_string << encoded << endl;
}
extern "C" int encrypt(lcm_security_ctx* ctx, uint32_t seqno, char * ptext, size_t ptextsize, char * ctext, size_t ctextsize) {
    auto enc = Botan::Cipher_Mode::create("AES-128/GCM", Botan::ENCRYPTION);

    enc->set_key(ctx->key);

    enc->start(ctx->create_IV(seqno));
    Botan::secure_vector<uint8_t> ct(ptext, ptext + ptextsize);
    enc->finish(ct);
    printf("tagsize %li\n", enc->tag_size());
    assert(enc->tag_size() == LCMCRYPTO_TAGSIZE);
    //FIXME: stupid implementation for now, take advantage of in-place encryption later
    memcpy(ctext, ct.data(), ct.size());

    std::cout << enc->name() << " " << Botan::hex_encode(ct) << "\n";
    return 0;
}
extern "C" int decrypt(lcm_security_ctx* ctx, uint32_t seqno, char * ctext, size_t ctextsize, char * ptext, size_t ptextsize) {
    auto dec = Botan::Cipher_Mode::create("AES-128/GCM", Botan::DECRYPTION);
    dec->set_key(ctx->key);

    dec->start(ctx->create_IV(seqno));
    Botan::secure_vector<uint8_t> pt(ctext, ctext + ctextsize);
    dec->finish(pt);
    //FIXME: stupid implementation for now, take advantage of in-place encryption later
    memcpy(ptext, pt.data(), pt.size());

    std::cout << dec->name() << " " << Botan::hex_encode(pt) << "\n";
    return 0;
}
