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

extern "C" int encrypt(lcm_security_ctx* ctx, uint32_t seqno, char * ptext, size_t ptextsize, char * ctext, size_t ctextsize) {
    auto enc = Botan::Cipher_Mode::create("AES-128/GCM", Botan::ENCRYPTION);

    enc->set_key(ctx->key);

    auto IV = ctx->create_IV(seqno);
    enc->start(IV);
    Botan::secure_vector<uint8_t> ct(ptext, ptext + ptextsize);
    enc->finish(ct);
    printf("tagsize %li\n", enc->tag_size());
    assert(enc->tag_size() == LCMCRYPTO_TAGSIZE);
    //FIXME: stupid implementation for now, take advantage of in-place encryption later
    memcpy(ctext, ct.data(), ct.size());

    CRYPTO_DBG("encrypted msg using %s with IV %s\n", enc->name().c_str(), Botan::hex_encode(IV).c_str());
    return 0;
}
extern "C" int decrypt(lcm_security_ctx* ctx, uint32_t seqno, char * ctext, size_t ctextsize, char * ptext, size_t ptextsize) {
    auto dec = Botan::Cipher_Mode::create("AES-128/GCM", Botan::DECRYPTION);
    dec->set_key(ctx->key);

    try {
        dec->start(ctx->create_IV(seqno));
        Botan::secure_vector<uint8_t> pt(ctext, ctext + ctextsize);
        dec->finish(pt);
        //FIXME: stupid implementation for now, take advantage of in-place encryption later
        memcpy(ptext, pt.data(), pt.size());

        CRYPTO_DBG("decrypted and authenticated msg using %s\n", dec->name().c_str());
    }
    catch(const Botan::Invalid_Authentication_Tag& err) {
        CRYPTO_DBG("%s\n", "got msg with invalid auth tag");
        return LCMCRYPTO_INVALID_AUTH_TAG;
    }
    return 0;
}
