#include "crypto_wrapper.h"
#include <udpm_util.h>
#include <assert.h>
#include <map>

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
#include <botan/aead.h>

class crypto_ctx {
    public:
        std::string algorithm;

        Botan::secure_vector<uint8_t> salt;
        uint16_t sender_id; 
        Botan::secure_vector<uint8_t> key;
        const int TAG_SIZE = LCMCRYPTO_TAGSIZE;

        crypto_ctx (lcm_security_parameters* params) :
            algorithm (params->algorithm),
            sender_id (params->sender_id),
            salt (Botan::hex_decode_locked(params->nonce)),
            key (Botan::hex_decode_locked(params->key)) {}


        Botan::secure_vector<uint8_t> get_decryption_IV( const uint32_t seqno, uint16_t sender_id) {
            //IV shall be (sequid | sender_id | fixed/salt )
            Botan::secure_vector<uint8_t> result;

            assert(LCMCRYPTO_IVSIZE==12); //nessecary for hardcoded values in this function here
            result.resize(LCMCRYPTO_IVSIZE);
            assert(salt.size() == LCMCRYPTO_SESSION_NONCE_SIZE);

            auto data = &result[0];
            memcpy(data, &seqno, 4);
            memcpy(data + 4, &sender_id, 2);
            memcpy(data + 6, &salt[0], 6);

            return result; //RVO should elide copy
        }
        Botan::secure_vector<uint8_t> get_encryption_IV( const uint32_t seqno) {
            return get_decryption_IV(seqno, this->sender_id);
        }

        void set_ciphermode_key(Botan::Cipher_Mode& mode) {
            mode.set_key(&key[0], key.size());
        }
};

class _lcm_security_ctx {
    public:
        std::unique_ptr<crypto_ctx> group_ctx;

    private:
    //Use map with std::string as keys for storage; but compare with char* so we avoid additional allocation (cpy construction) during lookup
    struct str_cmp {
        bool operator()(const char* a, const char* b) const {
            return std::strcmp(a, b) < 0;
        }
    };

    std::map<char*, std::unique_ptr<crypto_ctx>, str_cmp> channel_ctx_map;

    public:
    _lcm_security_ctx(lcm_security_parameters* params, size_t param_len) {
        for (int i = 0; i < param_len; i++) {
            if(params[i].channelname == nullptr) {
                group_ctx = std::make_unique<crypto_ctx>(params + i);
            }
            else {
                channel_ctx_map[strndup(params[i].channelname, LCM_MAX_CHANNEL_NAME_LENGTH)] = std::make_unique<crypto_ctx>(params+i);
            }
        }
    }
    ~_lcm_security_ctx() {
        for (auto it = channel_ctx_map.begin(); it != channel_ctx_map.end(); it++) {
            char* name = it->first;
            std::memset(name, 0, strnlen(name, LCM_MAX_CHANNEL_NAME_LENGTH)); //clear channelname, it may be confidential in some circumstances
            channel_ctx_map.erase(it);
            free(name);
        }
    }

    crypto_ctx* get_crypto_ctx(const char* channelname) {
        auto it =  channel_ctx_map.find((char*) channelname);
        if(it==channel_ctx_map.end())
            return nullptr;
        return it->second.get();
    }
};

extern "C" lcm_security_ctx* lcm_create_security_ctx (lcm_security_parameters *params, size_t param_len){
    return new _lcm_security_ctx(params, param_len);
}

extern "C" void lcm_destroy_security_ctx (lcm_security_ctx* ctx){delete ctx;}

extern "C" int lcm_encrypt_message(lcm_security_ctx* ctx, const char* channelname, uint32_t seqno, char* ptext, size_t ptextsize, char* ctext, size_t ctextsize) {
    auto crypto_ctx = ctx->get_crypto_ctx(channelname);

    if(!crypto_ctx) {
        fprintf(stderr, "Cannot encrypt message: no security context registered for channel %s\n", channelname);
        return LCMCRYPTO_ENCRYPTION_ERROR;
    }


    auto enc = Botan::AEAD_Mode::create_or_throw("AES-128/GCM", Botan::ENCRYPTION);

    crypto_ctx->set_ciphermode_key(*enc);
    enc->set_associated_data((const uint8_t*) channelname, strlen(channelname));

    auto IV = crypto_ctx->get_encryption_IV(seqno);
    enc->start(IV);
    Botan::secure_vector<uint8_t> ct(ptext, ptext + ptextsize);
    enc->finish(ct);
    assert(enc->tag_size() == LCMCRYPTO_TAGSIZE);
    //FIXME: stupid implementation for now, take advantage of in-place encryption later

    if(ctextsize < ct.size()) {
        fprintf(stderr, "ctext buffer too small\n");
        return LCMCRYPTO_ENCRYPTION_ERROR;
    }

    memcpy(ctext, ct.data(), ct.size());

    CRYPTO_DBG("encrypted msg using %s with IV %s\n", enc->name().c_str(), Botan::hex_encode(IV).c_str());
    return 0;
}

extern "C" int lcm_decrypt_message(lcm_security_ctx* ctx, const char* channelname, uint16_t sender_id, uint32_t seqno, char* ctext, size_t ctextsize, char* ptext, size_t ptextsize){
    auto crypto_ctx = ctx->get_crypto_ctx(channelname);
    if(!crypto_ctx) {
        fprintf(stderr, "Cannot decrypt message: no security context registered for channel %s\n", channelname);
        return LCMCRYPTO_DECRYPTION_ERROR;
    }

    auto dec = Botan::AEAD_Mode::create_or_throw("AES-128/GCM", Botan::DECRYPTION);
    crypto_ctx->set_ciphermode_key(*dec);
    dec->set_associated_data((const uint8_t*) channelname, strlen(channelname));

    auto IV = crypto_ctx->get_decryption_IV(seqno, sender_id);
    try {
        dec->start(IV);
        Botan::secure_vector<uint8_t> pt(ctext, ctext + ctextsize);
        dec->finish(pt);
        //FIXME: stupid implementation for now, take advantage of in-place encryption later

        if(ptextsize < pt.size()) {
            fprintf(stderr, "ptext buffer too small\n");
            return LCMCRYPTO_DECRYPTION_ERROR;
        }

        memcpy(ptext, pt.data(), pt.size());

        CRYPTO_DBG("decrypted and authenticated msg using %s and IV = %s\n", dec->name().c_str(), Botan::hex_encode(IV).c_str());
    }
    catch(const Botan::Invalid_Authentication_Tag& err) {
        CRYPTO_DBG("%s, IV was %s\n", "got msg with invalid auth tag", Botan::hex_encode(IV).c_str());
        return LCMCRYPTO_INVALID_AUTH_TAG;
    }
    return 0;
}

extern "C" int lcm_encrypt_channelname(lcm_security_ctx* ctx, uint32_t seqno, char* ptext, size_t ptextsize, char* ctext, size_t ctextsize) {
    auto crypto_ctx = ctx->group_ctx.get();

    auto enc = Botan::Cipher_Mode::create("AES-128/GCM", Botan::ENCRYPTION);

    crypto_ctx->set_ciphermode_key(*enc);

    auto IV = crypto_ctx->get_encryption_IV(seqno);
    enc->start(IV);
    Botan::secure_vector<uint8_t> ct(ptext, ptext + ptextsize);
    enc->finish(ct);
    assert(enc->tag_size() == LCMCRYPTO_TAGSIZE);
    //FIXME: stupid implementation for now, take advantage of in-place encryption later

    if(ctextsize < ct.size()) {
        fprintf(stderr, "ctext buffer too small\n");
        return LCMCRYPTO_ENCRYPTION_ERROR;
    }

    memcpy(ctext, ct.data(), ct.size());

    CRYPTO_DBG("encrypted channelname using %s with IV %s\n", enc->name().c_str(), Botan::hex_encode(IV).c_str());
    return 0;
}

extern "C" int lcm_decrypt_channelname(lcm_security_ctx* ctx, uint16_t sender_id, uint32_t seqno, char* ctext, size_t ctextsize, char* ptext, size_t ptextsize) {
    auto crypto_ctx = ctx->group_ctx.get();

    auto dec = Botan::Cipher_Mode::create_or_throw("AES-128/GCM", Botan::DECRYPTION);

    crypto_ctx->set_ciphermode_key(*dec);

    auto IV = crypto_ctx->get_decryption_IV(seqno, sender_id);
    try {
        dec->start(IV);
        Botan::secure_vector<uint8_t> pt(ctext, ctext + ctextsize);
        dec->finish(pt);
        //FIXME: stupid implementation for now, take advantage of in-place encryption later
        //FIXME: use AEAD in some cases

        if(ptextsize < pt.size()) {
            fprintf(stderr, "ptext buffer too small\n");
            return LCMCRYPTO_DECRYPTION_ERROR;
        }

        memcpy(ptext, pt.data(), pt.size());

        CRYPTO_DBG("decrypted and authenticated msg using %s and IV = %s\n", dec->name().c_str(), Botan::hex_encode(IV).c_str());
    }
    catch(const Botan::Invalid_Authentication_Tag& err) {
        CRYPTO_DBG("%s, IV was %s\n", "got msg with invalid auth tag", Botan::hex_encode(IV).c_str());
        return LCMCRYPTO_INVALID_AUTH_TAG;
    }
    return 0;
}

extern "C" uint16_t get_sender_id_from_cryptoctx(lcm_security_ctx* ctx, const char* channelname) {
    assert(ctx->get_crypto_ctx(channelname));
    return ctx->get_crypto_ctx(channelname)->sender_id;
}
