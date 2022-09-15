#include "crypto_wrapper.h"

#include <assert.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/stream_cipher.h>
#include <udpm_util.h>

#include <functional>
#include <iostream>
#include <map>
#include <stack>
#include <string>

#include "gkexchg.h"
#include "lcmsec/eventloop.hpp"

namespace lcmsec_impl {

// Crypotgraphy for a specific channel or group
class crypto_ctx {
    // Buffers to avoid allocations during runtime
    Botan::secure_vector<uint8_t> IV;  // buffer for IV to avoid allocation during execution
  public:
    const std::string algorithm;

    const Botan::secure_vector<uint8_t> salt;
    const uint16_t sender_id;
    const Botan::secure_vector<uint8_t> key;
    const int TAG_SIZE = LCMCRYPTO_TAGSIZE;

    Key_Exchange_Manager keyExchangeManager;

    explicit crypto_ctx(Key_Exchange_Manager mgr, lcm_security_parameters *params)
        : algorithm(params->algorithm),
          sender_id(params->sender_id),
          salt(Botan::hex_decode_locked(params->nonce)),
          key(Botan::hex_decode_locked(params->key)),
          keyExchangeManager(mgr)
    {
        IV.resize(LCMCRYPTO_IVSIZE);
    }

    Botan::secure_vector<uint8_t> &get_decryption_IV(const uint32_t seqno, uint16_t sender_id)
    {
        assert(LCMCRYPTO_IVSIZE == 12);  // necessary for hardcoded values in this function here
        IV.resize(LCMCRYPTO_IVSIZE);
        assert(salt.size() == LCMCRYPTO_SESSION_NONCE_SIZE);

        auto data = &IV[0];
        memcpy(data, &seqno, 4);
        memcpy(data + 4, &sender_id, 2);
        memcpy(data + 6, &salt[0], 6);

        return IV;
    }
    Botan::secure_vector<uint8_t> &get_encryption_IV(const uint32_t seqno)
    {
        return get_decryption_IV(seqno, this->sender_id);
    }

    template <typename Cipher>
    void set_cipher_key(Cipher &cipher)
    {
        cipher.set_key(&key[0], key.size());
    }

    Botan::secure_vector<uint8_t>
        crypto_buf;  // reduce number of allocations during encryption and decryption
};

}  // namespace lcmsec_impl

// Collection ctx for the group + collection of crypto_ctx for each configured channel
// entrypoint for the cpp implementation of the crypto
class _lcm_security_ctx {
  public:
    std::unique_ptr<lcmsec_impl::crypto_ctx> group_ctx;

  private:
    // Use map with std::string as keys for storage; but compare with char* so we avoid additional
    // allocation (cpy construction) during lookup
    struct str_cmp {
        bool operator()(const char *a, const char *b) const
        {
            return std::strncmp(a, b, LCM_MAX_CHANNEL_NAME_LENGTH) < 0;
        }
    };

    std::map<char *, std::unique_ptr<lcmsec_impl::crypto_ctx>, str_cmp> channel_ctx_map;

  public:
    _lcm_security_ctx(lcm_security_parameters *params, size_t param_len)
    {
        lcmsec_impl::eventloop ev_loop;

        for (int i = 0; i < param_len; i++) {
            if (params[i].channelname == nullptr) {
                // FIXME: Group context does not perform group key exchange for now - is static
                // Probably there should be a specialized subclass for the group_ctx too
                lcmsec_impl::Key_Exchange_Manager keyExchangeManager(std::string("keyxchg_channel_group"), ev_loop);
                group_ctx = std::make_unique<lcmsec_impl::crypto_ctx>(std::move(keyExchangeManager), params + i);
            } else {
                lcmsec_impl::Key_Exchange_Manager keyExchangeManager(params[i].channelname, ev_loop);
                channel_ctx_map[strndup(params[i].channelname, LCM_MAX_CHANNEL_NAME_LENGTH)] =
                    std::make_unique<lcmsec_impl::crypto_ctx>(keyExchangeManager, params + i);
            }
        }

        ev_loop.run();
    }

    ~_lcm_security_ctx()
    {
        for (auto it = channel_ctx_map.begin(); it != channel_ctx_map.end();) {
            char *name = it->first;
            std::memset(
                name, 0,
                strnlen(name, LCM_MAX_CHANNEL_NAME_LENGTH));  // clear channelname, it may be
                                                              // confidential in some circumstances
            it = channel_ctx_map.erase(it);
            free(name);
        }
    }

    lcmsec_impl::crypto_ctx *get_crypto_ctx(const char *channelname)
    {
        // cppcheck-suppress cstyleCast
        auto it = channel_ctx_map.find((char *) channelname);
        if (it == channel_ctx_map.end())
            return nullptr;
        return it->second.get();
    }
};

extern "C" lcm_security_ctx *lcm_create_security_ctx(lcm_security_parameters *params,
                                                     size_t param_len)
{
    return new _lcm_security_ctx(params, param_len);
}

extern "C" void lcm_destroy_security_ctx(lcm_security_ctx *ctx)
{
    delete ctx;
}

extern "C" int lcm_encrypt_message(lcm_security_ctx *ctx, const char *channelname, uint32_t seqno,
                                   const uint8_t *ptext, size_t ptextsize, uint8_t **ctext)
{
    auto crypto_ctx = ctx->get_crypto_ctx(channelname);

    if (!crypto_ctx) {
        fprintf(stderr, "Cannot encrypt message: no security context registered for channel %s\n",
                channelname);
        return LCMCRYPTO_ENCRYPTION_ERROR;
    }

    auto enc = Botan::AEAD_Mode::create_or_throw("AES-128/GCM", Botan::ENCRYPTION);

    crypto_ctx->set_cipher_key(*enc);
    enc->set_associated_data((const uint8_t *) channelname, strlen(channelname));

    auto IV = crypto_ctx->get_encryption_IV(seqno);
    enc->start(IV);

    auto &buf = crypto_ctx->crypto_buf;
    buf.resize(ptextsize);
    memcpy(buf.data(), ptext, ptextsize);
    enc->finish(buf);
    assert(enc->tag_size() == LCMCRYPTO_TAGSIZE);

    CRYPTO_DBG("encrypted msg using %s with IV %s\n", enc->name().c_str(),
               Botan::hex_encode(IV).c_str());
    *ctext = buf.data();
    return buf.size();
}

extern "C" int lcm_decrypt_message(lcm_security_ctx *ctx, const char *channelname,
                                   uint16_t sender_id, uint32_t seqno, uint8_t *ctext,
                                   size_t ctextsize, uint8_t **rptext)
{
    auto crypto_ctx = ctx->get_crypto_ctx(channelname);
    if (!crypto_ctx) {
        fprintf(stderr, "Cannot decrypt message: no security context registered for channel %s\n",
                channelname);
        return LCMCRYPTO_DECRYPTION_ERROR;
    }

    auto dec = Botan::AEAD_Mode::create_or_throw("AES-128/GCM", Botan::DECRYPTION);

    crypto_ctx->set_cipher_key(*dec);
    dec->set_associated_data((const uint8_t *) channelname,
                             strnlen(channelname, LCM_MAX_CHANNEL_NAME_LENGTH));

    auto IV = crypto_ctx->get_decryption_IV(seqno, sender_id);
    try {
        dec->start(IV);
        auto &buf = crypto_ctx->crypto_buf;
        buf.assign(ctext, ctext + ctextsize);
        dec->finish(buf);

        CRYPTO_DBG("decrypted and authenticated msg using %s and IV = %s\n", dec->name().c_str(),
                   Botan::hex_encode(IV).c_str());

        *rptext = buf.data();
        return buf.size();
    } catch (const Botan::Invalid_Authentication_Tag &err) {
        CRYPTO_DBG("%s, IV was %s\n", "got msg with invalid auth tag",
                   Botan::hex_encode(IV).c_str());
        return LCMCRYPTO_INVALID_AUTH_TAG;
    }
}

extern "C" int lcm_encrypt_channelname(lcm_security_ctx *ctx, uint32_t seqno, const char *ptext,
                                       size_t ptextsize, char *ctext, size_t ctextsize)
{
    assert(ptextsize == ctextsize);
    auto crypto_ctx = ctx->group_ctx.get();

    auto cipher = Botan::StreamCipher::create_or_throw("CTR(AES-128)");

    crypto_ctx->set_cipher_key(*cipher);

    auto IV = crypto_ctx->get_encryption_IV(seqno);
    cipher->set_iv(&IV[0], IV.size());
    Botan::secure_vector<uint8_t> ct(ptext, ptext + ptextsize);
    cipher->encipher(ct);
    // FIXME: stupid implementation for now, take advantage of in-place encryption later
    // note: probably return an opaque ctext_buffer, that will be used later..

    if (ctextsize < ct.size()) {
        fprintf(stderr, "ctext buffer too small\n");
        return LCMCRYPTO_ENCRYPTION_ERROR;
    }
    memcpy(ctext, ct.data(), ct.size());

    CRYPTO_DBG("encrypted channelname using %s with IV %s\n", cipher->name().c_str(),
               Botan::hex_encode(IV).c_str());
    return 0;
}

extern "C" int lcm_decrypt_channelname(lcm_security_ctx *ctx, uint16_t sender_id, uint32_t seqno,
                                       const char *ctext, size_t ctextsize, char *ptext,
                                       size_t ptextsize)
{
    auto crypto_ctx = ctx->group_ctx.get();

    auto cipher = Botan::StreamCipher::create_or_throw("CTR(AES-128)");

    crypto_ctx->set_cipher_key(*cipher);

    auto IV = crypto_ctx->get_decryption_IV(seqno, sender_id);
    cipher->set_iv(&IV[0], IV.size());
    Botan::secure_vector<uint8_t> pt(ctext, ctext + ctextsize);
    cipher->encipher(pt);
    // FIXME: stupid implementation for now, take advantage of in-place encryption later

    if (ptextsize < pt.size()) {
        fprintf(stderr, "ptext buffer too small\n");
        return LCMCRYPTO_DECRYPTION_ERROR;
    }

    memcpy(ptext, pt.data(), pt.size());

    CRYPTO_DBG("decrypted channelname %s using %s and IV = %s\n", ptext, cipher->name().c_str(),
               Botan::hex_encode(IV).c_str());
    return 0;
}

extern "C" uint16_t get_sender_id_from_cryptoctx(lcm_security_ctx *ctx, const char *channelname)
{
    assert(ctx->get_crypto_ctx(channelname));
    return ctx->get_crypto_ctx(channelname)->sender_id;
}
