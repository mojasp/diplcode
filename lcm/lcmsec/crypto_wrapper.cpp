#include "crypto_wrapper.h"

#include <assert.h>
#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/stream_cipher.h>
#include <botan/x509cert.h>
#include <udpm_util.h>

#include <functional>
#include <iostream>
#include <map>
#include <stack>
#include <string>

#include "gkexchg.h"
#include "lcmsec/dsa.h"
#include "lcmsec/eventloop.hpp"

namespace lcmsec_impl {

// Crypotgraphy for a specific channel or group
class crypto_ctx {
    // Buffers to avoid allocations during runtime
    Botan::secure_vector<uint8_t> IV;  // buffer for IV to avoid allocation during execution
  public:
    const std::string algorithm;

    std::unique_ptr<Key_Exchange_Manager> keyExchangeManager;

    Botan::secure_vector<uint8_t> salt{0};  // FIXME: think about the salt.
    const uint16_t sender_id;
    std::optional<const Botan::secure_vector<uint8_t>>
        key;  // caching the key derivation to improve performance. This needs to be done in the
              // manager class when/if we want rekeying

    static constexpr int TAG_SIZE = LCMCRYPTO_TAGSIZE;
    static constexpr int KEY_SIZE = 16;  // AES-128 key size.

    explicit crypto_ctx(std::unique_ptr<Key_Exchange_Manager> mgr, uint16_t sender_id,
                        std::string algorithm)
        : keyExchangeManager(std::move(mgr)), algorithm(std::move(algorithm)), sender_id(sender_id)
    // read sender_id from our own certificate FIXME -> urn parsing
    {
        IV.resize(LCMCRYPTO_IVSIZE);
        salt.resize(LCMCRYPTO_SESSION_NONCE_SIZE);
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
        if (!key)
            key.emplace(keyExchangeManager->get_session_key(KEY_SIZE));

        // std::cout << "ch: " << keyExchangeManager->channelname() << "key: " <<
        // Botan::hex_encode(*key) << std::endl;

        cipher.set_key(&(key->operator[](0)), key->size());
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
        // Parse our own certificate file to register the proper channel
        //  NOTE: it is probably a good idea to eventually register the channels in a lazy way (upon
        //  subscribe or join()?) - or give the user a choice which channels shall be registered

        auto &param = *params;
        std::string cert_file = param.certificate;
        Botan::X509_Certificate cert(cert_file);  // FIXME: params not as array
        auto capabilities = lcmsec_impl::parse_certificate_capabilities(cert);

        lcm::LCM lcm;  // FIXME use nondefault instance (respecting initialization parameters)

        lcmsec_impl::eventloop ev_loop(lcm);
        int channels{0};

        // Setup group key exchange and for the channels for which we have capabilities
        for (auto &[group, m] : capabilities) {
            for (auto &[channel, uid] : m) {
                channels++;
                if (channel == std::nullopt) {
                    // the channel for the group config
                    std::string group_keyxchg_channel =
                        group;  // FIXME - this should be handled differently and documented
                    auto keyExchangeManager = std::make_unique<lcmsec_impl::Key_Exchange_Manager>(
                        group, group_keyxchg_channel, ev_loop, lcm, uid);
                    lcm.subscribe("lcm://"+ group_keyxchg_channel,
                                  &lcmsec_impl::Key_Exchange_Manager::handleMessage,
                                  keyExchangeManager.get());
                    group_ctx = std::make_unique<lcmsec_impl::crypto_ctx>(
                        std::move(keyExchangeManager), uid, "AES-128/GCM");
                } else {
                    auto keyExchangeManager = std::make_unique<lcmsec_impl::Key_Exchange_Manager>(
                        group, channel.value(), ev_loop, lcm, uid);
                    lcm.subscribe("lcm://" + channel.value(),
                                  &lcmsec_impl::Key_Exchange_Manager::handleMessage,
                                  keyExchangeManager.get());
                    channel_ctx_map[strndup(channel.value().c_str(), LCM_MAX_CHANNEL_NAME_LENGTH)] =
                        std::make_unique<lcmsec_impl::crypto_ctx>(std::move(keyExchangeManager),
                                                                  uid, "AES_128/GCM");
                }
            }
        }

        //Initialize signer with our key; verifier with the root ca
        lcmsec_impl::DSA_signer::getInst(param.keyfile);
        lcmsec_impl::DSA_verifier::getInst(param.root_ca);

        ev_loop.run(channels);
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
