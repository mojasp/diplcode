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

#include <cstdio>
#include <string>

#include "gkexchg.h"
#include "lcmsec/dsa.h"
#include "lcmsec/eventloop.hpp"

namespace lcmsec_impl {

// Crypotgraphy for a specific channel or group
class channel_crypto_ctx {
    // Buffers to avoid allocations during runtime
    Botan::secure_vector<uint8_t> IV;  // buffer for IV to avoid allocation during execution

    std::string algorithm_aead;
    std::string algorithm_stream;
    int key_size;

    // maybe use subclass instead
    bool is_group;
    std::optional<std::unique_ptr<Botan::AEAD_Mode>> cipher_aead_enc;
    std::optional<std::unique_ptr<Botan::AEAD_Mode>> cipher_aead_dec;
    std::optional<std::unique_ptr<Botan::StreamCipher>> cipher_stream;

    std::unique_ptr<KeyExchangeLCMHandler> keyExchangeManager;

    uint16_t sender_id;
    std::optional<Botan::secure_vector<uint8_t>>
        keymat;  // caching the key derivation to improve performance. This needs to be done in the
                 // manager class when/if we want rekeying

    static constexpr int TAG_SIZE = LCMCRYPTO_TAGSIZE;
    static constexpr int KEY_SIZE_CHACHA = 32;  // ChaCha20Poly1305 key size.
    static constexpr int KEY_SIZE_AESGCM = 16;  // AES-128 key size.

  public:
    int getSenderID() { return sender_id; }

    const std::string &get_algorithm_aead() { return algorithm_aead; }
    const std::string &get_algorithm_stream() { return algorithm_stream; }

    explicit channel_crypto_ctx(std::unique_ptr<KeyExchangeLCMHandler> mgr, uint16_t sender_id,
                                std::string _algorithm, bool is_group = false)
        : keyExchangeManager(MOV(mgr)),
          algorithm_aead(MOV(_algorithm)),
          sender_id(sender_id),
          is_group(is_group)
    {
        if (algorithm_aead == "AES-128/GCM") {
            key_size = KEY_SIZE_AESGCM;
            algorithm_stream = "CTR(AES-128)";
        } else if (algorithm_aead == "ChaCha20Poly1305") {
            key_size = KEY_SIZE_CHACHA;
            algorithm_stream = "ChaCha20";
        } else
            throw lcmsec_exception("internal error: invalid algorithm '" + algorithm_aead +
                                   "' string in channel_crypto_ctx. Was: '");

        if (is_group) {
            cipher_stream = Botan::StreamCipher::create_or_throw(algorithm_stream);
        } else {
            cipher_aead_enc = Botan::AEAD_Mode::create_or_throw(algorithm_aead, Botan::ENCRYPTION);
            cipher_aead_dec = Botan::AEAD_Mode::create_or_throw(algorithm_aead, Botan::DECRYPTION);
        }

        IV.resize(LCMCRYPTO_IVSIZE);
    }

    Botan::secure_vector<uint8_t> &get_decryption_IV(const uint32_t seqno, uint16_t sender_id)
    {
        IV.resize(LCMCRYPTO_IVSIZE);

        auto data = &IV[0];
        memcpy(data, &(*keymat)[0] + key_size,
               LCMCRYPTO_SALTSIZE);  // salt is in the end of the keying material
        memcpy(data + LCMCRYPTO_SALTSIZE, &sender_id, sizeof(sender_id));
        memcpy(data + LCMCRYPTO_SALTSIZE + sizeof(sender_id), &seqno, sizeof(seqno));
        memset(data + LCMCRYPTO_SALTSIZE + sizeof(sender_id) + sizeof(seqno), 0,
               4);  // zero last 4 bytes
        return IV;
    }
    Botan::secure_vector<uint8_t> &get_encryption_IV(const uint32_t seqno)
    {
        return get_decryption_IV(seqno, this->sender_id);
    }

    void update_keymat()
    {
        // Multiple threads play a role here: for instance:
        //  * hasNewKey flag is indicated by keyexchangemgr, which is exectued by the tasks in the
        //  eventloop
        //  * a recvthread may call it on incoming message to decrypt - this is always a thread
        //  controlled by lcm, (*not* called by lcm.handle())
        //  * a publish thread - controlled by the user
        // as such, we need to avoid the race condition. However, this is acomplished by using
        // compareexchange within the hasNewKey() function.
        //
        //  Note also that when this function is first called, there should always be an available
        //  secret
        //  - since a keyagreement is performed at startup (instance creation blocks until it is
        //  done)
        if (keyExchangeManager->hasNewKey()) {
            keymat = keyExchangeManager->get_session_key(key_size + LCMCRYPTO_SALTSIZE);

            if (is_group) {
                cipher_stream.value()->set_key(&(keymat->operator[](0)), key_size);
            } else {
                cipher_aead_dec.value()->set_key(&(keymat->operator[](0)), key_size);
                cipher_aead_enc.value()->set_key(&(keymat->operator[](0)), key_size);
            }
        }
    }

    Botan::AEAD_Mode *get_dec() { return cipher_aead_dec.value().get(); }

    Botan::AEAD_Mode *get_enc() { return cipher_aead_enc.value().get(); }

    Botan::StreamCipher *get_stream() { return cipher_stream.value().get(); }

    // reduce number of allocations during encryption and decryption
    Botan::secure_vector<uint8_t> message_crypto_buf;
    Botan::secure_vector<uint8_t> channel_crypto_buf;
};

}  // namespace lcmsec_impl

// Collection ctx for the group + collection of crypto_ctx for each configured channel
// entrypoint for the cpp implementation of the crypto
class _lcm_security_ctx {
  public:
    std::unique_ptr<lcmsec_impl::channel_crypto_ctx> group_ctx;

  private:
    // Use map with std::string as keys for storage; but compare with char* so we avoid additional
    // allocation (cpy construction) during lookup
    struct str_cmp {
        bool operator()(const char *a, const char *b) const
        {
            return std::strncmp(a, b, LCM_MAX_CHANNEL_NAME_LENGTH) < 0;
        }
    };

    std::map<char *, std::unique_ptr<lcmsec_impl::channel_crypto_ctx>, str_cmp> channel_ctx_map;

    // separate lcm instance used to perform the key exchange
    std::unique_ptr<lcm::LCM> lcm;

    std::unique_ptr<lcmsec_impl::eventloop> ev_loop;

    std::atomic_bool signal_shutdown = false;
    std::vector<std::thread> keyagree_threads;

  public:
    _lcm_security_ctx(lcm_security_parameters *params)
    {
        std::string algorithm;
        if(params->algorithm==NULL)
            algorithm = std::string("AES-128/GCM");
        else
            algorithm = params->algorithm;
        if (algorithm == "")
            algorithm = std::string("AES-128/GCM");
        else if (!(algorithm == "AES-128/GCM" || algorithm == "ChaCha20Poly1305")) {
            throw lcmsec_impl::lcmsec_exception("invalid algorithm string ('" + algorithm +
                                                "') in lcm_security_parameters");
        }

        lcm = std::make_unique<lcm::LCM>(params->keyexchange_url);
        if (!lcm->good()) {
            throw std::runtime_error("lcm instance for keyagreemend: creation failed");
        }

        ev_loop = std::make_unique<lcmsec_impl::eventloop>(*lcm);

        // Usage of constant singleton classes to get global access to the private key and
        // certificates in the future - this should probably be changed to something more robust
        lcmsec_impl::DSA_signer::getInst(params->keyfile);
        lcmsec_impl::DSA_verifier::getInst(params->root_ca);
        lcmsec_impl::DSA_certificate_self::getInst(params->certificate);

        // Parse our own certificate file to register the proper channels
        //  NOTE: it is probably a good idea to eventually register the channels in a lazy way (upon
        //  subscribe or join()?) - or give the user a choice which channels shall be registered
        std::string cert_file = params->certificate;
        Botan::X509_Certificate cert(cert_file);

        // Setup group key exchange for the channels for which we have capabilities
        auto capabilities = lcmsec_impl::capability::from_certificate(cert);
        // Counting by the number of channels is a bit of a hack but i don't see any way it breaks.
        int channels = capabilities.size();
        for (auto &cap : MOV(capabilities)) {
            std::string keyxchg_channel;
            if (cap.channelname == std::nullopt) {
                // the channel for the group config
                keyxchg_channel = cap.mcasturl;
            } else {
                keyxchg_channel = *cap.channelname;
            }
            auto keyExchangeManager =
                std::make_unique<lcmsec_impl::KeyExchangeLCMHandler>(cap, *ev_loop, *lcm);
            // FIXME: this should be handled in a different way
            lcm->subscribe("lcm://" + keyxchg_channel,
                           &lcmsec_impl::KeyExchangeLCMHandler::handleMessage,
                           keyExchangeManager.get());
            lcm->subscribe("joinlcm://" + keyxchg_channel,
                           &lcmsec_impl::KeyExchangeLCMHandler::handle_JOIN,
                           keyExchangeManager.get());
            lcm->subscribe("join_resplcm://" + keyxchg_channel,
                           &lcmsec_impl::KeyExchangeLCMHandler::handle_JOIN_response,
                           keyExchangeManager.get());
            lcm->subscribe("attestlcm://" + keyxchg_channel,
                           &lcmsec_impl::KeyExchangeLCMHandler::handle_Attestation_Evidence,
                           keyExchangeManager.get());
            if (cap.channelname) {
                char *copy = (char *) malloc(LCM_MAX_CHANNEL_NAME_LENGTH + 1);
                strncpy(copy, cap.channelname->c_str(), LCM_MAX_CHANNEL_NAME_LENGTH);
                copy[LCM_MAX_CHANNEL_NAME_LENGTH] = 0;
                channel_ctx_map[copy] = std::make_unique<lcmsec_impl::channel_crypto_ctx>(
                    MOV(keyExchangeManager), cap.uid, algorithm);
            } else {
                group_ctx = std::make_unique<lcmsec_impl::channel_crypto_ctx>(
                    MOV(keyExchangeManager), cap.uid, algorithm, true);
            }
        }
        ev_loop->run(1 + channel_ctx_map.size());

        std::thread t([this] { perform_keyexchange(); });
        keyagree_threads.push_back(MOV(t));
    }

    void perform_keyexchange()
    {
        // continuously run keyexchange
        // Note that the listeners are already set up
        ev_loop->run(&signal_shutdown);
    }

    ~_lcm_security_ctx()
    {
        // end keyagree threads FIRST in case they access the memory we clear and free later
        signal_shutdown = true;
        for (std::thread &t : keyagree_threads) {
            t.join();
        }
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

    lcmsec_impl::channel_crypto_ctx *get_crypto_ctx(const char *channelname)
    {
        // cppcheck-suppress cstyleCast
        auto it = channel_ctx_map.find((char *) channelname);
        if (it == channel_ctx_map.end())
            return nullptr;
        return it->second.get();
    }
};

extern "C" lcm_security_ctx *lcm_create_security_ctx(lcm_security_parameters *params)
{
    return new _lcm_security_ctx(params);
}

extern "C" int lcm_crypto_perform_keyexchange(lcm_security_ctx *ctx)
{
    ctx->perform_keyexchange();
    return 0;
}

#include <vector>
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

    crypto_ctx->update_keymat();

    auto enc = crypto_ctx->get_enc();

    enc->set_associated_data((const uint8_t *) channelname, strlen(channelname));

    auto IV = crypto_ctx->get_encryption_IV(seqno);
    enc->start(IV);

    auto &buf = crypto_ctx->message_crypto_buf;
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

    crypto_ctx->update_keymat();

    auto dec = crypto_ctx->get_dec();

    dec->set_associated_data((const uint8_t *) channelname,
                             strnlen(channelname, LCM_MAX_CHANNEL_NAME_LENGTH));

    auto IV = crypto_ctx->get_decryption_IV(seqno, sender_id);
    try {
        dec->start(IV);
        auto &buf = crypto_ctx->message_crypto_buf;
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
                                       size_t ptextsize, uint8_t **ctext)
{
    assert(ptextsize <= LCM_MAX_CHANNEL_NAME_LENGTH + 1);

    auto crypto_ctx = ctx->group_ctx.get();
    crypto_ctx->update_keymat();

    auto cipher = crypto_ctx->get_stream();

    auto IV = crypto_ctx->get_encryption_IV(seqno);
    cipher->set_iv(&IV[0], IV.size());

    crypto_ctx->channel_crypto_buf.resize(ptextsize);
    std::memcpy(crypto_ctx->channel_crypto_buf.data(), ptext, ptextsize);
    cipher->encipher(crypto_ctx->channel_crypto_buf);

    *ctext = crypto_ctx->channel_crypto_buf.data();
    CRYPTO_DBG("encrypted channelname using %s with IV %s\n", cipher->name().c_str(),
               Botan::hex_encode(IV).c_str());
    return 0;
}

// decrypts channelname bytewise until finding null_terminater.
extern "C" int lcm_decrypt_channelname(lcm_security_ctx *ctx, uint16_t sender_id, uint32_t seqno,
                                       const char *ctext, size_t ctext_max_size, uint8_t **ptext)
{
    auto crypto_ctx = ctx->group_ctx.get();
    crypto_ctx->update_keymat();
    auto cipher = crypto_ctx->get_stream();
    auto IV = crypto_ctx->get_decryption_IV(seqno, sender_id);
    cipher->set_iv(&IV[0], IV.size());

    // take an extra byte into account (LCM_MAX_CHANNEL_NAME_LENGTH is strlen, we need the amount of
    // bytes that will hold it)
    int max_sz = std::min<int>(ctext_max_size, LCM_MAX_CHANNEL_NAME_LENGTH + 1);
    crypto_ctx->channel_crypto_buf.resize(max_sz);

    int bytes_enciphered{0};
    bool success{false};
    do {
        cipher->cipher(reinterpret_cast<const uint8_t *>(ctext + bytes_enciphered),
                       crypto_ctx->channel_crypto_buf.data() + bytes_enciphered, 1);
        if (crypto_ctx->channel_crypto_buf.data()[bytes_enciphered] == '\0') {
            success = true;
            break;
        }
        bytes_enciphered++;
    } while (bytes_enciphered < max_sz);
    if (!success) {
        CRYPTO_DBG("%s", "Error decrypting channelname: no null terminator\n");
        return LCM_MAX_CHANNEL_NAME_LENGTH + 1;
    }

    *ptext = crypto_ctx->channel_crypto_buf.data();
    CRYPTO_DBG("decrypted channelname %s using %s and IV = %s\n",
               std::string(*(char **) ptext, bytes_enciphered).c_str(), cipher->name().c_str(),
               Botan::hex_encode(IV).c_str());
    return bytes_enciphered;
}

extern "C" uint16_t get_sender_id_from_cryptoctx(lcm_security_ctx *ctx, const char *channelname)
{
    assert(ctx->get_crypto_ctx(channelname));
    return ctx->get_crypto_ctx(channelname)->getSenderID();
}
