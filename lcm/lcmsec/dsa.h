
#ifndef DSA_H

#define DSA_H

#include <botan/auto_rng.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>
#include <botan/x509_ca.h>
#include <botan/x509cert.h>
#include <botan/asn1_alt_name.h>

#include <iostream>
#include <ostream>
#include <string>

#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

const static std::string emca = "EMSA1(SHA-256)";
// sign using ESMSA1 with SHA-256 over secp521r1
class DSA_signer {
  private:
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::Private_Key> key;

    std::unique_ptr<Botan::PK_Signer> signer()
    {
        key->pkcs8_algorithm_identifier();

        return std::make_unique<Botan::PK_Signer>(*key, rng, emca);
    }

    explicit DSA_signer(std::string keyfile)
    {
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(keyfile, rng, "pwd"));

    }

  public:

    static DSA_signer& getInst(std::string keyfile)
    {
        static DSA_signer inst(keyfile);
        return inst;
    }

    std::vector<uint8_t> db_sign(const Dutta_Barua_message &msg)
    {
        Botan::AutoSeeded_RNG rng;
        auto signer = this->signer();

        signer->update((const uint8_t *) &msg.u, 4);
        signer->update(msg.round);
        signer->update((const uint8_t *) msg.public_value.data(), msg.public_value.size());
        signer->update((const uint8_t *) &msg.d, 4);

        return signer->signature(rng);
    }
};

// verify using ESMSA1 with SHA-256 over secp521r1
class DSA_verifier {
  private:
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::Public_Key> key;

    std::unique_ptr<Botan::PK_Verifier> verifier()
    {
        return std::make_unique<Botan::PK_Verifier>(*key, emca);
    }

  public:
    DSA_verifier(int uid)
    {
        if (uid > 4 || uid <= 0)
            throw std::out_of_range("uid out of range [1,4], was " + std::to_string(uid));

        std::string filename = "testkeys/user" + std::to_string(uid) + ".pub";
        key = std::unique_ptr<Botan::Public_Key>(Botan::X509::load_key(filename));
    }

    bool db_verify(const Dutta_Barua_message *msg)
    {
        auto verifier = this->verifier();
        verifier->update((const uint8_t *) &msg->u, 4);
        verifier->update(msg->round);
        verifier->update((const uint8_t *) msg->public_value.data(), msg->public_value.size());
        verifier->update((const uint8_t *) &msg->d, 4);

        return verifier->check_signature((const uint8_t *) msg->sig.data(), msg->sig_size);
    }
};

#endif /* end of include guard: DSA_H */
