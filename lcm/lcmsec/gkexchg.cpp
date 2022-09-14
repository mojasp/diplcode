#include "gkexchg.h"

#include <assert.h>
#include <botan/auto_rng.h>
#include <botan/dh.h>
#include <botan/dl_group.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/numthry.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "lcm-cpp.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

const static std::string emca = "EMSA1(SHA-256)";
// sign using ESMSA1 with SHA-256 over secp521r1
class ecdsa_private {
  private:
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::Private_Key> key;

  public:
    ecdsa_private(int uid)
    {
        if (uid > 4 || uid <= 0)
            throw std::out_of_range("uid out of range [1,4]");
        std::string filename = "testkeys/user" + std::to_string(uid) + ".priv";
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(filename, rng));
    }
    std::unique_ptr<Botan::PK_Signer> signer()
    {
        return std::make_unique<Botan::PK_Signer>(*key, rng, emca);
    }
};

// verify using ESMSA1 with SHA-256 over secp521r1
class ecdsa_public {
  private:
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::Public_Key> key;

  public:
    ecdsa_public(int uid)
    {
        if (uid > 4 || uid <= 0)
            throw std::out_of_range("uid out of range [1,4]");
        std::string filename = "testkeys/user" + std::to_string(uid) + ".pub";
        key = std::unique_ptr<Botan::Public_Key>(Botan::X509::load_key(filename));
    }

    std::unique_ptr<Botan::PK_Verifier> verifier()
    {
        return std::make_unique<Botan::PK_Verifier>(*key, emca);
    }
};

static void generate_testing_keypairs()
{
    for (int i = 1; i < 5; i++) {
        Botan::AutoSeeded_RNG rng;
        Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp521r1"));

        std::ofstream o;  // ofstream is the class for fstream package
        std::string filename = "testkeys/user" + std::to_string(i);
        o.open(filename + ".priv");  // open is the method of ofstream
        o << Botan::PKCS8::PEM_encode(key);
        o.close();
        o.open(filename + ".pub");  // open is the method of ofstream
        o << Botan::X509::PEM_encode(key);
        o.close();
    }
}

Dutta_Barua_GKE::Dutta_Barua_GKE()
{
    generate_testing_keypairs();
    printf("Dutta_Barua_GKE::Dutta_Barua_GKE()\n");
    printf("----round 1-----\n");

    partial_session_id.push_back(uid);  // initialize the partial session id with

    constexpr int group_bitsize = 4096;
    Botan::DL_Group group("modp/ietf/" + std::to_string(group_bitsize));

    Botan::AutoSeeded_RNG rng;

    Botan::DH_PrivateKey privKey(rng, group);

    // public value; i.e. g^x mod q; where x is private key. This public value is called capital X
    // in Dutta Barua paper
    Botan::BigInt X = privKey.get_y();

    printf("X (bigint) needs %lu bytes for storage\n", X.bits());

    
    ecdsa_private dsa_private(uid.u);
    auto signer = dsa_private.signer();
    Dutta_Barua_message r1_message;

    r1_message.u = this->uid.u;
    signer->update((const uint8_t *) &r1_message.u, 4);

    r1_message.round = 1;
    signer->update(r1_message.round);

    r1_message.public_value_size = X.bits();
    r1_message.public_value.resize(X.bits());
    signer->update((const uint8_t *) r1_message.public_value.data(),
                   r1_message.public_value.size());

    r1_message.d = this->uid.d;
    signer->update((const uint8_t *) &r1_message.d, 4);

    std::vector<uint8_t> signature = signer->signature(rng);

    r1_message.sig_size = signature.size();
    r1_message.sig = std::vector<int8_t>((int8_t *) signature.data(),
                                         (int8_t *) (signature.data() + r1_message.sig_size));

    //----- Send over the air - shim for now -------- ///
    const std::string channelname = "example";
    lcm::LCM lcm;

    Dutta_Barua_message received;
    lcm::LCM::HandlerFunction<Dutta_Barua_message> handler =
        [&](const lcm::ReceiveBuffer *rbuf, const std::string &channel,
            const Dutta_Barua_message *msg) { received = *msg; };
    lcm.subscribe(channelname, handler);

    lcm.publish("example", &r1_message);
    printf("waiting on key exchange messages\n");
    lcm.handleTimeout(500);

    //------- Decode and check signature --------//
    ecdsa_public dsa_public(received.u);
    auto verifier = dsa_public.verifier();
    verifier->update((const uint8_t *) &received.u, 4);
    verifier->update(received.round);
    verifier->update((const uint8_t *) received.public_value.data(), received.public_value_size);
    verifier->update((const uint8_t *) &received.d, 4);
    bool success =
        verifier->check_signature((const uint8_t *) received.sig.data(), received.sig_size);
    printf("verified signature successfully\n");
}

void Dutta_Barua_GKE::round1() {}
