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
#include <stack>
#include <vector>

#include "crypto_wrapper.h"
#include "lcm-cpp.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

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
            throw std::out_of_range("uid out of range [1,4], was " + std::to_string(uid));
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
            throw std::out_of_range("uid out of range [1,4], was " + std::to_string(uid));
        std::string filename = "testkeys/user" + std::to_string(uid) + ".pub";
        key = std::unique_ptr<Botan::Public_Key>(Botan::X509::load_key(filename));
    }

    std::unique_ptr<Botan::PK_Verifier> verifier()
    {
        return std::make_unique<Botan::PK_Verifier>(*key, emca);
    }
};

// static void generate_testing_keypairs()
// {
//     for (int i = 1; i < 5; i++) {
//         Botan::AutoSeeded_RNG rng;
//         Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp521r1"));
//         std::ofstream o;
//         std::string filename = "testkeys/user" + std::to_string(i);
//         o.open(filename + ".priv");
//         o << Botan::PKCS8::PEM_encode(key);
//         o.close();
//         o.open(filename + ".pub");
//         o << Botan::X509::PEM_encode(key);
//         o.close();
//     }
// }

void Dutta_Barua_GKE::round1()
{
    debug("Dutta_Barua_GKE::Dutta_Barua_GKE()\n");
    debug("----round 1-----");

    partial_session_id.push_back(uid);  // initialize the partial session id with

    constexpr int group_bitsize = 4096;
    Botan::DL_Group group("modp/ietf/" + std::to_string(group_bitsize));

    Botan::AutoSeeded_RNG rng;

    Botan::DH_PrivateKey privKey(rng, group);

    // public value; i.e. g^x mod q; where x is private key. This public value is called capital X
    // in Dutta Barua paper
    Botan::BigInt X = privKey.get_y();

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
    lcm.publish(channelname, &r1_message);
}

Dutta_Barua_GKE::Dutta_Barua_GKE(std::string channelname, eventloop &ev_loop, lcm::LCM &lcm, int uid)
    : channelname(std::move(channelname)), evloop(ev_loop), lcm(lcm), uid{uid+1, 1}
{
}

bool verify_db_message(const Dutta_Barua_message *msg, ecdsa_public &dsa_instance)
{
    auto verifier = dsa_instance.verifier();
    verifier->update((const uint8_t *) &msg->u, 4);
    verifier->update(msg->round);
    verifier->update((const uint8_t *) msg->public_value.data(), msg->public_value_size);
    verifier->update((const uint8_t *) &msg->d, 4);

    return verifier->check_signature((const uint8_t *) msg->sig.data(), msg->sig_size);
}

void Dutta_Barua_GKE::on_msg(const Dutta_Barua_message *msg)
{
    // Check first whether or not the message is meant for us
    if (msg->round == 1 && !is_neighbour(msg))
        return;

    ecdsa_public dsa_public(msg->u);
    if (!verify_db_message(msg, dsa_public))
        return;
    debug("verified signature successfully");

    if (msg->round == 1) {
        if (is_left_neighbour(msg))
            r1_messages.left = *msg;
        if(is_right_neighbour(msg))
            r1_messages.right = *msg;
    } else {
        if (msg->round != 2) {
            auto error = "keyexchange on channel " + channelname +
                         " failed: faulty message (msg->round) but valid signature";
            throw std::runtime_error(error);
        }
        r2_messages.push_back(*msg);
    }

    // Check prerequisites for next round
    if (!r2_finished && r1_messages.left && r1_messages.right) {
        evloop.push_task([this] { round2(); });
    }
    if (r2_finished && r2_messages.size() == participants) {
        evloop.push_task([this] { computeKey(); });
    }
}

void Dutta_Barua_GKE::round2()
{
    debug(("Channel" + channelname + " : round2()").c_str());
}
void Dutta_Barua_GKE::computeKey()
{
    debug(("Channel "+channelname+" : computeKey()").c_str());
}

Key_Exchange_Manager::Key_Exchange_Manager(std::string channelname, eventloop &ev_loop,
                                           lcm::LCM &lcm, int uid)
    : impl(channelname, ev_loop, lcm, uid)
{
    auto r1 = [=] { this->impl.round1(); };
    ev_loop.push_task(r1);
};

void Key_Exchange_Manager::handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                         const Dutta_Barua_message *msg)
{
    impl.on_msg(msg);
}

}  // namespace lcmsec_impl
