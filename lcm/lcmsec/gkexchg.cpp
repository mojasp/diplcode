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

    std::unique_ptr<Botan::PK_Signer> signer()
    {
        return std::make_unique<Botan::PK_Signer>(*key, rng, emca);
    }

  public:
    ecdsa_private(int uid)
    {
        if (uid > 4 || uid <= 0)
            throw std::out_of_range("uid out of range [1,4], was " + std::to_string(uid));
        std::string filename = "testkeys/user" + std::to_string(uid) + ".priv";
        key = std::unique_ptr<Botan::Private_Key>(Botan::PKCS8::load_key(filename, rng));
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
class ecdsa_public {
  private:
    Botan::AutoSeeded_RNG rng;
    std::unique_ptr<Botan::Public_Key> key;

    std::unique_ptr<Botan::PK_Verifier> verifier()
    {
        return std::make_unique<Botan::PK_Verifier>(*key, emca);
    }

  public:
    ecdsa_public(int uid)
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

Dutta_Barua_GKE::Dutta_Barua_GKE(std::string channelname, eventloop &ev_loop, lcm::LCM &lcm,
                                 int uid)
    : channelname(std::move(channelname)), evloop(ev_loop), lcm(lcm), uid{uid + 1, 1}
{
}

void Dutta_Barua_GKE::sign_and_dispatch(Dutta_Barua_message& msg) {
    ecdsa_private dsa_private(uid.u);
    auto signature = dsa_private.db_sign(msg);

    msg.sig_size = signature.size();
    msg.sig = std::vector<int8_t>((int8_t *) signature.data(),
                                         (int8_t *) (signature.data() + msg.sig_size));
    lcm.publish(channelname, &msg);
}

void Dutta_Barua_GKE::db_set_public_value(Dutta_Barua_message& msg, const Botan::BigInt& bigint){
    msg.public_value_size = bigint.bits();
    msg.public_value.resize(bigint.bits());
    bigint.binary_encode((uint8_t*)(msg.public_value.data()), bigint.bits());
}

void Dutta_Barua_GKE::on_msg(const Dutta_Barua_message *msg)
{
    // Check first whether or not the message is meant for us
    if (msg->round == 1 && !is_neighbour(msg))
        return;

    ecdsa_public dsa_public(msg->u);
    if (!dsa_public.db_verify(msg))
        return;
    debug("verified signature successfully");

    if (msg->round == 1) {
        if (is_left_neighbour(msg))
            r1_messages.left = *msg;
        if (is_right_neighbour(msg))
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
void Dutta_Barua_GKE::round1()
{
    debug("Dutta_Barua_GKE::Dutta_Barua_GKE()\n");
    debug("----round 1-----");

    partial_session_id.push_back(uid);  // initialize the partial session id with

    constexpr int group_bitsize = 4096;
    Botan::DL_Group group("modp/ietf/" + std::to_string(group_bitsize));

    Botan::AutoSeeded_RNG rng;

    x_i = Botan::DH_PrivateKey(rng, group);

    // public value; i.e. g^x mod q; where x is private key. This public value is called capital X
    // in Dutta Barua paper
    Botan::BigInt X = x_i->get_y();

    Dutta_Barua_message msg;

    msg.u = this->uid.u;
    msg.round = 1;
    db_set_public_value(msg, X);
    msg.d = this->uid.d;

    sign_and_dispatch(msg);
}

void Dutta_Barua_GKE::round2()
{
    debug(("Channel" + channelname + " : round2()").c_str());
    auto x_i_value = x_i->get_x();

    auto& msgleft = r1_messages.left;
    auto& msgright = r1_messages.right;

    Botan::BigInt left_X;
    left_X.binary_decode((uint8_t*)msgleft->public_value.data(), msgleft->public_value.size());
    auto leftkey = Botan::power_mod(left_X, x_i_value, x_i->group_p());

    Botan::BigInt right_X;
    right_X.binary_decode((uint8_t*)msgright->public_value.data(), msgright->public_value.size());
    auto rightkey = Botan::power_mod(right_X, x_i_value, x_i->group_p());

    auto Y = rightkey/leftkey;

    Dutta_Barua_message msg;
    msg.u = uid.u;
    msg.round=2;
    db_set_public_value(msg, Y);
    msg.d=uid.d;

    sign_and_dispatch(msg);

    r2_finished = true;
}

void Dutta_Barua_GKE::computeKey()
{
    debug(("Channel " + channelname + " : computeKey()").c_str());
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
