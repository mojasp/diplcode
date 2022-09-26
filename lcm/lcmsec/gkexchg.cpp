#include "gkexchg.h"

#include <assert.h>
#include <botan/auto_rng.h>
#include <botan/dh.h>
#include <botan/kdf.h>
#include <botan/numthry.h>
#include <botan/pkix_types.h>
#include <botan/pubkey.h>

#include <algorithm>
#include <numeric>
#include <vector>

#include "lcmsec/dsa.h"
#include "lcmsec/lcmtypes/Dutta_Barua_SYN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {


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

Dutta_Barua_GKE::Dutta_Barua_GKE(capability cap,
                                 eventloop &ev_loop, lcm::LCM &lcm)
     : groupexchg_channelname(std::string(std::string("lcm://") + cap.channelname.value_or(cap.mcasturl))),
    channelname(MOV(cap.channelname)),
      mcastgroup(MOV(cap.mcasturl)),
      evloop(ev_loop),
      lcm(lcm),
      uid{cap.uid, 1}
{
}

static void botan_x509_example(Dutta_Barua_message &msg)
{
    auto &signer = DSA_signer::getInst();
    auto signature = signer.db_sign(msg);

    std::cout << " verify message for test " << std::endl;

    std::string cert_file = "x509v3/bob.crt";
    std::string rootcert = "x509v3/root_ca.crt";

    Botan::X509_Certificate cert(cert_file);
    Botan::X509_Certificate root_ca(rootcert);

    if (cert.check_signature(root_ca.subject_public_key()))
        std::cout << "certificate valid\n";
    else
        std::cout << "certificate INVALID\n";

    // Certificate is valid => check if the message is signed by that certificate
    auto pkey = cert.subject_public_key();
    std::cout << "algname" << pkey->algo_name() << std::endl;
    const static std::string ecdsa_emca = "EMSA1(SHA-256)";
    Botan::PK_Verifier verifier(*pkey, ecdsa_emca);
    verifier.update((const uint8_t *) &msg.u, 4);
    verifier.update(msg.round);
    verifier.update((const uint8_t *) msg.public_value.data(), msg.public_value.size());
    verifier.update((const uint8_t *) &msg.d, 4);

    if (verifier.check_signature(signature))
        std::cout << "msg signature valid" << std::endl;
    else
        std::cout << "msg signature INVALID" << std::endl;

    // check if permissions are good
    std::string channelname = "channel1";
    Botan::AlternativeName altname = cert.subject_alt_name();
    bool found_permission = false;
    std::string expected_urn;
    std::string group_keyxchg_channel = "group_keyxchg_channel";  // workaround for now
    std::string mcasturl = "239.255.76.67:7667";  // another workaround, only default url
    // (=mcastgroup) allowed right now
    if (channelname == group_keyxchg_channel) {
        std::string expected_urn = "urn:lcmsec:gkexchg:" + mcasturl + channelname + ":2";
    } else {
        expected_urn = "urn:lcmsec:gkexchg_g:" + mcasturl +
                       ":2";  // Workaround: get uid/senderid from certificate
    }
    for (const auto &[k, v] : altname.get_attributes()) {
        std::cout << k << ": " << v << std::endl;
        std::string URI = "URI";
        if (k != URI)
            continue;
        if (expected_urn == v) {
            found_permission = true;
            break;
        }
    }
    if (found_permission)
        std::cout << "permissions exist. msg is good." << std::endl;
    else
        std::cout << "did not find permissions (" << expected_urn << ")for msg in certificate"
                  << std::endl;
}
void Dutta_Barua_GKE::sign_and_dispatch(Dutta_Barua_message &msg)
{
    auto &signer = DSA_signer::getInst();
    auto signature = signer.db_sign(msg);

    msg.sig_size = signature.size();
    msg.sig = std::vector<int8_t>((int8_t *) signature.data(),
                                  (int8_t *) (signature.data() + msg.sig_size));
    lcm.publish(groupexchg_channelname, &msg);
}

void Dutta_Barua_GKE::db_set_public_value(Dutta_Barua_message &msg, const Botan::BigInt &bigint)
{
    assert(bigint != 0);
    msg.public_value_size = bigint.bits();
    msg.public_value.resize(bigint.bits());
    bigint.binary_encode((uint8_t *) (msg.public_value.data()), bigint.bits());
}

void Dutta_Barua_GKE::db_get_public_value(const Dutta_Barua_message &msg, Botan::BigInt &bigint)
{
    bigint.binary_decode((uint8_t *) msg.public_value.data(), msg.public_value.size());
}

void Dutta_Barua_GKE::on_msg(const Dutta_Barua_message *msg)
{
    // Check first whether or not the message is meant for us
    if (msg->round == 1 && !is_neighbour(msg))
        return;

    auto &verifier = DSA_verifier::getInst();
    if (!verifier.db_verify(msg, mcastgroup, channelname.value_or(mcastgroup))) {
        debug("signature verification failed");
        return;
    }

    if (msg->round == 1) {
        // Note: it is intended that in the case of two participants, both of the conditions hold;
        // i.e. the 2-party case is just a special case of the key exchange algorithm
        if (is_left_neighbour(msg))
            r1_messages.left = *msg;
        if (is_right_neighbour(msg))
            r1_messages.right = *msg;
    } else {
        if (msg->round != 2) {
            auto error = "keyexchange on channel " + groupexchg_channelname +
                         " failed: faulty message (msg->round) but valid signature";
            throw std::runtime_error(error);
        }
        r2_messages[uid_to_protocol_uid(msg->u)] = *msg;
    }

    // Check prerequisites for next round
    if (!r2_finished && r1_messages.left && r1_messages.right) {
        evloop.push_task([this] { round2(); });
    }
    if (r2_finished && r2_messages.size() == participants.size()) {
        evloop.push_task([this] { computeKey(); });
    }
}

inline void Dutta_Barua_GKE::SYN()
{
    Dutta_Barua_SYN syn;
    auto now = std::chrono::high_resolution_clock::now();
    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
    syn.timestamp_milli = now_ms.time_since_epoch().count();

    auto &cert = DSA_certificate_self::getInst().cert;
    auto data = cert.BER_encode();
    syn.cert_size = data.size();
    syn.x509_certificate_BER =
        std::vector<int8_t>((int8_t *) data.data(), (int8_t *) (data.data() + syn.cert_size));

    std::string ch = std::string("syn") + groupexchg_channelname;
    lcm.publish(ch, &syn);

    if (!syn_finished_at) {  // not received any other syn - SYN ourselves again
        evloop.push_task([this]() { SYN(); });
        return;
    }
    if (syn_finished_at) {
        // Already received a SYN
        auto now = std::chrono::high_resolution_clock::now();
        auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
        auto count = now_ms.time_since_epoch().count();
        if (count < syn_finished_at.value()) {
            // BUt not ready for round1 yet -> SYN again
            evloop.push_task([this]() { SYN(); });
            return;
        } else {
            // Good to start round1
            auto r1 = [=] { round1(); };
            evloop.push_task(r1);
        }
    }
}

inline void Dutta_Barua_GKE::onSYN(const Dutta_Barua_SYN *syn_msg)
{
    if (!syn_finished_at) {  // no syn has yet been received
        // check against current time to avoid some sort of DOS attack in which an attack
        // causes the protocol to never start by setting the timestamp into the future
        //  NOTE: this is nesecary because the timestamp is not signed
        auto now = std::chrono::high_resolution_clock::now();
        auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
        int count_now = now_ms.time_since_epoch().count();
        if (syn_msg->timestamp_milli < count_now + SYN_waitperiod_ms) {
            syn_finished_at = syn_msg->timestamp_milli + SYN_waitperiod_ms;
        } else {
            syn_finished_at = syn_msg->timestamp_milli + SYN_waitperiod_ms;
        }
    }

    auto &verifier = DSA_verifier::getInst();
    verifier.add_certificate(syn_msg);
}

void Dutta_Barua_GKE::round1()
{
    auto &verifier = DSA_verifier::getInst();
    participants = verifier.participant_uids(mcastgroup, channelname);
    std::sort(participants.begin(), participants.end());

    debug(("------ starting Dutta_Barua_GKE with " + std::to_string(participants.size()) +
           "participants ------- ")
              .c_str());
    partial_session_id.push_back(
        user_id{uid_to_protocol_uid(uid.u),
                uid.d});  // initialize the partial session id with the *protocol_user_id*

    constexpr int group_bitsize = 4096;
    Botan::DL_Group group("modp/ietf/" + std::to_string(group_bitsize));

    Botan::AutoSeeded_RNG rng;

    x_i = Botan::DH_PrivateKey(rng, group);

    // public value; i.e. g^x mod q; where x is private key. This public value is called
    // capital X in Dutta Barua paper
    Botan::BigInt X = x_i->get_y();

    Dutta_Barua_message msg;

    // For sending messages; use the true user_ids that correspond to the capabilities configured in
    // the protocol
    msg.u = this->uid.u;
    msg.round = 1;
    db_set_public_value(msg, X);
    msg.d = this->uid.d;

    sign_and_dispatch(msg);
}

void Dutta_Barua_GKE::round2()
{
    assert(r1_messages.left && r1_messages.right);
    auto x_i_value = x_i->get_x();

    auto &msgleft = r1_messages.left;
    auto &msgright = r1_messages.right;

    Botan::BigInt left_X;
    db_get_public_value(*msgleft, left_X);

    r1_results.left = Botan::power_mod(left_X, x_i_value, x_i->group_p());

    Botan::BigInt right_X;
    db_get_public_value(*msgright, right_X);
    r1_results.right = Botan::power_mod(right_X, x_i_value, x_i->group_p());

    assert(r1_results.right != 0);
    assert(r1_results.left != 0);

    auto leftkey_inverse = Botan::inverse_mod(r1_results.left, x_i->group_p());
    Botan::BigInt Y = (r1_results.right * leftkey_inverse) % x_i->group_p();

    assert(Y != 0);
    Dutta_Barua_message msg;
    msg.u = uid.u;
    msg.round = 2;
    db_set_public_value(msg, Y);
    msg.d = uid.d;

    sign_and_dispatch(msg);

    r2_finished = true;
}

void Dutta_Barua_GKE::computeKey()
{
    for (auto &[i, incoming] : r2_messages) {
        partial_session_id.push_back(user_id{uid_to_protocol_uid(incoming.u), incoming.d});
    }
    auto wrapindex = [=](int i) {
        return ((i - 1) % participants.size()) +
               1;  // wraparound respecting 1-indexing of dutta barua paper
    };

    std::map<int, Botan::BigInt> right_keys;

    // we can immediately add our own right key (computed from the previous round)
    int protocol_uid = uid_to_protocol_uid(uid.u);
    right_keys[protocol_uid] = Botan::BigInt(r1_results.right);

    Botan::BigInt current_rightkey = r1_results.right;

    Botan::BigInt Y;
    db_get_public_value(r2_messages[wrapindex(protocol_uid + 1)], Y);

    current_rightkey = (Y * current_rightkey) % x_i->group_p();
    right_keys[wrapindex(protocol_uid + 1)] = Botan::BigInt(current_rightkey);

    for (int i = 2; i <= participants.size() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        // debug(("idx: " + std::to_string(idx)).c_str());
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = (Y * current_rightkey) % x_i->group_p();

        right_keys[idx] = Botan::BigInt(current_rightkey);
    }

    // correctness check
    int lastindex = wrapindex(protocol_uid + participants.size() - 1);
    bool correctness = right_keys[lastindex] == r1_results.left;
    if (correctness)
        debug("group key exchange successful!");
    else {
        debug("key computation correctness check failed");
        return;  // FIXME failure should be signaled in some form is actionable for the
                 // consumer of the API
    }
    shared_secret = std::accumulate(right_keys.begin(), right_keys.end(), Botan::BigInt(1),
                                    [this](Botan::BigInt acc, std::pair<int, Botan::BigInt> value) {
                                        return (acc * value.second) % x_i->group_p();
                                    });

    using namespace std;
    // cout << channelname << " u: " << uid.u << "computed session key: " << session_key <<
    // endl;

    evloop.channel_finished();
}
Botan::secure_vector<uint8_t> Dutta_Barua_GKE::get_session_key(size_t key_size)
{
    if (!shared_secret)
        throw std::runtime_error(
            "get_session_key(): No shared secret has been agreed upon. Maybe the group key "
            "exchange algorithm was not successful");
    auto kdf = Botan::get_kdf("KDF2(SHA-256)");
    auto encoded = Botan::BigInt::encode_locked(*shared_secret);

    return kdf->derive_key(key_size, encoded);
}

Key_Exchange_Manager::Key_Exchange_Manager(capability cap, eventloop &ev_loop, lcm::LCM &lcm)
    : impl(cap, ev_loop, lcm)
{
    auto t = [this] { impl.SYN(); };
    ev_loop.push_task(t);
};

void Key_Exchange_Manager::handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                         const Dutta_Barua_message *msg)
{
    impl.on_msg(msg);
}

void Key_Exchange_Manager::handle_SYN(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                      const Dutta_Barua_SYN *syn_msg)
{
    impl.onSYN(syn_msg);
}

}  // namespace lcmsec_impl
