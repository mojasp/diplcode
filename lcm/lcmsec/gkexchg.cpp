#include "gkexchg.h"

#include <assert.h>
#include <botan/auto_rng.h>
#include <botan/dh.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/kdf.h>
#include <botan/numthry.h>
#include <botan/pkix_types.h>
#include <botan/pubkey.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <numeric>

#include "lcmsec/dsa.h"
#include "lcmsec/lcmexcept.hpp"
#include "lcmsec/lcmsec_util.h"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN_response.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

#define LCMSEC_CHECKSTATE(...)        \
    do {                              \
        if (!checkState(__VA_ARGS__)) \
            return;                   \
    } while (0);

KeyExchangeManager::KeyExchangeManager(capability cap, eventloop &ev_loop, lcm::LCM &lcm)
    : Dutta_Barua_GKE(cap.uid),
      groupexchg_channelname(
          std::string(std::string("lcm://") + cap.channelname.value_or(cap.mcasturl))),
      channelname(MOV(cap.channelname)),
      mcastgroup(MOV(cap.mcasturl)),
      evloop(ev_loop),
      lcm(lcm)
{
    // start join later, to avoid race condition in which we JOIN, accept the JOIN, and finish the
    // gkexchg before being subscribed with our LCM instance and able to receive on the management
    // channel
    add_task(std::chrono::steady_clock::now(), [this] { JOIN(); });

    // prepare a timeout task - will not be called in case of success of the group key exchange, since in that
    // case the invocation count will have increased already
    add_task(std::chrono::steady_clock::now() + gkexchg_timeout, [this] {
        std::cerr << channelname.value_or("nullopt") << ": groupkeyexchange timed out on channel, restarting..." << std::endl;
        gkexchg_failure();
    });


}

Dutta_Barua_GKE::Dutta_Barua_GKE(int uid) : uid{uid, 1} {}
Dutta_Barua_GKE::~Dutta_Barua_GKE() {}

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

void KeyExchangeManager::sign_and_dispatch(Dutta_Barua_message &msg)
{
    auto &signer = DSA_signer::getInst();
    msg.sig = signer.db_sign(msg);

    msg.sig_size = msg.sig.size();
    lcm.publish(groupexchg_channelname, &msg);
}

static void db_set_public_value(Dutta_Barua_message &msg, const Botan::BigInt &bigint)
{
    assert(bigint != 0);
    msg.public_value_size = bigint.bits();
    msg.public_value.resize(bigint.bits());
    bigint.binary_encode((uint8_t *) (msg.public_value.data()), bigint.bits());
}

static void db_get_public_value(const Dutta_Barua_message &msg, Botan::BigInt &bigint)
{
    bigint.binary_decode((uint8_t *) msg.public_value.data(), msg.public_value.size());
}

void KeyExchangeManager::add_task(eventloop::timepoint_t tp, std::function<void()> f)
{
    auto task = [=,this, invo_cnt = uid.d, f = MOV(f)]() {
        assert(this->uid.d >= invo_cnt);
        if (invo_cnt != this->uid.d) {
            return;
        }
        try {
            f();
        } catch (keyagree_exception &e) {
            std::cerr << "keyagree failed on channel"
                      << channelname.value_or("nullopt") + " with: " << e.what()
                      << " ! Restarting Key agreement...." << std::endl;
            gkexchg_failure();
        }
    };
    evloop.push_task(tp, task);
};

void KeyExchangeManager::add_task(std::function<void()> f)
{
    add_task(std::chrono::steady_clock::now(), MOV(f));
};

void KeyExchangeManager::on_msg(const Dutta_Barua_message *msg)
{
    managed_state.prepare_join();
    state = STATE::keyexchg_in_progress;

    auto &verifier = DSA_verifier::getInst();
    if (!verifier.verify(msg, mcastgroup, channelname)) {
        debug("signature verification failed");
        return;
    }

    int remote_uid = managed_state.uid_to_protocol_uid(msg->u);

    if (role == JOIN_ROLE::passive) {
        if (msg->round == 1) {
            int left = 1;
            int right = 3;
            auto remote_proto_uid = managed_state.uid_to_protocol_uid(msg->u);
            if (remote_proto_uid == left)
                r1_messages.left = *msg;
            if (remote_proto_uid == right)
                r1_messages.right = *msg;
        } else {
            if (msg->round != 2) {
                auto err = "lcmsec: keyexchange on channel " + groupexchg_channelname +
                           " failed: faulty message (msg->round = " + std::to_string(msg->round) +
                           ") but valid signature";
                throw remote_faulty(err);
            }
            r2_messages[managed_state.uid_to_protocol_uid(msg->u)] = *msg;
        }

        if (r1_messages.left && r1_messages.right &&
            r2_messages.size() == managed_state.active_participants()) {
            // All condition for calculating the key are met
            round2();
            computeKey_passive();
        }
    } else {
        if (msg->round == 1) {
            // Note: it is intended that in the case of two participants, both of the conditions
            // hold; i.e. the 2-party case is just a special case of the group key exchange
            // algorithm
            if (managed_state.is_left_neighbour(uid.u, msg))
                r1_messages.left = *msg;
            if (managed_state.is_right_neighbour(uid.u, msg))
                r1_messages.right = *msg;
        } else {
            if (msg->round != 2) {
                auto err = "lcmsec: keyexchange on channel " + groupexchg_channelname +
                           " failed: faulty message (msg->round = " + std::to_string(msg->round) +
                           ") but valid signature";
                throw remote_faulty(err);
            }
            r2_messages[managed_state.uid_to_protocol_uid(msg->u)] = *msg;
        }

        // Check prerequisites for next round
        if (!r2_finished && r1_messages.left && r1_messages.right) {
            round2();
        }
        if (r2_finished && r2_messages.size() == managed_state.active_participants()) {
            computeKey();
        }
    }
}

void KeyExchangeManager::JOIN()
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started);

    Dutta_Barua_JOIN join;

    join.sig_size = 0; //FIXME
    auto requested_r1start = std::chrono::steady_clock::now() + JOIN_waitperiod;
    auto requested_r1start_us =
        std::chrono::time_point_cast<std::chrono::microseconds>(requested_r1start);
    join.timestamp_r1start_us = requested_r1start_us.time_since_epoch().count();

    auto &cert = DSA_certificate_self::getInst().cert;
    join.certificate.x509_certificate_BER = cert.BER_encode();
    join.certificate.cert_size = join.certificate.x509_certificate_BER.size();

    std::string ch = std::string("join") + groupexchg_channelname;
    lcm.publish(ch, &join);
}

/*
 * issue a join response if a group exists already
 */
void KeyExchangeManager::JOIN_response(int uid_of_join, int64_t requested_r1start_us)
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::keyexchg_successful);

    std::cerr << channelname.value_or("nullopt") << ": joinof( " << uid_of_join << ")\t"
              << managed_state.get_joining() << " : " << managed_state.get_participants()
              << std::endl;
    // Note that we do not need to test (in this method) whether or not we are a good candidate to
    // dispatch a join_response
    //
    // Either we are a better candidate than the other join responses that we have so far observed -
    // in which case we will have rejected them, thus, joining_participants will *not* contain
    // uid_of join - or we are not, in which case we will have accepted their  response and thus
    // uid_of_join *will* be part of joining_participants.
    if (managed_state.exists_in_joining(uid_of_join)) {
        debug("join answered already, skipping join_response");
        return;
    }

    auto &verif = DSA_verifier::getInst();
    Dutta_Barua_JOIN_response response;
    capability cap_template(mcastgroup, channelname, {});
    enum class role { participant, joining };

    auto add_cert_to_response = [&](int uid, role r) {
        cap_template.uid = uid;
        auto cert_ber = verif.get_certificate(cap_template);
        if (!cert_ber)
            throw uid_unknown("found no certificate for uid " + std::to_string(uid) +
                              " in certificate_store");
        Dutta_Barua_cert db_cert;
        db_cert.cert_size = cert_ber->size();
        db_cert.x509_certificate_BER = MOV(*cert_ber);
        if (r == role::joining)
            response.certificates_joining.push_back(MOV(db_cert));
        else if (r == role::participant)
            response.certificates_participants.push_back(MOV(db_cert));
        else
            assert(false);
    };

    // NOTE: we do not need to add uid_of_join to our managed state: We will receive our own
    // join_response anyways; so we will simply accept it when we receive it
    add_cert_to_response(uid_of_join, role::joining);

    for (int u : managed_state.get_joining()) {
        add_cert_to_response(u, role::joining);
    }
    for (int i : managed_state.get_participants()) {
        add_cert_to_response(i, role::participant);
    }

    response.joining = response.certificates_joining.size();
    response.participants = response.certificates_participants.size();

    response.sig_size = 0; //FIXME

    // Same note as above: it suffices to set this field in the response
    std::chrono::steady_clock::time_point req_r1start{std::chrono::microseconds(requested_r1start_us)};
    response.timestamp_r1start_us = std::chrono::time_point_cast<std::chrono::microseconds>(
                                        earliest_time(req_r1start, managed_state.r1start()))
                                        .time_since_epoch()
                                        .count();

    static constexpr int td_range_us = 20000;
    srand(std::chrono::system_clock::now().time_since_epoch().count());
    int us_offset = (std::rand() % (2 * td_range_us)) - td_range_us;
    response.timestamp_r1start_us += us_offset;

    std::string ch = std::string("join_resp") + groupexchg_channelname;
    lcm.publish(ch, &response);

    debug("dispatching join_response with {" + std::to_string(response.participants) + ", " +
          std::to_string(response.joining) + "}");
}

void KeyExchangeManager::on_JOIN_response(const Dutta_Barua_JOIN_response *join_response)
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::keyexchg_successful);

    auto dbg_reject = [=](std::string msg) {
        debug("rejecting join_response with {" + std::to_string(join_response->participants) +
              ", " + std::to_string(join_response->joining) + "} :" + msg);
    };
    auto dbg_accept = [=] {
        debug("accepting join_response with {" + std::to_string(join_response->participants) +
              ", " + std::to_string(join_response->joining) + "}");
    };

    auto &verifier = DSA_verifier::getInst();

    // First: achieve consensus on participants, while adding all certificants that we have not yet
    // observed
    std::vector<int> candidate_participants;
    for (const auto &cert : join_response->certificates_participants) {
        auto uid = verifier.add_certificate(cert, mcastgroup, channelname);
        if (!uid) {
            throw remote_invalid_cert("certificate contained in received join_response invalid");
        }
        candidate_participants.push_back(uid.value());
    }
    if (!managed_state.process_participant(&candidate_participants)) {
        dbg_reject("response.participants < participants");
        return;
    }

    // Second: achieve consensus on joining participants, while adding all certificants that we have
    // not yet observed
    std::vector<int> candidate_joining;
    for (const auto &cert : join_response->certificates_joining) {
        auto uid = verifier.add_certificate(cert, mcastgroup, channelname);
        if (!uid) {
            throw remote_invalid_cert("certificate contained in received join_response invalid");
        }
        candidate_joining.push_back(uid.value());
    }
    if (!managed_state.process_joining(&candidate_joining)) {
        dbg_reject("response.participants == participants, but response.joining < joining");
        return;
    }

    // Third: achieve consensus on start of round
    std::chrono::steady_clock::time_point requested_starting_time{
        std::chrono::microseconds(join_response->timestamp_r1start_us)};
    if (!managed_state.process_timestamp(requested_starting_time)) {
        dbg_reject(
            "response.participants == participants && response.joining == joining but "
            "requested_starting_time > current_earliest_r1start");
        return;
    }
    dbg_accept();

    add_task(requested_starting_time, [=] { start_join(); });
}

void KeyExchangeManager::onJOIN(const Dutta_Barua_JOIN *join_msg)
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::keyexchg_successful);

    auto &verifier = DSA_verifier::getInst();
    auto remote_uid = verifier.add_certificate(join_msg->certificate, mcastgroup, channelname);
    if (!remote_uid)
        return;

    // dispatch JOIN_response at a random time
    using namespace std::chrono;
    int avgdelay_count_us = duration_cast<microseconds>(JOIN_response_avg_delay).count();
    int variance_us = duration_cast<microseconds>(JOIN_response_variance).count();
    srand(std::chrono::system_clock::now().time_since_epoch().count());
    int us_offset = (std::rand() % (2 * variance_us)) - variance_us;
    auto response_timepoint =
        steady_clock::now() + microseconds(avgdelay_count_us) + microseconds(us_offset);
    debug("sending response to (" + std::to_string(remote_uid.value()) + ") in " +
          std::to_string(
              (duration_cast<milliseconds>(response_timepoint - steady_clock::now())).count()) +
          "milliseconds");
    add_task(response_timepoint,
                     [ruid = remote_uid.value(), req_r1start = join_msg->timestamp_r1start_us,
                      this] { JOIN_response(ruid, req_r1start); });
}

void Dutta_Barua_GKE::round1()
{
    auto &verifier = DSA_verifier::getInst();
    for (const auto &e : managed_state.uid_view().get()) {
        std::cout << e << "\t";
    }
    std::cout << std::endl;

    debug(("------ starting Dutta_Barua_GKE with " +
           std::to_string(managed_state.active_participants()) + "participants ------- ")
              .c_str());
    partial_session_id.push_back(
        user_id{managed_state.uid_to_protocol_uid(uid.u),
                uid.d});  // initialize the partial session id with the *protocol_user_id*

    if (!x_i) {  // In the join phase, x_i might have to be preinitialized.
        // Only generate a new x_i in case it doesn't exist
        Botan::AutoSeeded_RNG rng;
        auto privkey = Botan::DH_PrivateKey(rng, group);
        x_i = privkey.get_x();
    }

    // public value; i.e. g^x mod q; where x is private key. This public value is called
    // capital X in Dutta Barua paper
    Botan::BigInt X = Botan::power_mod(group.get_g(), x_i.value(), group.get_p());

    Dutta_Barua_message msg;

    // For sending messages; use the true user_ids that correspond to the capabilities
    // configured in the protocol
    msg.u = this->uid.u;
    msg.round = 1;
    db_set_public_value(msg, X);
    msg.d = this->uid.d;

    sign_and_dispatch(msg);
}

void Dutta_Barua_GKE::round2()
{
    assert(r1_messages.left && r1_messages.right);
    assert(!r2_finished);
    auto &msgleft = r1_messages.left;
    auto &msgright = r1_messages.right;

    Botan::BigInt left_X;
    db_get_public_value(*msgleft, left_X);

    r1_results.left = Botan::power_mod(left_X, x_i.value(), group.get_p());

    Botan::BigInt right_X;
    db_get_public_value(*msgright, right_X);
    r1_results.right = Botan::power_mod(right_X, x_i.value(), group.get_p());

    assert(r1_results.right != 0);
    assert(r1_results.left != 0);

    if (getRole() != JOIN_ROLE::passive) {
        auto leftkey_inverse = Botan::inverse_mod(r1_results.left, group.get_p());
        Botan::BigInt Y = (r1_results.right * leftkey_inverse) % group.get_p();

        assert(Y != 0);
        Dutta_Barua_message msg;
        msg.u = uid.u;
        msg.round = 2;
        db_set_public_value(msg, Y);
        msg.d = uid.d;

        sign_and_dispatch(msg);
    }
    r2_finished = true;
}

void Dutta_Barua_GKE::computeKey_passive()
{
    std::map<int, Botan::BigInt> right_keys;

    auto wrapindex = [sz = managed_state.active_participants()](int i) {
        return ((i - 1) % sz) + 1;  // wraparound respecting 1-indexing of dutta barua paper
    };
    // we can immediately add our own right key (computed from the previous round)
    int protocol_uid = 2;
    right_keys[protocol_uid] = Botan::BigInt(r1_results.right);

    Botan::BigInt current_rightkey = r1_results.right;

    Botan::BigInt Y;
    db_get_public_value(r2_messages[wrapindex(protocol_uid + 1)], Y);

    current_rightkey = (Y * current_rightkey) % group.get_p();
    right_keys[wrapindex(protocol_uid + 1)] = Botan::BigInt(current_rightkey);

    for (int i = 2; i <= managed_state.active_participants() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = (Y * current_rightkey) % group.get_p();

        right_keys[idx] = Botan::BigInt(current_rightkey);
    }

    // correctness check
    int lastindex = wrapindex(protocol_uid + managed_state.active_participants() - 1);
    bool correctness = right_keys[lastindex] == r1_results.left;
    if (correctness)
        debug("group key exchange successful!");
    else {
        throw keyagree_exception("key computation correctness check failed");
    }
    shared_secret = std::accumulate(right_keys.begin(), right_keys.end(), Botan::BigInt(1),
                                    [this](Botan::BigInt acc, std::pair<int, Botan::BigInt> value) {
                                        return (acc * value.second) % group.get_p();
                                    });

    managed_state.gke_success();
    gkexchg_finished();
}

void Dutta_Barua_GKE::computeKey()
{
    for (auto &[i, incoming] : r2_messages) {
        partial_session_id.push_back(
            user_id{managed_state.uid_to_protocol_uid(incoming.u), incoming.d});
    }
    auto wrapindex = [sz = managed_state.active_participants()](int i) {
        return ((i - 1) % sz) + 1;  // wraparound respecting 1-indexing of dutta barua paper
    };

    std::map<int, Botan::BigInt> right_keys;

    // we can immediately add our own right key (computed from the previous round)
    int protocol_uid = managed_state.uid_to_protocol_uid(uid.u);
    right_keys[protocol_uid] = Botan::BigInt(r1_results.right);

    Botan::BigInt current_rightkey = r1_results.right;

    Botan::BigInt Y;
    db_get_public_value(r2_messages[wrapindex(protocol_uid + 1)], Y);

    current_rightkey = (Y * current_rightkey) % group.get_p();
    right_keys[wrapindex(protocol_uid + 1)] = Botan::BigInt(current_rightkey);

    for (int i = 2; i <= managed_state.active_participants() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        // debug(("idx: " + std::to_string(idx)).c_str());
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = (Y * current_rightkey) % group.get_p();

        right_keys[idx] = Botan::BigInt(current_rightkey);
    }

    // correctness check
    int lastindex = wrapindex(protocol_uid + managed_state.active_participants() - 1);
    bool correctness = right_keys[lastindex] == r1_results.left;
    if (correctness)
        debug("group key exchange successful!");
    else {
        throw keyagree_exception("key computation correctness check failed");
    }
    shared_secret = std::accumulate(right_keys.begin(), right_keys.end(), Botan::BigInt(1),
                                    [this](Botan::BigInt acc, std::pair<int, Botan::BigInt> value) {
                                        return (acc * value.second) % group.get_p();
                                    });

    gkexchg_finished();
}

void Dutta_Barua_GKE::cleanup_intermediates()
{
    // Cleanup any intermediate stuff
    r1_results.left.clear();
    r1_results.right.clear();
    r1_messages.left = {};
    r1_messages.right = {};

    r2_finished = false;
    r2_messages.clear();
}

void Dutta_Barua_GKE::start_join()
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::keyexchg_successful);
    state = STATE::keyexchg_in_progress;

    managed_state.prepare_join();

    if (managed_state.num_participants() < 3) {
        x_i.reset();
        return round1();
    }

    const auto &participants = managed_state.get_participants();
    bool first = participants.front() == uid.u;
    bool second = participants[1] == uid.u;
    bool last = participants.back() == uid.u;

    if (!first && !last) {
        // initialize x_i from shared_secret instead FIXME hash
        x_i = shared_secret;
    }
    if (first || second || last) {
        getRole() = JOIN_ROLE::active;
        debug("join:active r1 started");
        return round1();
    } else if (managed_state.exists_in_joining(uid.u)) {
        getRole() = JOIN_ROLE::joining;
        debug("joining group");
        return round1();
    } else
        getRole() = JOIN_ROLE::passive;
}

Botan::secure_vector<uint8_t> KeyExchangeManager::get_session_key(size_t key_size)
{
    // leave this exception for now: it should not be an exception at all, instead, the error should
    // be signaled to the library user with an error code. However, this is will change when the API
    // reaches a more mature stater / is designed properly
    if (!shared_secret)
        throw std::runtime_error(
            "get_session_key(): No shared secret has been agreed upon on channel " +
            channelname.value_or("nullopt") +
            ". Maybe the group key "
            "exchange algorithm was not successful\n");
    auto kdf = Botan::get_kdf("KDF2(SHA-256)");
    auto encoded = Botan::BigInt::encode_locked(*shared_secret);

    return kdf->derive_key(key_size, encoded);
}

KeyExchangeLCMHandler::KeyExchangeLCMHandler(capability cap, eventloop &ev_loop, lcm::LCM &lcm)
    : impl(cap, ev_loop, lcm){};

void KeyExchangeLCMHandler::handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                          const Dutta_Barua_message *msg)
{
    try {
        impl.on_msg(msg);
    } catch (keyagree_exception &e) {
        std::cerr << "keyagree failed on channel" << channelname() + " with: " << e.what()
                  << " ! Restarting Key agreement...." << std::endl;
        impl.gkexchg_failure();
    }
}

void KeyExchangeLCMHandler::handle_JOIN(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                        const Dutta_Barua_JOIN *join_msg)
{
    try {
        impl.onJOIN(join_msg);
    } catch (keyagree_exception &e) {
        std::cerr << "keyagree failed on channel" << channelname() + " with: " << e.what()
                  << " ! Restarting Key agreement...." << std::endl;
        impl.gkexchg_failure();
    }
}

void KeyExchangeLCMHandler::handle_JOIN_response(const lcm::ReceiveBuffer *rbuf,
                                                 const std::string &chan,
                                                 const Dutta_Barua_JOIN_response *join_response)
{
    try {
        impl.on_JOIN_response(join_response);
    } catch (keyagree_exception &e) {
        std::cerr << "keyagree failed on channel" << channelname() + " with: " << e.what()
                  << " ! Restarting Key agreement...." << std::endl;
        impl.gkexchg_failure();
    }
}

}  // namespace lcmsec_impl
