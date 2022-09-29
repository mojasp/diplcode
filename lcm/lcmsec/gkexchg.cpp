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

#include <cstdlib>
#include <numeric>

#include "lcmsec/dsa.h"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN_response.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

KeyExchangeManager::KeyExchangeManager(capability cap, eventloop &ev_loop, lcm::LCM &lcm)
    : Dutta_Barua_GKE(cap.uid),
      groupexchg_channelname(
          std::string(std::string("lcm://") + cap.channelname.value_or(cap.mcasturl))),
      channelname(MOV(cap.channelname)),
      mcastgroup(MOV(cap.mcasturl)),
      evloop(ev_loop),
      lcm(lcm)
{
    // create the appropriate join tasks
    auto now = std::chrono::steady_clock::now();
    auto curr = now;
    while (curr < now + JOIN_waitperiod) {
        auto t = [this] { JOIN(); };
        ev_loop.push_task(curr, t);
        curr += JOIN_rebroadcast_interval;
    }
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

/*
 * uid layout
 * ----------------------
 *
 * assume 5 participants with uid's 1, 2, 4, 5, 7 have agreed to a key.
 *
 * Now 3 users with respective UID 3, 6, 8 execute join()
 *
 * there is a uid vector : [1,2,4,5,7] at the start. simply add [3, 6, 8] to that vector, so the
 * vector looks like this: [1, 2, 4, 5, 7, 3, 6, 8] Now we need a view into the vector that looks
 * like this: [1, 2, 7, 3, 6, 8] - size l = m+3
 *
 * If we instead use an ordered map (constant time lookup from uid's to protocol uids ):
 *  start: 1-1 2-2 4-3 5-4 7-5
 *  after join: 1-1 2-2 4-3 5-4 7-5 3-6 6-7 8-9
 *      Note that the actual user ID's are not important, what is important is consensus among
 * participants view for key exchange: 1-1 2-2 7-5 3-6- 6-7 8-9 Note that we need to create a new
 *
 * In both cases what we really need is a way to go map n to l(=m+3)
 *  the indices stay the same actually
 *  The map version is more efficient probably: we get const time lookup - although even better
 * would be a vector with flipped indices (i.e.; reserve space in vector<int> first; then assign
 * vec[10] = 1 when uid 10 gets protoUid 1)
 */

void KeyExchangeManager::on_msg(const Dutta_Barua_message *msg)
{
    // Check first whether or not the message is meant for us - quick bailout so we avoid checking
    // the signature in some cases.
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
    if (r2_finished && r2_messages.size() == joining_participants.size()) {
        evloop.push_task([this] { computeKey(); });
    }
}

void KeyExchangeManager::JOIN()
{
    if (state != STATE::keyexchg_not_started) {
        debug(std::string("not executing join(): keyexchange has already started, in state: ") +
              state_name(state));
        return;
    }
    Dutta_Barua_JOIN join;
    // FIXME: consistent r1start - use helper function, make this actually correct - behaviour is
    // already correct but code confusing
    auto requested_r1start = std::chrono::steady_clock::now() + JOIN_waitperiod;
    auto requested_r1start_ms =
        std::chrono::time_point_cast<std::chrono::milliseconds>(requested_r1start);
    join.timestamp_r1start_ms = requested_r1start_ms.time_since_epoch().count();

    auto &cert = DSA_certificate_self::getInst().cert;
    join.certificate.x509_certificate_BER = cert.BER_encode();
    join.certificate.cert_size = join.certificate.x509_certificate_BER.size();

    std::string ch = std::string("join") + groupexchg_channelname;
    lcm.publish(ch, &join);

    if (!current_earliest_r1start || requested_r1start < current_earliest_r1start) {
        current_earliest_r1start = requested_r1start;
        evloop.push_task(requested_r1start, [this]() { round1(); });
    }
}

/*
 * issue a join response if a group exists already
 */
void KeyExchangeManager::JOIN_response(int64_t requested_r1start)
{
    // Skip answering the join if there has already been an answer since the remote started sending
    // join's
    std::chrono::steady_clock::time_point requested_starting_time{
        std::chrono::milliseconds(requested_r1start)};
    auto remote_began_sending = requested_starting_time - JOIN_waitperiod;
    if (last_answered_join && last_answered_join > remote_began_sending) {
        debug("skip joinresponse early");
        return;
    }
    debug("dispatching join_resp");

    // FIXME: ADD OUR OWN CERTIFICATE! - or do we? we need to sign the message though! if we do the
    // remote will have our cert

    Dutta_Barua_JOIN_response response;

    for (auto &cert :
         MOV(DSA_verifier::getInst().certificates_for_channel(mcastgroup, channelname))) {
        Dutta_Barua_cert db_cert;
        db_cert.cert_size = cert.size();
        db_cert.x509_certificate_BER = MOV(cert);
        response.certificates.push_back(MOV(db_cert));
    }
    response.participants = response.certificates.size();

    current_earliest_r1start =
        conditionally_create_task(requested_starting_time, [this] { join_existing(); });

    std::string ch = std::string("join_resp") + groupexchg_channelname;
    lcm.publish(ch, &response);
    last_answered_join = std::chrono::steady_clock::now();
}

/*
 * refactor this away once we have implemented improved method of looking up uid's
 */
static void add_participant(std::vector<int> &participants, int remote_uid)
{
    participants.push_back(remote_uid);

    // deleting duplicates - FIXME Make this more efficient later - look up protocol uids by
    // value of configured uid's; instead of searching through array each time
    std::sort(participants.begin(), participants.end());
    participants.erase(std::unique(participants.begin(), participants.end()), participants.end());
}

void KeyExchangeManager::on_JOIN_response(const Dutta_Barua_JOIN_response *join_response)
{
    switch (state) {
    case Dutta_Barua_GKE::STATE::keyexchg_not_started: {
        auto &verifier = DSA_verifier::getInst();
        for (const auto &cert : join_response->certificates) {
            auto uid = verifier.add_certificate(cert, mcastgroup, channelname);
            if (!uid)
                return;
            add_participant(participants, *uid);
        }

        // add earlier start to the join phsae in case it is required
        std::chrono::steady_clock::time_point requested_r1start{
            std::chrono::milliseconds(join_response->timestamp_r1start_ms)};
        current_earliest_r1start =
            conditionally_create_task(requested_r1start, [this] { join_new(); });
        state = Dutta_Barua_GKE::STATE::join_in_progress;
        break;
    }
    case Dutta_Barua_GKE::STATE::keyexchg_successful: {
        // FIXME: this is problematic if the timestamps are not signed - DOS
        last_answered_join = std::chrono::steady_clock::now();

        // add earlier start to the join phase in case it is required
        std::chrono::steady_clock::time_point requested_r1start{
            std::chrono::milliseconds(join_response->timestamp_r1start_ms)};
        current_earliest_r1start =
            conditionally_create_task(requested_r1start, [this] { join_existing(); });
        state = Dutta_Barua_GKE::STATE::join_in_progress;

        prepare_join();
    } break;
    default:;
        // ignore join responses in the middle of a running keyexchange
    }
}

void KeyExchangeManager::onJOIN(const Dutta_Barua_JOIN *join_msg)
{
    switch (state) {
    case STATE::keyexchg_not_started: {
        auto &verifier = DSA_verifier::getInst();
        auto remote_uid = verifier.add_certificate(join_msg->certificate, mcastgroup, channelname);
        if (!remote_uid)
            return;
        add_participant(joining_participants, *remote_uid);

        std::chrono::steady_clock::time_point requested_r1start{
            std::chrono::milliseconds(join_msg->timestamp_r1start_ms)};
        if (!current_earliest_r1start || requested_r1start < *current_earliest_r1start) {
            evloop.push_task(requested_r1start, [this]() { round1(); });
            current_earliest_r1start = requested_r1start;
        }
        break;
    }
    case STATE::keyexchg_successful: {
        auto &verifier = DSA_verifier::getInst();
        auto remote_uid = verifier.add_certificate(join_msg->certificate, mcastgroup, channelname);
        if (!remote_uid)
            return;
        add_participant(joining_participants, *remote_uid);

        // dispatch JOIN_response at a random time
        using namespace std::chrono;
        int avgdelay_count_us = duration_cast<microseconds>(JOIN_response_avg_delay).count();
        int us_offset = (std::rand() % 2 * avgdelay_count_us) - avgdelay_count_us;
        auto response_timepoint = steady_clock::now() + microseconds(us_offset);

        // it is very important to name this variable.
        // if it is unnamed, join_msg will be captured by value, instead of only the member - this
        // is problematic, because join_msg will not be pointing to valid memory in the future (its
        // lifetime is managed by LCM)
        int requested_r1start = join_msg->timestamp_r1start_ms;

        evloop.push_task(response_timepoint, [=] { JOIN_response(requested_r1start); });
        break;
    }
    default:
        debug("ignoring remote join() during execution of keyexchange...");
    }
}

void Dutta_Barua_GKE::round1()
{
    switch (getState()) {
    case STATE::keyexchg_not_started: //fallthrough
    case STATE::join_in_progress:
        break;
    default: return; //avoid accidentally starting round1 multiple times - this would happen since it is very possible that multiple round1 tasks are queued up.
    }
    std::sort(joining_participants.begin(),
              joining_participants.end());  // FIXME do this in a better way

    auto &verifier = DSA_verifier::getInst();
    for (auto &e : joining_participants) {
        std::cout << e << "\t";
    }

    debug(("------ starting Dutta_Barua_GKE with " + std::to_string(joining_participants.size()) +
           "participants ------- ")
              .c_str());
    partial_session_id.push_back(
        user_id{uid_to_protocol_uid(uid.u),
                uid.d});  // initialize the partial session id with the *protocol_user_id*

    if(!x_i) {
        Botan::AutoSeeded_RNG rng;
        auto privkey = Botan::DH_PrivateKey(rng, group);
        x_i = privkey.get_x();
    }

    // public value; i.e. g^x mod q; where x is private key. This public value is called
    // capital X in Dutta Barua paper
    Botan::BigInt X = Botan::power_mod(group.get_g(), x_i.value(), group.get_p());

    Dutta_Barua_message msg;

    // For sending messages; use the true user_ids that correspond to the capabilities configured in
    // the protocol
    msg.u = this->uid.u;
    msg.round = 1;
    db_set_public_value(msg, X);
    msg.d = this->uid.d;

    sign_and_dispatch(msg);
    auto &state = getState();
    state = STATE::round1_done;
}

void Dutta_Barua_GKE::round2()
{
    assert(r1_messages.left && r1_messages.right);
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

    auto leftkey_inverse = Botan::inverse_mod(r1_results.left, group.get_p());
    Botan::BigInt Y = (r1_results.right * leftkey_inverse) % group.get_p();

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
        return ((i - 1) % joining_participants.size()) +
               1;  // wraparound respecting 1-indexing of dutta barua paper
    };

    std::map<int, Botan::BigInt> right_keys;

    // we can immediately add our own right key (computed from the previous round)
    int protocol_uid = uid_to_protocol_uid(uid.u);
    right_keys[protocol_uid] = Botan::BigInt(r1_results.right);

    Botan::BigInt current_rightkey = r1_results.right;

    Botan::BigInt Y;
    db_get_public_value(r2_messages[wrapindex(protocol_uid + 1)], Y);

    current_rightkey = (Y * current_rightkey) % group.get_p();
    right_keys[wrapindex(protocol_uid + 1)] = Botan::BigInt(current_rightkey);

    for (int i = 2; i <= joining_participants.size() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        // debug(("idx: " + std::to_string(idx)).c_str());
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = (Y * current_rightkey) % group.get_p();

        right_keys[idx] = Botan::BigInt(current_rightkey);
    }

    // correctness check
    int lastindex = wrapindex(protocol_uid + joining_participants.size() - 1);
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
                                        return (acc * value.second) % group.get_p();
                                    });

    using namespace std;
    // cout << channelname << " u: " << uid.u << "computed session key: " << session_key <<
    // endl;

    participants = MOV(joining_participants);
    joining_participants.clear();
    gkexchg_finished();
}

void Dutta_Barua_GKE::prepare_join()
{
    if (getState() != STATE::join_in_progress) {
        debug("prepare_join: wrong state: " + std::string(state_name(getState())) + ", exiting..");
        return;
    }

    // Cleanup any intermediate stuff
    r1_results.left.clear();
    r1_results.right.clear();
    r2_finished = false;
    r2_messages.clear();
}
void Dutta_Barua_GKE::join_existing()
{
    if (getState() != STATE::join_in_progress) {
        debug("prepare_join: wrong state: " + std::string(state_name(getState())) + ", exiting..");
        return;
    }

    debug("join from existing group member");

    if (participants.size() <= 3) {
        // need a group of more than 3 participants to perform the dynamic version of the
        // keyexchange
        debug("existing group small: reform group instead of joining");
        joining_participants.insert(joining_participants.end(), participants.begin(),
                                    participants.end());
        std::sort(joining_participants.begin(), joining_participants.end());
        joining_participants.erase(
            std::unique(joining_participants.begin(), joining_participants.end()),
            joining_participants.end());
        participants.clear();
        getState() = STATE::keyexchg_not_started;
        return round1();
    }

    joining_participants.insert(joining_participants.begin(), participants.begin(), participants.begin() + 3);
    int our_proto_uid = uid_to_protocol_uid(uid.u);
    if(our_proto_uid == 2) {
        //initialize x_i from shared_secret 
        //WIP 
        //FIXME this is incorrect, should be that members x_1 x_2 and x_n are active, not - like i did it here - x1,x2,x3
        auto& g = group.get_g();
        auto Y = Botan::power_mod(g, shared_secret.value(), group.get_p());
    }
    if(our_proto_uid==1 && our_proto_uid == 3) //execute group key agreement normally 
    {}
}
void Dutta_Barua_GKE::join_new()
{
    if (getState() != STATE::join_in_progress) {
        debug("prepare_join: wrong state: " + std::string(state_name(getState())) + ", exiting..");
        return;
    }

    debug("join from new group member");

    if (participants.size() <= 3) {
        // need a group of more than 3 participants to perform the dynamic version of the
        // keyexchange
        debug("existing group small: reform group instead of joining");
        joining_participants.insert(joining_participants.end(), participants.begin(),
                                    participants.end());
        std::sort(joining_participants.begin(), joining_participants.end());
        joining_participants.erase(
            std::unique(joining_participants.begin(), joining_participants.end()),
            joining_participants.end());
        participants.clear();
        getState()=STATE::keyexchg_not_started;
        round1();
    }
    joining_participants.insert(joining_participants.begin(), participants.begin(), participants.begin() + 3);
    round1();
}

Botan::secure_vector<uint8_t> KeyExchangeManager::get_session_key(size_t key_size)
{
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
    impl.on_msg(msg);
}

void KeyExchangeLCMHandler::handle_JOIN(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                        const Dutta_Barua_JOIN *join_msg)
{
    impl.onJOIN(join_msg);
}

void KeyExchangeLCMHandler::handle_JOIN_response(const lcm::ReceiveBuffer *rbuf,
                                                 const std::string &chan,
                                                 const Dutta_Barua_JOIN_response *join_response)
{
    impl.on_JOIN_response(join_response);
}

}  // namespace lcmsec_impl
