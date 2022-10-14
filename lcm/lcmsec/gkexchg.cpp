#include "gkexchg.h"

#include <assert.h>
#include <botan/auto_rng.h>
#include <botan/curve_gfp.h>
#include <botan/dh.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/kdf.h>
#include <botan/numthry.h>
#include <botan/pkix_types.h>
#include <botan/point_gfp.h>
#include <botan/pubkey.h>

#include <algorithm>
#include <cstdlib>
#include <numeric>

#include "lcmsec/dsa.h"
#include "lcmsec/lcmsec_util.h"
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
    // start join later, to avoid race condition in which we JOIN, accept the JOIN, and finish the
    // gkexchg before being subscribed with our LCM instance and able to receive on the management
    // channel
    evloop.push_task([this] { JOIN(); });
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

void Dutta_Barua_GKE::db_set_public_value(Dutta_Barua_message &msg, const Botan::PointGFp &point)
{
    msg.public_value = point.encode(Botan::PointGFp::Compression_Type::COMPRESSED);
    msg.public_value_size = msg.public_value.size();
}

void Dutta_Barua_GKE::db_get_public_value(const Dutta_Barua_message &msg, Botan::PointGFp &p)
{
    p = group.OS2ECP(msg.public_value);
}

const Botan::EC_Group Dutta_Barua_GKE::group{"secp256r1"};

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
    if (role == Dutta_Barua_GKE::JOIN_ROLE::passive) {
        auto remote_proto_uid = uid_to_protocol_uid(msg->u);
        int left = 1;
        int right = 3;
        if (msg->round == 1) {
            if (remote_proto_uid != left && remote_proto_uid != right)
                return;  // we only care about 1 and 3
        }

        auto &verifier = DSA_verifier::getInst();
        if (!verifier.db_verify(msg, mcastgroup, channelname.value_or(mcastgroup))) {
            debug("signature verification failed");
            return;
        }

        if (msg->round == 1) {
            if (remote_proto_uid == left)
                r1_messages.left = *msg;
            else if (remote_proto_uid == right)
                r1_messages.right = *msg;
            else
                assert(false);  /// unreachable
        } else {
            if (msg->round != 2) {
                auto error = "keyexchange on channel " + groupexchg_channelname +
                             " failed: faulty message (msg->round) but valid signature";
                throw std::runtime_error(error);
            }
            r2_messages[uid_to_protocol_uid(msg->u)] = *msg;
        }

        if (r1_messages.left && r1_messages.right &&
            r2_messages.size() == joining_participants.size()) {
            // If we have everything we can immediately compute the key
            round2();
            computeKey_passive();
        }
    } else {
        // Check first whether or not the message is meant for us - quick bailout so we avoid
        // checking the signature in some cases.
        if (msg->round == 1 && !is_neighbour(msg))
            return;

        auto &verifier = DSA_verifier::getInst();
        if (!verifier.db_verify(msg, mcastgroup, channelname.value_or(mcastgroup))) {
            debug("signature verification failed");
            return;
        }

        if (msg->round == 1) {
            // Note: it is intended that in the case of two participants, both of the conditions
            // hold; i.e. the 2-party case is just a special case of the group key exchange
            // algorithm
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
}

void KeyExchangeManager::JOIN()
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started);

    Dutta_Barua_JOIN join;

    auto requested_r1start = std::chrono::steady_clock::now() + JOIN_waitperiod;
    auto requested_r1start_ms =
        std::chrono::time_point_cast<std::chrono::milliseconds>(requested_r1start);
    join.timestamp_r1start_ms = requested_r1start_ms.time_since_epoch().count();

    auto &cert = DSA_certificate_self::getInst().cert;
    join.certificate.x509_certificate_BER = cert.BER_encode();
    join.certificate.cert_size = join.certificate.x509_certificate_BER.size();

    std::string ch = std::string("join") + groupexchg_channelname;
    lcm.publish(ch, &join);
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

// print containers - debugging
static std::ostream &operator<<(std::ostream &stream, const std::vector<int> &container)
{
    for (const auto &i : container)
        stream << i << "\t";
    return stream;
}
/*
 * issue a join response if a group exists already
 */
void KeyExchangeManager::JOIN_response(int uid_of_join, int64_t requested_r1start)
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::keyexchg_successful);

    std::cerr << channelname.value_or("nullopt") << ": joinof( " << uid_of_join << ")\t"
              << joining_participants << " : " << participants << std::endl;
    // Note that we do not need to test (in this method) whether or not we are a good candidate to
    // dispatch a join_response
    //
    // Either we are a better candidate than the other join responses that we have so far observed -
    // in which case we will have rejected them, thus, joining_participants will *not* contain
    // uid_of join - or we are not, in which case we will have accepted their  response and thus
    // uid_of_join *will* be part of joining_participants.
    if (std::find(joining_participants.begin(), joining_participants.end(), uid_of_join) !=
        joining_participants.end()) {
        debug("join answered already, skipping join_response");
        return;
    }

    add_participant(joining_participants, uid_of_join);

    Dutta_Barua_JOIN_response response;
    for (auto &[uid, cert] :
         MOV(DSA_verifier::getInst().certificates_for_channel(mcastgroup, channelname))) {
        Dutta_Barua_cert db_cert;
        db_cert.cert_size = cert.size();
        db_cert.x509_certificate_BER = MOV(cert);

        if (std::binary_search(joining_participants.begin(), joining_participants.end(), uid)) {
            response.certificates_joining.push_back(MOV(db_cert));
        }
        if (std::binary_search(participants.begin(), participants.end(), uid)) {
            response.certificates_participants.push_back(MOV(db_cert));
        }
    }
    response.joining = response.certificates_joining.size();
    response.participants = response.certificates_participants.size();

    std::chrono::steady_clock::time_point req_r1start{std::chrono::milliseconds(requested_r1start)};
    response.timestamp_r1start_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(
                                        earliest_time(req_r1start, current_earliest_r1start))
                                        .time_since_epoch()
                                        .count();
    // FIXME: change timedelta to us
    static constexpr int td_range = 20;
    srand(std::chrono::system_clock::now().time_since_epoch().count());
    int us_offset = (std::rand() % (2 * td_range)) - td_range;
    response.timestamp_r1start_ms += us_offset;

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
    // First: achieve consensus on participants, while adding all certificants that we have not yet
    // observed
    auto &verifier = DSA_verifier::getInst();
    std::vector<int> candidate_participants;

    for (const auto &cert : join_response->certificates_participants) {
        auto uid = verifier.add_certificate(cert, mcastgroup, channelname);
        if (!uid) {
            throw std::runtime_error("certificate contained in received join_response invalid");
        }
        candidate_participants.push_back(uid.value());
    }
    if (candidate_participants.size() < participants.size()) {
        // reject join_response remote as RAFT leader
        // warrants no further action, return early
        dbg_reject("response.participants < participants");
        return;
    }

    // Second: achieve consensus on joining participants, while adding all certificants that we have
    // not yet observed
    std::vector<int> candidate_joining;
    for (const auto &cert : join_response->certificates_joining) {
        auto uid = verifier.add_certificate(cert, mcastgroup, channelname);
        if (!uid) {
            throw std::runtime_error("certificate contained in received join_response invalid");
        }
        candidate_joining.push_back(uid.value());
    }
    if (candidate_participants.size() == participants.size() &&
        candidate_joining.size() < joining_participants.size()) {
        // reject join_response / remote as RAFT leader
        // warrants no further action, return early
        dbg_reject("response.participants == participants and response.joining < joining");
        return;
    }

    // Third: achieve consensus on start of round
    std::chrono::steady_clock::time_point requested_starting_time{
        std::chrono::milliseconds(join_response->timestamp_r1start_ms)};

    if (candidate_participants.size() == participants.size() &&
        candidate_joining.size() == joining_participants.size() &&
        !is_earlier(requested_starting_time, current_earliest_r1start)) {
        // reject join_response / remote as RAFT leader
        dbg_reject("response.participants == participants and response.joining < joining");
        return;
    }

    dbg_accept();
    // Accept remote as RAFT leader
    participants = candidate_participants;
    std::sort(participants.begin(), participants.end());
    joining_participants = candidate_joining;
    std::sort(joining_participants.begin(), joining_participants.end());

    evloop.push_task(requested_starting_time, [=] { start_join(); });
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
    debug("sending response in " +
          std::to_string(
              (duration_cast<milliseconds>(response_timepoint - steady_clock::now())).count()) +
          "milliseconds");
    evloop.push_task(response_timepoint,
                       [ruid = remote_uid.value(), req_r1start = join_msg->timestamp_r1start_ms,
                        this] { JOIN_response(ruid, req_r1start); });
}

void Dutta_Barua_GKE::round1()
{
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

    Botan::PointGFp X;
    Botan::AutoSeeded_RNG rng;
    if (!x_i) {  // In the join phase, x_i might have to be preinitialized.
        // Only generate a new x_i in case it doesn't exist
        auto privkey = Botan::ECDH_PrivateKey(rng, group);
        x_i = privkey.private_value();
        X = privkey.public_point();
    } else {
        std::vector<Botan::BigInt> ws;
        X = group.blinded_base_point_multiply(*x_i, rng, ws);
    }

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

    Botan::PointGFp left_X;
    db_get_public_value(*msgleft, left_X);

    r1_results.left = left_X * x_i.value();

    Botan::PointGFp right_X;
    db_get_public_value(*msgright, right_X);
    r1_results.right = right_X * x_i.value();

    if (getRole() != JOIN_ROLE::passive) {
        auto Y = r1_results.right - r1_results.left;

        assert(!Y.is_zero());
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
    std::map<int, Botan::PointGFp> right_keys;

    auto wrapindex = [sz = joining_participants.size()](int i) {
        return ((i - 1) % sz) + 1;  // wraparound respecting 1-indexing of dutta barua paper
    };
    // we can immediately add our own right key (computed from the previous round)
    int protocol_uid = 2;
    right_keys[protocol_uid] = r1_results.right;

    auto current_rightkey = r1_results.right;

    Botan::PointGFp Y;
    db_get_public_value(r2_messages[wrapindex(protocol_uid + 1)], Y);

    current_rightkey = Y + current_rightkey;
    right_keys[wrapindex(protocol_uid + 1)] = (current_rightkey);

    for (int i = 2; i <= joining_participants.size() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        // debug(("idx: " + std::to_string(idx)).c_str());
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = Y + current_rightkey;

        right_keys[idx] = current_rightkey;
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

    shared_secret = group.zero_point();
    for (auto kr : right_keys) {
        *shared_secret += kr.second;
    }

    participants = MOV(joining_participants);
    joining_participants.clear();
    gkexchg_finished();
}

void Dutta_Barua_GKE::computeKey()
{
    for (auto &[i, incoming] : r2_messages) {
        partial_session_id.push_back(user_id{uid_to_protocol_uid(incoming.u), incoming.d});
    }
    auto wrapindex = [sz = joining_participants.size()](int i) {
        return ((i - 1) % sz) + 1;  // wraparound respecting 1-indexing of dutta barua paper
    };

    std::map<int, Botan::PointGFp> right_keys;

    // we can immediately add our own right key (computed from the previous round)
    int protocol_uid = uid_to_protocol_uid(uid.u);
    right_keys[protocol_uid] = r1_results.right;

    auto current_rightkey = r1_results.right;

    Botan::PointGFp Y;
    db_get_public_value(r2_messages[wrapindex(protocol_uid + 1)], Y);

    current_rightkey = Y + current_rightkey;
    right_keys[wrapindex(protocol_uid + 1)] = (current_rightkey);

    for (int i = 2; i <= joining_participants.size() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        // debug(("idx: " + std::to_string(idx)).c_str());
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = Y + current_rightkey;

        right_keys[idx] = current_rightkey;
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

    shared_secret = group.zero_point();
    for (auto kr : right_keys) {
        *shared_secret += kr.second;
    }

    participants = MOV(joining_participants);
    joining_participants.clear();
    gkexchg_finished();
}

void Dutta_Barua_GKE::prepare_join()
{
    // Cleanup any intermediate stuff
    r1_results.left = {};
    r1_results.right = {};
    r1_messages.left = {};
    r1_messages.right = {};

    r2_finished = false;
    r2_messages.clear();

    auto mgr = dynamic_cast<KeyExchangeManager *>(this);  // probably just implement this in parent
    assert(mgr);
    mgr->current_earliest_r1start = {};
}

void Dutta_Barua_GKE::start_join()
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::keyexchg_successful);
    state = STATE::keyexchg_in_progress;

    prepare_join();

    if (participants.size() < 3) {
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
        x_i.reset();
        return round1();
    }

    joining_participants.insert(joining_participants.begin(), participants.back());
    joining_participants.insert(joining_participants.begin(), *(participants.begin() + 1));
    joining_participants.insert(joining_participants.begin(), participants.front());

    bool first = participants.front() == uid.u;
    bool second = participants[1] == uid.u;
    bool last = participants.back() == uid.u;

    if (!first && !last) {
        // initialize x_i from shared_secret
        auto kdf = Botan::get_kdf("KDF2(SHA-256)");
        auto encoded = shared_secret->encode(Botan::PointGFp::Compression_Type::UNCOMPRESSED);
        x_i = Botan::BigInt(encoded);
    }
    if (first || second || last) {
        getRole() = JOIN_ROLE::active;
        debug("join:active r1 started");
        return round1();
    } else if (std::binary_search(joining_participants.begin(), joining_participants.end(),
                                  uid.u)) {
        getRole() = JOIN_ROLE::joining;
        debug("joining group");
        return round1();
    } else
        getRole() = JOIN_ROLE::passive;
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
    auto encoded = shared_secret->encode(Botan::PointGFp::Compression_Type::UNCOMPRESSED);
    Botan::secure_vector<uint8_t> secure_encoded(
        encoded.data(),
        encoded.data() + encoded.size());  // FIXME: this is stupid. can it even be fixed??!

    return kdf->derive_key(key_size, secure_encoded);
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
