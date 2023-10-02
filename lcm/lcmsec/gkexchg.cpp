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
#include <chrono>
#include <cstdlib>
#include <numeric>
#include <iterator>
#include <sstream>

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
    debug_channelname = channelname.value_or("gkechg_g");

    // start join later, to avoid race condition in which we JOIN, accept the JOIN, and finish the
    // gkexchg before being subscribed with our LCM instance and able to receive on the management
    // channel
    add_task(std::chrono::high_resolution_clock::now(), [this] { JOIN(); });

    // prepare a timeout task - will not be called in case of success of the group key exchange,
    // since in that case the invocation count will have increased already
    add_task(std::chrono::high_resolution_clock::now() + gkexchg_timeout, [this] {
        std::cerr << channelname.value_or("nullopt")
                  << ": groupkeyexchange timed out on channel, restarting..." << std::endl;
        gkexchg_failure();
    });
}

Dutta_Barua_GKE::Dutta_Barua_GKE(int uid) : uid{uid, 1} {}
Dutta_Barua_GKE::~Dutta_Barua_GKE() {}

template <typename message_t>
static void sign_msg(message_t &msg)
{
    auto &signer = DSA_signer::getInst();
    msg.sig = signer.sign(msg);
    msg.sig_size = msg.sig.size();
}

void KeyExchangeManager::publish(Dutta_Barua_message &msg)
{
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

void KeyExchangeManager::add_task(eventloop::timepoint_t tp, std::function<void()> f)
{
    auto task = [=, this, invo_cnt = uid.d, f = MOV(f)]() {
        // Since a handcrafted cooperative multitasking approach is used for doing the keyagreement
        // on multiple channels simultaneously, we need to use the tracy-facilites for fibers
        TracyFiberEnter(debug_channelname.c_str());

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
        TracyFiberLeave;
    };
    evloop.push_task(tp, task);
};

void KeyExchangeManager::add_task(std::function<void()> f)
{
    add_task(std::chrono::high_resolution_clock::now(), MOV(f));
};

void KeyExchangeManager::on_msg(const Dutta_Barua_message *msg)
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_in_progress, STATE::consensus_phase);
    if (state == STATE::consensus_phase) {
        start_join();
    }

    auto &verifier = DSA_verifier::getInst();
    if (!verifier.verify(msg, mcastgroup, channelname)) {
        debug("signature verification failed");
        return;
    }

    // in case of nonexistent map key (fresh user), int default construtcs to 0 - works out since d
    // starts at 1 for fresh user
    if (msg->d <= session_id[msg->u]) {  // msg not valid: instance id not fresh
        debug(std::string("instance id ") + std::to_string(msg->d) + " not fresh for user " +
              std::to_string(msg->u) + ". must be larger than " +
              std::to_string(session_id[msg->u]) + ". Dropping Dutta_Barua_message.");
        return;
        //Note that replaying a message of the current round possible, but it will not have an effect
    }

    int remote_uid = managed_state.uid_to_protocol_uid(msg->u);

    if (role == JOIN_ROLE::passive) {
        if (msg->round == 1) {
            int left = 1;
            int right = 3;
            auto remote_proto_uid = managed_state.uid_to_protocol_uid(msg->u);
            if (remote_proto_uid == left)
                if(!r1_messages.left)
                    r1_messages.left = *msg;
            if (remote_proto_uid == right)
                if(!r1_messages.right)
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
    // A Join should be permitted even if we are already in the consensus phase; since we might have
    // observed an earlier join(advanced to the consensus phase); but not had the opportunity to
    // dispatchn our own yet
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::consensus_phase);
    if (state != STATE::consensus_phase) {
        TracyCZoneN(ctx, "group key agreement", 1);
        TRACY_ASSIGN_CTX(gkexchg_context, ctx);
        if (state == STATE::keyexchg_not_started)
            role = JOIN_ROLE::joining;
        else
            role = JOIN_ROLE::active;

        state = STATE::consensus_phase;
    }
    ZoneScopedN("JOIN");

    Dutta_Barua_JOIN join;

    auto requested_r1start = std::chrono::high_resolution_clock::now() + JOIN_waitperiod;
    auto requested_r1start_us =
        std::chrono::time_point_cast<std::chrono::microseconds>(requested_r1start);
    join.timestamp_r1start_us = requested_r1start_us.time_since_epoch().count();

    auto &cert = DSA_certificate_self::getInst().cert;
    join.certificate.x509_certificate_BER = cert.BER_encode();
    join.certificate.cert_size = join.certificate.x509_certificate_BER.size();

    sign_msg(join);

    std::string ch = std::string("join") + groupexchg_channelname;
    lcm.publish(ch, &join);
}

void KeyExchangeManager::JOIN_response()
{
    // Dispatching a join response is only valid if we are in the consensus phase
    LCMSEC_CHECKSTATE(STATE::consensus_phase);
    TracyCZoneN(tracy_ctx, "JOIN_response", 1);

    // Since a JOIN_reponse either answers all join's or notices that they have already been
    // answered, the observed_joins are cleared every time.
    auto atexit = finally([&] { observed_joins.clear(); });

    // First build a vector of all the joins that have not yet been answered, i.e. the ones that we
    // have observed, but are not part of our managed_state. we can improve the managed state by
    // adding them to it, since the managed_state is the best consensus candidate observed so far.
    std::vector<const joindesc *> unanswered_joins;
    for (int i = 0; i < observed_joins.size(); i++) {
        int uid_of_join = observed_joins[i].uid;
        if (!managed_state.exists_in_joining(uid_of_join)) {
            unanswered_joins.push_back(&observed_joins.front() + i);
        }
    }

    if (unanswered_joins.empty()) {
        TracyCZoneEnd(tracy_ctx);
        return;  // All joins answered: we cannot improve the managed_state
    }

    // Note that we do not need to test (in this method) whether or not we are a good candidate to
    // dispatch a join_response

    // Either we are a better candidate than the other join responses that we have so far observed -
    // in which case we will have rejected them, thus, joining_participants will *not* contain
    // uid_of join - or we are not, in which case we will have accepted their  response and thus
    // uid_of_join *will* be part of joining_participants.

    auto &verif = DSA_verifier::getInst();
    Dutta_Barua_JOIN_response response{0};
    capability cap_template(mcastgroup, channelname, {});
    enum class consensus_role { participant, joining };

    auto add_cert_to_response = [&](int uid, consensus_role r) {
        cap_template.uid = uid;
        auto cert_ber = verif.get_certificate(cap_template);
        if (!cert_ber)
            throw uid_unknown("found no certificate for uid " + std::to_string(uid) +
                              " in certificate_store");
        Dutta_Barua_cert db_cert{0};
        db_cert.x509_certificate_BER = MOV(*cert_ber);
        db_cert.cert_size = db_cert.x509_certificate_BER.size();

        if (r == consensus_role::joining) {
            if (uid == this->uid.u) {
                return;  // Add our own cert somewhere else
            } else
                response.certificates_joining.push_back(MOV(db_cert));
        } else if (r == consensus_role::participant)
            if (uid == this->uid.u) {
                return;  // Add our own cert somewhere else
            } else
                response.certificates_participants.push_back(MOV(db_cert));
        else
            assert(false);
    };

    const auto &self = DSA_certificate_self::getInst();
    response.self.x509_certificate_BER = self.cert.BER_encode();
    response.self.cert_size = response.self.x509_certificate_BER.size();

    // This is a bit hacky unfortunately - improve later - join role is initially set during the
    // transition to the consensus_phase state (but only to either active or passive) We use this
    // information here, then later use join_role differently: to differentiate between active,
    // passive and joining participants
    assert(role != JOIN_ROLE::invalid);
    assert(role != JOIN_ROLE::passive);
    if (role == JOIN_ROLE::joining) {
        response.role = response.ROLE_JOINING;
    } else if (role == JOIN_ROLE::active) {
        response.role = response.ROLE_PARTICIPANT;
    } else
        assert(false);

    debug("setting role in join_response to : " + std::string(join_role_name(role)));

    for (const joindesc *e : unanswered_joins) {
        add_cert_to_response(e->uid, consensus_role::joining);
    }

    for (int u : managed_state.get_joining()) {
        add_cert_to_response(u, consensus_role::joining);
    }
    for (int u : managed_state.get_participants()) {
        add_cert_to_response(u, consensus_role::participant);
    }

    response.joining = response.certificates_joining.size();
    response.participants = response.certificates_participants.size();

    int64_t earliest_requested_r1start_us =
        std::accumulate(unanswered_joins.begin(), unanswered_joins.end(), INT64_MAX,
                        [](int64_t a, const joindesc *b) { return std::min(b->req_r1start, a); });
    // Same note as above: it suffices to set this field in the response
    std::chrono::high_resolution_clock::time_point req_r1start{
        std::chrono::microseconds(earliest_requested_r1start_us)};
    response.timestamp_r1start_us = std::chrono::time_point_cast<std::chrono::microseconds>(
                                        earliest_time(req_r1start, managed_state.r1start()))
                                        .time_since_epoch()
                                        .count();

    static constexpr int td_range_us = 20000;
    srand(std::chrono::system_clock::now().time_since_epoch().count());
    int us_offset = (std::rand() % (2 * td_range_us)) - td_range_us;
    response.timestamp_r1start_us += us_offset;

    sign_msg(response);
    std::string ch = std::string("join_resp") + groupexchg_channelname;

    debug("dispatching join_response with {" +
          std::to_string(response.participants + (response.role == response.ROLE_PARTICIPANT)) +
          ", " + std::to_string(response.joining + (response.role == response.ROLE_JOINING)) + "}");

    // Update managed state according to the join_response we are transmitting.
    for (const joindesc *e : unanswered_joins) {
        managed_state.add_joining(e->uid);
    }

    TracyCZoneEnd(tracy_ctx);

    lcm.publish(ch, &response);
}

void KeyExchangeManager::on_JOIN_response(const Dutta_Barua_JOIN_response *join_response)
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::consensus_phase,
                      STATE::keyexchg_successful);
    if (state != STATE::consensus_phase) {
        TracyCZoneN(ctx, "group key agreement", 1);
        TRACY_ASSIGN_CTX(gkexchg_context, ctx);

        state = STATE::consensus_phase;
        if (state == STATE::keyexchg_not_started)
            role = JOIN_ROLE::joining;
        else
            role = JOIN_ROLE::active;

        state = STATE::consensus_phase;
    }

    ZoneScopedN("on_JOIN_response");

    auto dbg_reject = [=, this](std::string msg) {
        debug("rejecting join_response with {" +
              std::to_string(join_response->participants +
                             (join_response->role == join_response->ROLE_PARTICIPANT)) +
              ", " +
              std::to_string(join_response->joining +
                             (join_response->role == join_response->ROLE_JOINING)) +
              "} :" + msg);
    };
    auto dbg_accept = [=, this] {
        debug("accepting join_response with {" +
              std::to_string(join_response->participants +
                             (join_response->role == join_response->ROLE_PARTICIPANT)) +
              ", " +
              std::to_string(join_response->joining +
                             (join_response->role == join_response->ROLE_JOINING)) +
              "}");
    };

    std::vector<int> candidate_participants;
    std::vector<int> candidate_joining;

    auto &verifier = DSA_verifier::getInst();
    auto remote_uid = verifier.add_certificate(join_response->self, mcastgroup, channelname);
    if (!remote_uid)
        return;

    if (!verifier.verify(join_response, mcastgroup, channelname, *remote_uid))
        return;

    if (join_response->role == join_response->ROLE_JOINING) {
        candidate_joining.push_back(*remote_uid);
    } else if (join_response->role == join_response->ROLE_PARTICIPANT) {
        candidate_participants.push_back(*remote_uid);
    } else {
        throw remote_faulty("wrong role parameter in join_response");
    }

    // First: achieve consensus on participants, while adding all certificants that we have not
    // yet observed
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

    // Second: achieve consensus on joining participants, while adding all certificants that we
    // have not yet observed
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
    std::chrono::high_resolution_clock::time_point requested_starting_time{
        std::chrono::microseconds(join_response->timestamp_r1start_us)};
    if (!managed_state.process_timestamp(requested_starting_time)) {
        dbg_reject(
            "response.participants == participants && response.joining == joining but "
            "requested_starting_time > current_earliest_r1start");
        return;
    }
    dbg_accept();

    add_task(requested_starting_time, [this] { start_join(); });
}

void KeyExchangeManager::onJOIN(const Dutta_Barua_JOIN *join_msg)
{
    LCMSEC_CHECKSTATE(STATE::keyexchg_not_started, STATE::consensus_phase,
                      STATE::keyexchg_successful);
    if (checkState(STATE::keyexchg_not_started, STATE::keyexchg_successful)) {
        TracyCZoneN(ctx, "group key agreement", 1);
        TRACY_ASSIGN_CTX(gkexchg_context, ctx);

        state = STATE::consensus_phase;
        if (state == STATE::keyexchg_not_started)
            role = JOIN_ROLE::joining;
        else
            role = JOIN_ROLE::active;

        state = STATE::consensus_phase;
    }

    ZoneScopedN("on_JOIN");

    auto &verifier = DSA_verifier::getInst();
    auto remote_uid = verifier.add_certificate(join_msg->certificate, mcastgroup, channelname);
    if (!remote_uid)
        return;

    if (!verifier.verify(join_msg, mcastgroup, channelname, *remote_uid))
        return;

    // dispatch JOIN_response at a random time
    using namespace std::chrono;
    int avgdelay_count_us = duration_cast<microseconds>(JOIN_response_avg_delay).count();
    int variance_us = duration_cast<microseconds>(JOIN_response_variance).count();
    srand(std::chrono::system_clock::now().time_since_epoch().count());
    int us_offset = (std::rand() % (2 * variance_us)) - variance_us;
    auto response_timepoint =
        high_resolution_clock::now() + microseconds(avgdelay_count_us) + microseconds(us_offset);
    debug("sending response to (" + std::to_string(remote_uid.value()) + ") in " +
          std::to_string(
              (duration_cast<milliseconds>(response_timepoint - high_resolution_clock::now()))
                  .count()) +
          "milliseconds");
    observed_joins.push_back(joindesc{remote_uid.value(), join_msg->timestamp_r1start_us});
    add_task(response_timepoint, [this] { JOIN_response(); });
}

static std::ostringstream uid_vector_string(const std::vector<int> &v)
{
    std::ostringstream ss;
    if (!v.empty()) {
        std::copy(v.begin(), v.end() - 1, std::ostream_iterator<int>(ss, ","));
        ss << v.back();
    }
    return ss;
}

void Dutta_Barua_GKE::round1()
{
    ZoneScopedN("round1");
    auto &verifier = DSA_verifier::getInst();

    debug(uid_vector_string(managed_state.uid_view().get()).str());

    debug(("------ starting Dutta_Barua_GKE with " +
           std::to_string(managed_state.active_participants()) + "participants ------- ")
              .c_str());
    partial_session_id.clear();
    partial_session_id[uid.u] = uid.d;

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
    assert(!X.is_zero());

    Dutta_Barua_message msg;

    // For sending messages; use the true user_ids that correspond to the capabilities
    // configured in the protocol
    msg.u = this->uid.u;
    msg.round = 1;
    db_set_public_value(msg, X);
    msg.d = this->uid.d;

    sign_msg(msg);
    publish(msg);
}

void Dutta_Barua_GKE::round2()
{
    ZoneScopedN("round2");
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

        Dutta_Barua_message msg;
        msg.u = uid.u;
        msg.round = 2;
        db_set_public_value(msg, Y);
        msg.d = uid.d;

        sign_msg(msg);
        publish(msg);
    }
    r2_finished = true;
}

void Dutta_Barua_GKE::computeKey_passive()
{
    std::map<int, Botan::PointGFp> right_keys;
    TracyCZoneN(tracy_ctx, "computeKey_passive", 1);

    auto wrapindex = [sz = managed_state.active_participants()](int i) {
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

    for (int i = 2; i <= managed_state.active_participants() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        // debug(("idx: " + std::to_string(idx)).c_str());
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = Y + current_rightkey;

        right_keys[idx] = current_rightkey;
    }

    // correctness check
    int lastindex = wrapindex(protocol_uid + managed_state.active_participants() - 1);
    bool correctness = right_keys[lastindex] == r1_results.left;

    if (correctness)
        debug("group key exchange successful!");
    else {
        TracyCZoneEnd(tracy_ctx);
        throw keyagree_exception("key computation correctness check failed");
    }

    shared_secret = group.zero_point();
    for (auto kr : right_keys) {
        *shared_secret += kr.second;
    }

    TracyCZoneEnd(tracy_ctx);
    managed_state.gke_success();
    gkexchg_finished();
}

void Dutta_Barua_GKE::computeKey()
{
    TracyCZoneN(tracy_ctx, "computeKey_passive", 1);
    for (auto &[i, incoming] : r2_messages) {
        partial_session_id[incoming.u] = incoming.d;
    }
    auto wrapindex = [sz = managed_state.active_participants()](int i) {
        return ((i - 1) % sz) + 1;  // wraparound respecting 1-indexing of dutta barua paper
    };

    std::map<int, Botan::PointGFp> right_keys;

    // we can immediately add our own right key (computed from the previous round)
    int protocol_uid = managed_state.uid_to_protocol_uid(uid.u);
    right_keys[protocol_uid] = r1_results.right;

    auto current_rightkey = r1_results.right;

    Botan::PointGFp Y;
    db_get_public_value(r2_messages[wrapindex(protocol_uid + 1)], Y);

    current_rightkey = Y + current_rightkey;
    right_keys[wrapindex(protocol_uid + 1)] = (current_rightkey);

    for (int i = 2; i <= managed_state.active_participants() - 1; i++) {
        int idx = wrapindex(i + protocol_uid);
        // debug(("idx: " + std::to_string(idx)).c_str());
        assert(r2_messages.count(idx) == 1);
        db_get_public_value(r2_messages[idx], Y);
        current_rightkey = Y + current_rightkey;

        right_keys[idx] = current_rightkey;
    }

    // correctness check
    int lastindex = wrapindex(protocol_uid + managed_state.active_participants() - 1);
    bool correctness = right_keys[lastindex] == r1_results.left;

    TracyCZoneEnd(tracy_ctx);
    if (correctness)
        debug("group key exchange successful!");
    else {
        throw keyagree_exception("key computation correctness check failed");
    }

    shared_secret = group.zero_point();
    for (auto kr : right_keys) {
        *shared_secret += kr.second;
    }
    session_id = partial_session_id;

    gkexchg_finished();
}

void Dutta_Barua_GKE::cleanup_intermediates()
{
    x_i = std::nullopt;
    // Cleanup any intermediate stuff
    r1_results.left = {};
    r1_results.right = {};
    r1_messages.left = {};
    r1_messages.right = {};

    r2_finished = false;
    r2_messages.clear();
}

void Dutta_Barua_GKE::start_join()
{
    LCMSEC_CHECKSTATE(STATE::consensus_phase);
    managed_state.prepare_join();
    state = STATE::keyexchg_in_progress;

    if (managed_state.num_participants() < 3) {
        x_i.reset();
        return round1();
    }

    const auto &participants = managed_state.get_participants();
    bool first = participants.front() == uid.u;
    bool second = participants[1] == uid.u;
    bool last = participants.back() == uid.u;

    assert(!x_i);
    auto gen_xi_from_shared_secret = [&] {
        // initialize x_i from shared_secret
        assert(shared_secret);
        auto encoded = shared_secret->encode(Botan::PointGFp::Compression_Type::UNCOMPRESSED);
        x_i = Botan::BigInt(encoded);
    };

    if (first || second || last) {
        if (second)
            gen_xi_from_shared_secret();
        getRole() = JOIN_ROLE::active;
        return round1();
    } else if (managed_state.exists_in_joining(uid.u)) {
        getRole() = JOIN_ROLE::joining;
        return round1();
    } else {
        gen_xi_from_shared_secret();
        getRole() = JOIN_ROLE::passive;
    }
}

void KeyExchangeManager::gkexchg_failure()
{
    auto atexit = finally([&] { TracyCZoneEnd(gkexchg_context); });
    ZoneScopedN("gkexchg_failure");

    state = STATE::keyexchg_not_started;
    role = JOIN_ROLE::invalid;
    uid.d++;
    cleanup_intermediates();
    managed_state.gke_failure();
    add_task(std::chrono::high_resolution_clock::now(), [this] { JOIN(); });
}
void KeyExchangeManager::gkexchg_finished()
{
    auto atexit = finally([&] { TracyCZoneEnd(gkexchg_context); });
    ZoneScopedN("gkexchg_success");

    state = STATE::keyexchg_successful;
    role = JOIN_ROLE::invalid;
    uid.d++;
    evloop.channel_finished();
    has_new_key = true;
    cleanup_intermediates();
    managed_state.gke_success();
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
    std::vector<uint8_t> encoded = shared_secret->encode(Botan::PointGFp::Compression_Type::UNCOMPRESSED);

    // set salt and label to empty vector. This is the same thing that the kdf->encode(size_t,
    // Botan::secure_vector<uint8_t>) overload does, however, it cannot deal with an std::vector.
    // Converting vectors is not possible without copying, so we do this instead
    static const std::vector<uint8_t> empty;

    return kdf->derive_key(key_size, MOV(encoded), empty, empty);
}

KeyExchangeLCMHandler::KeyExchangeLCMHandler(capability cap, eventloop &ev_loop, lcm::LCM &lcm)
    : impl(cap, ev_loop, lcm){};

void KeyExchangeLCMHandler::handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                          const Dutta_Barua_message *msg)
{
    TracyFiberEnter(impl.debug_channelname.c_str());
    try {
        impl.on_msg(msg);
    } catch (keyagree_exception &e) {
        std::cerr << "keyagree failed on channel" << channelname() + " with: " << e.what()
                  << " ! Restarting Key agreement...." << std::endl;
        impl.gkexchg_failure();
    } catch (Botan::Exception &e) {
        std::cerr << "keyagree failed on channel" << channelname()
                  << " with BOTAN Exception: " << e.what() << " ! Restarting Key agreement...."
                  << std::endl;
        impl.gkexchg_failure();
    }
    TracyFiberLeave;
}

void KeyExchangeLCMHandler::handle_JOIN(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                        const Dutta_Barua_JOIN *join_msg)
{
    TracyFiberEnter(impl.debug_channelname.c_str());
    try {
        impl.onJOIN(join_msg);
    } catch (keyagree_exception &e) {
        std::cerr << "keyagree failed on channel" << channelname() + " with: " << e.what()
                  << " ! Restarting Key agreement...." << std::endl;
        impl.gkexchg_failure();
    } catch (Botan::Exception &e) {
        std::cerr << "keyagree failed on channel" << channelname()
                  << " with BOTAN Exception: " << e.what() << " ! Restarting Key agreement...."
                  << std::endl;
        impl.gkexchg_failure();
    }
    TracyFiberLeave;
}

void KeyExchangeLCMHandler::handle_JOIN_response(const lcm::ReceiveBuffer *rbuf,
                                                 const std::string &chan,
                                                 const Dutta_Barua_JOIN_response *join_response)
{
    TracyFiberEnter(impl.debug_channelname.c_str());
    try {
        impl.on_JOIN_response(join_response);
    } catch (keyagree_exception &e) {
        std::cerr << "keyagree failed on channel" << channelname() + " with: " << e.what()
                  << " ! Restarting Key agreement...." << std::endl;
        impl.gkexchg_failure();
    } catch (Botan::Exception &e) {
        std::cerr << "keyagree failed on channel" << channelname()
                  << " with BOTAN Exception: " << e.what() << " ! Restarting Key agreement...."
                  << std::endl;
        impl.gkexchg_failure();
    }
    TracyFiberLeave;
}

}  // namespace lcmsec_impl
