#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <botan/bigint.h>
#include <botan/dh.h>
#include <botan/ecdh.h>

#include <cassert>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto_wrapper.h"
#include "dsa.h"
#include "lcm.h"
#include "lcmsec/eventloop.hpp"
#include "lcmsec/lcmexcept.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN_response.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"
#include "lcmsec/managed_state.hpp"
#include "lcmsec/tracy_stubs.hpp"

namespace lcmsec_impl {

class Dutta_Barua_GKE {
  public:
    Dutta_Barua_GKE(int uid);
    virtual ~Dutta_Barua_GKE();

  protected:
    TracyCZoneCtx tracy_startupctx;
    TracyCZoneCtx tracy_attestctx;
    TracyCZoneCtx tracy_gkexchgctx;
    TracyCZoneCtx tracy_gkandattest_ctx;

  public:
    virtual void publish(Dutta_Barua_message &msg) = 0;
    virtual void gkexchg_finished() = 0;          // hook for child to override
    virtual void check_finished() = 0;
    [[nodiscard]] virtual STATE &getState() = 0;  // hook for child to override
    [[nodiscard]] virtual inline JOIN_ROLE &getRole() = 0;

    void round1();
    void round2();
    void computeKey();
    void computeKey_passive();

    void cleanup_intermediates();
    void start_join();

    struct user_id {
        int u, d;
    };
    user_id uid;

    struct {
        Botan::PointGFp left;   // K_i^l
        Botan::PointGFp right;  // K_i^r
    } r1_results;

    bool r2_finished = false;

    std::map<int, int> session_id;  // map u to d
    std::map<int, int> partial_session_id;

    std::optional<Botan::BigInt>
        x_i;  // no default constructor for DH_PrivateKey and it cannot be immediately initialized
    static constexpr int group_bitsize = 4096;
    static const Botan::EC_Group group;

    std::map<int, Dutta_Barua_message> r2_messages;
    struct {
        std::optional<Dutta_Barua_message> left;   // message from U_{i-1}
        std::optional<Dutta_Barua_message> right;  // message from U_{i+1}
    } r1_messages;

    std::optional<Botan::PointGFp> shared_secret;
    bool has_new_key;  // FIXME synchronization?

    virtual void debug(std::string msg) = 0;

    bool _checkState(STATE s) const { return (state == s) ? true : false; }
    template <typename STATE, typename... States>
    bool _checkState(STATE s, States... ss) const
    {
        return checkState(s) || checkState(ss...);
    }
    template <typename... States>
    bool checkState(States... ss) const
    {
        bool result = _checkState(ss...);
        // if (!result) {
        //     debug(std::string("invalid state ") + state_name(state));
        // }
        return result;
    }

  protected:
    std::optional<std::vector<uint8_t>> ra_prev_round_challenge;
    int64_t prev_r1start = {0};
    std::optional<std::vector<uint8_t>> chosen_challenge;

    GkexchgManagedState managed_state;
    STATE state{STATE::keyexchg_not_started};
    RA_STATE ra_state {RA_STATE::not_started};
    JOIN_ROLE role{JOIN_ROLE::invalid};

    static void db_set_public_value(Dutta_Barua_message &msg, const Botan::PointGFp &point);
    static void db_get_public_value(const Dutta_Barua_message &msg, Botan::PointGFp &point);
};

class KeyExchangeManager : public Dutta_Barua_GKE {

  public:
    // Recovery management:
    //
    // Recall that the primary strategy we use to avoid raceconditions are idempotent tasks that are
    // registered with our eventloop. This poses a challenge from the recovery standpoint
    // (restarting the keyexchange after something goes wrong) - even after the cleanup, there still
    // might be "old" tasks in our eventloop
    //
    // Solution:
    // Keep track of the current invocation count of our keyexchange. On Error, increase this count.
    // when tasks are called, ignore all those with an old invocation count
    void add_task(eventloop::timepoint_t tp, std::function<void()> f);
    void add_task(std::function<void()> f);

    KeyExchangeManager(capability cap, eventloop &ev_loop, lcm::LCM &lcm);

    void JOIN();
    void JOIN_response();
    void onJOIN(const Dutta_Barua_JOIN *join_msg);
    void on_JOIN_response(const Dutta_Barua_JOIN_response *join_response);

    void ra_attest_asnyc();
    void ra_attest_finish();

    void ra_verify(const Attestation_Evidence& evidence);

    void on_msg(const Dutta_Barua_message *msg);

    inline bool hasNewKey()
    {
        if (has_new_key) {
            has_new_key = false;
            return true;
        }
        return false;
    }

    Botan::secure_vector<uint8_t> get_session_key(size_t key_size);

    std::string
        groupexchg_channelname;  // the channelname used for the management of the keyexchange

    // Not used for publishing, but to check permissions of the certificates on incoming messages
    std::optional<std::string> channelname;
    std::string debug_channelname;
    std::string mcastgroup;

    const std::chrono::milliseconds JOIN_waitperiod = std::chrono::milliseconds(
        125);  // delay start of round1 after the first join() by this time
    const std::chrono::milliseconds JOIN_response_avg_delay = std::chrono::milliseconds(50);
    const std::chrono::milliseconds JOIN_response_variance = std::chrono::milliseconds(20);
    const std::chrono::milliseconds gkexchg_timeout = std::chrono::milliseconds(800);

    const std::chrono::milliseconds ra_t_variance = std::chrono::milliseconds(20);

    [[nodiscard]] virtual inline STATE &getState() override { return state; }

    [[nodiscard]] virtual inline JOIN_ROLE &getRole() override { return role; }

    void gkexchg_failure();

  private:
    eventloop &evloop;
    lcm::LCM &lcm;

    struct joindesc {
        int uid;
        int64_t req_r1start;
    };

    static constexpr int att_randomness_bytes = 32;
    std::vector<joindesc> observed_joins;
    std::vector<std::vector<uint8_t>> ra_challenges;
    Botan::secure_vector<uint8_t> joint_challenge;
    std::chrono::high_resolution_clock::time_point ra_tp_prev_invocation =
        std::chrono::high_resolution_clock::time_point::min();
    std::vector<int> verified_peers;

    struct joinresponse_ra_params {
        std::vector<std::array<uint8_t, att_randomness_bytes>> observed_challenges_buffer;
        int n_observed_challenges;

        int nodes_to_verify;
        enum class RA_ROLE {joining, representative, passive} ra_role;

        uint8_t challenge[att_randomness_bytes];
        uint8_t randomlocal[att_randomness_bytes];

        int64_t t_r1start;

        // copy into existing jr_ra_params while reusing memory if possible.
        void from_JOIN_Response(const Dutta_Barua_JOIN_response *from, int num_joining, int num_participants,
                                const KeyExchangeManager &mgr);

        // check whether challenge exists in observed_joins from the response; or is equal to the
        // challenge included in the accepted join response
        //
        // Note: we assume that observed challenges are not super big; so that it is more efficient
        // to compare with O(n) instead of sorting when inserting new elements
        bool lookup_challenge(const uint8_t *challenge, size_t challenge_sz,
                              const KeyExchangeManager &mgr);

        // reuse buffer for observed joins: add the chosen challenge to the end
        // NOTE: it is safe to call lookup_challenge after prep_joint_challenge
        void prep_joint_challenge(const KeyExchangeManager &mgr);
    };
    std::optional<joinresponse_ra_params> jr_ra_params;

    void publish(Dutta_Barua_message &msg) override;
    static void db_get_public_value(const Dutta_Barua_message &msg, Botan::BigInt &bigint);

    inline void debug(std::string msg) override
    {
        CRYPTO_DBG("u%i: ch:%s %s\n", uid.u, groupexchg_channelname.c_str(), msg.c_str());
    }

    void check_finished() override;
    void gkexchg_finished() override;
};

/**
 * @class Key_Exchange_Manager
 * @brief separate the interfacing with LCM from the key exchange implementation
 */
class KeyExchangeLCMHandler {
  public:
    KeyExchangeLCMHandler(capability cap, eventloop &ev_loop, lcm::LCM &lcm);

    void handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                       const Dutta_Barua_message *msg);

    void handle_JOIN(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                     const Dutta_Barua_JOIN *join_msg);
    void handle_JOIN_response(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                              const Dutta_Barua_JOIN_response *join_response);

    void handle_Attestation_Evidence(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                                     const Attestation_Evidence *evidence);

    bool hasNewKey() { return impl.hasNewKey(); }
    /*
     * deleted copy and move constructors
     * This is important since this class will be used as an lcm handler object. Thus, its
     * address must not not change (which prohibits the move constructor). For the copy
     * constructors, semantics would be unclear, so delete it as well
     */
    KeyExchangeLCMHandler(KeyExchangeLCMHandler &&) = delete;
    KeyExchangeLCMHandler(const KeyExchangeLCMHandler &) = delete;
    KeyExchangeLCMHandler &operator=(const KeyExchangeLCMHandler &) = delete;
    KeyExchangeLCMHandler &operator=(const KeyExchangeLCMHandler &&) = delete;

    inline Botan::secure_vector<uint8_t> get_session_key(size_t key_size)
    {
        return impl.get_session_key(key_size);
    }
    inline const std::string &channelname() { return impl.groupexchg_channelname; }
    inline ~KeyExchangeLCMHandler() {}

  private:
    KeyExchangeManager impl;
};

}  // namespace lcmsec_impl
#endif  // !GKEXCHG_H
