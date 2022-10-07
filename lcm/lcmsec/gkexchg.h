#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <botan/bigint.h>
#include <botan/dh.h>

#include <cassert>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto_wrapper.h"
#include "dsa.h"
#include "lcm.h"
#include "lcmsec/eventloop.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN_response.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

/*
 * there is  abit of more refactoring to do:
 *  * only use protocol uid's in this class instead of trnaslating
 *  * maybe use ragel to implement the state machine - in any case the state logic is not finished
 * at this point
 */
class Dutta_Barua_GKE {
  public:
    Dutta_Barua_GKE(int uid);
    virtual ~Dutta_Barua_GKE();

  public:
    enum class STATE : int {
        keyexchg_not_started = 0,
        round1_done,
        keyexchg_successful,

        join_in_progress,
        ENUMSIZE
    };
    inline const char *state_name(STATE s)
    {
        static const char *STATE_names[] = {"keyexchg_not_started", "round1_done",
                                            "keyexchg_successful", "join_in_progress"};
        static_assert(sizeof(STATE_names) / sizeof(char *) == static_cast<int>(STATE::ENUMSIZE),
                      "sizes dont match");
        return STATE_names[static_cast<int>(s)];
    }

    enum class JOIN_ROLE : int { 
        joining = 0, 
        active, 
        passive, 
        ENUMSIZE };
    inline const char *join_role_name(JOIN_ROLE r)
    {
        static const char *join_role_names[] = {"joining", "active", "passive"};
        static_assert(
            sizeof(join_role_names) / sizeof(char *) == static_cast<int>(JOIN_ROLE::ENUMSIZE),
            "sizes dont match");
        return join_role_names[static_cast<int>(r)];
    }

    virtual void sign_and_dispatch(Dutta_Barua_message &msg) = 0;
    virtual void gkexchg_finished() = 0;          // hook for child to override
    [[nodiscard]] virtual STATE &getState() = 0;  // hook for child to override
    [[nodiscard]] virtual inline JOIN_ROLE &getRole() = 0;

    void round1();
    void round2();
    void computeKey();

    void prepare_join();
    void join_existing();
    void join_new();

    struct user_id {
        int u, d;
    };
    user_id uid;

    // stateful members needed across multiple rounds of the keyexchange //
    std::vector<int> joining_participants;
    std::vector<int> participants;

    std::optional<std::chrono::steady_clock::time_point> last_answered_join{};

    struct {
        Botan::BigInt left;   // K_i^l
        Botan::BigInt right;  // K_i^r
    } r1_results;

    bool r2_finished = false;

    std::vector<user_id> partial_session_id;

    std::optional<Botan::BigInt> x_i;
    static constexpr int group_bitsize = 4096;
    Botan::DL_Group group{"modp/ietf/" + std::to_string(group_bitsize)};

    std::map<int, Dutta_Barua_message> r2_messages;
    struct {
        std::optional<Dutta_Barua_message> left;   // message from U_{i-1}
        std::optional<Dutta_Barua_message> right;  // message from U_{i+1}
    } r1_messages;

    std::optional<Botan::BigInt> shared_secret;
    bool has_new_key; //FIXME synchronization?

    virtual void debug(std::string msg) = 0;

    // ------ Helper methods --------//
    // Map virtual user ids (counting - sequentially - all the user ID's that are participating in
    // the protocol) to the real ones (the ones that are configured in the certificates, and are
    // part of the messages that are transmitted) NOTE: both use 1-indexing
    //
    // THIS METHOD AS IT STANDS MAY ONLY BE CALLED WITH VALID UID's
    inline int uid_to_protocol_uid(int uid)
    {
        auto it = std::lower_bound(joining_participants.cbegin(), joining_participants.cend(),
                                   uid);  // take advantage of sorted array and do a binary search
        if (it == joining_participants.cend()) {
            throw std::runtime_error("error: found no protocol uid for uid " + std::to_string(uid));
        } else
            return it - joining_participants.begin() +
                   1;  // else, return the index that we found (but use 1-indexing)
    }

    inline int protocol_uid_to_uid(int proto_uid)
    {
        // the protocol user ID's are the indices of participants
        //  NOTE: it is necessary to convert from and to 1-indexing here
        return joining_participants.at(proto_uid - 1) + 1;
    }
};

class KeyExchangeManager : public Dutta_Barua_GKE {
  public:
    KeyExchangeManager(capability cap, eventloop &ev_loop, lcm::LCM &lcm);

    void JOIN();
    void JOIN_response(int64_t requested_r1start);
    void onJOIN(const Dutta_Barua_JOIN *join_msg);
    void on_JOIN_response(const Dutta_Barua_JOIN_response *join_response);

    void on_msg(const Dutta_Barua_message *msg);

    inline bool hasNewKey() {
        if(has_new_key) {
            has_new_key = false;
            return true;
        }
        return false;
    }

    STATE state{STATE::keyexchg_not_started};
    JOIN_ROLE role;

    Botan::secure_vector<uint8_t> get_session_key(size_t key_size);

    std::string
        groupexchg_channelname;  // the channelname used for the management of the keyexchange

    // Not used for publishing, but to check permissions of the certificates on incoming messages
    std::optional<std::string> channelname;
    std::string mcastgroup;

    std::chrono::milliseconds JOIN_waitperiod = std::chrono::milliseconds(
        125);  // delay start of round1 after the first join() by this time
    std::chrono::milliseconds JOIN_rebroadcast_interval = std::chrono::milliseconds(50);
    std::chrono::milliseconds JOIN_response_avg_delay = std::chrono::milliseconds(50);
    std::optional<std::chrono::steady_clock::time_point> current_earliest_r1start = {};

    [[nodiscard]] virtual inline STATE &getState() override { return state; }

    [[nodiscard]] virtual inline JOIN_ROLE &getRole() override
    {
        assert(state == Dutta_Barua_GKE::STATE::join_in_progress);
        return role;
    }

  private:
    eventloop &evloop;
    lcm::LCM &lcm;

    inline bool is_neighbour(const Dutta_Barua_message *msg)
    {
        return is_left_neighbour(msg) || is_right_neighbour(msg);
    }

    inline bool is_left_neighbour(const Dutta_Barua_message *msg)
    {
        // FIXME when synchronization is done
        int my_uid = uid_to_protocol_uid(uid.u);
        int their_uid = uid_to_protocol_uid(msg->u);
        int neighbour = (my_uid == 1) ? joining_participants.size() : my_uid - 1;
        return their_uid == neighbour;
    }

    inline bool is_right_neighbour(const Dutta_Barua_message *msg)
    {
        int my_uid = uid_to_protocol_uid(uid.u);
        int their_uid = uid_to_protocol_uid(msg->u);

        int neighbour = (my_uid == joining_participants.size()) ? 1 : my_uid + 1;
        return their_uid == neighbour;
    }

    void sign_and_dispatch(Dutta_Barua_message &msg) override;
    static void db_get_public_value(const Dutta_Barua_message &msg, Botan::BigInt &bigint);

    inline void debug(std::string msg) override
    {
        CRYPTO_DBG("u%i: ch:%s %s\n", uid.u, groupexchg_channelname.c_str(), msg.c_str());
    }

    inline void gkexchg_finished() override
    {
        state = STATE::keyexchg_successful;
        evloop.channel_finished();
        current_earliest_r1start = std::nullopt;
        has_new_key = true;
    }

    std::chrono::steady_clock::time_point &earliest_time(
        std::chrono::steady_clock::time_point &tp,
        std::optional<std::chrono::steady_clock::time_point> &opt_tp)
    {
        if (!opt_tp || tp < opt_tp) {
            return tp;
        }
        return opt_tp.value();
    }

    std::chrono::steady_clock::time_point conditionally_create_task(
        std::chrono::steady_clock::time_point &tp, eventloop::task_t task)
    {
        if (!current_earliest_r1start || tp < current_earliest_r1start) {
            evloop.push_task(MOV(task));
            current_earliest_r1start = tp;
            return tp;
        }
        return *current_earliest_r1start;
    }
    std::chrono::steady_clock::time_point conditionally_create_r1_task(
        std::chrono::steady_clock::time_point &tp)
    {
        return conditionally_create_task(tp, [this] { round1(); });
    }
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


    bool hasNewKey() {
        return impl.hasNewKey();
    }
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
