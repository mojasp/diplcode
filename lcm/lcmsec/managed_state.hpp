#ifndef MANAGED_STATE_HPP

#define MANAGED_STATE_HPP

// state manged by the RAFT-inspired gkexchg protocol
#include <algorithm>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <vector>

#include "lcmsec/crypto_wrapper.h"
#include "lcmsec/lcmsec_util.h"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN_response.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"
#include "lcmsec/protocol_uid.hpp"
#include "state.hpp"

namespace lcmsec_impl {

class GkexchgManagedState {
  public:
    using time_point = std::chrono::high_resolution_clock::time_point;

  private:
    bool locked{false};  // prevent modification of state during execution of GKE
    //
    /*------------------------
     *-the agreed-upon state--
     *-----------------------*/
    // It is required that joining_participants and participants are sorted
    // Also usefol for faster lookup (binary search)
    std::vector<int> joining_participants;
    std::vector<int> participants;
    std::optional<time_point> current_earliest_r1start = {};
    //-------------------//

    ProtoUidView proto_uid_view;

    // Simulate a coroutine in which
    //  first, candidate_participants is checked
    //  then, candidate_joining
    //  last, tp is checked.
    //
    // This struct holds the state needed for that coroutine
    struct _process_state {
        const std::vector<int> *candidate_participants;
        const std::vector<int> *candidate_joining;
        time_point tp;

        // simple state machine to ensure coroutine-like behaviour for the process* functions
        // allowed transitions:
        //  particpants->join->tp->participants
        //  join->participants
        //  participants  ->participants
        enum class STATE { participants, joining, tp };
        STATE next{STATE::participants};
    } process_state;

  public:
    
    //Add uid to joinin vector.
    //Intended to be called before transmitting a joinresponse
    void add_joining(int uid);

    /**
     * process_* :
     *  process a candidate for consensus (in terms of RAFT: decide whether to accept remote as
     *  leader)
     *
     * The process* functions must be called consecutively until one of them fails, in a
     * coroutine-like behaviour
     */

    // call this process_participant first
    //   candidate_participants must point to valid memory across all coroutine calls, until one of
    //   them returns false or process_timestamp is called
    [[nodiscard]] bool process_participant(const std::vector<int> *candidate_participants);
    // call process_joining second
    //   candidate_joining must be point to valid memory across all coroutine calls, until one of
    //   them returns false or process_timestamp is called
    [[nodiscard]] bool process_joining(const std::vector<int> *candidate_joining);
    // call process_timestamp third
    [[nodiscard]] bool process_timestamp(time_point tp);

    // lock the object for modifications and generate a uid_view - used during ongoing key agreement
    // to produce an immutable uid_view for that duration
    //
    // Will modify joining_participants
    void prepare_join();

    // reset after finishing group key exchange
    void gke_success();

    // reset after failing group key exchange - same, but don't append joining members to
    // participants
    void gke_failure();

    [[nodiscard]] const std::vector<int> &get_participants() const;
    [[nodiscard]] inline int num_participants() const { return participants.size(); }

    [[nodiscard]] const std::vector<int> &get_joining() const;
    [[nodiscard]] inline int num_joining() const { return joining_participants.size(); }

    [[nodiscard]] std::optional<std::chrono::high_resolution_clock::time_point> r1start() const;

    [[nodiscard]] bool exists_in_participants(int uid) const;
    [[nodiscard]] bool exists_in_joining(int uid) const;

    [[nodiscard]] inline bool is_locked() const { return locked; }

    /*
     * The following functions may only be called if is_locked() is true; i.e., consensus is reached
     * and now < r1start + ε
     */
    // Map virtual user ids (counting - sequentially - all the user ID's that are participating in
    // the protocol) to the real ones (the ones that are configured in the certificates, and are
    // part of the messages that are transmitted) NOTE: both use 1-indexing
    [[nodiscard]] int uid_to_protocol_uid(int uid) const;

    /**
     * @brief return the number of participants that take active role in the groupkeyexchange
     */
    [[nodiscard]] int active_participants() const;
    [[nodiscard]] ProtoUidView const& uid_view() const;
    [[nodiscard]] bool is_neighbour(int uid, const Dutta_Barua_message *msg) const;
    [[nodiscard]] bool is_left_neighbour(int uid, const Dutta_Barua_message *msg) const;
    [[nodiscard]] bool is_right_neighbour(int uid, const Dutta_Barua_message *msg) const;
};

}  // namespace lcmsec_impl
#endif /* end of include guard: MANAGED_STATE_HPP */
