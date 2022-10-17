#ifndef MANAGED_STATE_HPP

#define MANAGED_STATE_HPP

// state manged by the RAFT-inspired gkexchg protocol
#include <algorithm>
#include <cassert>
#include <chrono>
#include <coroutine>
#include <functional>
#include <optional>
#include <stdexcept>
#include <vector>

#include "lcmsec/crypto_wrapper.h"
#include "lcmsec/lcmsec_util.h"
#include "lcmsec/lcmtypes/Dutta_Barua_JOIN_response.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"
#include "state.hpp"

namespace lcmsec_impl {

/**
 * @class ProtoUidView
 * @brief A sparse view of uids for fast lookup during protocol execution
 *
 * Intended to be generated before the first round of the protocol starts
 *
 * If we consider joining_participant a function that maps from uid to proto_uid,
 *   ProtoUidView.v will be its inverse
 *
 * If locked, no modification of v is permitted
 * v is only valid if locked = true
 *
 * Uses 1-indexing of proto-uids for now
 */
class ProtoUidView {
    bool valid{false};
    std::vector<int> v;
    size_t size;  // cache size

  public:
    inline void generate(const std::vector<int> &participants)
    {
        assert(!valid);
        static constexpr int sentinel = -1;
        for (int i = 0; i < participants.size(); i++) {
            int proto_uid = i + 1;
            int uid = participants[i];
            while (v.size() <= uid)
                v.push_back(sentinel);
            assert(v.at(uid) == sentinel);  // no duplicates allowed
            v[uid] = proto_uid;
        }
        valid = true;
        size = participants.size();
    }

    inline void generate(const std::vector<int> &participants, int uid_first, int uid_second,
                         int uid_last)
    {
        static constexpr int sentinel = -1;
        auto loop_it = [&](int i, int elem) {
            int proto_uid = i + 1;
            int uid = elem;
            while (v.size() <= uid)
                v.push_back(sentinel);
            assert(v.at(uid) == sentinel);  // no duplicates allowed
            v[uid] = proto_uid;
        };

        int i = 0;
        for (int elem : {uid_first, uid_second, uid_last}) {
            loop_it(i, elem);
            i++;
        }

        for (int i = 3; i < participants.size() + 3; i++) {
            loop_it(i, participants[i - 3]);
        }
        size = participants.size() + 3;

        valid = true;
    }

    inline void clear()
    {
        assert(valid);
        v.clear();
        assert(v.size() == 0);
        valid = false;
    }

    inline const std::vector<int> &get() const
    {
        assert(valid);
        return v;
    }
    inline size_t get_size() const { return size; }
};

class GkexchgManagedState {
  public:
    using time_point = std::chrono::steady_clock::time_point;

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

    [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> r1start() const;

    [[nodiscard]] bool find_uid_in_participants(int uid) const;
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

    [[nodiscard]] bool is_neighbour(int uid, const Dutta_Barua_message *msg) const;
    [[nodiscard]] bool is_left_neighbour(int uid, const Dutta_Barua_message *msg) const;
    [[nodiscard]] bool is_right_neighbour(int uid, const Dutta_Barua_message *msg) const;
};

}  // namespace lcmsec_impl
#endif /* end of include guard: MANAGED_STATE_HPP */
