#include "managed_state.hpp"

#include <algorithm>
#include <cassert>
#include <stdexcept>
#include <string>

#include "crypto_wrapper.h"
#include "lcmsec/lcmexcept.hpp"
#include "lcmsec_util.h"

namespace lcmsec_impl {
int GkexchgManagedState::uid_to_protocol_uid(int uid) const
{
    assert(locked);

    try {
        return proto_uid_view.at(uid);
    }
    catch(std::out_of_range& e){
        throw uid_unknown("managed state: uid " + std::to_string(uid) + " not part of ProtocolUidView");
    }
}

const std::vector<int> &GkexchgManagedState::get_participants() const
{
    return participants;
}

const std::vector<int> &GkexchgManagedState::get_joining() const
{
    return joining_participants;
}

bool GkexchgManagedState::process_participant(const std::vector<int> *candidate_participants)
{
    assert(!locked);
    assert(process_state.next == _process_state::STATE::participants);

    if (candidate_participants->size() < participants.size()) {
        process_state.next = _process_state::STATE::participants;
        return false;
    }
    process_state.candidate_participants = candidate_participants;

    process_state.next = _process_state::STATE::joining;
    return true;
}

bool GkexchgManagedState::process_joining(const std::vector<int> *candidate_joining)
{
    assert(!locked);
    assert(process_state.next == _process_state::STATE::joining);
    assert(process_state.candidate_participants);

    if (process_state.candidate_participants->size() == participants.size() &&
        candidate_joining->size() < joining_participants.size()) {
        process_state.next = _process_state::STATE::participants;
        return false;
    }
    process_state.candidate_joining = candidate_joining;

    process_state.next = _process_state::STATE::tp;
    return true;
}

bool GkexchgManagedState::process_timestamp(time_point tp)
{
    assert(!locked);
    assert(process_state.next = _process_state::STATE::tp);
    assert(process_state.candidate_participants);
    assert(process_state.candidate_joining);

    if (process_state.candidate_participants->size() == participants.size() &&
        process_state.candidate_joining->size() == joining_participants.size() &&
        !is_earlier(tp, current_earliest_r1start)) {
        // reset process_state
        process_state = _process_state{};
        return false;
    }
    // accept candidate
    current_earliest_r1start = tp;
    participants = *process_state.candidate_participants;
    joining_participants = *process_state.candidate_joining;
    std::sort(participants.begin(), participants.end());
    std::sort(joining_participants.begin(), joining_participants.end());

    // reset entire process_state; including process_state.next
    process_state = _process_state{};
    return true;
}

[[nodiscard]] std::optional<std::chrono::steady_clock::time_point> GkexchgManagedState::r1start()
    const
{
    return current_earliest_r1start;
}

[[nodiscard]] int GkexchgManagedState::active_participants() const{
    return proto_uid_view.get_size();
}

bool GkexchgManagedState::is_neighbour(int uid, const Dutta_Barua_message *msg) const
{
    assert(locked);
    return is_left_neighbour(uid, msg) || is_right_neighbour(uid, msg);
}

bool GkexchgManagedState::is_left_neighbour(int uid, const Dutta_Barua_message *msg) const
{
    assert(locked);
    int my_uid = uid_to_protocol_uid(uid);
    int their_uid = uid_to_protocol_uid(msg->u);
    int neighbour = (my_uid == 1) ? proto_uid_view.get_size() : my_uid - 1;
    return their_uid == neighbour;
}

bool GkexchgManagedState::is_right_neighbour(int uid, const Dutta_Barua_message *msg) const
{
    assert(locked);
    int my_uid = uid_to_protocol_uid(uid);
    int their_uid = uid_to_protocol_uid(msg->u);

    int neighbour = (my_uid == proto_uid_view.get_size()) ? 1 : my_uid + 1;
    return their_uid == neighbour;
}

bool GkexchgManagedState::find_uid_in_participants(int uid) const
{
    throw("unimplemented");
}

[[nodiscard]] ProtoUidView const& GkexchgManagedState::uid_view() const{

    assert(locked);
    return proto_uid_view;
}

bool GkexchgManagedState::exists_in_joining(int uid) const
{
    return std::binary_search(joining_participants.begin(), joining_participants.end(), uid);
}

// prepare_join will be called multiple times; depending on which is earlier: our own start of
// round1, or the first received round1_message. In any case, this is the time we need to prepare
// the join in order to have access to protocol uid's
//
// Idempotent method
void GkexchgManagedState::prepare_join()
{
    if (locked)
        return;

    if (participants.size() < 3) {
        // need a group of more than 3 participants to perform the dynamic version of the
        // keyexchange
        CRYPTO_DBG("%s", "existing group small: reform group instead of joining\n");

        joining_participants.insert(joining_participants.end(), participants.begin(),
                                    participants.end());
        std::sort(joining_participants.begin(), joining_participants.end());
        joining_participants.erase(
            std::unique(joining_participants.begin(), joining_participants.end()),
            joining_participants.end());  // for good measure, i think it is not needed though
        participants.clear();
        proto_uid_view.generate(joining_participants);
    } else {
        proto_uid_view.generate(joining_participants, participants.front(), participants.at(1),
                                participants.back());
    }
    locked = true;
}

// reset after finishing group key exchange
void GkexchgManagedState::gke_success()
{
    locked = false;

    proto_uid_view.clear();

    process_state = _process_state{};

    current_earliest_r1start = std::nullopt;
    participants.insert(participants.end(), joining_participants.begin(),
                        joining_participants.end());
    joining_participants.clear();
}

// reset after failing group key exchange - same, but don't append joining members to participants
void GkexchgManagedState::gke_failure()
{
    locked = false;

    proto_uid_view.clear();

    process_state = _process_state{};

    current_earliest_r1start = std::nullopt;

    joining_participants.clear();
    participants.clear();
}

}  // namespace lcmsec_impl
//
