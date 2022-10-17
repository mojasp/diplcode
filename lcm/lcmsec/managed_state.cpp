#include "managed_state.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>

#include "crypto_wrapper.h"
#include "lcmsec_util.h"

namespace lcmsec_impl {
int GkexchgManagedState::uid_to_protocol_uid(int uid) const
{
    assert(locked);
    auto it = std::find(joining_participants.cbegin(), joining_participants.cend(),
                        uid);  // take advantage of sorted array and do a binary search
    if (it == joining_participants.cend()) {
        throw std::runtime_error("error: found no protocol uid for uid " + std::to_string(uid));
    } else
        return it - joining_participants.begin() +
               1;  // else, return the index that we found (but use 1-indexing)
}

int GkexchgManagedState::protocol_uid_to_uid(int proto_uid) const
{
    assert(locked);
    // the protocol user ID's are the indices of participants
    //  NOTE: it is necessary to convert from and to 1-indexing here
    return joining_participants.at(proto_uid - 1) + 1;
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

bool GkexchgManagedState::is_neighbour(int uid, const Dutta_Barua_message *msg) const
{
    assert(locked);
    return is_left_neighbour(uid, msg) || is_right_neighbour(uid, msg);
}

bool GkexchgManagedState::is_left_neighbour(int uid, const Dutta_Barua_message *msg) const
{
    assert(locked);
    // FIXME when synchronization is done
    int my_uid = uid_to_protocol_uid(uid);
    int their_uid = uid_to_protocol_uid(msg->u);
    int neighbour = (my_uid == 1) ? joining_participants.size() : my_uid - 1;
    return their_uid == neighbour;
}

bool GkexchgManagedState::is_right_neighbour(int uid, const Dutta_Barua_message *msg) const
{
    int my_uid = uid_to_protocol_uid(uid);
    int their_uid = uid_to_protocol_uid(msg->u);

    int neighbour = (my_uid == joining_participants.size()) ? 1 : my_uid + 1;
    return their_uid == neighbour;
}

bool GkexchgManagedState::find_uid_in_participants(int uid) const
{
    throw("unimplemented");
}

bool GkexchgManagedState::exists_in_joining(int uid) const
{
    return std::find(joining_participants.begin(), joining_participants.end(), uid) != joining_participants.end();
}

// prepare_join will be called multiple times; depending on which is earlier: our own start of
// round1, or the first received round1_message. In any case, this is the time we need to prepare
// the join in order to have access to protocol uid's
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
    } else {
        joining_participants.insert(joining_participants.begin(), participants.back());
        joining_participants.insert(joining_participants.begin(), *(participants.begin() + 1));
        joining_participants.insert(joining_participants.begin(), participants.front());

        joining_participants.erase(
            std::unique(joining_participants.begin(), joining_participants.end()),
            joining_participants.end());  // for good measure, i think it is not needed though
    }
    locked = true;
    proto_uid_view.generate(joining_participants);
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
}

}  // namespace lcmsec_impl
//
