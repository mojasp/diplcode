#include <cassert>
#include <string>
#include <stdint.h>
#include "lcmsec/protocol_uid.hpp"
#include "lcmsec/lcmexcept.hpp"

namespace lcmsec_impl{

void ProtoUidView::generate(const std::vector<int> &participants)
{
    assert(!valid);
    for (int i = 0; i < participants.size(); i++) {
        int proto_uid = i + 1;
        int uid = participants[i];
        while (v.size() <= uid)
            v.push_back(sentinel);
        if(v.at(uid) != sentinel){
            //uid is already part of group
            throw rejoin_error("uid  " + std::to_string(uid) + " tries to join, but is part of group already");
        }  
        v[uid] = proto_uid;
    }
    valid = true;
    size = participants.size();
}

void ProtoUidView::generate(const std::vector<int> &participants, int uid_first, int uid_second,
                     int uid_last)
{
    // This would be a lot easier with an extra copy of the participant vector, but it is possible
    // without

    auto loop_it = [&](int i, int elem) {
        int proto_uid = i + 1;
        int uid = elem;
        while (v.size() <= uid)
            v.push_back(sentinel);
        if(v.at(uid) != sentinel){
            //uid is already part of group
            throw rejoin_error("uid  " + std::to_string(uid) + " tries to join, but is part of group already");
        }  
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

void ProtoUidView::clear()
{
    v.clear();
    assert(v.size() == 0);
    valid = false;
}

const std::vector<int> &ProtoUidView::get() const
{
    assert(valid);
    return v;
}

int ProtoUidView::at(int uid) const
{
    assert(valid);
    auto result = v.at(uid);
    if(result == sentinel)
        throw uid_unknown("managed state: uid " + std::to_string(uid) + " not part of ProtocolUidView");
    return result;
}

std::size_t ProtoUidView::get_size() const
{
    assert(valid);
    return size;
}

}
