#ifndef PROTOCOL_UID_HPP

#define PROTOCOL_UID_HPP

#include <vector>
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
    std::size_t size;  // cache size

    static constexpr int sentinel = -1;

  public:
    void generate(const std::vector<int> &participants);

    void generate(const std::vector<int> &participants, int uid_first, int uid_second,
                         int uid_last);


    int at(int uid) const;
    std::size_t get_size() const;
    const std::vector<int> &get() const;

    void clear();
};
}
#endif /* end of include guard: PROTOCOL_UID_HPP */
