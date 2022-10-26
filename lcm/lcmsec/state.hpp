#ifndef STATE_HPP

#define STATE_HPP

namespace lcmsec_impl {

enum class STATE : int {
    keyexchg_not_started = 0,
    consensus_phase,
    keyexchg_in_progress,
    keyexchg_successful,
    ENUMSIZE
};
inline const char *state_name(STATE s)
{
    static const char *STATE_names[] = {"keyexchg_not_started", "consensus_phase", "in_progress",
                                        "keyexchg_successful"};
    static_assert(sizeof(STATE_names) / sizeof(char *) == static_cast<int>(STATE::ENUMSIZE),
                  "sizes dont match");
    return STATE_names[static_cast<int>(s)];
}
enum class JOIN_ROLE : int { invalid = 0, joining, active, passive, ENUMSIZE };
inline const char *join_role_name(JOIN_ROLE r)
{
    static const char *join_role_names[] = {"invalid", "joining", "active", "passive"};
    static_assert(sizeof(join_role_names) / sizeof(char *) == static_cast<int>(JOIN_ROLE::ENUMSIZE),
                  "sizes dont match");
    return join_role_names[static_cast<int>(r)];
}

}  // namespace lcmsec_impl
#endif /* end of include guard: STATE_HPP */
