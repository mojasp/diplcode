#ifndef STATE_HPP

#define STATE_HPP

namespace lcmsec_impl {

enum class STATE : int {
    keyexchg_not_started = 0,
    consensus_phase,
    keyexchg_in_progress,
    computekey_done,
    keyexchg_successful,
    ENUMSIZE
};
inline const char *state_name(STATE s)
{
    static const char *STATE_names[] = {"keyexchg_not_started", "consensus_phase", "in_progress",
                                        "computekey_done", "keyexchg_successful"};
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

enum class RA_STATE : int {
    not_started,
    self_attest_started,
    self_attest_done,
    all_verified,
    ENUMSIZE
};
inline const char *ra_state_name(RA_STATE s)
{
    static const char *RA_STATE_names[] = {"not_stareted", "self_attest_started",  "self_attest_done","all_verified" };
    static_assert(sizeof(RA_STATE_names) / sizeof(char *) == static_cast<int>(RA_STATE::ENUMSIZE),
                  "sizes dont match");
    return RA_STATE_names[static_cast<int>(s)];
}
enum class RA_STATIC_STATE : int {
    not_started,
    started,
    self_attest_done,
    ENUMSIZE
};

inline const char *ra_static_state_name(RA_STATE s)
{
    static const char *RA_STATIC_STATE_names[] = {"not_stareted", "started",  "done"};
    static_assert(sizeof(RA_STATIC_STATE_names) / sizeof(char *) == static_cast<int>(RA_STATIC_STATE::ENUMSIZE),
                  "sizes dont match");
    return RA_STATIC_STATE_names[static_cast<int>(s)];
}

}  // namespace lcmsec_impl
#endif /* end of include guard: STATE_HPP */
