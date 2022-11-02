#ifndef UTIL_HPP

#define UTIL_HPP

#include <iostream>
#include <type_traits>
#include <vector>
#include <chrono>
#include <optional>

namespace lcmsec_impl {

// replace std::move/std::forward (cast instead of equivalent function calls).
// Motivation
//  * better compile times
//  * better debugging experience

//  static_cast to rvalue reference
#define MOV(...) static_cast<std::remove_reference_t<decltype(__VA_ARGS__)> &&>(__VA_ARGS__)
// static_cast to identity
#define FWD(...) static_cast<decltype(__VA_ARGS__) &&>(__VA_ARGS__)

// print containers - debugging
inline std::ostream &operator<<(std::ostream &stream, const std::vector<int> &container)
{
    for (const auto &i : container)
        stream << i << "\t";
    return stream;
}

inline bool is_earlier(std::chrono::steady_clock::time_point lhs,
                       std::optional<std::chrono::steady_clock::time_point> rhs)
{
    return !rhs || lhs < *rhs;
}

inline std::chrono::steady_clock::time_point earliest_time(
    std::chrono::steady_clock::time_point &tp,
    std::optional<std::chrono::steady_clock::time_point> opt_tp)
{
    if (is_earlier(tp, opt_tp))
        return tp;
    return opt_tp.value();
}

};  // namespace lcmsec

#endif /* end of include guard: UTIL_HPP */
