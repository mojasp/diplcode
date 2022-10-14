#ifndef UTIL_HPP

#define UTIL_HPP

#include <iostream>
#include <type_traits>
#include <vector>

namespace lcmsec {

// replace std::move/std::forward (cast instead of equivalent function calls).
// Motivation
//  * better compile times
//  * better debugging experience

//  static_cast to rvalue reference
#define MOV(...) static_cast<std::remove_reference_t<decltype(__VA_ARGS__)> &&>(__VA_ARGS__)
// static_cast to identity
#define FWD(...) static_cast<decltype(__VA_ARGS__) &&>(__VA_ARGS__)

};  // namespace lcmsec

// print containers - debugging
inline std::ostream &operator<<(std::ostream &stream, const std::vector<int>& container)
{
    for (const auto &i : container)
        stream << i << "\t";
    return stream;
}


#endif /* end of include guard: UTIL_HPP */
