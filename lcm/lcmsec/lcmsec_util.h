#ifndef UTIL_HPP

#define UTIL_HPP

#include <type_traits>

namespace lcmsec{

// static_cast to rvalue reference
#define MOV(...) static_cast<std::remove_reference_t<decltype(__VA_ARGS__)> &&>(__VA_ARGS__)
// static_cast to identity
#define FWD(...) static_cast<decltype(__VA_ARGS__) &&>(__VA_ARGS__)

};


#endif /* end of include guard: UTIL_HPP */
