#ifndef UTIL_HPP

#define UTIL_HPP

#include <iostream>
#include <type_traits>
#include <vector>
#include <chrono>
#include <optional>

#include <utility>

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

inline bool is_earlier(std::chrono::high_resolution_clock::time_point lhs,
                       std::optional<std::chrono::high_resolution_clock::time_point> rhs)
{
    return !rhs || lhs < *rhs;
}
inline bool earlier_or_equal(std::chrono::high_resolution_clock::time_point lhs,
                       std::optional<std::chrono::high_resolution_clock::time_point> rhs)
{
    return !rhs || lhs <= *rhs;
}

inline std::chrono::high_resolution_clock::time_point earliest_time(
    std::chrono::high_resolution_clock::time_point &tp,
    std::optional<std::chrono::high_resolution_clock::time_point> opt_tp)
{
    if (is_earlier(tp, opt_tp))
        return tp;
    return opt_tp.value();
}

// taken from microsofts implementation of the guidelines support library
// final_action allows you to ensure something gets run at the end of a scope
template <class F>
class final_action
{
public:
    static_assert(!std::is_reference<F>::value && !std::is_const<F>::value &&
                      !std::is_volatile<F>::value,
                  "Final_action should store its callable by value");

    explicit final_action(F f) noexcept : f_(std::move(f)) {}

    final_action(final_action&& other) noexcept
        : f_(std::move(other.f_)), invoke_(std::exchange(other.invoke_, false))
    {}

    final_action(const final_action&) = delete;
    final_action& operator=(const final_action&) = delete;
    final_action& operator=(final_action&&) = delete;

    ~final_action() noexcept
    {
        if (invoke_) f_();
    }

private:
    F f_;
    bool invoke_{true};
};

// finally() - convenience function to generate a final_action
template <class F>
[[nodiscard]] final_action<typename std::remove_cv<typename std::remove_reference<F>::type>::type>
finally(F&& f) noexcept
{
    return final_action<typename std::remove_cv<typename std::remove_reference<F>::type>::type>(
        std::forward<F>(f));
}

};  // namespace lcmsec

#endif /* end of include guard: UTIL_HPP */
