#ifndef EVENTLOOP_H

#define EVENTLOOP_H

/**
 * @class eventloop
 * @brief Simple, single threaded event loop to facilitate multiple group key exchanges (in case
 * multiple channels are configured) Since lcm does not require linking pthread, we do not want to
 * be dependent on threads here either.
 *
 * Right now implemented with a stack. Can be more efficient by using lcm_get_fileno and poll/select
 */
#include <functional>
#include <stack>

namespace lcmsec_impl {

class eventloop {
  public:
    using task_t = std::function<void()>;
    std::stack<task_t> tasks;

  public:
    inline void push_task(eventloop::task_t task) { tasks.push(std::move(task)); }

    inline void run()
    {
        while (!tasks.empty()) {
            auto t = tasks.top();
            t();
            tasks.pop();
        }
    }
};

}

#endif /* end of include guard: EVENTLOOP_H */
