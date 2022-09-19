#ifndef EVENTLOOP_H

#define EVENTLOOP_H

#include <functional>
#include <queue>

#include "lcm-cpp.hpp"

namespace lcmsec_impl {
/*
 * Brief explanation of the eventloop logic
 *
 * Motivation:
 *  We do need some multitasking because we have to do network IO to perform the
 *  groupkeyexchange. If multiple channels are to be configured (which should be supported), doing
 *  the groupkeyexchange for each channel sequentially would be grossly inefficient; Thus we need
 *  some form of eventloop that supports lcm.
 *
 * rough Pseudocode of the group key exchange logic/usage of the eventloop:
 * begin:
 *
 *  lcm = lcm_instance;
 *  channels = configured_channels;
 *
 *  managers = map<channel, keyexchgmanager> //Save this somewhere to enable dynamic execution of
 *                                           //protocol later on
 *  int unfinished_channels = sizeof(configured_channels)
 *
 *  ev = Eventloop(&managers);
 *
 *  lcmcallback = function(channel ch) { //Closure over managers
 *      manager = managers.lookup(ch)
 *      if(manager.round2_prerequisites)
 *          ev.register_task(do_round_2, manager)
 *      else if(manager.round3_prerequisites)
 *          ev.register.(do_round_3, manager, &unfinished_channels) //compute key and decrement
 *                                                                  //unfinished_channels
 *  }
 *
 *  for ch in channels:
 *      lcm.subscribe(ch.channelname, lcmcallback)
 *
 *      m = new keyexchgmanager(ch)
 *      managers.add(m) //will register round 1
 *
 *  evloop.run()
 *
 * end
 *
 *
 * Pseudocode of the eventloop itself:
 *  while(unfinished_channels && task is available) {
 *       lcm.listen(timeout) //Probably better to use select/poll
 *       if(task.available)
 *           do task
 *  }
 *
 */

/**
 * @class eventloop
 * @brief Simple, single threaded event loop to facilitate multiple group key exchanges (in case
 * multiple channels are configured)
 *
 * Right now implemented with a queue. Can be more efficient by using lcm_get_fileno and poll/select
 *
 */
class eventloop {
  public:
    using task_t = std::function<void()>;
    std::queue<task_t> tasks;

    int lcm_timeout_ms;
    lcm::LCM &lcm;

    int unfinished_channels;

  public:
    inline eventloop(lcm::LCM &lcm, int lcm_timeout_ms = 50)
        : lcm(lcm), lcm_timeout_ms(lcm_timeout_ms)
    {
    }
    inline void push_task(eventloop::task_t task) { tasks.push(task); }

    inline void run(int channels_to_configure)
    {
        unfinished_channels = channels_to_configure;
        while (!tasks.empty() || unfinished_channels > 0) {
            if (!tasks.empty()) {
                auto t = tasks.front();
                t();
                tasks.pop();
            }
            if (unfinished_channels) {
                lcm.handleTimeout(lcm_timeout_ms);
            }
        }
    }
    inline void channel_finished() {unfinished_channels--;}
};

}  // namespace lcmsec_impl

#endif /* end of include guard: EVENTLOOP_H */
