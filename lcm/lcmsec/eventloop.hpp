#ifndef EVENTLOOP_H

#define EVENTLOOP_H

#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <list>
#include <thread>

#include "lcm-cpp.hpp"
#include "lcmsec_util.h"

#ifdef WIN32
#include <winsock2.h>

#include "windows/WinPorting.h"
#else
#include <sys/select.h>
typedef int SOCKET;
#endif

namespace lcmsec_impl {
/*
 * Motivation:
 *  We do need some multitasking because we have to do network IO to perform the
 *  groupkeyexchange. If multiple channels are to be configured, doing
 *  the groupkeyexchange for each channel sequentially would be grossly inefficient; Thus we need
 *  some form of eventloop that supports lcm.
 *
 *  This thing is essentially a cooperative multitasking event loop.
 */

/**
 * @class eventloop
 * @brief Simple, single threaded event loop to facilitate multiple group key exchanges (in case
 * multiple channels are configured)
 *
 * Right now implemented with a queue. Can be more efficient by using lcm_get_fileno and poll/select
 */
class eventloop {
  public:
    using task_t = std::function<void()>;
    using timepoint_t = std::chrono::time_point<std::chrono::high_resolution_clock>;
    using listelem_t = std::pair<timepoint_t, task_t>;

  private:
    // linked list as storage, sorted by timepoints
    // Strictly speaking it is not really sorted: timepoints now are considered equal to those in
    // the past; timepoints in the future are sorted.
    std::list<listelem_t> tasks;

    lcm::LCM &lcm;

    int unfinished_channels;
    std::chrono::milliseconds default_poll_interval;

    inline void handle_tasks()
    {
        // Handle next task if it is available
        auto now = std::chrono::high_resolution_clock::now();
        while (!tasks.empty() && now > tasks.front().first) {
            auto t = tasks.front();
            t.second();
            tasks.pop_front();
        }
    }

    inline void handle_lcm()
    {
        // handle all available messages first => it is better to listen than to send!.
        // listening might mean that we no longer have to send. dont be greedy!
        while (1) {
            auto now = std::chrono::high_resolution_clock::now();
            auto next_task_delta =
                tasks.empty() ? default_poll_interval : tasks.front().first - now;

            // ensure timeouts are not below 0
            struct timeval timeout = {
                std::max<int64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(next_task_delta).count(), 0),
                std::max<int64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(next_task_delta).count(),
                    0) % 1'000'000}; //trunacate microsecondcount in case it is larger than a second

            int lcm_fd = lcm.getFileno();
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(lcm_fd, &fds);

            int status = select(lcm_fd + 1, &fds, 0, 0, &timeout);

            if (status < 0) {
                throw std::runtime_error("lcmsec: select error in eventloop: " +
                                         std::string(strerror(errno)));
            }
            if (status > 0 && FD_ISSET(lcm_fd, &fds)) {
                // handle incoming messages for the keyexchg protocol
                lcm.handle();  // guaranteed to be nonblocking
            }
            if (status == 0) {
                // no lcmdata
                break;
            }
        }
    }

  public:
    inline eventloop(lcm::LCM &lcm, int lcm_timeout_ms = 1000)
        : lcm(lcm), default_poll_interval(lcm_timeout_ms)
    {
    }

    inline void push_task(eventloop::task_t task)
    {
        auto now = std::chrono::high_resolution_clock::now();
        tasks.emplace_front(std::make_pair(MOV(now), MOV(task)));
    }

    inline void push_task(timepoint_t timepoint, eventloop::task_t task)
    {
        // keep list sorted while inserting
        // for clarity: std::lower_bound returns an iterator to the first item for which
        // (e.first < tp) is false - i.e. the place at which we insert
        tasks.insert(std::lower_bound(
                         tasks.begin(), tasks.end(), timepoint,
                         [](const listelem_t &e, const timepoint_t &tp) { return e.first < tp; }),
                     std::make_pair(MOV(timepoint), MOV(task)));
    }
    /*
     * run until channels are configured - useful for initializing the keyexchange
     */
    inline void run(int channels_to_configure)
    {
        unfinished_channels = channels_to_configure;
        handle_tasks();
        do {
            handle_lcm();
            handle_tasks();  // Switch order in this case to avoid extra wait on lcm when
                             // were already done
        } while (unfinished_channels > 0);
    }

    /*
     * run forever - useful for performing keyexchg in background
     */
    inline void run(const volatile std::atomic_bool *signal_shutdown)
    {
        while (!(*signal_shutdown)) {
            handle_tasks();
            handle_lcm();
        }
    }

    inline void channel_finished() { unfinished_channels--; }
};

}  // namespace lcmsec_impl

#endif /* end of include guard: EVENTLOOP_H */
