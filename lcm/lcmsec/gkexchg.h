#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <memory>
#include <string>
#include <vector>

#include "lcm.h"
#include "lcmsec/eventloop.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

class Dutta_Barua_GKE {
  public:
    Dutta_Barua_GKE(std::string channelname, eventloop &ev_loop, lcm::LCM &lcm);
    void round1();
    void on_msg(const Dutta_Barua_message* msg);

  private:
    std::string channelname;
    eventloop &evloop;
    lcm::LCM& lcm;

    struct user_id {
        int u, d;
    };
    const user_id uid{1, 1};
    std::vector<user_id> partial_session_id;

    bool is_neighbour(int u_id) { return true;} //TODO
};


/**
 * @class Key_Exchange_Manager
 * @brief separate the interfacing with LCM from the key exchange implementation
 */
class Key_Exchange_Manager {
  public:
    Key_Exchange_Manager(std::string channelname, eventloop &ev_loop, lcm::LCM &lcm);

    void handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                       const Dutta_Barua_message *msg);

    /*
     * deleted copy and move (assignment-)constructors
     * This is important since this class will be used as an lcm handler object. Thus, its address must not not change (which prohibits the move constructor)
     * The semantics for copy construction would also be extremely unclear as well
     */
    Key_Exchange_Manager(Key_Exchange_Manager &&) = delete;
    Key_Exchange_Manager(const Key_Exchange_Manager &) = delete;
    Key_Exchange_Manager &operator=(const Key_Exchange_Manager &) = delete;
    Key_Exchange_Manager &operator=(const Key_Exchange_Manager &&) = delete;
    inline ~Key_Exchange_Manager () {}

  private:

    Dutta_Barua_GKE impl;

};

}  // namespace lcmsec_impl
#endif  // !GKEXCHG_H
