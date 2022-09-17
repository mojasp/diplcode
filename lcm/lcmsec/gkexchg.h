#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <memory>
#include <string>
#include <vector>
#include <optional>

#include "lcm.h"
#include "lcmsec/eventloop.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

class Dutta_Barua_GKE {
  public:
    Dutta_Barua_GKE(std::string channelname, eventloop &ev_loop, lcm::LCM &lcm);
    void round1();
    void round2();
    void computeKey();
    void on_msg(const Dutta_Barua_message* msg);

  private:
    std::string channelname;
    eventloop &evloop;
    lcm::LCM& lcm;

    struct user_id {
        int u, d;
    };
    const user_id uid{1, 1};
    int participants = 3; //Number of participants in the protocol
    std::vector<user_id> partial_session_id;

    std::vector<Dutta_Barua_message> r2_messages;
    struct {
        std::optional<Dutta_Barua_message> left; //from U_{i-1}
        std::optional<Dutta_Barua_message> right; //from U_{i+1}
    } r1_messages;

    bool r2_finished = false;

    inline bool is_neighbour(const Dutta_Barua_message* msg) { return  is_left_neighbour(msg) || is_right_neighbour(msg); }
    inline bool is_left_neighbour(const Dutta_Barua_message* msg) { 
        //FIXME when synchronization is done
        int neighbour = (msg->u == 1)? participants : msg->u  - 1;
        return msg->u == neighbour;
    } 
    inline bool is_right_neighbour(const Dutta_Barua_message* msg) { 
        //FIXME when synchronization is done
        int neighbour = (msg->u == participants)? 1 : msg->u + 1;
        return msg->u == neighbour;
    }
};


/**
 * @class Key_Exchange_Manager
 * @brief separate the interfacing with LCM from the key exchange implementation
 */
class Key_Exchange_Manager {
  public:
      Key_Exchange_Manager(std::string channelname, eventloop &ev_loop,
                                           lcm::LCM &lcm);

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
