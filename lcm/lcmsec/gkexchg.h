#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <botan/bigint.h>
#include <botan/dh.h>

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "crypto_wrapper.h"
#include "dsa.h"
#include "lcm.h"
#include "lcmsec/eventloop.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_SYN.hpp"
#include "lcmsec/lcmtypes/Dutta_Barua_message.hpp"

namespace lcmsec_impl {

class Dutta_Barua_GKE {
  public:
    Dutta_Barua_GKE(std::string mcastgroup, std::string channelname, eventloop &ev_loop,
                    lcm::LCM &lcm, int uid);

    inline void SYN();
    inline void onSYN(const Dutta_Barua_SYN *syn_msg);

    void round1();
    void round2();
    void computeKey();
    void on_msg(const Dutta_Barua_message *msg);

    Botan::secure_vector<uint8_t> get_session_key(size_t key_size);

    const std::string
        groupexchg_channelname;  // the channelname used for the management of the keyexchange

    // Not used for publishing, but to check permissions of the certificates on incoming messages
    const std::string channelname; const std::string mcastgroup;

    const int SYN_waitperiod_ms = 1200;
    std::optional<int> syn_finished_at;

  private:
    eventloop &evloop;
    lcm::LCM &lcm;

    struct user_id {
        int u, d;
    };
    const user_id uid{1, 1};

    // stateful members needed across multiple rounds of the keyexchange //
    int participants = 3;  // Number of participants in the protocol

    std::vector<user_id> partial_session_id;
    std::optional<Botan::DH_PrivateKey>
        x_i;  // no default constructor for DH_PrivateKey and it cannot be immediately initialized

    std::map<int, Dutta_Barua_message> r2_messages;
    struct {
        std::optional<Dutta_Barua_message> left;   // message from U_{i-1}
        std::optional<Dutta_Barua_message> right;  // message from U_{i+1}
    } r1_messages;

    struct {
        Botan::BigInt left;   // K_i^l
        Botan::BigInt right;  // K_i^r
    } r1_results;

    bool r2_finished = false;

    // ------ Helper methods --------//
    inline bool is_neighbour(const Dutta_Barua_message *msg)
    {
        return is_left_neighbour(msg) || is_right_neighbour(msg);
    }
    inline bool is_left_neighbour(const Dutta_Barua_message *msg)
    {
        // FIXME when synchronization is done
        int neighbour = (uid.u == 1) ? participants : uid.u - 1;
        return msg->u == neighbour;
    }
    inline bool is_right_neighbour(const Dutta_Barua_message *msg)
    {
        // FIXME when synchronization is done
        int neighbour = (uid.u == participants) ? 1 : uid.u + 1;
        return msg->u == neighbour;
    }

    void sign_and_dispatch(Dutta_Barua_message &msg);
    static void db_set_public_value(Dutta_Barua_message &msg, const Botan::BigInt &bigint);
    static void db_get_public_value(const Dutta_Barua_message &msg, Botan::BigInt &bigint);

    template <typename T>
    inline void debug(T msg)
    {
        CRYPTO_DBG("u%i: ch:%s %s\n", uid.u, groupexchg_channelname.c_str(), msg);
    }

    std::optional<Botan::BigInt> shared_secret;
};

/**
 * @class Key_Exchange_Manager
 * @brief separate the interfacing with LCM from the key exchange implementation
 */
class Key_Exchange_Manager {
  public:
    Key_Exchange_Manager(std::string mcastgroup, std::string channelname, eventloop &ev_loop,
                         lcm::LCM &lcm, int uid);

    void handleMessage(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                       const Dutta_Barua_message *msg);

    void handle_SYN(const lcm::ReceiveBuffer *rbuf, const std::string &chan,
                    const Dutta_Barua_SYN *syn_msg);
    /*
     * deleted copy and move constructors
     * This is important since this class will be used as an lcm handler object. Thus, its address
     * must not not change (which prohibits the move constructor).
     * For the copy constructors, semantics would be unclear, so delete it as well
     */
    Key_Exchange_Manager(Key_Exchange_Manager &&) = delete;
    Key_Exchange_Manager(const Key_Exchange_Manager &) = delete;
    Key_Exchange_Manager &operator=(const Key_Exchange_Manager &) = delete;
    Key_Exchange_Manager &operator=(const Key_Exchange_Manager &&) = delete;

    inline Botan::secure_vector<uint8_t> get_session_key(size_t key_size)
    {
        return impl.get_session_key(key_size);
    }
    inline const std::string &channelname() { return impl.groupexchg_channelname; }
    inline ~Key_Exchange_Manager() {}

  private:
    Dutta_Barua_GKE impl;
};

}  // namespace lcmsec_impl
#endif  // !GKEXCHG_H
