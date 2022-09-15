#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <memory>
#include <string>
#include <vector>

#include "lcm.h"
#include "lcmsec/eventloop.hpp"

namespace lcmsec_impl {

class Dutta_Barua_GKE;

class Key_Exchange_Manager {
  public:
    /**
     * @brief Perform group key exchange on the configured channels
     *
     * @param channels the channels on which the groupkeyexchange shall take space
     * @param eventloop event loop used to facilitate the key exchange
     */
    explicit Key_Exchange_Manager(std::string channelname, eventloop& ev_loop);

  private:
    std::shared_ptr<Dutta_Barua_GKE> impl;
};
}  // namespace lcmsec_impl
#endif  // !GKEXCHG_H
