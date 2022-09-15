#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <string>
#include <vector>

class gkexch_manager {
  public:
    /**
     * @brief Initialize group key exchange on the configured channels
     *
     * @param channels the channels on which the groupkeyexchange shall take space
     */
    gkexch_manager(const std::vector<std::string> channels);
};

class Dutta_Barua_GKE {
  public:
    Dutta_Barua_GKE();

  private:
    struct user_id {
        int u, d;
    };
    const user_id uid{1, 1};
    std::vector<user_id> partial_session_id;

    void round1();
};

#endif  // !GKEXCHG_H
