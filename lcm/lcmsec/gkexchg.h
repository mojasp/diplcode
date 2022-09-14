#ifndef GKEXCHG_H
#define GKEXCHG_H

#include <vector>

class Dutta_Barua_GKE
{
public:
    Dutta_Barua_GKE();

private:

    struct user_id {
        int u, d;
    };
    const user_id uid {1 ,1};
    std::vector<user_id> partial_session_id;

    void round1();
};

#endif // !GKEXCHG_H
