#ifndef RA_HPP
#define RA_HPP

#include <botan/rng.h>
#include <botan/system_rng.h>
#include <cstdint>
#include <cstdlib>
#include <vector>


//TODO: STUBS for now
namespace RA {

    inline void sample_challenge(std::vector<uint8_t> & buffer) {
        auto& rng = Botan::system_rng();
        rng.randomize(buffer.data(), buffer.size());
    }

    inline uint64_t attest(){
        return std::rand();
    }

    inline bool verify(uint64_t evidence){
        return true;
    }
}

#endif
