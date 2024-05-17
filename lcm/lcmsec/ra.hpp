#ifndef RA_HPP
#define RA_HPP

#include <cstdint>
#include <cstdlib>

//TODO: STUBS for now
namespace RA {

    inline uint64_t sample_challenge(){
        return std::rand();
    }

    inline uint64_t attest(){
        return std::rand();
    }

    inline bool verify(uint64_t evidence){
        return true;
    }
}

#endif
