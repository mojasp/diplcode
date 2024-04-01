#ifndef RA_HPP
#define RA_HPP

#include <cstdint>
#include <cstdlib>

//TODO: STUBS for now
namespace RA {

#define SECPARAM
    
    inline uint64_t sample_random(){
        return std::rand();
    }

    inline uint64_t attest(){
        return std::rand();
    }

    inline bool verify(uint64_t evidence){
        return std::rand();
    }
}

#endif
