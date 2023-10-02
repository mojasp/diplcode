#ifndef TRACY_STUBS_HPP
#define TRACY_STUBS_HPP

//If a build with tracy is desired, it can be enabled with the USE_TRACY cmake option via the command line
//This file provides either the include for tracy; or stubs for the macros needed in lcmsec (mostly gkexchg.cpp)

#ifdef TRACY_ENABLE
#include <tracy/Tracy.hpp>
#include <tracy/TracyC.h>
#define TRACY_ASSIGN_CTX(to, from) \
    do {                           \
        to = from;                 \
    } while (0)
#else
//Stubs for tracy macros, to be used when tracy is disabled.
#define TRACY_ASSIGN_CTX(to, from) ;
#define TracyCZoneEnd(name) ;
#define TracyCZoneN(c, x, y) ;
#define ZoneScopedN(name) ;
#define TracyFiberEnter(name) ;
#define TracyFiberLeave ;

#define TracyCZoneCtx struct 

#endif

#endif
