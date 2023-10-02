if(UNIX)
  find_package(Threads)
endif()

include(FetchContent)

set(lcm_sources
  eventlog.c
  lcm.c
  lcm_file.c
  lcm_memq.c
  lcm_mpudpm.c
  lcm_tcpq.c
  lcm_udpm.c
  ringbuffer.c
  udpm_util.c
  lcmtypes/channel_port_map_update_t.c
  lcmtypes/channel_to_port_t.c
  lcmsec/crypto_wrapper.cpp
  lcmsec/gkexchg.cpp
  lcmsec/dsa.cpp
  lcmsec/managed_state.cpp
  lcmsec/protocol_uid.cpp
  lcmsec/crypto_wrapper.h
  lcmsec/gkexchg.h
  lcmsec/dsa.h
  lcmsec/eventloop.hpp
  lcmsec/managed_state.hpp
  lcmsec/protocol_uid.hpp
)

set(CMAKE_CXX_STANDARD 20)

set(lcm_install_headers
  eventlog.h
  lcm.h
  lcm_coretypes.h
  lcm_version.h
  lcm-cpp.hpp
  lcm-cpp-impl.hpp
  ${CMAKE_CURRENT_BINARY_DIR}/lcm_export.h
)

if(LCMSEC_VERBOSE)
    add_compile_definitions(LCMSEC_DEBUG=1)
else()
    add_compile_definitions(LCMSEC_DEBUG=0)
endif()

if(WIN32)
  list(APPEND lcm_sources
    windows/WinLCM.cpp
    windows/WinPorting.cpp
  )
  list(APPEND lcm_install_headers
    windows/WinPorting.h
  )
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(lcm-coretypes INTERFACE)
add_library(lcm-static STATIC ${lcm_sources})
add_library(lcm SHARED ${lcm_sources})

if(USE_TRACY)
    option(TRACY_ENABLE "" ON)
    option(TRACY_FIBERS "" ON)
else()
    #disable the tracy_enable macro otherwise we get linker error
    option(TRACY_ENABLE "" OFF)
endif()
#we always need the tracy header - will cause no runtime overhead if tracy is disabled
FetchContent_Declare(
    tracy
    GIT_REPOSITORY https://github.com/wolfpld/tracy.git
    GIT_TAG master
    GIT_SHALLOW TRUE
    GIT_PROGRESS TRUE
)
FetchContent_MakeAvailable(tracy)

foreach(lcm_lib lcm lcm-static)
  target_compile_definitions(${lcm_lib} PRIVATE
    _FILE_OFFSET_BITS=64
    _LARGEFILE_SOURCE
    _REENTRANT
  )

  set_target_properties(${lcm_lib} PROPERTIES
    VERSION ${LCM_VERSION}
    SOVERSION ${LCM_ABI_VERSION}
    PUBLIC_HEADER "${lcm_install_headers}"
  )

  target_include_directories(${lcm_lib} INTERFACE
    $<BUILD_INTERFACE:${lcm_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    ${BOTAN2_INCLUDE_DIRS}
  )

  target_link_libraries(${lcm_lib} PRIVATE
    GLib2::glib
    Botan2::Botan2
    ${CMAKE_THREAD_LIBS_INIT}
  )

  if(USE_TRACY)
      target_link_libraries(${lcm_lib} PRIVATE TracyClient)
  else()
      target_include_directories(${lcm_lib} PRIVATE ${tracy_SOURCE_DIR}/public) #we still need the tracy header
  endif()

  if(WIN32)
    target_link_libraries(${lcm_lib} PRIVATE wsock32 ws2_32)
  endif()
endforeach()

generate_export_header(lcm STATIC_DEFINE LCM_STATIC)

target_compile_definitions(lcm-static PUBLIC LCM_STATIC)
if(NOT WIN32)
  set_target_properties(lcm-static PROPERTIES OUTPUT_NAME lcm)
endif()

target_include_directories(lcm-coretypes INTERFACE
  $<BUILD_INTERFACE:${lcm_SOURCE_DIR}>
)

#Tracy is used only for local/development builds, not as part of install builds
if(NOT USE_TRACY)
    install(TARGETS lcm-coretypes lcm-static lcm
        EXPORT lcmTargets
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib${LIB_SUFFIX}
        ARCHIVE DESTINATION lib${LIB_SUFFIX}
        PUBLIC_HEADER DESTINATION include/lcm
        INCLUDES DESTINATION include
        )
endif()
