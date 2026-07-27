add_executable (server "server.c")

set_property(TARGET server PROPERTY C_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
target_compile_definitions(server PRIVATE H2O_USE_LIBUV=0)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET server PROPERTY CXX_STANDARD 26)
endif()

option(BUILD_LOCAL OFF)
if(BUILD_LOCAL)
    set(DEPS_DIR "${PROJECT_SOURCE_DIR}/include")
    target_compile_definitions(server PRIVATE LOCAL=1)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
else()
    set(DEPS_DIR "${PROJECT_SOURCE_DIR}/include_server")
    include(CheckCCompilerFlag)
    check_c_compiler_flag(-march=haswell COMPILER_SUPPORTS_HASWELL)
    if(COMPILER_SUPPORTS_HASWELL)
        target_compile_options(server PRIVATE -march=haswell)
    endif()
    check_c_compiler_flag(-flto COMPILER_SUPPORTS_FLTO)
    if(COMPILER_SUPPORTS_FLTO)
        target_compile_options(server PRIVATE -flto)
        target_link_options(server PRIVATE -flto)
    endif()
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

target_include_directories(server PRIVATE
    ${DEPS_DIR}/include
)

target_link_directories(server PRIVATE
    ${DEPS_DIR}/lib
)

find_library(H2O_EVLOOP_STATIC 
    NAMES libh2o-evloop.a h2o-evloop 
    PATHS ${DEPS_DIR}/lib 
    NO_DEFAULT_PATH
)

find_library(WSLAY_STATIC 
    NAMES libwslay.a wslay 
    PATHS ${DEPS_DIR}/lib 
    NO_DEFAULT_PATH
)

target_link_libraries(server PRIVATE
    ${H2O_EVLOOP_STATIC}
    ${WSLAY_STATIC}
    ssl
    crypto
    z
    zstd
    brotlienc
    brotlidec
    m
)

