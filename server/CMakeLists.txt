add_executable (server "server.c")

set_property(TARGET server PROPERTY C_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
target_compile_definitions(server PRIVATE H2O_USE_LIBUV=0)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET server PROPERTY CXX_STANDARD 26)
endif()

target_include_directories(server PRIVATE
    ${PROJECT_SOURCE_DIR}/include/include
)

target_link_directories(server PRIVATE
    ${PROJECT_SOURCE_DIR}/include/lib
)

find_library(H2O_EVLOOP_STATIC 
    NAMES libh2o-evloop.a h2o-evloop 
    PATHS ${PROJECT_SOURCE_DIR}/include/lib 
    NO_DEFAULT_PATH
)

find_library(WSLAY_STATIC 
    NAMES libwslay.a wslay 
    PATHS ${PROJECT_SOURCE_DIR}/include/lib 
    NO_DEFAULT_PATH
)

target_link_libraries(server PRIVATE
    h2o-evloop
    wslay
    ssl
    crypto
    z
    zstd
    brotlienc
    brotlidec
    m
)

