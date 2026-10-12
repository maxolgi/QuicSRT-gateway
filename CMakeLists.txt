cmake_minimum_required(VERSION 3.24)

project(websrt-gateway
    VERSION 0.1.0
    DESCRIPTION "CLI-parity C++ replacement of the Rust WebSRT gateway"
    LANGUAGES CXX C)

# Strict warnings for OUR targets only; deps/libwebsrt and everything it
# pulls in (srt fork, lsquic) build with their own settings.
add_library(gateway_warnings INTERFACE)
target_compile_options(gateway_warnings INTERFACE -Wall -Wextra -Wpedantic)

# The gateway is a libwebsrt CONSUMER: it sees the library exclusively
# through the exported interface targets (websrt::websrt, websrt::srt-deps,
# websrt::wt-deps) - never raw deps/ include paths. BoringSSL must already
# be fetched + built inside the libwebsrt checkout (./build.sh setup).
set(WEBSRT_ENABLE_WT ON CACHE BOOL "WebTransport support (the gateway requires it)")
add_subdirectory(deps/libwebsrt)

if(NOT WEBSRT_ENABLE_WT)
    message(FATAL_ERROR "websrt-gateway requires WEBSRT_ENABLE_WT=ON")
endif()

find_package(Threads REQUIRED)

# Gateway core library (refinement item 1): everything the embeddable
# gateway owns - accept loop machinery, session policy seam, registry - so a
# C++ app can link the gateway in-process. The CLI binary only wires
# CLI/config/ingest. Include dir exposes "gateway/..." headers.
add_library(websrtgw STATIC src/gateway/selftest.cpp)
target_compile_features(websrtgw PUBLIC cxx_std_20)
set_target_properties(websrtgw PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(websrtgw PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(websrtgw PUBLIC gateway_warnings Threads::Threads websrt::websrt websrt::wt-deps)

# Thin CLI binary over the core library.
add_executable(websrt-gateway src/main.cpp)
target_link_libraries(websrt-gateway PRIVATE websrtgw)

enable_testing()

# Smoke registration: the binary's --selftest runs the consumer gate
# (libwebsrt exports, srt fork gate, lsquic init, EventLoop).
add_test(NAME gateway_selftest COMMAND websrt-gateway --selftest)
set_tests_properties(gateway_selftest PROPERTIES TIMEOUT 30)
