cmake_minimum_required(VERSION 3.24)

project(websrt-gateway
    VERSION 0.1.0
    DESCRIPTION "CLI-parity C++ replacement of the Rust WebSRT gateway"
    LANGUAGES CXX C)

# Strict warnings for OUR targets only; deps/libwebsrt and everything it
# pulls in (srt fork, lsquic) build with their own settings.
add_library(gateway_warnings INTERFACE)
target_compile_options(gateway_warnings INTERFACE -Wall -Wextra -Wpedantic)
# lsquic.h gates the server-side WebTransport API (lsquic_stream_set_
# webtransport_session etc.) behind this define; libwebsrt compiles lsquic
# with it but does not propagate it through websrt::wt-deps, so the gateway
# - the one consumer hosting a server engine - defines it for its own TUs.
target_compile_definitions(gateway_warnings INTERFACE LSQUIC_WEBTRANSPORT_SERVER_SUPPORT=1)

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
add_library(websrtgw STATIC
    src/gateway/cert.cpp
    src/gateway/gateway.cpp
    src/gateway/policy.cpp
    src/gateway/selftest.cpp
    src/gateway/session_registry.cpp
    src/gateway/srt_initiator.cpp
    src/gateway/ingest/srt_ingest.cpp
    src/gateway/web_server.cpp
    src/gateway/wt_server.cpp)
target_compile_features(websrtgw PUBLIC cxx_std_20)
set_target_properties(websrtgw PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(websrtgw PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(websrtgw PUBLIC gateway_warnings Threads::Threads websrt::websrt websrt::wt-deps)

# Thin CLI binary over the core library.
#
# toml++ (header-only, deps/tomlplusplus) is a gateway-binary-side
# dependency by design (refinement item 2): config parsing lives in
# websrtgw_config, never in the embeddable websrtgw core.
add_library(tomlplusplus INTERFACE)
target_include_directories(tomlplusplus INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/deps/tomlplusplus/include)

add_library(websrtgw_config STATIC src/gateway/config.cpp)
target_compile_features(websrtgw_config PUBLIC cxx_std_20)
set_target_properties(websrtgw_config PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(websrtgw_config PUBLIC gateway_warnings websrtgw tomlplusplus)

add_executable(websrt-gateway src/main.cpp)
target_link_libraries(websrt-gateway PRIVATE websrtgw_config)

enable_testing()

# Unit tests (plain-check style, libwebsrt tests/ pattern).
add_executable(policy_test tests/policy_test.cpp)
target_compile_features(policy_test PRIVATE cxx_std_20)
set_target_properties(policy_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(policy_test PRIVATE gateway_warnings websrtgw)
add_test(NAME policy_test COMMAND policy_test)
set_tests_properties(policy_test PROPERTIES TIMEOUT 30)

add_executable(config_test tests/config_test.cpp)
target_compile_features(config_test PRIVATE cxx_std_20)
set_target_properties(config_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(config_test PRIVATE gateway_warnings websrtgw_config)
add_test(NAME config_test COMMAND config_test)
set_tests_properties(config_test PROPERTIES TIMEOUT 30)

add_executable(cert_test tests/cert_test.cpp)
target_compile_features(cert_test PRIVATE cxx_std_20)
set_target_properties(cert_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(cert_test PRIVATE gateway_warnings websrtgw)
add_test(NAME cert_test COMMAND cert_test)
set_tests_properties(cert_test PROPERTIES TIMEOUT 30)

# End-to-end: libwebsrt's WTClient against the gateway's WtServer over
# loopback (127.0.0.1:4434, ephemeral fallback inside the test).
add_executable(wt_server_test tests/wt_server_test.cpp)
target_compile_features(wt_server_test PRIVATE cxx_std_20)
set_target_properties(wt_server_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(wt_server_test PRIVATE gateway_warnings websrtgw)
add_test(NAME wt_server_test COMMAND wt_server_test)
set_tests_properties(wt_server_test PROPERTIES TIMEOUT 60)

# G4: per-session SRT initiator + registry ticker over WT loopback, driven
# by libwebsrt's public Subscriber/Publisher (127.0.0.1:4435, ephemeral
# fallback inside the test).
add_executable(srt_initiator_test tests/srt_initiator_test.cpp)
target_compile_features(srt_initiator_test PRIVATE cxx_std_20)
set_target_properties(srt_initiator_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(srt_initiator_test PRIVATE gateway_warnings websrtgw)
add_test(NAME srt_initiator_test COMMAND srt_initiator_test)
set_tests_properties(srt_initiator_test PROPERTIES TIMEOUT 60)

# G5: the full gateway loop (admission, ring, first-wins occupancy, waiting
# viewers) driven by libwebsrt's public Subscriber/Publisher, configured from
# a real TOML allowlist (127.0.0.1:4434, ephemeral fallback inside the test).
add_executable(gateway_e2e_test tests/gateway_e2e_test.cpp)
target_compile_features(gateway_e2e_test PRIVATE cxx_std_20)
set_target_properties(gateway_e2e_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(gateway_e2e_test PRIVATE gateway_warnings websrtgw_config)
add_test(NAME gateway_e2e_test COMMAND gateway_e2e_test)
set_tests_properties(gateway_e2e_test PROPERTIES TIMEOUT 180)

# G6: the SRT/UDP ingest end to end - a stock-libsrt publisher over the real
# SrtIngest into the real Gateway core, with a libwebsrt Subscriber on the
# far side (127.0.0.1:9100, ephemeral fallback inside the test).
add_executable(srt_ingest_test tests/srt_ingest_test.cpp)
target_compile_features(srt_ingest_test PRIVATE cxx_std_20)
set_target_properties(srt_ingest_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(srt_ingest_test PRIVATE gateway_warnings websrtgw_config)
add_test(NAME srt_ingest_test COMMAND srt_ingest_test)
set_tests_properties(srt_ingest_test PROPERTIES TIMEOUT 180)

# G7: the web server end to end - static serving, /health, /stats and
# cert-hash.js over real TLS, against a live gateway core with a
# libwebsrt publisher/subscriber and a stock-libsrt ingest behind it.
# Ephemeral ports only (the web/health servers ask for 0).
add_executable(web_server_test tests/web_server_test.cpp)
target_compile_features(web_server_test PRIVATE cxx_std_20)
set_target_properties(web_server_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(web_server_test PRIVATE gateway_warnings websrtgw_config)
add_test(NAME web_server_test COMMAND web_server_test)
set_tests_properties(web_server_test PROPERTIES TIMEOUT 120)

# G8: the 50-viewer concurrency gate - one gateway core, 50 Subscriber
# threads + 1 Publisher at a realistic ~2.7 Mbps rate for ~15 s (ephemeral
# fallback inside the test; default 127.0.0.1:4436).
add_executable(concurrency_test tests/concurrency_test.cpp)
target_compile_features(concurrency_test PRIVATE cxx_std_20)
set_target_properties(concurrency_test PROPERTIES CXX_EXTENSIONS OFF)
target_link_libraries(concurrency_test PRIVATE gateway_warnings websrtgw)
add_test(NAME concurrency_test COMMAND concurrency_test)
set_tests_properties(concurrency_test PROPERTIES TIMEOUT 180)

# Smoke registration: the binary's --selftest runs the consumer gate
# (libwebsrt exports, srt fork gate, lsquic init, EventLoop).
add_test(NAME gateway_selftest COMMAND websrt-gateway --selftest)
set_tests_properties(gateway_selftest PROPERTIES TIMEOUT 30)
