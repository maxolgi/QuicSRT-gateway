// The embedded example configuration: scripts/gateway.example.conf baked
// into the binary at compile time (generated table, like the embedded
// player). A bare binary - the release artifact ships nothing else - is
// self-documenting: on the first run WITHOUT --config, main.cpp writes
// this body to ./gateway.conf so the operator has a fully commented
// starting point next to the binary. Never written when --config is
// given: an explicit path is the operator's decision, and a missing file
// there stays an error.

#ifndef QUICSRT_GATEWAY_EMBEDDED_EXAMPLE_CONF_H
#define QUICSRT_GATEWAY_EMBEDDED_EXAMPLE_CONF_H

#include <string_view>

namespace quicsrt::gateway
{

/// The full text of scripts/gateway.example.conf (never empty).
[[nodiscard]] std::string_view EmbeddedExampleConf();

} // namespace quicsrt::gateway

#endif // QUICSRT_GATEWAY_EMBEDDED_EXAMPLE_CONF_H
