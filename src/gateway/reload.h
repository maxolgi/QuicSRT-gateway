// SIGHUP config hot-reload (P4.1): re-parse the config file, validate, and
// apply the runtime-swappable subset to a RUNNING gateway; everything else
// keeps running unchanged and is logged as requiring restart when it
// changed. On any parse/validation failure the old config stays active and
// the gateway stays healthy.
//
// CLI-binary-side like config.h: the gateway core stays config-free; an
// embedded consumer drives its own reload through
// Gateway::ApplyRuntimeConfig directly.

#ifndef WEBSRT_GATEWAY_RELOAD_H
#define WEBSRT_GATEWAY_RELOAD_H

#include <optional>
#include <string>

#include "gateway/config.h"
#include "gateway/gateway.h"

namespace quicsrt::gateway
{

/// Re-parse `path` and hot-apply what a running gateway can take at
/// runtime, all of it landing atomically (one Gateway::ApplyRuntimeConfig
/// post): the stream allowlist (a new SessionPolicy consulted on new
/// CONNECTs and new ingest connections only - sessions already accepted
/// keep their already-granted access), max_viewers (checked at every
/// attach), log_level (lsquic diagnostics; the --log-level flag is
/// boot-time only, a reload follows the file) and the [webhooks] settings
/// (P4.3: on_event_url/timeout, on<->off - events still queued drain
/// under the new settings). Restart-required settings that CHANGED are
/// logged; unchanged ones keep running as they are. `current` is the
/// previously applied config (the diff base, and the config that stays
/// active on failure). Returns the new config on success; nullopt with
/// *error set on a parse/validation failure.
[[nodiscard]] std::optional<Config>
ReloadConfig(const std::string& path, Gateway& gateway, const Config& current, std::string* error);

} // namespace quicsrt::gateway

#endif // WEBSRT_GATEWAY_RELOAD_H
