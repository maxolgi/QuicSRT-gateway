// Consumer gate over libwebsrt's exported surface (websrt::websrt +
// websrt::wt-deps) - the same contract tests/consumer/ proves inside
// libwebsrt. Lives in the gateway library so embedded consumers can run the
// same gate; the CLI exposes it via --selftest (the ctest smoke entry).

#ifndef WEBSRT_GATEWAY_SELFTEST_H
#define WEBSRT_GATEWAY_SELFTEST_H

namespace websrt::gateway
{

// Runs the consumer-gate checks (libwebsrt exports, srt fork gate, lsquic
// init, EventLoop). Returns 0 when every check passes, 1 otherwise; prints
// failures to stderr and the OK line to stdout.
int RunSelftest();

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_SELFTEST_H
