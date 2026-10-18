// Consumer gate over libquicsrt's exported surface (quicsrt::quicsrt +
// quicsrt::wt-deps) - the same contract tests/consumer/ proves inside
// libquicsrt. Lives in the gateway library so embedded consumers can run the
// same gate; the CLI exposes it via --selftest (the ctest smoke entry).

#ifndef QUICSRT_GATEWAY_SELFTEST_H
#define QUICSRT_GATEWAY_SELFTEST_H

namespace quicsrt::gateway
{

// Runs the consumer-gate checks (libquicsrt exports, srt fork gate, lsquic
// init, EventLoop). Returns 0 when every check passes, 1 otherwise; prints
// failures to stderr and the OK line to stdout.
int RunSelftest();

} // namespace quicsrt::gateway

#endif // QUICSRT_GATEWAY_SELFTEST_H
