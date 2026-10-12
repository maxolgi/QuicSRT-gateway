// websrt-gateway: CLI-parity C++ replacement of the Rust WebSRT gateway.
// Thin CLI over the websrtgw core library (refinement item 1): argument
// wiring lives here, gateway machinery lives in src/gateway/. --selftest is
// the ctest smoke entry (the consumer gate).

#include <cstdio>
#include <cstring>

#include "gateway/selftest.h"

int main(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--selftest") != 0)
        {
            std::fprintf(stderr, "usage: websrt-gateway [--selftest]\n");
            return 2;
        }
    }

    return websrt::gateway::RunSelftest();
}
