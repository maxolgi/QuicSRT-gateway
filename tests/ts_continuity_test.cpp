// TS-continuity probe units: the test set ported from the Rust oracle's
// ingest/continuity.rs (which itself exercises the mpeg2ts fork's
// CcChecker). Plain checks (not assert) so Release stays meaningful,
// following libwebsrt's test style.

#include "gateway/ingest/ts_continuity.h"

#include <array>
#include <cstdio>
#include <vector>

namespace
{

using websrt::gateway::TsContinuityChecker;

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "ts_continuity_test: FAIL: %s\n", what);
    }
    return cond;
}

constexpr std::size_t kTsPacketSize = 188;

std::array<std::uint8_t, kTsPacketSize> MakeTsPacket(std::uint16_t pid, std::uint8_t cc, std::uint8_t afc)
{
    std::array<std::uint8_t, kTsPacketSize> pkt{};
    pkt[0] = 0x47;
    pkt[1] = static_cast<std::uint8_t>((pid >> 8) & 0x1F);
    pkt[2] = static_cast<std::uint8_t>(pid);
    pkt[3] = static_cast<std::uint8_t>((afc << 4) | (cc & 0x0F));
    return pkt;
}

// afc=0b11 with a real one-byte adaptation field whose flags byte carries
// discontinuity_indicator (bit 7).
std::array<std::uint8_t, kTsPacketSize> MakeTsPacketWithDisc(std::uint16_t pid, std::uint8_t cc)
{
    auto pkt = MakeTsPacket(pid, cc, 0b11);
    pkt[4]   = 1;    // adaptation_field_length: one flags byte follows
    pkt[5]   = 0x80; // discontinuity_indicator = 1
    return pkt;
}

void ScanPackets(TsContinuityChecker& checker, const std::vector<std::array<std::uint8_t, kTsPacketSize>>& packets)
{
    std::vector<std::uint8_t> buf;
    for (const auto& p : packets)
    {
        buf.insert(buf.end(), p.begin(), p.end());
    }
    checker.Scan(buf.data(), buf.size());
}

// continuity.rs: packets without payload never participate.
bool TestAfcNoPayloadSkipsCcCheck()
{
    TsContinuityChecker checker;
    ScanPackets(checker, {MakeTsPacket(0x100, 5, 0b00), MakeTsPacket(0x100, 9, 0b10), MakeTsPacket(0x100, 3, 0b00)});
    Check(checker.Stats().cc_checks == 0, "afc no-payload: no checks");
    Check(checker.Stats().cc_gaps == 0, "afc no-payload: no gaps");
    return checker.Stats().cc_checks == 0 && checker.Stats().cc_gaps == 0;
}

bool TestSequentialCcStreamNeverReportsGap()
{
    TsContinuityChecker checker;
    ScanPackets(checker,
                {MakeTsPacket(0x100, 0, 0b01),
                 MakeTsPacket(0x100, 1, 0b01),
                 MakeTsPacket(0x100, 2, 0b01),
                 MakeTsPacket(0x100, 3, 0b01),
                 MakeTsPacket(0x100, 4, 0b01)});
    Check(checker.Stats().cc_checks == 5, "sequential: 5 checks");
    Check(checker.Stats().cc_gaps == 0, "sequential: no gaps");
    return checker.Stats().cc_checks == 5 && checker.Stats().cc_gaps == 0;
}

bool TestCcGapDetected()
{
    TsContinuityChecker checker;
    ScanPackets(checker, {MakeTsPacket(0x100, 0, 0b01), MakeTsPacket(0x100, 2, 0b01)});
    Check(checker.Stats().cc_gaps == 1, "gap: detected");
    // The received counter re-seeds the sequence (CcChecker: state is
    // re-seeded with the got value).
    ScanPackets(checker, {MakeTsPacket(0x100, 3, 0b01)});
    Check(checker.Stats().cc_gaps == 1, "gap: re-seeded, next packet is clean");
    return checker.Stats().cc_gaps == 1;
}

bool TestCcWraparoundNotAGap()
{
    TsContinuityChecker checker;
    ScanPackets(checker, {MakeTsPacket(0x100, 15, 0b01), MakeTsPacket(0x100, 0, 0b01)});
    Check(checker.Stats().cc_gaps == 0, "wrap 15->0: not a gap");
    return checker.Stats().cc_gaps == 0;
}

bool TestDiscontinuityIndicatorResetsState()
{
    TsContinuityChecker checker;
    ScanPackets(checker, {MakeTsPacket(0x100, 0, 0b01), MakeTsPacketWithDisc(0x100, 1), MakeTsPacket(0x100, 5, 0b01)});
    Check(checker.Stats().cc_gaps == 0, "disc indicator: signalled reset is not a gap");
    // The reset packet itself is not a check.
    Check(checker.Stats().cc_checks == 2, "disc indicator: the reset packet is not counted");
    return checker.Stats().cc_gaps == 0 && checker.Stats().cc_checks == 2;
}

bool TestMultiplePidsIndependent()
{
    TsContinuityChecker checker;
    ScanPackets(checker,
                {MakeTsPacket(0x100, 0, 0b01),
                 MakeTsPacket(0x200, 0, 0b01),
                 MakeTsPacket(0x100, 1, 0b01),
                 MakeTsPacket(0x200, 1, 0b01),
                 MakeTsPacket(0x100, 2, 0b01),
                 MakeTsPacket(0x200, 2, 0b01)});
    Check(checker.Stats().cc_gaps == 0, "multi-pid: independent sequences");
    return checker.Stats().cc_gaps == 0;
}

bool TestSyncByteMismatchSkipped()
{
    TsContinuityChecker checker;
    auto                pkt = MakeTsPacket(0x100, 0, 0b01);
    pkt[0]                  = 0xFF;
    const std::vector<std::array<std::uint8_t, kTsPacketSize>> one{pkt};
    ScanPackets(checker, one);
    Check(checker.Stats().cc_checks == 0, "bad sync: skipped");
    Check(checker.Stats().cc_gaps == 0, "bad sync: no gaps");
    return checker.Stats().cc_checks == 0;
}

// continuity.rs regression: afc=0b11 with adaptation_field_length == 0 is
// legal single-byte stuffing; byte 5 is PAYLOAD, not AF flags. A payload
// byte with bit 7 set must not be mistaken for discontinuity_indicator,
// and the tracking must survive to catch the real gap that follows.
bool TestAfc11ZeroLenAfPayloadBit7DoesNotResetCc()
{
    TsContinuityChecker checker;
    auto                stuffed = MakeTsPacket(0x100, 3, 0b11);
    Check(stuffed[4] == 0, "regression: the stuffed packet has af length 0");
    stuffed[5] = 0xFF; // payload byte with bit 7 set
    ScanPackets(checker, {MakeTsPacket(0x100, 2, 0b01), stuffed, MakeTsPacket(0x100, 5, 0b01)});
    Check(checker.Stats().cc_checks == 3, "regression: all three payload packets counted");
    Check(checker.Stats().cc_gaps == 1, "regression: the real gap after the stuffed packet is caught");
    return checker.Stats().cc_checks == 3 && checker.Stats().cc_gaps == 1;
}

// CcChecker: duplicate packets are legal (§2.4.3.3) and tolerated.
bool TestDuplicatePacketIsTolerated()
{
    TsContinuityChecker checker;
    ScanPackets(checker, {MakeTsPacket(0x100, 3, 0b01), MakeTsPacket(0x100, 3, 0b01), MakeTsPacket(0x100, 4, 0b01)});
    Check(checker.Stats().cc_gaps == 0, "duplicate: tolerated");
    Check(checker.Stats().cc_checks == 3, "duplicate: counted as checks");
    return checker.Stats().cc_gaps == 0;
}

// The first payload-bearing packet on a PID initializes the sequence -
// any starting value is accepted.
bool TestFirstPacketOnAPidInitializes()
{
    TsContinuityChecker checker;
    ScanPackets(checker, {MakeTsPacket(0x100, 13, 0b01), MakeTsPacket(0x100, 14, 0b01)});
    Check(checker.Stats().cc_gaps == 0, "first packet: initializes at any value");
    return checker.Stats().cc_gaps == 0;
}

// messages_seen counts scanned messages; a sub-188 tail holds no complete
// packet and is ignored (the oracle's chunks_exact).
bool TestMessagesSeenCountsMessages()
{
    TsContinuityChecker checker;
    ScanPackets(checker, {MakeTsPacket(0x100, 0, 0b01)});
    ScanPackets(checker, {MakeTsPacket(0x100, 1, 0b01)});
    std::array<std::uint8_t, 100> tail{};
    checker.Scan(tail.data(), tail.size());
    Check(checker.Stats().messages_seen == 3, "messages_seen: every scanned message");
    Check(checker.Stats().cc_checks == 2, "messages_seen: the tail holds no packet");
    Check(checker.Stats().cc_gaps == 0, "messages_seen: no gaps across messages");
    return checker.Stats().messages_seen == 3 && checker.Stats().cc_checks == 2;
}

} // namespace

int main()
{
    bool ok = true;
    ok &= TestAfcNoPayloadSkipsCcCheck();
    ok &= TestSequentialCcStreamNeverReportsGap();
    ok &= TestCcGapDetected();
    ok &= TestCcWraparoundNotAGap();
    ok &= TestDiscontinuityIndicatorResetsState();
    ok &= TestMultiplePidsIndependent();
    ok &= TestSyncByteMismatchSkipped();
    ok &= TestAfc11ZeroLenAfPayloadBit7DoesNotResetCc();
    ok &= TestDuplicatePacketIsTolerated();
    ok &= TestFirstPacketOnAPidInitializes();
    ok &= TestMessagesSeenCountsMessages();
    std::fprintf(stderr, "ts_continuity_test: %s\n", ok && g_ok ? "PASS" : "FAIL");
    return ok && g_ok ? 0 : 1;
}
