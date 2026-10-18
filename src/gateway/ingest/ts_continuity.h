// Per-connection MPEG-TS continuity-counter probe (wrapping every
// ingester message) over the mpeg2ts fork's CcChecker semantics
// (ISO/IEC 13818-1 / ITU-T H.222.0 §2.4.3.3).
//
// PURPOSE. A read-only diagnostic: a CC gap seen here indicates loss
// UPSTREAM of the gateway (OBS/publisher -> ingest); the absence of gaps
// means any downstream loss originates in the broadcaster fanout or the
// per-session SRT/QUIC path. The counters surface in /health's ingester
// slot (per stream name): cc_checks, cc_gaps, messages_seen.
//
// RULES (CcChecker, ported exactly):
//   - Only payload-bearing packets (adaptation_field_control 0b01/0b11)
//     participate; a packet without payload never advances a PID's
//     sequence (and is not counted as a check).
//   - The first payload-bearing packet on a PID initializes the sequence
//     (counted as a check, never a gap).
//   - expected = last + 1 (mod 16). A wrap 15 -> 0 is in-sequence.
//   - Duplicate packets (same counter as the previous payload-bearing
//     packet) are legal per §2.4.3.3 and tolerated.
//   - discontinuity_indicator set (afc 0b11, adaptation_field_length >= 1,
//     flags bit 7): a signalled reset - the PID's state is cleared, the
//     next packet on the PID starts a new sequence, and the packet is NOT
//     counted as a check. With length == 0 the field at offset 5 is a
//     single stuffing byte and the PAYLOAD follows - it must not be
//     misread as flags (a fixed regression).
//   - A non-0x47 sync byte fails the parse: the packet is skipped.
//   - Null packets (PID 0x1FFF) are tracked like any other PID;
//     transport_error_indicator is not treated specially.
//
// cc_checks counts every payload-bearing packet that participated in a
// comparison (everything except signalled resets); cc_gaps counts
// continuity breaks (the received counter re-seeds the sequence).
//
// SCAN POINT. A raw-message scan would use
// chunks_exact(188); this gateway's TsChunker framing (srt_ingest.cpp
// FeedAndChunk) guarantees every published chunk is already a whole
// number of 188-byte packets, so the probe scans those - same coverage
// of every complete TS packet, without misalignment
// exposure. messages_seen counts the messages scanned. The probe stays pure and
// lets the counters speak - the ingest thread owns logging.
//
// THREADING: owned by the ingest connection (one probe per publisher
// connection, state never shared); single-threaded by construction.

#ifndef QUICSRT_GATEWAY_INGEST_TS_CONTINUITY_H
#define QUICSRT_GATEWAY_INGEST_TS_CONTINUITY_H

#include <cstddef>
#include <cstdint>
#include <map>

namespace quicsrt::gateway
{

/// The probe's live counters - the /health ingester values, per stream
/// name.
struct TsCcStats
{
    std::uint64_t cc_checks     = 0; ///< payload-bearing packets compared
    std::uint64_t cc_gaps       = 0; ///< continuity breaks
    std::uint64_t messages_seen = 0; ///< messages scanned
};

/// Per-connection TS continuity probe: per-PID sequence tracking over
/// 188-aligned messages, pure diagnostic (the bytes are never modified).
class TsContinuityChecker
{
public:
    /// Scan one message - a whole number of 188-byte TS packets (plus an
    /// optional sub-188 tail, which holds no complete packet and is
    /// ignored). Per-PID state and counters persist across messages.
    void Scan(const std::uint8_t* data, std::size_t len)
    {
        ++stats_.messages_seen;
        for (std::size_t off = 0; off + kTsPacketSize <= len; off += kTsPacketSize)
        {
            const std::uint8_t* p = data + off;
            if (p[0] != kSyncByte)
            {
                continue; // parse failure: skipped
            }
            const std::uint16_t pid = static_cast<std::uint16_t>(((p[1] & 0x1F) << 8) | p[2]);
            const unsigned      afc = static_cast<unsigned>((p[3] >> 4) & 0x3);
            const std::uint8_t  cc  = static_cast<std::uint8_t>(p[3] & 0x0F);

            // Only payload-bearing packets advance a PID's sequence.
            if (afc != 0b01 && afc != 0b11)
            {
                continue;
            }
            // afc 0b11: the adaptation field starts at [4] (its length);
            // with length >= 1 the flags byte at [5] carries
            // discontinuity_indicator (bit 7). length == 0 is a single
            // stuffing byte - [5] is PAYLOAD, never flags.
            if (afc == 0b11 && p[4] != 0 && (p[5] & 0x80) != 0)
            {
                last_.erase(pid); // signalled reset: not a check
                continue;
            }
            ++stats_.cc_checks;
            const auto it = last_.find(pid);
            if (it == last_.end())
            {
                last_.emplace(pid, cc); // first packet on this PID
                continue;
            }
            const std::uint8_t expected = static_cast<std::uint8_t>((it->second + 1) & 0x0F);
            if (cc == it->second)
            {
                continue; // legal duplicate (§2.4.3.3): tolerated
            }
            it->second = cc; // the received counter re-seeds the sequence
            if (cc != expected)
            {
                ++stats_.cc_gaps;
            }
        }
    }

    [[nodiscard]] TsCcStats Stats() const { return stats_; }

private:
    static constexpr std::uint8_t kSyncByte     = 0x47;
    static constexpr std::size_t  kTsPacketSize = 188;

    std::map<std::uint16_t, std::uint8_t> last_; ///< pid -> last payload-bearing CC
    TsCcStats                             stats_;
};

} // namespace quicsrt::gateway

#endif // QUICSRT_GATEWAY_INGEST_TS_CONTINUITY_H
