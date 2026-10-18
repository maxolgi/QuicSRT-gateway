// CertProvider units (P3 step 1): self mode mirrors wtransport's
// self-signed semantics (parses back, P-256, ~14-day validity, correct
// SHA-256, regenerated per instance), mkcert round-trips through PEM
// files and rejects mismatched pairs, and cert-hash.js matches the Rust
// gateway's byte format. Plain checks (not assert) so Release stays
// meaningful, following libquicsrt's style.

#include "gateway/cert.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <ios>
#include <iterator>
#include <string>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/sha2.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace
{

bool g_ok = true;

bool Check(bool cond, const char* what)
{
    if (!cond)
    {
        g_ok = false;
        std::fprintf(stderr, "cert_test: FAIL: %s\n", what);
    }
    return cond;
}

std::string HexLower(const unsigned char* bytes, std::size_t len)
{
    static const char* kHex = "0123456789abcdef";
    std::string        out;
    for (std::size_t i = 0; i < len; ++i)
    {
        out.push_back(kHex[bytes[i] >> 4]);
        out.push_back(kHex[bytes[i] & 0x0f]);
    }
    return out;
}

std::string ReadFileOrEmpty(const std::string& path)
{
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        return {};
    }
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

/// Unique temp paths under /tmp (PID + counter).
std::string TempPath(const char* suffix)
{
    static int counter = 0;
    return "/tmp/QuicSRTgw_cert_test_" + std::to_string(::getpid()) + "_" + std::to_string(counter++) + suffix;
}

void WriteFileOrThrow(const std::string& path, const std::string& content)
{
    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
}

bool IsLowercaseHex64(const std::string& s)
{
    return s.size() == 64 &&
           std::ranges::all_of(s, [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

void TestSelfMode()
{
    const quicsrt::gateway::CertProvider p;
    Check(p.Mode() == quicsrt::gateway::CertMode::Self, "self: mode is Self");
    Check(p.PinnedHash(), "self: hash is pinned");

    // Parses back through the DER decoder.
    unsigned char* der  = nullptr;
    const int      dlen = i2d_X509(p.Cert(), &der);
    Check(dlen > 0, "self: cert marshals to DER");
    const unsigned char* walk   = der;
    auto*                parsed = d2i_X509(nullptr, &walk, dlen);
    Check(parsed != nullptr, "self: cert parses back via d2i_X509");
    X509_free(parsed);
    OPENSSL_free(der);

    // Key is EC P-256.
    const int key_type = EVP_PKEY_base_id(p.Key());
    Check(key_type == EVP_PKEY_EC, "self: key type is EC");
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(p.Key());
    Check(ec != nullptr && EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) == NID_X9_62_prime256v1,
          "self: key curve is P-256");

    // Validity: notBefore <= now <= notAfter, notAfter - notBefore == 14 days.
    std::int64_t not_before = 0;
    std::int64_t not_after  = 0;
    Check(ASN1_TIME_to_posix(X509_getm_notBefore(p.Cert()), &not_before) == 1, "self: notBefore converts");
    Check(ASN1_TIME_to_posix(X509_getm_notAfter(p.Cert()), &not_after) == 1, "self: notAfter converts");
    const std::int64_t now = std::time(nullptr);
    Check(not_before <= now && now <= not_after, "self: cert currently valid");
    Check(not_after - not_before == 14LL * 24 * 60 * 60, "self: validity is exactly 14 days");

    // SHA-256: 64 lowercase hex chars and equal to an independently
    // computed digest of the DER (X509_digest vs our i2d+SHA256 path).
    const std::string hex = p.Sha256Hex();
    Check(IsLowercaseHex64(hex), "self: hash is 64 lowercase hex chars");
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int  digest_len = 0;
    Check(X509_digest(p.Cert(), EVP_sha256(), digest, &digest_len) == 1 && digest_len == sizeof(digest),
          "self: X509_digest computes");
    Check(hex == HexLower(digest, digest_len), "self: hash matches independent digest");

    // SANs present: DNS:localhost, IP 127.0.0.1, IP ::1.
    void* sans_raw = X509_get_ext_d2i(p.Cert(), NID_subject_alt_name, nullptr, nullptr);
    Check(sans_raw != nullptr, "self: SAN extension present");
    if (sans_raw != nullptr)
    {
        const auto* sans = static_cast<const STACK_OF(GENERAL_NAME)*>(sans_raw);
        Check(sk_GENERAL_NAME_num(sans) == 3, "self: three SANs");
        const GENERAL_NAME* first = sk_GENERAL_NAME_value(sans, 0);
        Check(first != nullptr && first->type == GEN_DNS &&
                  std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(first->d.dNSName)),
                              static_cast<std::size_t>(ASN1_STRING_length(first->d.dNSName))) == "localhost",
              "self: first SAN is DNS:localhost");
        const GENERAL_NAME* second = sk_GENERAL_NAME_value(sans, 1);
        Check(second != nullptr && second->type == GEN_IPADD, "self: second SAN is an IP");
        const GENERAL_NAME* third = sk_GENERAL_NAME_value(sans, 2);
        Check(third != nullptr && third->type == GEN_IPADD, "self: third SAN is an IP");
        sk_GENERAL_NAME_pop_free(static_cast<STACK_OF(GENERAL_NAME)*>(sans_raw), GENERAL_NAME_free);
    }

    // PEM exports round-trip: the cert PEM carries a CERTIFICATE section,
    // the key PEM is PKCS#8 ("BEGIN PRIVATE KEY").
    const std::string cert_pem = p.CertPem();
    const std::string key_pem  = p.KeyPem();
    Check(cert_pem.find("-----BEGIN CERTIFICATE-----") != std::string::npos, "self: CertPem is a certificate PEM");
    Check(key_pem.find("-----BEGIN PRIVATE KEY-----") != std::string::npos, "self: KeyPem is PKCS#8");
}

void TestSelfModeRegenerates()
{
    const quicsrt::gateway::CertProvider a;
    const quicsrt::gateway::CertProvider b;
    Check(a.Sha256Hex() != b.Sha256Hex(), "self: two instances produce different hashes");
}

void TestMkcertRoundTrip()
{
    const std::string cert_path      = TempPath(".cert.pem");
    const std::string key_path       = TempPath(".key.pem");
    const std::string other_key_path = TempPath(".other.key.pem");

    try
    {
        const quicsrt::gateway::CertProvider self_provider;
        const quicsrt::gateway::CertProvider other_provider;
        WriteFileOrThrow(cert_path, self_provider.CertPem());
        WriteFileOrThrow(key_path, self_provider.KeyPem());
        WriteFileOrThrow(other_key_path, other_provider.KeyPem());

        // Round-trip: same cert DER, same hash, mkcert mode flags.
        const quicsrt::gateway::CertProvider mk(cert_path, key_path);
        Check(mk.Mode() == quicsrt::gateway::CertMode::Mkcert, "mkcert: mode is Mkcert");
        Check(!mk.PinnedHash(), "mkcert: hash not pinned");
        Check(mk.Sha256Hex() == self_provider.Sha256Hex(), "mkcert: hash round-trips");

        // Mismatched pair: second provider's key against first's cert.
        bool threw = false;
        try
        {
            const quicsrt::gateway::CertProvider bad(cert_path, other_key_path);
            (void)bad;
        }
        catch (const quicsrt::gateway::CertError& e)
        {
            threw = true;
            Check(std::string(e.what()).find("does not match") != std::string::npos, "mkcert: mismatch error is clear");
        }
        Check(threw, "mkcert: mismatched key rejected");

        // Missing file: clear error.
        threw = false;
        try
        {
            const quicsrt::gateway::CertProvider missing("/tmp/QuicSRTgw_cert_test_does_not_exist.pem", key_path);
            (void)missing;
        }
        catch (const quicsrt::gateway::CertError& e)
        {
            threw = true;
            Check(std::string(e.what()).find("cannot open") != std::string::npos,
                  "mkcert: missing file error is clear");
        }
        Check(threw, "mkcert: missing file rejected");
    }
    catch (...)
    {
        std::remove(cert_path.c_str());
        std::remove(key_path.c_str());
        std::remove(other_key_path.c_str());
        throw;
    }
    std::remove(cert_path.c_str());
    std::remove(key_path.c_str());
    std::remove(other_key_path.c_str());
}

void TestCertHashJs()
{
    // Self mode: hash form, exact Rust byte format (no trailing newline).
    {
        const quicsrt::gateway::CertProvider p;
        const std::string                    js = p.BuildCertHashJs(4433);
        Check(js == "window.CERT_HASH = \"" + p.Sha256Hex() + "\";\nwindow.WT_PORT = 4433;",
              "cert-hash.js: self form matches Rust format byte-for-byte");
        Check(js.starts_with("window.CERT_HASH = "), "cert-hash.js: starts with window.CERT_HASH assignment");
    }

    // Mkcert mode: null form.
    {
        const quicsrt::gateway::CertProvider self_provider;
        const std::string                    cert_path = TempPath(".cert.pem");
        const std::string                    key_path  = TempPath(".key.pem");
        WriteFileOrThrow(cert_path, self_provider.CertPem());
        WriteFileOrThrow(key_path, self_provider.KeyPem());

        const quicsrt::gateway::CertProvider mk(cert_path, key_path);
        const std::string                    js = mk.BuildCertHashJs(8443);
        Check(js == "window.CERT_HASH = null;\nwindow.WT_PORT = 8443;", "cert-hash.js: mkcert form is the null form");

        std::remove(cert_path.c_str());
        std::remove(key_path.c_str());
    }
}

} // namespace

int main()
{
    TestSelfMode();
    TestSelfModeRegenerates();
    TestMkcertRoundTrip();
    TestCertHashJs();
    if (!g_ok)
    {
        std::fprintf(stderr, "cert_test: FAILURES\n");
        return 1;
    }
    std::printf("cert_test: OK\n");
    return 0;
}
