// Certificate provider implementation (see cert.h for the mirrored Rust
// semantics). All BoringSSL state is created through bssl::UniquePtr and
// released into the owning members only after every fallible step passed,
// so failure paths never leak and never leave half-built state behind.

#include "gateway/cert.h"

#include <fstream>
#include <ios>
#include <iterator>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/pem.h>
#include <openssl/sha2.h>

namespace websrt::gateway
{

namespace
{

using BsslX509 = bssl::UniquePtr<X509>;
using BsslPkey = bssl::UniquePtr<EVP_PKEY>;

/// The Rust gateway's fixed self-signed SAN list (main.rs:336-341).
constexpr const char* kSelfSans[] = {"localhost", "127.0.0.1", "::1"};

/// "wtransport self-signed" - the CN wtransport's builder writes (tls.rs:1215).
constexpr const char* kSelfCommonName = "wtransport self-signed";

/// 14-day validity, wtransport's self-signed lifetime (tls.rs:348).
constexpr long kSelfValiditySeconds = 14LL * 24 * 60 * 60;

std::string HexLower(const unsigned char* bytes, std::size_t len)
{
    static const char* kHex = "0123456789abcdef";
    std::string        out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i)
    {
        out.push_back(kHex[bytes[i] >> 4]);
        out.push_back(kHex[bytes[i] & 0x0f]);
    }
    return out;
}

/// DER bytes of a marshalled X509.
std::vector<unsigned char> CertDer(X509* cert)
{
    unsigned char* der = nullptr;
    const int      len = i2d_X509(cert, &der);
    if (len < 0 || der == nullptr)
    {
        throw CertError("failed to marshal certificate DER");
    }
    std::vector<unsigned char> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// Read everything buffered on a memory BIO (BIO_get_mem_data is not
/// exported by BoringSSL; BIO_pending + BIO_read is the idiom there).
std::string DrainMemBio(BIO* bio)
{
    const std::size_t pending = BIO_pending(bio);
    std::string       out(pending, '\0');
    if (pending > 0 && BIO_read(bio, out.data(), static_cast<int>(pending)) != static_cast<int>(pending))
    {
        throw CertError("failed to drain memory BIO");
    }
    return out;
}

/// One SAN entry: IP-looking strings as GEN_IPADD, everything else as
/// GEN_DNS (rcgen's classification). Returns nullptr on failure; on
/// success the caller owns the entry.
GENERAL_NAME* MakeSanEntry(const char* san)
{
    GENERAL_NAME* gen = GENERAL_NAME_new();
    if (gen == nullptr)
    {
        return nullptr;
    }
    ASN1_OCTET_STRING* ip = a2i_IPADDRESS(san);
    if (ip != nullptr)
    {
        gen->type        = GEN_IPADD;
        gen->d.iPAddress = ip;
        return gen;
    }
    ASN1_IA5STRING* dns = ASN1_IA5STRING_new();
    if (dns == nullptr || ASN1_STRING_set(dns, san, -1) != 1)
    {
        ASN1_IA5STRING_free(dns);
        GENERAL_NAME_free(gen);
        return nullptr;
    }
    gen->type      = GEN_DNS;
    gen->d.dNSName = dns;
    return gen;
}

/// Generate the self-signed cert onto `cert`/`key`: fresh ECDSA P-256 key,
/// SHA-256 signature, SANs as the only extension.
void BuildSelfSigned(X509* cert, EVP_PKEY* key)
{
    bssl::UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (ec == nullptr || EC_KEY_generate_key(ec.get()) != 1 || EVP_PKEY_assign_EC_KEY(key, ec.release()) != 1)
    {
        throw CertError("self: failed to generate ECDSA P-256 key");
    }

    if (X509_set_version(cert, 2) != 1) // v3
    {
        throw CertError("self: failed to set certificate version");
    }

    // Serial: first 20 bytes of SHA-256(public key bytes), MSB cleared
    // (rcgen certificate.rs:437-443).
    {
        const EC_KEY* ec_key    = EVP_PKEY_get0_EC_KEY(key);
        const size_t  point_len = EC_POINT_point2oct(EC_KEY_get0_group(ec_key),
                                                    EC_KEY_get0_public_key(ec_key),
                                                    POINT_CONVERSION_UNCOMPRESSED,
                                                    nullptr,
                                                    0,
                                                    nullptr);
        if (point_len == 0)
        {
            throw CertError("self: failed to encode public key point");
        }
        std::vector<unsigned char> buf(point_len);
        if (EC_POINT_point2oct(EC_KEY_get0_group(ec_key),
                               EC_KEY_get0_public_key(ec_key),
                               POINT_CONVERSION_UNCOMPRESSED,
                               buf.data(),
                               buf.size(),
                               nullptr) == 0)
        {
            throw CertError("self: failed to encode public key point");
        }
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(buf.data(), buf.size(), digest);
        digest[0] &= 0x7f; // keep the serial non-negative in 20 bytes
        const bssl::UniquePtr<BIGNUM> bn(BN_bin2bn(digest, 20, nullptr));
        if (bn == nullptr || BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(cert)) == nullptr)
        {
            throw CertError("self: failed to set serial number");
        }
    }

    // Validity: notBefore = now (wtransport applies NO back-skew, tls.rs
    // from_now_utc), notAfter = notBefore + 14 days.
    if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(cert), kSelfValiditySeconds) == nullptr)
    {
        throw CertError("self: failed to set validity period");
    }

    // Self-signed: issuer == subject, CN as wtransport writes it.
    X509_NAME* name = X509_get_subject_name(cert);
    if (X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(kSelfCommonName), -1, -1, 0) != 1 ||
        X509_set_issuer_name(cert, name) != 1)
    {
        throw CertError("self: failed to set subject/issuer name");
    }

    if (X509_set_pubkey(cert, key) != 1)
    {
        throw CertError("self: failed to set public key");
    }

    // SANs are the ONLY extension (rcgen IsCa default NoCa writes no
    // BasicConstraints/SKI/KeyUsage).
    {
        STACK_OF(GENERAL_NAME)* sans = sk_GENERAL_NAME_new_null();
        if (sans == nullptr)
        {
            throw CertError("self: failed to allocate SAN list");
        }
        for (const char* san : kSelfSans)
        {
            GENERAL_NAME* gen = MakeSanEntry(san);
            if (gen == nullptr || sk_GENERAL_NAME_push(sans, gen) == 0) // push returns the new length
            {
                GENERAL_NAME_free(gen);
                sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
                throw CertError(std::string("self: failed to build SAN entry '") + san + "'");
            }
        }
        const int added = X509_add1_ext_i2d(cert, NID_subject_alt_name, sans, /*crit=*/0, /*flags=*/0);
        sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
        if (added != 1)
        {
            throw CertError("self: failed to add subjectAltName extension");
        }
    }

    if (X509_sign(cert, key, EVP_sha256()) == 0)
    {
        throw CertError("self: failed to sign certificate");
    }
}

/// Read a whole file as a string (clear error when unreadable).
std::string ReadFile(const std::string& path, const char* what)
{
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        throw CertError(std::string("mkcert: cannot open ") + what + " file '" + path + "'");
    }
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

/// Parse one PEM object from `text` using `read` (PEM_read_bio_*). Returns
/// null on parse failure; the caller owns the result.
template <typename T>
T* PemParse(const std::string& text, T* (*read)(BIO*, T**, pem_password_cb*, void*))
{
    const bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(text.data(), static_cast<int>(text.size())));
    if (bio == nullptr)
    {
        return nullptr;
    }
    return read(bio.get(), nullptr, nullptr, nullptr);
}

} // namespace

CertProvider::CertProvider()
{
    BsslX509 cert(X509_new());
    BsslPkey key(EVP_PKEY_new());
    if (cert == nullptr || key == nullptr)
    {
        throw CertError("self: out of memory");
    }
    BuildSelfSigned(cert.get(), key.get());

    mode_ = CertMode::Self;
    cert_ = cert.release();
    key_  = key.release();
}

CertProvider::CertProvider(const std::string& cert_pem_path, const std::string& key_pem_path)
{
    const std::string cert_pem = ReadFile(cert_pem_path, "certificate PEM");
    const std::string key_pem  = ReadFile(key_pem_path, "key PEM");

    BsslX509 cert(PemParse(cert_pem, &PEM_read_bio_X509));
    if (cert == nullptr)
    {
        throw CertError("mkcert: no CERTIFICATE section found in '" + cert_pem_path + "'");
    }
    BsslPkey key(PemParse(key_pem, &PEM_read_bio_PrivateKey));
    if (key == nullptr)
    {
        throw CertError("mkcert: no private key found in '" + key_pem_path + "'");
    }

    // The pair must match: the certificate's public key IS this key.
    const BsslPkey cert_pub(X509_get_pubkey(cert.get()));
    if (cert_pub == nullptr)
    {
        throw CertError("mkcert: cannot extract public key from '" + cert_pem_path + "'");
    }
    if (EVP_PKEY_cmp(cert_pub.get(), key.get()) != 1)
    {
        throw CertError("mkcert: certificate '" + cert_pem_path + "' does not match private key '" + key_pem_path +
                        "'");
    }

    mode_ = CertMode::Mkcert;
    cert_ = cert.release();
    key_  = key.release();
}

CertProvider::~CertProvider()
{
    X509_free(cert_);
    EVP_PKEY_free(key_);
}

CertProvider::CertProvider(CertProvider&& other) noexcept
    : mode_(other.mode_)
    , cert_(other.cert_)
    , key_(other.key_)
{
    other.cert_ = nullptr;
    other.key_  = nullptr;
}

CertProvider& CertProvider::operator=(CertProvider&& other) noexcept
{
    if (this != &other)
    {
        X509_free(cert_);
        EVP_PKEY_free(key_);
        mode_       = other.mode_;
        cert_       = other.cert_;
        key_        = other.key_;
        other.cert_ = nullptr;
        other.key_  = nullptr;
    }
    return *this;
}

std::string CertProvider::CertPem() const
{
    const bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr || PEM_write_bio_X509(bio.get(), cert_) != 1)
    {
        throw CertError("failed to export certificate PEM");
    }
    return DrainMemBio(bio.get());
}

std::string CertProvider::KeyPem() const
{
    const bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr || PEM_write_bio_PKCS8PrivateKey(bio.get(), key_, nullptr, nullptr, 0, nullptr, nullptr) != 1)
    {
        throw CertError("failed to export private key PEM");
    }
    return DrainMemBio(bio.get());
}

std::string CertProvider::Sha256Hex() const
{
    const std::vector<unsigned char> der = CertDer(cert_);
    unsigned char                    digest[SHA256_DIGEST_LENGTH];
    SHA256(der.data(), der.size(), digest);
    return HexLower(digest, sizeof(digest));
}

std::string CertProvider::BuildCertHashJs(std::uint16_t wt_port) const
{
    // Byte-for-byte the Rust gateway's format (main.rs:385-395): hash form
    // for self mode, null form for mkcert, single \n between the two
    // statements, NO trailing newline.
    const std::string js =
        PinnedHash() ? "window.CERT_HASH = \"" + Sha256Hex() + "\";\n" : std::string("window.CERT_HASH = null;\n");
    return js + "window.WT_PORT = " + std::to_string(wt_port) + ";";
}

SSL_CTX* NewServerSslCtx(const CertProvider& cert)
{
    // Ownership stays with the provider; the SSL_CTX takes its own
    // references (wt_server.cpp's note). TLS 1.3 only, as the WT server
    // already pinned it: both listeners speak the same floor, so a pinned
    // hash means the same thing on either.
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    if (ctx == nullptr)
    {
        return nullptr;
    }
    if (SSL_CTX_use_certificate(ctx, cert.Cert()) != 1 || SSL_CTX_use_PrivateKey(ctx, cert.Key()) != 1 ||
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1)
    {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

} // namespace websrt::gateway
