// Certificate provider for the WebTransport server - a port of the Rust
// oracle's crates/websrt/src/cert.rs (P3 step 1).
//
// Self mode (the default) mirrors wtransport 0.7.1's Identity::self_signed
// exactly (tls.rs:1213-1232 via tls.rs:340-350): a fresh ECDSA P-256 key
// with SHA-256 signature, CN "wtransport self-signed", SANs
// localhost/127.0.0.1/::1 (the Rust gateway's fixed list, main.rs:336-341),
// notBefore = now (NO back-skew), notAfter = now + 14 days, serial = first
// 20 bytes of SHA-256(public key bytes) with the MSB cleared (rcgen
// certificate.rs:437-443), and SANs as the ONLY extension (rcgen's IsCa
// default NoCa writes no BasicConstraints/SKI). A new cert is generated on
// EVERY construction (one boot = one provider = one cert) and is NEVER
// written to disk by the provider.
//
// Mkcert mode loads a PEM cert + key pair from files and validates that the
// key matches the certificate's public key; the browser then uses normal
// PKI validation (no pinned hash).
//
// WT-server wiring (G3): lsquic takes the server SSL_CTX through
// ea_get_ssl_ctx (wt_server.cpp builds it with NewServerSslCtx() below -
// the identity reference stays with this provider; the SSL_CTX takes its
// own reference) - the HTTPS web server (G7) builds its listener through
// the same helper so both listeners present EXACTLY the same certificate,
// which is what lets one pinned hash (cert-hash.js) cover the page AND
// the WebTransport handshake.

#ifndef WEBSRT_GATEWAY_CERT_H
#define WEBSRT_GATEWAY_CERT_H

#include <cstdint>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace websrt::gateway
{

/// Cert generation/loading failure with context (mode, path, reason).
/// Thrown by CertProvider construction and WriteCertHashJs.
class CertError : public std::runtime_error
{
public:
    explicit CertError(const std::string& message)
        : std::runtime_error(message)
    {
    }
};

/// Cert modes, mirroring the Rust oracle's --cert-mode flag.
enum class CertMode : std::uint8_t
{
    /// Self-signed ECDSA P-256, regenerated on every boot, never persisted.
    Self,
    /// PEM cert/key files loaded from disk (e.g. produced by mkcert).
    Mkcert,
};

/// A ready-to-use server certificate plus the DER SHA-256 the browser pins
/// in Self mode. Immutable after construction; thread-safe to read.
class CertProvider
{
public:
    /// Self mode: generate a fresh self-signed certificate now.
    /// Throws CertError on BoringSSL failure (practically OOM only).
    CertProvider();

    /// Mkcert mode: load cert PEM + key PEM from files. Throws CertError on
    /// unreadable files, PEM parse failure, or a cert/key pair mismatch.
    CertProvider(const std::string& cert_pem_path, const std::string& key_pem_path);

    ~CertProvider();

    CertProvider(CertProvider&& other) noexcept;
    CertProvider& operator=(CertProvider&& other) noexcept;
    CertProvider(const CertProvider&)            = delete;
    CertProvider& operator=(const CertProvider&) = delete;

    /// Leaf certificate (BoringSSL X509, borrowed - ownership stays here).
    [[nodiscard]] X509* Cert() const { return cert_; }

    /// Private key (BoringSSL EVP_PKEY, borrowed - ownership stays here).
    [[nodiscard]] EVP_PKEY* Key() const { return key_; }

    /// Leaf certificate as PEM (single CERTIFICATE section).
    [[nodiscard]] std::string CertPem() const;

    /// Private key as unencrypted PKCS#8 PEM ("PRIVATE KEY" section).
    [[nodiscard]] std::string KeyPem() const;

    /// SHA-256 of the leaf certificate DER, lowercase hex (64 chars) - the
    /// value browsers pin via serverCertificateHashes. Computable in both
    /// modes but only ADVERTISED (PinnedHash()) in Self mode.
    [[nodiscard]] std::string Sha256Hex() const;

    /// True when the browser must pin Sha256Hex() (Self mode); Mkcert mode
    /// uses normal PKI validation and cert-hash.js carries null.
    [[nodiscard]] bool PinnedHash() const { return mode_ == CertMode::Self; }

    /// Which mode this provider was built in.
    [[nodiscard]] CertMode Mode() const { return mode_; }

    /// Write cert-hash.js in the EXACT format the Rust gateway produces
    /// (websrt-gateway main.rs:381-397; no trailing newline):
    ///   Self:    window.CERT_HASH = "<sha256-hex>";\nwindow.WT_PORT = <port>;
    ///   Mkcert:  window.CERT_HASH = null;\nwindow.WT_PORT = <port>;
    /// The parent directory must already exist (web-root wiring owns mkdir).
    /// Throws CertError when the file cannot be written.
    void WriteCertHashJs(const std::string& path, std::uint16_t wt_port) const;

private:
    CertMode  mode_ = CertMode::Self;
    X509*     cert_ = nullptr;
    EVP_PKEY* key_  = nullptr;
};

/// A TLS 1.3-only server SSL_CTX carrying `cert`'s identity. Shared by the
/// WebTransport server (wt_server.cpp, which adds its h3 ALPN selector to
/// the result) and the HTTPS web server (web_server.cpp), so both listeners
/// present the same certificate and one pinned hash covers both. Returns
/// nullptr on BoringSSL failure; the caller owns the SSL_CTX (SSL_CTX_free)
/// and the provider keeps owning the certificate and key.
[[nodiscard]] SSL_CTX* NewServerSslCtx(const CertProvider& cert);

} // namespace websrt::gateway

#endif // WEBSRT_GATEWAY_CERT_H
