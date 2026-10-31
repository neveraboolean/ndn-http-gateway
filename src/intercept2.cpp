// intercept2.cpp - LD_PRELOAD client shim for HTTPS. Like intercept.cpp but only port 443 is redirected:
//  the shim acts as a local TLS server using a per-host certificate signed by a local CA the client must trust
//  (e.g. curl --cacert ca.pem), decrypts the request, fetches via NDN /https/..., and re-encrypts the reply.
// CA files: $NDN_CA_DIR (default /workspace/ca) containing ca.pem and ca.key.
// Security note: whoever holds ca.key can impersonate any site to clients that trust it; keep it private.
// Port 443 -> local TLS termination (per-host leaf cert signed by local CA) -> NDN /https/...
// Non-443 connections to hooked hostnames are resolved and connected normally.
#include <dlfcn.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <thread>
#include <mutex>
#include <map>
#include <string>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <ndn-cxx/face.hpp>
using namespace ndn;

// Hostname <-> fake IP tables (host byte order), as in intercept.cpp.
static std::map<uint32_t, std::string> ip2host;
static std::map<std::string, uint32_t> host2ip;
// mu protects the IP tables; cmu protects the SSL context cache.
static std::mutex mu, cmu;
// Set in bridge threads so their own lookups/connects are not re-intercepted.
static thread_local bool bypass = false;
// Fake range starts at 10.255.0.1.
static const uint32_t BASE = 0x0AFF0000;

// Function-pointer type matching libc getaddrinfo.
typedef int (*gai_t)(const char*, const char*, const addrinfo*, addrinfo**);
// Lazily resolve and cache the real getaddrinfo (RTLD_NEXT = next definition after this library).
static gai_t realGai() { static gai_t r = (gai_t)dlsym(RTLD_NEXT, "getaddrinfo"); return r; }

// Hook: returns fake IPs for hostnames, same logic as intercept.cpp.
extern "C" int getaddrinfo(const char* node, const char* svc, const addrinfo* hints, addrinfo** res) {
  // Scratch for detecting IP literals.
  in_addr tmp;
  // Pass through for bypass threads, NULL node, IP literals, localhost, IPv6.
  if (bypass || !node || inet_pton(AF_INET, node, &tmp) || !strcmp(node, "localhost") || strchr(node, ':'))
    return realGai()(node, svc, hints, res);
  // Look up or allocate the hostname's fake IP under the lock.
  uint32_t ip;
  { std::lock_guard<std::mutex> l(mu);
    auto it = host2ip.find(node);
    if (it == host2ip.end()) { ip = BASE + 1 + host2ip.size(); host2ip[node] = ip; ip2host[ip] = node; }
    else ip = it->second; }
  char buf[32]; in_addr a{htonl(ip)}; inet_ntop(AF_INET, &a, buf, sizeof buf);
  addrinfo h{}; if (hints) h = *hints; h.ai_family = AF_INET; h.ai_flags |= AI_NUMERICHOST;
  return realGai()(buf, svc, &h, res);
}

// ---- local CA / leaf certs ----
// Local CA certificate/key (loaded from disk) and one EC key reused by all leaf certificates.
static X509* caCert; static EVP_PKEY *caKey, *leafKey;
// Cache: hostname -> TLS server context holding that host's forged certificate.
static std::map<std::string, SSL_CTX*> ctxs;
// Load the CA once (thread-safe via std::call_once).
static void initCA() {
  static std::once_flag f;
  // Body runs a single time even with concurrent callers.
  std::call_once(f, [] {
    // CA directory from NDN_CA_DIR, default /workspace/ca; missing files leave pointers null (TLS then fails).
    const char* d = getenv("NDN_CA_DIR"); std::string dir = d ? d : "/workspace/ca";
    FILE* fp = fopen((dir + "/ca.pem").c_str(), "r"); if (fp) { caCert = PEM_read_X509(fp, 0, 0, 0); fclose(fp); }
    fp = fopen((dir + "/ca.key").c_str(), "r"); if (fp) { caKey = PEM_read_PrivateKey(fp, 0, 0, 0); fclose(fp); }
    // Generate a P-256 key shared by every leaf certificate (OpenSSL 3.x API).
    leafKey = EVP_EC_gen("P-256");
  });
}
// Return (creating if needed) a TLS context whose certificate is for `host`, signed by the local CA.
static SSL_CTX* ctxFor(const std::string& host) {
  initCA(); if (!caCert || !caKey || !leafKey) return nullptr;
  // Serialise cache access and certificate creation.
  std::lock_guard<std::mutex> l(cmu);
  auto it = ctxs.find(host); if (it != ctxs.end()) return it->second;
  // Build the leaf certificate.
  X509* x = X509_new();
  // Version value 2 = X.509 v3 (needed for the SAN extension).
  X509_set_version(x, 2);
  // Serial number: current time plus cache size, to keep serials distinct.
  ASN1_INTEGER_set(X509_get_serialNumber(x), (long)::time(0) + (long)ctxs.size());
  // Validity: from 1 hour ago (clock skew margin) to 1 year ahead.
  X509_gmtime_adj(X509_getm_notBefore(x), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x), 86400L * 365);
  // Certificate holds the shared leaf public key.
  X509_set_pubkey(x, leafKey);
  // Subject CN = hostname.
  X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC, (const unsigned char*)host.c_str(), -1, -1, 0);
  // Issuer = the local CA's subject.
  X509_set_issuer_name(x, X509_get_subject_name(caCert));
  // Context for building extensions (issuer = CA, subject = this cert).
  X509V3_CTX c; X509V3_set_ctx_nodb(&c); X509V3_set_ctx(&c, caCert, x, 0, 0, 0);
  // Subject Alternative Name: modern clients validate the hostname against SAN, not CN.
  std::string san = "DNS:" + host;
  X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, &c, NID_subject_alt_name, san.c_str());
  if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
  // Sign the certificate with the CA private key (SHA-256).
  X509_sign(x, caKey, EVP_sha256());
  // TLS server context using this certificate and key.
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_use_certificate(ctx, x); SSL_CTX_use_PrivateKey(ctx, leafKey);
  X509_free(x);
  // Cache and return the context (the X509 can be freed; the context holds its own reference).
  return ctxs[host] = ctx;
}

// Percent-decode a URL path segment.
static std::string pdecode(const std::string& s) {
  std::string o;
  for (size_t i = 0; i < s.size(); i++)
    if (s[i] == '%' && i + 2 < s.size()) { o += (char)strtol(s.substr(i + 1, 2).c_str(), 0, 16); i += 2; }
    else o += s[i];
  return o;
}

// Per-connection worker thread. `fd` is our end of the socketpair: TLS server toward the app, NDN consumer toward the gateway.
static void bridge(int fd, std::string host) {
  // Skip hooks for this thread's own calls.
  bypass = true;
  // Get the forged-cert context for this host; abort the connection if unavailable.
  SSL_CTX* ctx = ctxFor(host);
  SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
  if (!ssl) { close(fd); return; }
  // Run TLS over the socketpair fd.
  SSL_set_fd(ssl, fd);
  // TLS handshake as the server; fail -> clean up and close.
  if (SSL_accept(ssl) <= 0) { SSL_free(ssl); close(fd); return; }
  // Decrypt and read until the end of the HTTP headers (or 16 KiB).
  std::string req; char b[2048];
  while (req.find("\r\n\r\n") == std::string::npos && req.size() < 16384) {
    int n = SSL_read(ssl, b, sizeof b); if (n <= 0) goto done; req.append(b, n);
  }
  {
    // Parse request line; split target into path and ?query.
    size_t s1 = req.find(' '), s2 = req.find(' ', s1 + 1);
    std::string target = req.substr(s1 + 1, s2 - s1 - 1), query;
    if (size_t q = target.find('?'); q != std::string::npos) { query = target.substr(q); target.resize(q); }
    // Build /https/<host>/<path components...>[/<?query>].
    Name base("/https"); base.append(name::Component(host));
    for (size_t i = 0; i < target.size();) {
      size_t j = target.find('/', i); if (j == std::string::npos) j = target.size();
      if (j > i) base.append(name::Component(pdecode(target.substr(i, j - i))));
      i = j + 1;
    }
    if (!query.empty()) base.append(name::Component(query));

    // Fetch segments 0..last sequentially; `last` learned from FinalBlockId.
    std::string body; int status = 200; uint64_t last = 0;
    try {
      for (uint64_t seg = 0; seg <= last && status == 200; seg++) {
        // New Face per segment.
        Face face;
        Interest i(Name(base).appendSegment(seg)); i.setInterestLifetime(10_s);
        bool got = false;
        // Data -> append payload and update `last`; Nack/timeout -> got stays false -> 504.
        face.expressInterest(i,
          [&](const Interest&, const Data& d) {
            got = true;
            body.append(reinterpret_cast<const char*>(d.getContent().value()), d.getContent().value_size());
            auto fb = d.getFinalBlock(); last = (fb && fb->isSegment()) ? fb->toSegment() : seg;
          }, [&](auto&&...) {}, [&](auto&&...) {});
        face.processEvents();
        if (!got) status = 504;
      }
    } catch (...) { status = 502; }
    if (status != 200) body.clear();
    // Build a minimal HTTP/1.1 response (Content-Length, Connection: close).
    std::string out = "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK" : " Error") +
        "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    // Encrypt and send through SSL_write, looping over partial writes.
    for (size_t o = 0; o < out.size();) { int n = SSL_write(ssl, out.data() + o, (int)(out.size() - o)); if (n <= 0) break; o += n; }
  }
// Common cleanup label (reached via goto on read failure): close TLS session and fd.
done:
  SSL_shutdown(ssl); SSL_free(ssl); close(fd);
}

// Hook: overrides libc connect().
extern "C" int connect(int fd, const sockaddr* sa, socklen_t len) {
  static auto real = (int(*)(int, const sockaddr*, socklen_t))dlsym(RTLD_NEXT, "connect");
  // Only IPv4 connects from non-bypass threads can target a fake IP.
  if (!bypass && sa->sa_family == AF_INET) {
    const sockaddr_in* in = (const sockaddr_in*)sa;
    uint32_t ip = ntohl(in->sin_addr.s_addr); std::string host;
    { std::lock_guard<std::mutex> l(mu); auto it = ip2host.find(ip); if (it != ip2host.end()) host = it->second; }
    if (!host.empty()) {
      // Port 443: swap the app's socket for a socketpair end (dup2) and serve it in a bridge thread.
      if (ntohs(in->sin_port) == 443) {
        // sv[0] becomes the app's fd; sv[1] is served by bridge().
        int sv[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -1;
        int fl = fcntl(fd, F_GETFL); dup2(sv[0], fd); close(sv[0]);
        if (fl & O_NONBLOCK) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        // Detached worker; return 0 so the app believes connect() succeeded.
        std::thread(bridge, sv[1], host).detach();
        return 0;
      }
      // Other ports on a hooked hostname: resolve the real IP with the real getaddrinfo and connect normally.
      addrinfo hh{}, *r = nullptr; hh.ai_family = AF_INET; hh.ai_socktype = SOCK_STREAM;   // other ports: real network
      if (realGai()(host.c_str(), std::to_string(ntohs(in->sin_port)).c_str(), &hh, &r) || !r) return -1;
      int rc = real(fd, r->ai_addr, r->ai_addrlen); freeaddrinfo(r); return rc;
    }
  }
  // Not a fake IP: delegate to libc's real connect().
  return real(fd, sa, len);
}