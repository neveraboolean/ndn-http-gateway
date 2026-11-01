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


static std::map<uint32_t, std::string> ip2host;
static std::map<std::string, uint32_t> host2ip;
static std::mutex mu, cmu;
static thread_local bool bypass = false;
static const uint32_t BASE = 0x0AFF0000;

// Function-pointer type matching libc getaddrinfo.
typedef int (*gai_t)(const char*, const char*, const addrinfo*, addrinfo**);

// Lazily resolve and cache the real getaddrinfo (RTLD_NEXT = next definition after this library).
static gai_t realGai() { static gai_t r = (gai_t)dlsym(RTLD_NEXT, "getaddrinfo"); return r; }

// Intercepts getaddrinfo to map regular hostnames to fake 10.255.x.y local IPs.
extern "C" int getaddrinfo(const char* node, const char* svc, const addrinfo* hints, addrinfo** res) {
  in_addr tmp;
  if (bypass || !node || inet_pton(AF_INET, node, &tmp) || !strcmp(node, "localhost") || strchr(node, ':'))
    return realGai()(node, svc, hints, res);
  
  uint32_t ip;
  { std::lock_guard<std::mutex> l(mu);
    auto it = host2ip.find(node);
    if (it == host2ip.end()) { ip = BASE + 1 + host2ip.size(); host2ip[node] = ip; ip2host[ip] = node; }
    else ip = it->second; }
  
  char buf[32]; in_addr a{htonl(ip)}; inet_ntop(AF_INET, &a, buf, sizeof buf);
  addrinfo h{}; if (hints) h = *hints; h.ai_family = AF_INET; h.ai_flags |= AI_NUMERICHOST;
  return realGai()(buf, svc, &h, res);
}

// ---- local CA / leaf certs ----YET TO UNDERSTAND THIS

static X509* caCert; static EVP_PKEY *caKey, *leafKey;
static std::map<std::string, SSL_CTX*> ctxs;

/*
It Loads the local Certificate Authority (CA) credentials from disk once.

What it does:
1. Checks the 'NDN_CA_DIR' environment variable (defaults to '/workspace/ca')
2. Reads the local CA's public certificate ('ca.pem') and private key ('ca.key') so we have the cryptographic authority to sign forged certificates
3. Generates a shared P-256 key (`leafKey`) that will be embedded inside every dynamically generated leaf certificate
4. Uses `std::call_once` to ensure this initialization only happens once
*/
static void initCA() {
  static std::once_flag f;

  std::call_once(f, [] {
    const char* d = getenv("NDN_CA_DIR"); std::string dir = d ? d : "/workspace/ca";
    FILE* fp = fopen((dir + "/ca.pem").c_str(), "r"); if (fp) { caCert = PEM_read_X509(fp, 0, 0, 0); fclose(fp); }
    fp = fopen((dir + "/ca.key").c_str(), "r"); if (fp) { caKey = PEM_read_PrivateKey(fp, 0, 0, 0); fclose(fp); }
    leafKey = EVP_EC_gen("P-256");
  });
}

/*
This function creates, signs, and caches an SSL server context with a forged certificate for any requested hostname on the fly.

What it does:
1. Ensures the local CA is loaded by calling `initCA()`
2. Checks a thread-safe cache (`ctxs`) to see if we already forged a certificate for this specific hostname. If found, it returns the cached SSL context immediately[cite: 1].
3. If not cached, it creates a brand new X.509 v3 certificate structure
4. Sets the Common Name (CN) and Subject Alternative Name (SAN) to match the target `host` (e.g., `google.com`)
5. Sets the issuer to our local CA and signs the certificate using the local CA's private key (`caKey`) and SHA-256
6. Builds a new OpenSSL server context (`SSL_CTX`), binds the forged certificate and shared leaf key to it, caches it, and returns it so the local proxy 
can complete a trusted TLS handshake with the app
 */
static SSL_CTX* ctxFor(const std::string& host) {
  initCA(); if (!caCert || !caKey || !leafKey) return nullptr;
  std::lock_guard<std::mutex> l(cmu);
  auto it = ctxs.find(host); if (it != ctxs.end()) return it->second;
  X509* x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), (long)::time(0) + (long)ctxs.size());
  X509_gmtime_adj(X509_getm_notBefore(x), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x), 86400L * 365);
  X509_set_pubkey(x, leafKey);
  X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC, (const unsigned char*)host.c_str(), -1, -1, 0);
  X509_set_issuer_name(x, X509_get_subject_name(caCert));
  X509V3_CTX c; X509V3_set_ctx_nodb(&c); X509V3_set_ctx(&c, caCert, x, 0, 0, 0);
  std::string san = "DNS:" + host;
  X509_EXTENSION* e = X509V3_EXT_conf_nid(nullptr, &c, NID_subject_alt_name, san.c_str());
  if (e) { X509_add_ext(x, e, -1); X509_EXTENSION_free(e); }
  X509_sign(x, caKey, EVP_sha256());
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_use_certificate(ctx, x); SSL_CTX_use_PrivateKey(ctx, leafKey);
  X509_free(x);
  return ctxs[host] = ctx;
}

static std::string pdecode(const std::string& s) {
  std::string o;
  for (size_t i = 0; i < s.size(); i++)
    if (s[i] == '%' && i + 2 < s.size()) { o += (char)strtol(s.substr(i + 1, 2).c_str(), 0, 16); i += 2; }
    else o += s[i];
  return o;
}


static void bridge(int fd, std::string host) {
  bypass = true;
  SSL_CTX* ctx = ctxFor(host);
  SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
  if (!ssl) { close(fd); return; }
  SSL_set_fd(ssl, fd);
  if (SSL_accept(ssl) <= 0) { SSL_free(ssl); close(fd); return; }
  std::string req; char b[2048];
  while (req.find("\r\n\r\n") == std::string::npos && req.size() < 16384) {
    int n = SSL_read(ssl, b, sizeof b); if (n <= 0) goto done; req.append(b, n);
  }
  {
    
    size_t s1 = req.find(' '), s2 = req.find(' ', s1 + 1);
    std::string target = req.substr(s1 + 1, s2 - s1 - 1), query;
    if (size_t q = target.find('?'); q != std::string::npos) { query = target.substr(q); target.resize(q); }

    Name base("/https"); base.append(name::Component(host));
    for (size_t i = 0; i < target.size();) {
      size_t j = target.find('/', i); if (j == std::string::npos) j = target.size();
      if (j > i) base.append(name::Component(pdecode(target.substr(i, j - i))));
      i = j + 1;
    }
    if (!query.empty()) base.append(name::Component(query));

    std::string body; int status = 200; uint64_t last = 0;
    try {
      for (uint64_t seg = 0; seg <= last && status == 200; seg++) {
        Face face;
        Interest i(Name(base).appendSegment(seg)); i.setInterestLifetime(10_s);
        bool got = false;
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
    std::string out = "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK" : " Error") +
        "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    for (size_t o = 0; o < out.size();) { int n = SSL_write(ssl, out.data() + o, (int)(out.size() - o)); if (n <= 0) break; o += n; }
  }
done:
  SSL_shutdown(ssl); SSL_free(ssl); close(fd);
}


extern "C" int connect(int fd, const sockaddr* sa, socklen_t len) {
  static auto real = (int(*)(int, const sockaddr*, socklen_t))dlsym(RTLD_NEXT, "connect");
  if (!bypass && sa->sa_family == AF_INET) {
    const sockaddr_in* in = (const sockaddr_in*)sa;
    uint32_t ip = ntohl(in->sin_addr.s_addr); std::string host;
    { std::lock_guard<std::mutex> l(mu); auto it = ip2host.find(ip); if (it != ip2host.end()) host = it->second; }
    if (!host.empty()) {
      if (ntohs(in->sin_port) == 443) {
        int sv[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -1;
        int fl = fcntl(fd, F_GETFL); dup2(sv[0], fd); close(sv[0]);
        if (fl & O_NONBLOCK) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
        std::thread(bridge, sv[1], host).detach();
        return 0;
      }
      addrinfo hh{}, *r = nullptr; hh.ai_family = AF_INET; hh.ai_socktype = SOCK_STREAM;   
      if (realGai()(host.c_str(), std::to_string(ntohs(in->sin_port)).c_str(), &hh, &r) || !r) return -1;
      int rc = real(fd, r->ai_addr, r->ai_addrlen); freeaddrinfo(r); return rc;
    }
  }
  return real(fd, sa, len);
}
