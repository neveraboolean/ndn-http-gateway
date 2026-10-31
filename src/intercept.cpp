// intercept.cpp - LD_PRELOAD client shim (plain HTTP). Preloaded into an unmodified program (e.g. curl):
//  1. getaddrinfo() hands out a fake 10.255.x.y IP per hostname and remembers the mapping.
//  2. connect() to a fake IP is replaced by a socketpair; the app thinks it connected via TCP.
//  3. A helper thread reads the app's HTTP request, sends NDN Interests, and writes an HTTP reply back.
// Note: every hooked connection is treated as HTTP regardless of port; use intercept2.cpp for HTTPS.
// LD_PRELOAD shim: getaddrinfo() returns a fake IP per hostname; connect() to a fake IP is
// replaced by a socketpair served by a thread that turns the HTTP GET into NDN Interests.
#include <dlfcn.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <mutex>
#include <map>
#include <string>
#include <ndn-cxx/face.hpp>
using namespace ndn;

// Bidirectional hostname <-> fake IP tables (host byte order).
static std::map<uint32_t, std::string> ip2host;   // host-order fake IP -> hostname
static std::map<std::string, uint32_t> host2ip;
// Protects both tables (apps may resolve/connect from several threads).
static std::mutex mu;
// Set in bridge threads so their own lookups/connects are not re-intercepted.
static thread_local bool bypass = false;
// Fake addresses start at 10.255.0.1 (0x0AFF0000 = 10.255.0.0).
static const uint32_t BASE = 0x0AFF0000;           // 10.255.0.0/16 = fake range

// Hook: overrides libc's resolver. extern "C" keeps the unmangled symbol name so the dynamic linker picks it.
extern "C" int getaddrinfo(const char* node, const char* svc, const addrinfo* hints, addrinfo** res) {
  static auto real = (int(*)(const char*, const char*, const addrinfo*, addrinfo**))dlsym(RTLD_NEXT, "getaddrinfo");
  // Scratch for inet_pton, used to detect literal IPv4 addresses.
  in_addr tmp;
  // Pass through to the real resolver for: bypass threads, NULL node, IP literals, localhost, IPv6 (has ':').
  if (bypass || !node || inet_pton(AF_INET, node, &tmp) || !strcmp(node, "localhost") || strchr(node, ':'))
    return real(node, svc, hints, res);
  // Look up or allocate this hostname's fake IP under the lock.
  uint32_t ip;
  { std::lock_guard<std::mutex> l(mu);
    auto it = host2ip.find(node);
    if (it == host2ip.end()) { ip = BASE + 1 + host2ip.size(); host2ip[node] = ip; ip2host[ip] = node; }
    else ip = it->second; }
  // Format the fake IP as text and call the real getaddrinfo on it (numeric, IPv4) so the app receives a normal addrinfo.
  char buf[32]; in_addr a{htonl(ip)}; inet_ntop(AF_INET, &a, buf, sizeof buf);
  // Copy caller's hints but force IPv4 + numeric-host, so no real DNS happens.
  addrinfo h{}; if (hints) h = *hints; h.ai_family = AF_INET; h.ai_flags |= AI_NUMERICHOST;
  return real(buf, svc, &h, res);
}

// Percent-decode a URL path segment ("%41" -> "A") before using it as an NDN name component.
static std::string pdecode(const std::string& s) {
  std::string o;
  for (size_t i = 0; i < s.size(); i++)
    if (s[i] == '%' && i + 2 < s.size()) { o += (char)strtol(s.substr(i + 1, 2).c_str(), 0, 16); i += 2; }
    else o += s[i];
  return o;
}
// Write all bytes to fd, looping over partial writes; give up on error.
static void wall(int fd, const std::string& s) {
  for (size_t o = 0; o < s.size();) { ssize_t n = write(fd, s.data() + o, s.size() - o); if (n <= 0) return; o += n; }
}

// Per-connection worker thread: HTTP request in -> NDN Interests out -> HTTP response back. `fd` is our end of the socketpair.
static void bridge(int fd, std::string host) {
  // Make this thread's own network calls skip the hooks.
  bypass = true;
  // Read until the end of the HTTP headers (blank line) or 16 KiB; close on EOF/error.
  std::string req; char b[2048];
  while (req.find("\r\n\r\n") == std::string::npos && req.size() < 16384) {
    ssize_t n = read(fd, b, sizeof b); if (n <= 0) { close(fd); return; } req.append(b, n);
  }
  // Parse the request line "GET <target> HTTP/1.1": target is between the first two spaces; split off the ?query.
  size_t s1 = req.find(' '), s2 = req.find(' ', s1 + 1);
  std::string target = req.substr(s1 + 1, s2 - s1 - 1), query;
  if (size_t q = target.find('?'); q != std::string::npos) { query = target.substr(q); target.resize(q); }
  // Build /http/<host>/<path components...>[/<?query>] (empty path components are skipped).
  Name base("/http"); base.append(name::Component(host));
  // Split target on '/', percent-decode each piece, append as a name component.
  for (size_t i = 0; i < target.size();) {
    size_t j = target.find('/', i); if (j == std::string::npos) j = target.size();
    if (j > i) base.append(name::Component(pdecode(target.substr(i, j - i))));
    i = j + 1;
  }
  if (!query.empty()) base.append(name::Component(query));

  // Fetch segments 0..last sequentially, concatenating payloads. `last` is learned from FinalBlockId.
  std::string body; int status = 200; uint64_t last = 0;
  try {
    for (uint64_t seg = 0; seg <= last && status == 200; seg++) {
      // New Face per segment (avoids reusing a stopped io context).
      Face face;                                  // fresh face per segment; talks to local NFD
      // Interest for base/seg=N with a 10 s lifetime.
      Interest i(Name(base).appendSegment(seg)); i.setInterestLifetime(10_s);
      bool got = false;
      // Callbacks: Data -> append payload and update `last`; Nack/timeout -> nothing (got stays false).
      face.expressInterest(i,
        [&](const Interest&, const Data& d) {
          got = true;
          body.append(reinterpret_cast<const char*>(d.getContent().value()), d.getContent().value_size());
          // FinalBlockId present: last = its segment number; else assume this segment is the last.
          auto fb = d.getFinalBlock(); last = (fb && fb->isSegment()) ? fb->toSegment() : seg;
        }, [&](auto&&...) {}, [&](auto&&...) {});
      // Run the event loop until the Interest is satisfied, nacked or timed out.
      face.processEvents();
      if (!got) status = 504;
    }
  // Any ndn-cxx exception (e.g. cannot reach NFD) -> HTTP 502.
  } catch (...) { status = 502; }
  // Failed fetches return an empty body.
  if (status != 200) body.clear();
  // Minimal HTTP response: status line, Content-Length, Connection: close, then the body.
  wall(fd, "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK" : " Error") +
       "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body);
  close(fd);
}

// Hook: overrides libc connect().
extern "C" int connect(int fd, const sockaddr* sa, socklen_t len) {
  static auto real = (int(*)(int, const sockaddr*, socklen_t))dlsym(RTLD_NEXT, "connect");
  // Only IPv4 connects from non-bypass threads can be to a fake IP.
  if (!bypass && sa->sa_family == AF_INET) {
    uint32_t ip = ntohl(((const sockaddr_in*)sa)->sin_addr.s_addr); std::string host;
    { std::lock_guard<std::mutex> l(mu); auto it = ip2host.find(ip); if (it != ip2host.end()) host = it->second; }
    if (!host.empty()) {
      // Fake IP found: create a connected AF_UNIX pair; sv[0] goes to the app, sv[1] to our thread.
      int sv[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -1;
      // dup2 replaces the app's socket fd with sv[0] (same fd number, now a unix socket); keep O_NONBLOCK if the app set it.
      int fl = fcntl(fd, F_GETFL); dup2(sv[0], fd); close(sv[0]);
      if (fl & O_NONBLOCK) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
      // Serve the connection in a detached thread; return 0 so the app believes connect() succeeded.
      std::thread(bridge, sv[1], host).detach();
      return 0;                                   // app believes the TCP connect succeeded
    }
  }
  // Not a fake IP: delegate to libc's real connect().
  return real(fd, sa, len);
}
