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

static std::map<uint32_t, std::string> ip2host;   // Bidirectional hostname <-> fake IP tables (host byte order).
static std::map<std::string, uint32_t> host2ip;
static std::mutex mu;   
static thread_local bool bypass = false;           //To avoid the background internal calls to trigger our hooks recursively.
static const uint32_t BASE = 0x0AFF0000;           // 10.255.0.0/16 = fake range

/* 
This function overrides libc's resolver. 
If the domain name is localhost, an IP literal or a bypass thread, it passes the request straight through to the real DNS system(dlysm).
Otherwise it checks if we assigned a fake IP(10.255.x.y), if not it assigns a new one.
It tricks curl by formatting that IP into the addrinfo format so the app thinks it successfully resolved the domain.
Note: extern "C" keeps the unmangled symbol name so the dynamic linker picks it.
*/
extern "C" int getaddrinfo(const char* node, const char* svc, const addrinfo* hints, addrinfo** res) {
  static auto real = (int(*)(const char*, const char*, const addrinfo*, addrinfo**))dlsym(RTLD_NEXT, "getaddrinfo");
  in_addr tmp;

  if (bypass || !node || inet_pton(AF_INET, node, &tmp) || !strcmp(node, "localhost") || strchr(node, ':'))
    return real(node, svc, hints, res);
  
  uint32_t ip;
  { std::lock_guard<std::mutex> l(mu);
    auto it = host2ip.find(node);
    if (it == host2ip.end()) { ip = BASE + 1 + host2ip.size(); host2ip[node] = ip; ip2host[ip] = node; }
    else ip = it->second; }
  
  char buf[32]; in_addr a{htonl(ip)}; inet_ntop(AF_INET, &a, buf, sizeof buf);
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

/*
Runs for every connection, converts the HTTP request to an NDN interest packet and then converts it back when recieved. 
Also fd is our end of the socketpair.
*/
static void bridge(int fd, std::string host) {
  bypass = true;

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
  for (size_t i = 0; i < target.size();) {
    size_t j = target.find('/', i); if (j == std::string::npos) j = target.size();
    if (j > i) base.append(name::Component(pdecode(target.substr(i, j - i))));
    i = j + 1;
  }
  if (!query.empty()) base.append(name::Component(query));

  // Fetch all content segments sequentially from NDN, accumulate the response body and write the final HTTP response back to the app.
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
  wall(fd, "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK" : " Error") +
       "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body);
  close(fd);
}

/* 
Hook: overrides libc connect().
Intercepts connection attempts, redirects fake IPs to a local UNIX socketpair, spawns a background bridge thread to handle NDN translation, and passes real IPs through.
*/
extern "C" int connect(int fd, const sockaddr* sa, socklen_t len) {
  static auto real = (int(*)(int, const sockaddr*, socklen_t))dlsym(RTLD_NEXT, "connect");
  if (!bypass && sa->sa_family == AF_INET) {
    uint32_t ip = ntohl(((const sockaddr_in*)sa)->sin_addr.s_addr); std::string host;
    { std::lock_guard<std::mutex> l(mu); auto it = ip2host.find(ip); if (it != ip2host.end()) host = it->second; }
    if (!host.empty()) {
      int sv[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return -1;
      int fl = fcntl(fd, F_GETFL); dup2(sv[0], fd); close(sv[0]);
      if (fl & O_NONBLOCK) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
      std::thread(bridge, sv[1], host).detach();
      return 0;                                   
    }
  }
  // Not a fake IP: delegate to libc's real connect().
  return real(fd, sa, len);
}
