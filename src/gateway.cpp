// gateway.cpp - NDN->HTTP gateway daemon for the /http prefix (see translate.cpp, packetize.cpp).
// Flow: Interest -> nameToUrl -> fetch (libcurl) -> putSegment (signed Data).
// NDN -> HTTP gateway: serves /http/<host>/<path>/seg=N by fetching the origin over HTTP(S).
// Env: GW_SCHEME=http|https (default http), GW_ALLOW=host1,host2 (default: allow all = open proxy!)
#include "translate.hpp"
#include "packetize.hpp"
#include <iostream>
#include <set>
#include <sstream>
using namespace ndn;

// Segment payload size in bytes. Must stay consistent across requests (segment N always = same byte range).
static const size_t SEG = 4000;
// Host allowlist from env GW_ALLOW. Empty = every host allowed (open proxy).
static std::set<std::string> allow;
// Connection to the local NFD, shared by all Interest callbacks. KeyChain signs outgoing Data.
static Face face;
static KeyChain kc;

// Called by ndn-cxx for each Interest under the registered prefix.
static void onInterest(const InterestFilter&, const Interest& i) {
  const Name& n = i.getName();
  Req r;
  // Translate the name to a URL; silently drop malformed requests (no Data -> requester times out).
  if (!nameToUrl(n, r)) return;
  // Enforce the host allowlist (component 1 of the name is the hostname).
  if (!allow.empty()) {
    std::string h(reinterpret_cast<const char*>(n[1].value()), n[1].value_size());
    if (!allow.count(h)) { std::cerr << "blocked host " << h << std::endl; return; }
  }
  // Blocking HTTP fetch of the requested segment from the origin.
  Resp p = fetch(r.url, r.seg, SEG);
  std::cout << r.url << " seg=" << r.seg << " status=" << p.status << " total=" << p.total
            << (p.err.empty() ? "" : " err=" + p.err) << std::endl;
  // Only 200/206 are served; origin errors produce no Data.
  if (p.status != 200 && p.status != 206) return;   // no Data -> requester times out
  // Data name: same as Interest if it had seg=N, otherwise append seg=0 (answers CanBePrefix Interests).
  Name dn = r.hasSeg ? n : Name(n).appendSegment(0); // CanBePrefix Interests w/o seg get seg=0
  // Build, sign and send the Data (Module 3).
  putSegment(face, kc, dn, p.body, lastSegFor(p.total, SEG));
}

// Entry point: read config, register the prefix with NFD, run the event loop.
int main() {
  // Parse GW_ALLOW (comma-separated hostnames) into the allowlist.
  if (const char* a = getenv("GW_ALLOW")) {
    std::stringstream ss(a); std::string h;
    while (std::getline(ss, h, ',')) if (!h.empty()) allow.insert(h);
  }
  // Register the prefix with NFD so matching Interests are delivered to onInterest; exit if registration fails.
  face.setInterestFilter("/http", onInterest, nullptr,
      [](const Name& pfx, const std::string& why) {
        std::cerr << "register failed " << pfx << ": " << why << std::endl; exit(1); });
  std::cout << "gateway up; prefix /http; scheme=" << (getenv("GW_SCHEME") ? getenv("GW_SCHEME") : "http") << std::endl;
  // Blocking event loop: runs forever, dispatching Interests.
  face.processEvents();
}
