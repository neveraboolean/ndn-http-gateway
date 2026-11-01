#include "translate.hpp"
#include "packetize.hpp"
#include <iostream>
#include <set>
#include <sstream>
using namespace ndn;

static const size_t SEG = 4000;
static std::set<std::string> allow;
static Face face;
static KeyChain kc;

// Handles incoming NDN Interests: validates the URL structure, enforces the host allowlist, 
// fetches the target segment via libcurl, and responds with a signed NDN Data packet.
static void onInterest(const InterestFilter&, const Interest& i) {
  const Name& n = i.getName();
  Req r;
  
  if (!nameToUrl(n, r)) return;
  
  if (!allow.empty()) {
    std::string h(reinterpret_cast<const char*>(n[1].value()), n[1].value_size());
    if (!allow.count(h)) { std::cerr << "blocked host " << h << std::endl; return; }
  }
  
  Resp p = fetch(r.url, r.seg, SEG);
  std::cout << r.url << " seg=" << r.seg << " status=" << p.status << " total=" << p.total
            << (p.err.empty() ? "" : " err=" + p.err) << std::endl;
            
  if (p.status != 200 && p.status != 206) return;   
  
  Name dn = r.hasSeg ? n : Name(n).appendSegment(0); 
  putSegment(face, kc, dn, p.body, lastSegFor(p.total, SEG));
}

// Parses environment configurations, registers the /http prefix with the local NFD daemon, 
// and starts the permanent event loop to process incoming Interests.
int main() {
  if (const char* a = getenv("GW_ALLOW")) {
    std::stringstream ss(a); std::string h;
    while (std::getline(ss, h, ',')) if (!h.empty()) allow.insert(h);
  }
  
  face.setInterestFilter("/http", onInterest, nullptr,
      [](const Name& pfx, const std::string& why) {
        std::cerr << "register failed " << pfx << ": " << why << std::endl; exit(1); });
        
  std::cout << "gateway up; prefix /http; scheme=" << (getenv("GW_SCHEME") ? getenv("GW_SCHEME") : "http") << std::endl;
  
  face.processEvents();
}
