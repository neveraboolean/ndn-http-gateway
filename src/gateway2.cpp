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

// This function handles the incoming HTTPS request(that is in the form of an NDN interest packet) and checks their URL
// "https://",then checks allowlists,and fetches via libcurl TLS, and returns signed data.
static void onInterest(const InterestFilter&, const Interest& i) {
  const Name& n = i.getName();
  Req r;
  
  // Translate name to URL and strictly ensure it uses the https:// scheme.
  if (!nameToUrl(n, r) || r.url.rfind("https://", 0) != 0) return;
  
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

// Registers the /https prefix with NFD and runs the permanent event loop.
int main() {
  if (const char* a = getenv("GW_ALLOW")) {
    std::stringstream ss(a); std::string h;
    while (std::getline(ss, h, ',')) if (!h.empty()) allow.insert(h);
  }
  
  // Registers the /https namespace prefix instead of /http.
  face.setInterestFilter("/https", onInterest, nullptr,
      [](const Name& pfx, const std::string& why) {
        std::cerr << "register failed " << pfx << ": " << why << std::endl; exit(1); });
        
  std::cout << "gateway2 up; prefix /https" << std::endl;
  face.processEvents();
}
