#pragma once
#include <ndn-cxx/name.hpp>
#include <string>

struct Req  { std::string url; uint64_t seg = 0; bool hasSeg = false; };
struct Resp { long status = 0; std::string body; size_t total = 0; std::string err; };

// /http/<host>/<path...>[/<?query>][/seg=N]  ->  <scheme>://<host>/<path>[?query], N
// Scheme comes from env GW_SCHEME (default "http"). If no seg=N component, seg=0 is assumed.
bool nameToUrl(const ndn::Name& n, Req& r);

// HTTP GET of segment `seg` using a Range request; body = that segment, total = full size.
Resp fetch(const std::string& url, uint64_t seg, size_t segSize = 4000);
