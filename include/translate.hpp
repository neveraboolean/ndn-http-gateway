// translate.hpp - Module 2 API: map an NDN name to an HTTP(S) URL and fetch one segment with libcurl.
// Used by gateway.cpp and gateway2.cpp (the NDN side never touches libcurl directly).
#pragma once
#include <ndn-cxx/name.hpp>
#include <string>

// Result of parsing an NDN name:
//   url    - origin URL to GET
//   seg    - segment number requested (from the trailing seg=N component)
//   hasSeg - false if the Interest carried no seg=N component (seg then defaults to 0)
struct Req  { std::string url; uint64_t seg = 0; bool hasSeg = false; };
// Result of one HTTP fetch:
//   status - HTTP status code (200/206 = success)
//   body   - bytes of the requested segment only
//   total  - full resource size in bytes (from Content-Range, or body size on 200)
//   err    - libcurl error text if the transfer itself failed
struct Resp { long status = 0; std::string body; size_t total = 0; std::string err; };

// /http/<host>/<path...>[/<?query>][/seg=N]  ->  <scheme>://<host>/<path>[?query], N
// Scheme comes from env GW_SCHEME (default "http"). If no seg=N component, seg=0 is assumed.
// Returns false if the name is not a valid /http or /https request.
bool nameToUrl(const ndn::Name& n, Req& r);

// HTTP GET of segment `seg` using a Range request; body = that segment, total = full size.
// segSize must match the SEG constant used by the gateway so segment N maps to the same byte range everywhere.
Resp fetch(const std::string& url, uint64_t seg, size_t segSize = 4000);