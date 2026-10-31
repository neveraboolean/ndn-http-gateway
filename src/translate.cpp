// translate.cpp - Module 2: NDN name -> URL translation and libcurl range fetch.
// Name format: /http|https/<host>/<path...>[/<?query>][/seg=N]
#include "translate.hpp"
#include <curl/curl.h>
#include <strings.h>
#include <cstdlib>
using ndn::Name;

// Runs once at load: initialise libcurl globally (needed before any curl_easy_* call).
static struct Init { Init() { curl_global_init(CURL_GLOBAL_DEFAULT); } } _init;

// Return a name component's raw bytes as a std::string (no URI escaping).
static std::string raw(const ndn::name::Component& c) {
  return std::string(reinterpret_cast<const char*>(c.value()), c.value_size());
}

// Parse an NDN name into an origin URL. Returns false for anything not shaped like a valid request.
bool nameToUrl(const Name& n, Req& r) {
  // First component selects scheme: "http" or "https". Anything else is rejected.
  std::string pfx = n.size() ? raw(n[0]) : "";
  if (n.size() < 2 || (pfx != "http" && pfx != "https")) return false;
  // `end` = number of components that describe the resource (excludes a trailing seg=N).
  size_t end = n.size();
  r.hasSeg = n[-1].isSegment();
  if (r.hasSeg) { r.seg = n[-1].toSegment(); end--; }
  if (end < 2) return false;

  // Component 1 is the hostname. Whitelist characters so names cannot inject paths, spaces or other URLs.
  std::string host = raw(n[1]);
  if (host.empty() || host.find_first_not_of(
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:") != std::string::npos)
    return false;

  // path accumulates "/a/b/c"; q holds an optional query string such as ?x=1.
  std::string path, q;
  // Temporary curl handle, used only for curl_easy_escape (percent-encoding).
  CURL* c = curl_easy_init();
  // Components 2..end-1 are path segments, except a last one starting with '?' which is the query.
  for (size_t i = 2; i < end; i++) {
    std::string s = raw(n[i]);
    if (i == end - 1 && !s.empty() && s[0] == '?') { q = s; continue; }  // query component
    char* e = curl_easy_escape(c, s.data(), s.size());
    path += "/" + std::string(e);
    curl_free(e);
  }
  curl_easy_cleanup(c);

  // /https always uses https; /http uses env GW_SCHEME (default http).
  const char* sch = getenv("GW_SCHEME");
  std::string scheme = pfx == "https" ? "https" : std::string(sch && *sch ? sch : "http");
  r.url = scheme + "://" + host + (path.empty() ? "/" : path) + q;
  return true;
}

// libcurl write callback: append each received chunk to the std::string passed via WRITEDATA.
static size_t wb(char* p, size_t s, size_t n, void* u) {
  static_cast<std::string*>(u)->append(p, s * n); return s * n;
}
// libcurl header callback: parse "Content-Range: bytes a-b/TOTAL" to learn the full resource size.
static size_t wh(char* p, size_t s, size_t n, void* u) {   // Content-Range: bytes a-b/total
  std::string h(p, s * n);
  if (strncasecmp(h.c_str(), "Content-Range:", 14) == 0) {
    auto k = h.rfind('/');
    if (k != std::string::npos) *static_cast<size_t*>(u) = strtoull(h.c_str() + k + 1, nullptr, 10);
  }
  return s * n;
}

// Fetch segment `seg` (bytes [seg*sz, seg*sz+sz-1]) using an HTTP Range request.
Resp fetch(const std::string& url, uint64_t seg, size_t sz) {
  Resp r; size_t off = seg * sz;
  std::string rg = std::to_string(off) + "-" + std::to_string(off + sz - 1);
  // Fresh handle per call (simple and thread-safe, at the cost of no connection reuse).
  CURL* c = curl_easy_init();
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  // Follow redirects (e.g. http -> https).
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
  // Ask the origin for just this segment's byte range.
  curl_easy_setopt(c, CURLOPT_RANGE, rg.c_str());
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wb);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
  // Route response headers to wh() so r.total is filled from Content-Range.
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, wh);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &r.total);
  // Perform the request (blocking). Transport failures are reported in r.err; HTTP codes in r.status.
  CURLcode rc = curl_easy_perform(c);
  if (rc != CURLE_OK) r.err = curl_easy_strerror(rc);
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.status);
  curl_easy_cleanup(c);
  // 200 (not 206) means the origin ignored Range and sent everything: take the whole size and slice the segment locally.
  if (r.status == 200) {                         // origin ignored Range: slice locally
    r.total = r.body.size();
    r.body = off < r.total ? r.body.substr(off, sz) : "";
  }
  return r;
}
