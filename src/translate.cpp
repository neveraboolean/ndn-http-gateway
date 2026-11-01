#include "translate.hpp"
#include <curl/curl.h>
#include <strings.h>
#include <cstdlib>
using ndn::Name;

static struct Init { Init() { curl_global_init(CURL_GLOBAL_DEFAULT); } } _init;

static std::string raw(const ndn::name::Component& c) {
  return std::string(reinterpret_cast<const char*>(c.value()), c.value_size());
}

// Translates a structured NDN name into a valid HTTP or HTTPS origin URL,
// extracting hostnames, path segments, query parameters, and segment numbers.
bool nameToUrl(const Name& n, Req& r) {
  std::string pfx = n.size() ? raw(n[0]) : "";
  if (n.size() < 2 || (pfx != "http" && pfx != "https")) return false;
  
  size_t end = n.size();
  r.hasSeg = n[-1].isSegment();
  if (r.hasSeg) { r.seg = n[-1].toSegment(); end--; }
  if (end < 2) return false;

  std::string host = raw(n[1]);
  if (host.empty() || host.find_first_not_of(
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:") != std::string::npos)
    return false;

  std::string path, q;
  CURL* c = curl_easy_init();
  
  for (size_t i = 2; i < end; i++) {
    std::string s = raw(n[i]);
    if (i == end - 1 && !s.empty() && s[0] == '?') { q = s; continue; }
    char* e = curl_easy_escape(c, s.data(), s.size());
    path += "/" + std::string(e);
    curl_free(e);
  }
  curl_easy_cleanup(c);

  const char* sch = getenv("GW_SCHEME");
  std::string scheme = pfx == "https" ? "https" : std::string(sch && *sch ? sch : "http");
  r.url = scheme + "://" + host + (path.empty() ? "/" : path) + q;
  return true;
}

static size_t wb(char* p, size_t s, size_t n, void* u) {
  static_cast<std::string*>(u)->append(p, s * n); return s * n;
}

static size_t wh(char* p, size_t s, size_t n, void* u) {
  std::string h(p, s * n);
  if (strncasecmp(h.c_str(), "Content-Range:", 14) == 0) {
    auto k = h.rfind('/');
    if (k != std::string::npos) *static_cast<size_t*>(u) = strtoull(h.c_str() + k + 1, nullptr, 10);
  }
  return s * n;
}

// Performs a blocking HTTP/HTTPS range request using libcurl to fetch a specific segment,
// parsing response headers for total resource size and handling fallbacks for 200 OK responses.
Resp fetch(const std::string& url, uint64_t seg, size_t sz) {
  Resp r; size_t off = seg * sz;
  std::string rg = std::to_string(off) + "-" + std::to_string(off + sz - 1);
  
  CURL* c = curl_easy_init();
  curl_easy_setopt(c, CURLOPT_URL, url.c_str());
  curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(c, CURLOPT_RANGE, rg.c_str());
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wb);
  curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
  curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, wh);
  curl_easy_setopt(c, CURLOPT_HEADERDATA, &r.total);
  
  CURLcode rc = curl_easy_perform(c);
  if (rc != CURLE_OK) r.err = curl_easy_strerror(rc);
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.status);
  curl_easy_cleanup(c);
  
  if (r.status == 200) {
    r.total = r.body.size();
    r.body = off < r.total ? r.body.substr(off, sz) : "";
  }
  return r;
}
