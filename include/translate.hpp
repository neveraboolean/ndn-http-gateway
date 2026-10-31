#pragma once
#include <ndn-cxx/name.hpp>
#include <string>

// Holds parameters parsed from an incoming NDN name request.
struct Req  { 
  std::string url; 
  uint64_t seg = 0; 
  bool hasSeg = false; 
};

// Holds the outcome and payload of a completed HTTP/HTTPS fetch operation.
struct Resp { 
  long status = 0; 
  std::string body; 
  size_t total = 0; 
  std::string err; 
};

// Parses and translates an NDN name into a corresponding HTTP or HTTPS origin URL.
bool nameToUrl(const ndn::Name& n, Req& r);

// Fetches a specific byte segment from an origin URL using an HTTP Range request via libcurl.
Resp fetch(const std::string& url, uint64_t seg, size_t segSize = 4000);