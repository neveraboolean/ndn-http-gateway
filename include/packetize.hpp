// packetize.hpp - Module 3 API: wrap response bytes in a signed NDN Data packet and send it.
#pragma once
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <string>

// Build a signed Data (name, content = seg bytes, FinalBlockId = lastSeg) and put it on the face.
// Creates a Data named `name` containing `seg`, marks the last segment number (FinalBlockId),
// signs it with the default key (kc), and sends it via face `f`. freshSec = cache freshness in seconds.
void putSegment(ndn::Face& f, ndn::KeyChain& kc, const ndn::Name& name,
                const std::string& seg, uint64_t lastSeg, int freshSec = 10);

// Index of the last segment for `total` bytes: ceil(total/segSize)-1, or 0 when empty.
// Requesters stop fetching when they reach this number.
inline uint64_t lastSegFor(size_t total, size_t segSize = 4000) {
  return total ? (total - 1) / segSize : 0;
}