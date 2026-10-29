#pragma once
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <string>

// Build a signed Data (name, content = seg bytes, FinalBlockId = lastSeg) and put it on the face.
void putSegment(ndn::Face& f, ndn::KeyChain& kc, const ndn::Name& name,
                const std::string& seg, uint64_t lastSeg, int freshSec = 10);

inline uint64_t lastSegFor(size_t total, size_t segSize = 4000) {
  return total ? (total - 1) / segSize : 0;
}
