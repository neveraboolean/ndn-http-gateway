#pragma once
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <string>

// Constructs a signed NDN Data packet containing the segment payload and final block marker, 
// signs it using the KeyChain, and puts it on the face.
void putSegment(ndn::Face& f, ndn::KeyChain& kc, const ndn::Name& name,
                const std::string& seg, uint64_t lastSeg, int freshSec = 10);

// Computes the index of the final segment for a given total byte size and segment size.
inline uint64_t lastSegFor(size_t total, size_t segSize = 4000) {
  return total ? (total - 1) / segSize : 0;
}