// packetize.cpp - builds, signs and publishes one NDN Data segment.
#include "packetize.hpp"
#include <ndn-cxx/encoding/block-helpers.hpp>
using namespace ndn;

// Data name is the same as the Interest's name (NDN requires the Data name to match the Interest).
void putSegment(Face& f, KeyChain& kc, const Name& name, const std::string& seg,
                uint64_t lastSeg, int freshSec) {
  // Heap-allocate the Data with its name.
  auto d = std::make_shared<Data>(name);
  // Payload: raw bytes of this segment, encoded as a TLV Content block.
  d->setContent(makeStringBlock(tlv::Content, seg));
  // How long caches may treat this Data as fresh for Interests with MustBeFresh.
  d->setFreshnessPeriod(time::seconds(freshSec));
  // Tells the consumer which segment is last so it knows when to stop requesting.
  d->setFinalBlock(name::Component::fromSegment(lastSeg));   // older ndn-cxx: setFinalBlockId
  // Sign with the default identity's default key. Requires `ndnsec key-gen` to have been run first.
  kc.sign(*d);
  // Hand the Data to the local NFD, which forwards it back along the PIT path.
  f.put(*d);
}
