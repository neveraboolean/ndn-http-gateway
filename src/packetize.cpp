#include "packetize.hpp"
#include <ndn-cxx/encoding/block-helpers.hpp>
using namespace ndn;

void putSegment(Face& f, KeyChain& kc, const Name& name, const std::string& seg,
                uint64_t lastSeg, int freshSec) {
  auto d = std::make_shared<Data>(name);
  d->setContent(makeStringBlock(tlv::Content, seg));
  d->setFreshnessPeriod(time::seconds(freshSec));
  d->setFinalBlock(name::Component::fromSegment(lastSeg));   // older ndn-cxx: setFinalBlockId
  kc.sign(*d);
  f.put(*d);
}
