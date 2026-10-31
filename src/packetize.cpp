// packetize.cpp - builds, signs and publishes one NDN Data segment.
#include "packetize.hpp"
#include <ndn-cxx/encoding/block-helpers.hpp>
using namespace ndn;

/*
Constructs an NDN Data packet containing the payload segment, sets its freshness period and final block marker, 
signs it with the local KeyChain, and pushes it back onto the Face.
*/
void putSegment(Face& f, KeyChain& kc, const Name& name, const std::string& seg,uint64_t lastSeg, int freshSec) {
  auto d = std::make_shared<Data>(name);
  d->setContent(makeStringBlock(tlv::Content, seg));
  d->setFreshnessPeriod(time::seconds(freshSec));
  d->setFinalBlock(name::Component::fromSegment(lastSeg)); 
  kc.sign(*d);
  f.put(*d);
}
