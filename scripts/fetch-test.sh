#!/bin/bash
# Run on a client node after add-route.sh. Needs build/libintercept.so (make).
set -x
R=$RANDOM
LD_PRELOAD=/workspace/build/libintercept.so curl -4 -s --noproxy '*' "http://neverssl.com/?rand=$R" | head -c 300; echo
ndnpeek -f -p "/http/neverssl.com/%3Frand%3D$R/seg=0" | head -c 300; echo
