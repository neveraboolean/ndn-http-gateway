#!/bin/bash
# Run on the gateway node: ensures a signing identity exists, builds if needed, starts gateway2.
set -e
cd /workspace
[ -x build/gateway2 ] || make
ndnsec list 2>/dev/null | grep -q . || ndnsec key-gen /gw >/dev/null
exec build/gateway2