#!/bin/bash
# Run on the gateway node: ensures a signing identity exists, builds if needed, starts the gateway.
set -e
cd /workspace
[ -x build/gateway ] || make
ndnsec list 2>/dev/null | grep -q . || ndnsec key-gen /gw >/dev/null
exec build/gateway
