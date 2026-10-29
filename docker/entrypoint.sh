#!/bin/bash
# Starts NFD in the background (every node needs its own NFD), then runs the given command.
set -e
mkdir -p /run/nfd
if ! pgrep -x nfd >/dev/null; then
  nfd --config /usr/local/etc/ndn/nfd.conf >/var/log/nfd.log 2>&1 &
  for _ in $(seq 50); do nfdc status >/dev/null 2>&1 && break; sleep 0.2; done
fi
exec "$@"
