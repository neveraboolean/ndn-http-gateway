#!/bin/bash
# usage: scripts/add-route.sh <gateway-hostname-or-ip>   (run on each client node)
set -e
GW="${1:?usage: add-route.sh <gateway-host-or-ip>}"
IP=$(getent hosts "$GW" | awk '{print $1; exit}'); IP=${IP:-$GW}
nfdc route add /http "udp4://$IP:6363"
nfdc route list | grep /http
