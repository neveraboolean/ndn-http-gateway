#!/bin/bash
# usage: scripts/add-route.sh <gateway-hostname-or-ip>   (run on each client node)
set -e
GW="${1:?usage: add-route.sh <gateway-host-or-ip>}"
IP=$(getent hosts "$GW" | awk '{print $1; exit}'); IP=${IP:-$GW}

# Create face once and capture its ID (or reuse if it exists)
FACE_ID=$(nfdc face create "udp4://$IP:6363" | grep -oP 'id=\K\d+' || nfdc face list | grep "remote=udp4://$IP:6363" | grep -oP 'id=\K\d+' | head -n1)

# Add routes using the Face ID
nfdc route add /http "$FACE_ID"
nfdc route add /https "$FACE_ID"
nfdc route list | grep -E '/http|/https'