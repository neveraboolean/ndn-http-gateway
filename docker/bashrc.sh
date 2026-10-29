# ---- ndn-http-gateway shell environment ----
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig:${PKG_CONFIG_PATH:-}
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64:${LD_LIBRARY_PATH:-}
export PATH=/usr/local/bin:/workspace/build:$PATH
export GW_SCHEME=${GW_SCHEME:-http}      # origin scheme used by the gateway (http|https)
export PS1='\[\e[32m\]\h\[\e[0m\]:\w\$ '
alias ll='ls -alF'
alias nfdlog='tail -f /var/log/nfd.log'
alias nfdrestart='pkill -x nfd; sleep 1; nfd --config /usr/local/etc/ndn/nfd.conf >/var/log/nfd.log 2>&1 &'
