# Self-contained dev/runtime image: ndn-cxx + NFD + ndn-tools + libcurl + C++ toolchain.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config git python3 ca-certificates \
    libboost-all-dev libssl-dev libsqlite3-dev libpcap-dev libcurl4-openssl-dev \
    procps sudo curl iproute2 iputils-ping tcpdump dnsutils less vim-tiny \
    && rm -rf /var/lib/apt/lists/*

# Optional pins (tag or branch); empty = default branch. Example:
#   docker build --build-arg NFD_REF=<tag> .   (use matching tags across the three repos)
ARG NDN_CXX_REF=""
ARG NFD_REF=""
ARG NDN_TOOLS_REF=""
WORKDIR /usr/src

RUN git clone --depth 1 ${NDN_CXX_REF:+--branch ${NDN_CXX_REF}} https://github.com/named-data/ndn-cxx.git && \
    cd ndn-cxx && ./waf configure && ./waf -j"$(nproc)" && ./waf install && ldconfig

RUN git clone --recursive --depth 1 ${NFD_REF:+--branch ${NFD_REF}} https://github.com/named-data/NFD.git && \
    cd NFD && ./waf configure --without-systemd && ./waf -j"$(nproc)" && ./waf install && \
    cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf

RUN git clone --depth 1 ${NDN_TOOLS_REF:+--branch ${NDN_TOOLS_REF}} https://github.com/named-data/ndn-tools.git && \
    cd ndn-tools && ./waf configure && ./waf -j"$(nproc)" && ./waf install

# Library search paths (ndn-cxx may install to lib or lib64)
RUN printf '/usr/local/lib\n/usr/local/lib64\n' > /etc/ld.so.conf.d/ndn.conf && ldconfig

# Shell environment + entrypoint
COPY docker/bashrc.sh /opt/docker/bashrc.sh
COPY docker/entrypoint.sh /opt/docker/entrypoint.sh
RUN chmod +x /opt/docker/entrypoint.sh && \
    cat /opt/docker/bashrc.sh >> /etc/bash.bashrc && \
    cat /opt/docker/bashrc.sh >> /root/.bashrc

WORKDIR /workspace
EXPOSE 6363/udp 6363/tcp
ENTRYPOINT ["/opt/docker/entrypoint.sh"]
CMD ["bash"]
