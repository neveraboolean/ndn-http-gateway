# ndn-http-gateway

Fetch ordinary HTTP content over **Named Data Networking**. Two pieces:

- **`gateway`** (daemon): registers `/http` with NFD; turns `Interest /http/<host>/<path>/seg=N` into an HTTP range request to the origin and answers with signed, segmented `Data`.
- **`libintercept.so`** (`LD_PRELOAD` client shim): makes unmodified programs such as `curl` speak NDN. `getaddrinfo` returns a fake IP, `connect` is redirected to a local socketpair, and the HTTP GET is turned into NDN Interests.

```
 [ Client Application ]  --->  (1) Intercept Syscalls (intercept.cpp : done by faking the address then overriding connect())
   (e.g., curl http://example.com)
                                   │
                                   ▼
                            (2) Translate HTTP to NDN Interest (translate.cpp)
                                   │
                                   ▼
                            (3) Local Client NFD
                                   │
                                   ▼  [ UDP Tunnel / Face ]
                            (4) Gateway NFD (NFD forwarding : done by the nfd itself)
                                   │
                                   ▼
                            (5) Gateway Daemon (gateway.cpp : since /http was registered, control goes to this code everytime a /http packet comes)
                                   │
                                   ▼
                            (6) Re-translate NDN Interest to HTTP GET
                                   │
                                   ▼
                            (7) Web Server (Origin)
                                   │
                                   ▼
                            (8) Return HTTP Body Data
                                   │
                                   ▼
                            (9) Packetize Data into NDN Data Segments (`seg=0`, `seg=1`...)
                                   │
                                   ▼
                            (10) Return NDN Data Packets back through NFDs to Client
```
Every node runs its **own NFD**; apps only talk to their local NFD.

## Layout
```
Dockerfile  docker-compose.yml  Makefile
docker/     bashrc.sh (env, aliases)  entrypoint.sh (starts NFD, then your command)
include/    translate.hpp  packetize.hpp
src/        gateway.cpp  translate.cpp  packetize.cpp  intercept.cpp
scripts/    start-gateway.sh  add-route.sh  smoke-test.sh
build/      (generated) gateway, libintercept.so
```
| File | Role |
|---|---|
| `translate.cpp` | NDN name to URL, libcurl range GET |
| `packetize.cpp` | segment to signed `Data` with `FinalBlockId`, `put` |
| `gateway.cpp` | `Face`, `/http` filter, glue |
| `intercept.cpp` | client `LD_PRELOAD` shim |

## 1. Build and launch
```bash
docker compose build            # ~10-20 min first time (compiles ndn-cxx, NFD, ndn-tools)
docker compose up -d            # gateway, client1, client2 (repo mounted at /workspace)
docker compose exec gateway bash      # terminal 1
docker compose exec client1 bash      # terminal 2
```
No compose? `docker build -t ndn-http-gw . && docker run -it --rm -v "$PWD:/workspace" ndn-http-gw`.
Pin versions (recommended; the three repos must match): `docker compose build --build-arg NFD_REF=<tag> ...` (also `NDN_CXX_REF`, `NDN_TOOLS_REF`).

## 2. Build the code (in any container)
```bash
cd /workspace && make          # -> build/gateway, build/libintercept.so
```
(Equivalent: `g++ -std=c++17 -Iinclude src/gateway.cpp build/translate.o build/packetize.o -o build/gateway $(pkg-config --cflags --libs libndn-cxx libcurl)`)

## 3. NFD and routes
NFD starts automatically via the entrypoint (check: `nfdc status`, log: `nfdlog`). Manual start: `nfd --config /usr/local/etc/ndn/nfd.conf &`.

On **gateway**:
```bash
scripts/start-gateway.sh        # creates /gw key if missing, runs build/gateway
```
On each **client**:
```bash
scripts/add-route.sh gateway    # = nfdc route add /http udp4://<gateway-ip>:6363
nfdc fib list ; nfdc face list  # verify /http -> udp4 face
```
Outside compose use `docker network create ndnnet`, attach containers to it, and pass the gateway's IP.

## 4. Test
**A. Unmodified curl through NDN** (client node):
```bash
LD_PRELOAD=./build/libintercept.so curl --noproxy '*' http://neverssl.com/
```
Gateway log shows `http://neverssl.com/ seg=0 status=206 ...`; `tcpdump -ni eth0 'udp port 6363'` shows NDN, no TCP/80 from the client.

**B. Pure NDN Interest** (client node):
```bash
ndnpeek -P /http/neverssl.com/        # CanBePrefix: no seg component needed; gateway answers seg=0
ndnpeek -p /http/neverssl.com/seg=0   # exact segment name
```
Flags differ by ndn-tools version: check `ndnpeek -h` (`-P`/`--canbeprefix` vs older `-p`; `-p` may mean "payload only"). Only **segment 0** (4000 bytes) is returned; use `curl` (above) for the whole body.

`scripts/smoke-test.sh` runs both with cache-busting.

## 5. Caching (NFD Content Store) and cache-busting
- Every NFD on the path caches `Data` in its **CS**. A repeated Interest is answered by the nearest copy: **no gateway log line, no HTTP request**.
- Gateway Data has `FreshnessPeriod = 10 s`. Interests with `MustBeFresh` (`ndnpeek -f`) only match copies younger than that. Interests **without** it may be served from CS after the 10 s elapse (until evicted), so the page can look stale.
- To force a new origin fetch use a new name: add a query component.
  - curl: `http://neverssl.com/?rand=1` (change the number each time).
  - ndnpeek: the `?` and `=` must be percent-encoded in a name URI: `ndnpeek -f -p "/http/neverssl.com/%3Frand%3D1/seg=0"`.
- Experiment: run the same request twice and watch the gateway log (one line, then none); `nfdc cs info` shows hits/misses; `nfdc cs erase /http` clears the cache.

## 6. Configuration
| Env | Default | Meaning |
|---|---|---|
| `GW_SCHEME` | `http` | scheme the gateway uses toward origins (`https` for TLS; redirects are followed) |
| `GW_ALLOW` | empty | comma list of allowed hosts. **Empty = open proxy: set it outside a lab.** |

## 7. Limits
- GET only, no request headers or response headers; `Content-Length` body only.
- `libintercept` handles plain `http://` via libc `getaddrinfo`; https URLs, statically linked or c-ares-based clients bypass it.
- One Interest in flight per segment (no pipelining); each segment is a fresh ranged GET at the gateway.
- Data is signed with the gateway's key; **clients do not validate** yet. G terminates the origin connection, so clients trust G, not the origin.
- Errors yield no Data (client timeout), apart from `libintercept` returning 502/504.
- ndn-cxx API names move between versions (`setFinalBlock` vs `setFinalBlockId`, `getFinalBlock`). Fix compile errors against your pinned version.

## 8. Troubleshooting
- `error while loading shared libraries`: `ldconfig`; check `/etc/ld.so.conf.d/ndn.conf`.
- `pkg-config` cannot find libndn-cxx: `export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig` (set by `bashrc.sh`).
- Timeout: `nfdc fib list` on the client (route?), gateway log, `ndnsec list` on gateway (key?).
- Start fresh: `docker compose down && docker compose up -d`.
