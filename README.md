# ndn-http-gateway

```
 [ Client Application ]  --->  (1) Intercept Syscalls (intercept.cpp : done by faking the address then overriding connect())
   (e.g., curl http://example.com)
                                   │
                                   ▼
                            (2) Translate HTTP to NDN Interest (done by intercept.cpp itself)
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
                            (6) Re-translate NDN Interest to HTTP GET (done by translate.cpp)
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
Every node runs its own NFD; apps only talk to their local NFD.

The endpoints of the NDN island are able to fetch ordinary HTTP content over ndn and vice versa through the below two programs:
- **`gateway`** (daemon): registers `/http` with NFD; turns `Interest /http/<host>/<path>/seg=N` into an HTTP request.
- **`libintercept.so`** (`LD_PRELOAD` client shim): makes unmodified programs such as `curl` speak NDN. `getaddrinfo` returns a fake IP, `connect` is redirected to a local socketpair, and the HTTP GET is turned into NDN Interests.

## 1. Build and launch
```bash
docker network create ndnnet            # Creates a network
docker build -t ndn-http-gw .           # ~10-20 min first time (compiles ndn-cxx, NFD, ndn-tools)
docker run -it --name gateway --net ndnnet -v "$PWD:/workspace" ndn-http-gw bash     # terminal 1, Runs a container(gateway) and enters its /workspace folder
docker run -it --name client1 --net ndnnet -v "$PWD:/workspace" ndn-http-gw bash     # terminal 2, In another terminal run the client
```
After the above steps you would be running the client and the gateway and in their workspace folder

## 2. Compiling the code files using make and starting the NFD in each container
```bash
make          # -> build/gateway, build/libintercept.so
```
(Equivalent: `g++ -std=c++17 -Iinclude src/gateway.cpp build/translate.o build/packetize.o -o build/gateway $(pkg-config --cflags --libs libndn-cxx libcurl)`)

Note: Running make in one container is enough since the workspace folder is common to both the containers and they will be able to access the object files.

```bash
nfd --config /usr/local/etc/ndn/nfd.conf &         # Run NFD in the background, (note you can press enter to get back control of the terminal (nfd will be running in the background)
nfdc status   # Check if NFD is running.
```
Note: NFD should be run in both the client and the gateway containers

Note: NFD should actually start automatically via the entrypoint (check: `nfdc status`, log: `nfdlog`). But for Manual start as above: `nfd --config /usr/local/etc/ndn/nfd.conf &`.

## 3. NFD and routes

On **gateway**:
```bash
scripts/start-gateway.sh        # creates /gw key if missing, runs build/gateway
```
On each **client**:
```bash
scripts/add-route.sh gateway    # = nfdc route add /http udp4://<gateway-ip>:6363
nfdc fib list ; nfdc face list  # verify /http -> udp4 face
```

## 4. Test
**A. Unmodified curl through NDN** (client node):
```bash
LD_PRELOAD=./build/libintercept.so curl -4 --noproxy '*' http://neverssl.com/     # The -4 is there since my code is only compatible with IPv4 (Yet to fix)
```
Gateway log shows `http://neverssl.com/ seg=0 status=206 ...`; 

We can verify this using `tcpdump -ni eth0 'udp port 6363'` which shows NDN, no TCP/80 from the client.

**B. Pure NDN Interest** (client node):
```bash
ndnpeek -P /http/neverssl.com/        # CanBePrefix: no seg component needed; gateway answers seg=0
ndnpeek -p /http/neverssl.com/seg=0   # exact segment name
```
Note: Flags differ by ndn-tools version: check `ndnpeek -h` (`-P`/`--canbeprefix` vs older `-p`; `-p` may mean "payload only").

---

## HTTPS / TLS Extension (`gateway2` & `intercept2`)

To support secure websites over NDN, the gateway architecture is extended with an HTTPS-capable proxy and a dynamic SSL interception library (`libintercept2.so`).

### The Problem with HTTPS
In order to send a normal HTTPS request, what usually happens is a TCP connection is made with the server (usually port 443) and the server sends a certificate that it is say "google.com". Once that is sent and verified, both the parties exchange symmetric keys to encrypt data and decrypt data.

This poses a problem since we do not have the keys nor do we have the site's certificate.

### The Workaround Soln: Local CA & Dynamic Interception
What we do is as follows:
1. We ovverride the `getaddrinfo` and `connect` functions and we open a local linux socketpair where one end goes to curl and the other end goes to us (which is handled by our background `bridge()` thread) and now we have our own certificate(we have a local CA(`ca.pem` and `ca.key`)) which is trusted by the app (since we run `curl` with `--cacert ca.pem` so it knows to trust our local CA.)

2. Now since `curl` completes a TLS handshake with our local thread, we get the keys and can decrypt the incoming HTTP request(`SSL_read`)

3. Once our thread has the decrypted HTTP request we drop TLS entirely and package it as NDN interest packets and send it over the NDN network.

4. Now once the NDN interest packet reaches the Gateway node, it uses `gateway2.cpp` file to call translate(to convert it back to a https request) and use `curl` to do its thing normally and once it gets the data back it again converts it to a data packet and sends it across the network. (Note: here no encryption keys are needed since `curl` handles everything)
### Quick Setup & Execution

#### 1. Generate Local CA (Host, Run Once)
```bash
mkdir -p ca && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca/ca.key -out ca/ca.pem -days 3650 -subj "/CN=NDN Gateway Local CA"
echo "ca/" >> .gitignore
```

#### 2. Build Binaries (Gateway Node)
```bash
make
scripts/start-gateway2.sh
```

#### 3. Register Routes & Test (Client Node)
```bash
scripts/add-route.sh gateway
LD_PRELOAD=/workspace/build/libintercept2.so curl -4 -s --noproxy '*' --cacert /workspace/ca/ca.pem "https://httpbin.org/get"
```

## Layout
```
Dockerfile  docker-compose.yml  Makefile
docker/     bashrc.sh (env, aliases)  entrypoint.sh (starts NFD, then your command)
include/    translate.hpp  packetize.hpp
src/        gateway.cpp  translate.cpp  packetize.cpp  intercept.cpp  gateway2.cpp  intercept2.cpp
scripts/    start-gateway.sh  add-route.sh  fetch-test.sh  start-gateway2.sh
build/      (generated) gateway, libintercept.so, gateway2, libintercept2.so, packetize.o, translate.o
```
A general outline of what each file can be found [here](src/README.md)