# Explanation of the code files:

## 1. intercept.cpp (The HTTP Client Shim)
This is an `LD_PRELOAD` library that hooks into standard HTTP apps (like `curl`). 
* **How it works:** When the app tries to resolve a website hostname, the shim steps in and gives it a fake local IP (`10.255.x.y`). When the app tries to `connect()` to that fake IP, the shim intercepts it and opens a local `socketpair` instead. Behind the scenes, a background thread reads the app's HTTP request, turns it into an NDN Interest, gets the data from the local NFD forwarder, and gives the HTTP reply right back to the app.

## 2. intercept2.cpp (The HTTPS Secure Shim)
This is the upgraded version of the HTTP shim that handles secure port 443 traffic. 
* **How it works:** HTTPS is tricky because it's heavily encrypted. For this to work, `intercept2` acts as a local proxy. It loads a local CA (`ca.pem`/`ca.key`) and on-the-fly dynamically generates and signs a forged certificate for whatever website you're trying to visit. Because your test client trusts that local CA, it completes a TLS handshake with our local thread. That lets our shim decrypt the request, turn it into an NDN `/https/...` interest, get the signed chunks back, re-encrypt them, and hand them back to the app securely.

## 3. gateway.cpp (The NDN-to-HTTP Gateway)
This is the server-side daemon that sits on the NDN network waiting for `/http` interests.
* **How it works:** It registers an interest filter with the local NFD. When an interest comes in, it checks your allowed host list, uses our translation helper to turn the NDN name into a real web URL, fetches the chunk using `libcurl`, wraps it into an NDN Data packet, signs it with the local KeyChain, and pushes it back out to the network.

## 4. gateway2.cpp (The NDN-to-HTTPS Gateway)
This is the secure counterpart to the regular gateway, handling everything under the `/https` prefix.
* **How it works:** It's super similar to the regular gateway, but it checks whether the translated URL actually starts with `https://`. It uses `libcurl` with proper TLS support to talk to  servers, gets the data, decrypts it, and makesvit into signed NDN Data packets.

## 5. translate.cpp & translate.hpp (The URL & Range Translator)
This is basically the translation engine shared by the gateways.
* **How it works:** It parses messy NDN name structures—like schemes, hostnames, paths, query strings, and trailing segment numbers (`seg=N`)—and turns them into a clean URL. It also manages HTTP Range requests via `libcurl` so we can fetch files chunk-by-chunk, handling things like `Content-Range` headers and fallback `200 OK` responses by slicing the data locally.

## 6. packetize.hpp (The NDN Data Wrapper)
This is a small helper module for packaging everything up.
* **How it works:** It takes raw payload bytes, wraps them into heap-allocated `ndn::Data` objects, updates freshness periods and `FinalBlockId` markers (so the client knows when a download is finished), signs everything with the default KeyChain, and puts it out on the face.