# Explanation of the code files:

## 1. intercept.cpp (The HTTP Client Shim)

* **How it works(in brief):** When the app tries to resolve a website hostname, the shim steps in and gives it a fake local IP (`10.255.x.y`). When the app tries to `connect()` to that fake IP, the shim intercepts it and opens a local `socketpair` instead. Behind the scenes, a background thread reads the app's HTTP request, turns it into an NDN Interest, gets the data from the local NFD forwarder, and gives the HTTP reply right back to the app.

* **Detailed Explanation:**

1. `LD_PRELOAD` loads our `libintercept.so` file before the all the standard system libraries. Hence when we run curl with `LD_PRELOAD` our custom `getaddrinfo` and `connect` functions run.

2. The `getaddrinfo` function

    1. The arguments for the `getaddrinfo` function are:
        1. `node`-> hostname or ip address
        2. `svc(or service)`-> service name(like http) or port number
        3. `hints`-> any other information like IPv4/IPv6 or TCP/UDP
        4. `res`-> its the resulting pointer pointing to a linked list with all resolved names

        We define `real` as the function pointer of the original `getaddrinfo` function(called using dlsym)

    2. Now we check if our already present mapping of fake addresses to hostnames has the hostname, if it doesn't have one we assign a new one for them.
    3. We then assign `buf` the new address and pass it in the `real` function.
    4. NOTE: `htonl` changes the byte order thus changing the `ip` variable byte order so that we can use it in the function `inet_ntop` as an argument.

3. The `connect` function

    1. Here the arguments are:
        1. `fd`-> The file descripter of the local socket on the computer
        2. `sa`-> The pointer to the destination socket address
        3. `len`-> Size of the socket address structure

        Again as above 'real' is the function pointer of the original `connect` function.  
    
    2. `ip` stands for the destination socket address and `host` is the hostname of the request(or mapped to `ip`).
    3. We open a local socket pair with the function between the two endpoints `sv[0]` and `sv[1]` with the function `socketpair(AF_UNIX, SOCK_STREAM, 0, sv)` and then set `fd` to `sv[0]` using the `dup2` function and passes`sv[1]` to the `bridge` function as an argument.
    4. NOTE: `fcntl` is the file control function that sets `fl` as the flags and then we make sure `fd` is set as NONBLOCKING.

4. The `bridge` function

    1. Arguments are:
        1. `fd` -> one end of the local socket pair(we passed `sv[1]` here)
        2. `host` -> the hostname or url of the request
    2. This function reads the `HTTP` request from `sv[1]` and then converts it into a NDN interest packet.
    3. It sends forwards the interest packet through NFD and once it recieves a response it reconstructs the `HTTP` response and writes it to `sv[1]` and then closes it.


## 2. intercept2.cpp (HTTPS client Shim)
This is the upgraded version of the HTTP shim that handles secure port 443 traffic. 
* **How it works:** HTTPS is tricky because it's heavily encrypted. For this to work, `intercept2` acts as a local proxy. It loads a local CA (`ca.pem`/`ca.key`) and on-the-fly dynamically generates and signs a forged certificate for whatever website you're trying to visit. Because your test client trusts that local CA, it completes a TLS handshake with our local thread. That lets our shim decrypt the request, turn it into an NDN `/https/...` interest, get the signed chunks back, re-encrypt them, and hand them back to the app securely.

## 3. gateway.cpp (NDN -HTTP gateway)
This is the server-side daemon that sits on the NDN network waiting for `/http` interests.
* **How it works:** It registers an interest filter with the local NFD. When an interest comes in, it checks your allowed host list, uses `translate.cpp` to turn the NDN name into a real web URL, fetches the chunk using `libcurl`, wraps it into an NDN Data packet, signs it with the local KeyChain, and pushes it back out to the network.

## 4. gateway2.cpp (NDN -HTTPS gateway)
This is the secure counterpart to the regular gateway, handling everything under the `/https` prefix.
* **How it works:** It's super similar to the regular gateway, but it checks whether the translated URL actually starts with `https://`. It uses `libcurl` with proper TLS support to talk to  servers, gets the data, decrypts it, and makesvit into signed NDN Data packets.

## 5. translate.cpp & translate.hpp (NDN to URL conversion)
This is basically the translation engine shared by the gateways.
* **How it works:** It parses messy NDN name structures—like schemes, hostnames, paths, query strings, and trailing segment numbers (`seg=N`)—and turns them into a clean URL. It also manages HTTP Range requests via `libcurl` so we can fetch files chunk-by-chunk, handling things like `Content-Range` headers and fallback `200 OK` responses by slicing the data locally.

## 6. packetize.hpp 
This is a small helper module for packaging everything up.
* **How it works:** It takes raw payload bytes, wraps them into heap-allocated `ndn::Data` objects, sets the freshness periods and `FinalBlockId` markers (so the client knows when a download is finished), signs everything with the default KeyChain, and puts it out on the face.
