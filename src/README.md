# Explanation of the code files:

## 1. intercept.cpp

When the app tries to resolve a website hostname, the `LD_PRELOAD` file (`libintercept.so`) steps in and gives it a fake local IP (`10.255.x.y`). When the app tries to `connect()` to that fake IP, the shim intercepts it and opens a local `socketpair` instead. A background thread reads the app's HTTP request, turns it into an NDN Interest, gets the data from the local NFD forwarder, and gives the HTTP reply right back to the app.

* **Detailed Explanation:**

1. `LD_PRELOAD` loads our `libintercept.so` file before the all the standard system libraries. Hence when we run `curl` with `LD_PRELOAD` our custom `getaddrinfo` and `connect` functions run.

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
    2. This function reads the `HTTP` request from `sv[1]` and then converts it into a NDN interest packet by the following process:
        1. It gets only the query and the target details by taking the substring between the two spaces.
        2. It then assigns `query` to the substring after `?` and the substring before this is `target`.
        3. `Name` is an NDN object and `name::Component` constructs an individual name component and thus our NDN name `base` becomes `/http/host` where `host` is the hostname.
        4. We then split target in places where `/` appear and append it to `base`.
        5. Finally we append `query` as well. Note that the query is being kept as a single component rather than splitting it like we did with `target`
        6. It creates an interest packet using `Interest` and  also appends the `seg` number.
    3. We then forward the interest using `face.expressInterest`
        1. The function has a Data callback function that converts the recieved data into a char of bytes `body` when a matching occurs.
        2. The other two callbacks are the `Nack` and `Timeout` callbacks, but the code doesnt do anything when they occur.
        3. We then construct the HTTP response back and send it to back using the `wall` function.

## 2. gateway.cpp

1. We listen to the incoming `http` requests using the `setInterestFilter` function which invokes the callback `onInterest` when a matching request is received.
2. The `OnInterest` function uses the `nametoUrl` of the translate file to obtain `r`(the url) and uses the `fetch` function(also from translate.cpp) on the url to recieve the response `p`(of struct type `Resp`).
3. We then use the `putSegment` function from packetize.cpp to make the NDN data packet and send it back.

## 3. translate.cpp
This is basically translates the NDN name to a URL

1. It takes the NDN name and runs the `nametoUrl` function that first typecasts the bytes to string and then uses the `curl` library function to ensure the URL is properly formed. (It uses the `curl` library to make sure things like ` ` are converted to `%20` etc).
2. Then it runs its `fetch` function that runs a HTTP range request using `libcurl` to fetch the data then the callback function `wb()` collects the response body and the the callback function `wh()` collects the size
3. `nametoUrl(n,r)` takes an NDN name `n` and a pointer to the translated response `r` and updates `r` in the function. It returns `1` if the name is converted and 0 if there is an error in the NDN name.
4. `fetch(url,seg,sz)` takes the `url` to fetch from, `seg`(segment number) specifically and `sz`(the desired size of the resulting fetch of the segment). It Outputs a `Resp` structure which contains `body`(content), `total`(size), `status`, `err`.


## 4. packetize.cpp 
Is a helper function to construct an NDN Data packet containing the payload segment, sets its freshness period and final block marker, 
signs it with the local KeyChain, and pushes it back onto the Face.


## 5. intercept2.cpp
This is the upgraded version of the HTTP shim that handles secure port 443 traffic. 
* **How it works:** HTTPS is tricky because it's heavily encrypted. For this to work, `intercept2` acts as a local proxy. It loads a local CA (`ca.pem`/`ca.key`) and on-the-fly dynamically generates and signs a forged certificate for whatever website you're trying to visit. Because your test client trusts that local CA, it completes a TLS handshake with our local thread. That lets our shim decrypt the request, turn it into an NDN `/https/...` interest, get the signed chunks back, re-encrypt them, and hand them back to the app securely.

## 6. gateway2.cpp
This is the secure counterpart to the regular gateway, handling everything under the `/https` prefix.
* **How it works:** It's super similar to the regular gateway, but it checks whether the translated URL actually starts with `https://`. It uses `libcurl` with proper TLS support to talk to  servers, gets the data, decrypts it, and makesvit into signed NDN Data packets.
