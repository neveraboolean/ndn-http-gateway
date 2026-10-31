.RECIPEPREFIX = >
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
INC      := -Iinclude
NDN      := $(shell pkg-config --cflags --libs libndn-cxx)
CURL     := $(shell pkg-config --cflags --libs libcurl)
B        := build

all: $(B)/gateway $(B)/gateway2 $(B)/libintercept.so $(B)/libintercept2.so
> chmod +x scripts/*.sh

$(B):
> mkdir -p $(B)

$(B)/translate.o: src/translate.cpp include/translate.hpp | $(B)
> $(CXX) $(CXXFLAGS) $(INC) -c $< -o $@ $(shell pkg-config --cflags libndn-cxx libcurl)

$(B)/packetize.o: src/packetize.cpp include/packetize.hpp | $(B)
> $(CXX) $(CXXFLAGS) $(INC) -c $< -o $@ $(shell pkg-config --cflags libndn-cxx)

$(B)/gateway: src/gateway.cpp $(B)/translate.o $(B)/packetize.o
> $(CXX) $(CXXFLAGS) $(INC) $^ -o $@ $(NDN) $(CURL)

$(B)/gateway2: src/gateway2.cpp $(B)/translate.o $(B)/packetize.o
> $(CXX) $(CXXFLAGS) $(INC) $^ -o $@ $(NDN) $(CURL)

$(B)/libintercept.so: src/intercept.cpp | $(B)
> $(CXX) $(CXXFLAGS) -shared -fPIC $< -o $@ $(NDN) -ldl -pthread

$(B)/libintercept2.so: src/intercept2.cpp | $(B)
> $(CXX) $(CXXFLAGS) -shared -fPIC $< -o $@ $(NDN) -lssl -lcrypto -ldl -pthread

clean:
> rm -rf $(B)

.PHONY: all clean
