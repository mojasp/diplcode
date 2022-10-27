Lightweight Communications and Marshalling (LCM)

LCM is a set of libraries and tools for message passing and data marshalling,
targeted at real-time systems where high-bandwidth and low latency are
critical. It provides a publish/subscribe message passing model and automatic
marshalling/unmarshalling code generation with bindings for applications in a
variety of programming languages.

# Looking for a new maintainer

2022 September - LCM isn't actively updated much these days. It should be
considered fairly stable on the platforms it was originally developed on, but
new feature development and bug fixes are unlikely. If you are interested in
taking over as the project maintainer and steering its direction going forwards,
please send a message to Albert.

# Quick Links

* [LCM downloads](https://github.com/lcm-proj/lcm/releases)
* [Website and documentation](https://lcm-proj.github.io)

# LCM-sec

LCM-sec is the attempt of including a hybrid cryptosystem into LCM. A rough overview of is provided below.

## Dependencies

Additional dependencies are Botan and libstdc++.

## Usage

### Quickstart guide

* use ```lcm_create_with_security(...) ``` (or use the c++ API in lcm-sec.hpp)
to create an LCM instance that has security enabled. This will block until the group key agreement has finished on all channels for which there are permissions in the certificate
* To disable debug output, set ```LCMCRYPTO_DEBUG ``` to 0 (lcm/lcmsec/crypto_wrapper.h:23)
* To use security features, you will need generate a root certificate and x509v3 certificate/key-pairs for each node that should communicate. The SAN of those certificates should be set appropriately (according to the permissions that the nodes should be provided with).
* The format of the SAN is a URI of the form: `urn:lcmsec:gkexchg:<mcastgroup>:<port>:<channelname>:<user_id>` 
    * example: ` urn:lcmsec:gkexchg:239.255.76.67:7667:channel1:4` (for a channel)
    * for the permission to be part of a multicast group, use the special string "gkexchg_g" and omit the channelname, for instance: ` urn:lcmsec:gkexchg_g:239.255.76.67:7667:4`
* call ```lcm_perform_keyexchange(lcm_t *lcm) ``` in a separate thread if the dynamic properties of the protocol (right now: joining and rejoining after crash) are needed. If the groups are static
    * Note: in the future it should also be able to get a file descriptor one can integrate into an eventloop with select to perform a nonblocking call whenever a keyagreement action is needed. 
    * another interface that should be provided a simple nonblocking one that the user can poll or one with a timeout

### Example 

An Example for an application using LCM-sec can be found in examples/cpp_security (running the application requires the toml++ library, available as a git submodule). 

The certificates for that example are in the x509v3/ folder, and were generated with the following commands:

```bash
    # create the certificate for charlie
    step-cli certificate create charlie charlie.crt charlie.key --san urn:lcmsec:gkexchg:239.255.76.67:7667:channel1:4 --san urn:lcmsec:gkexchg:239.255.76.67:7667:channel2:4 --san urn:lcmsec:gkexchg_g:239.255.76.67:7667:4   --profile leaf --ca ./root_ca.crt --ca-key ./root_ca.key
    # format in a way that botan can understand
    openssl pkcs8 -topk8 -in charlie.key -out charlie.pem
    mv charlie.pem charlie.key
```

An automated way to generate certificates will follow soon (needed for performance measurements)

The behaviour of the demo_instance (channels they send on / subscribe to) is then configured with the config files that are provided in the instances/ folder; a script to start multiple instances is provided as well.

## State of the implementation

* Forming a group with multiple channels via group key agreement and communication within that group etc. is supported. Note that in the case of a "lonely" node, it will simply create a group of size one (instead of blocking until another node is online)
* Joining of one or multiple nodes at the same time works
* I am not sure at the time of writing if multiple different multicast groups are supported
* Two Nodes with the same Certificate attempting to join the same group will lead to unpredictable behaviour or crashes
* I bumped the c++ version to c++20 (i think because i wanted to use coroutines before realizing it is not really possible without an external library). AFAIK it should be possible to go back to 17 if this is an issue.

### Rudimentary Issue List

- [ ] easy optimization of consensus: allow one join_response to carry answers to multiple joins
- [ ] Somehow detect that one participants uses its own uid twice - leads to unpredictable behaviour at the moment. Easiest fix: forcefully crash the participant when he detects someone else joining with his own uid. 
- [ ] fix the hacky way groupexchange channelnames are handled (are prefixed atm) 
- [ ] general: fix the hacky way groupexchange channelnames are handled (are prefixed atm) 
- [ ] hash to get seed from shared_secret instead of using it directly - necessary? probably.
- [ ] maybe fix UB in vanilla lcm itself (examples/cpp -> compile example/cpp with ubsan -> get error) 
- [ ] There should be a way for the consumer of the API to querey the keyexchange-status for a given channel; including number of participants - maybe even ids for remotes 
- [ ] synchronization - implement locking properly, theoretically there is a race condition right now; but it is very unlikely to happen. Wait until we know how the public API looks exactely
- [ ] rekeying 
- [ ] Related to rekeying: allow using the key for a certain period timeout 
- [ ] IV is not set properly right now (easy fixed, haven't gotten to it)

## Bindings

* C++ (lcm/lcm-cpp.hpp)
* Python are implemented (should work) but were were last tested on #f414e77 .
* other bindings are not implemented


# Features

* Low-latency inter-process communication
* Efficient broadcast mechanism using UDP Multicast
* Type-safe message marshalling
* User-friendly logging and playback
* No centralized "database" or "hub" -- peers communicate directly
* No daemons
* Few dependencies

## Supported platforms and languages

* Platforms:
  * GNU/Linux
  * OS X
  * Windows
  * Any POSIX-1.2001 system (e.g., Cygwin, Solaris, BSD, etc.)
* Languages
  * C
  * C++
  * C#
  * Go
  * Java
  * Lua
  * MATLAB
  * Python

# Build Status (master)

[![Build Status](https://travis-ci.com/lcm-proj/lcm.svg?branch=master)](https://travis-ci.com/lcm-proj/lcm)
