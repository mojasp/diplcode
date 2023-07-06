LCMsec - Security for the Lightweight Communications and Marshalling Protocol (LCM)

LCM is a set of libraries and tools for message passing and data marshalling,
targeted at real-time systems where high-bandwidth and low latency are
critical. It provides a publish/subscribe message passing model and automatic
marshalling/unmarshalling code generation with bindings for applications in a
variety of programming languages.

This fork, LCMsec, is a security extensions for LCM. A brief overview of the design goals is provided here:
* provide confidentiality, integrity and authenticity to LCM messages
* aim to minimize both overhead and computational complexity - as such, LCMsec is designed to be usable in most environments in which LCM is used.
* maintain the decentralized, peer-to-peer nature of LCM: no broker, no central instance to facilitate keyexchange
* Scalable to many peers, capable of dealing with dynamic communication topologies (hosts leaving and joining a channel) efficiently

This is achieved with the use of:
* a hybrid cryptosystem: a symmetric key is shared between all publishers and subscribers to a channel on a specific multicastgroup
* No distinction between subscribers and publishers, each subscriber is also allowed to publish messages. This makes it possible to use a single shared symmetric key, and avoids issues typically associated with multicast authentication
* An attribute-based access control mechanism (who is allowed to send on which channel and multicastgroups) through the use X.509 certificates
* A built-in, decentralized discovery protocol
* AES/GCM or ChaChaPoly1305 as the underlying authenticated encryption algorithm.
* The Dutta-Barua group key agreement (modified to use EC-Cryptography) to agree on the symmetric key minimizes the number of network interactions when a publisher or subscriber joins a topic (i.e., is turned on)

For more informations please refer to the paper we submitted, which will be provided here shortly.

# Limitations of LCMsec

* Additional dependencies are Botan and libstdc++.
* Not yet adressed are the issues of rekeying and certificate revocation, which will be a next next step. 
* Only C, C++ and Python bindings are available, Python bindings have not been tested recently
* lcm-logger and lcm-spy are not availe
* Only the udpm provider is available

# LCMsec Quickstart guide

* To use security features, you will need generate a root certificate and x509v3 certificate/key-pairs for each node that should communicate. Permissions are written into SAN of those certificates. An automated way to generate a PKI will follow shortly
* The format of the SAN is a URI of the form: `urn:lcmsec:gkexchg:<mcastgroup>:<port>:<channelname>:<user_id>` 
    * example: ` urn:lcmsec:gkexchg:239.255.76.67:7667:channel1:4` (for a channel)
    * for the permission to be part of a multicast group, use the special string "gkexchg_g" and omit the channelname, for instance: ` urn:lcmsec:gkexchg_g:239.255.76.67:7667:4`
* use ```lcm_create_with_security(...) ``` (or use the c++ API in lcm-sec.hpp)
to create an LCM instance that has security enabled. This call will block until the group key agreement has finished on all channels for which there are permissions in the certificate
* call ```lcm_perform_keyexchange(lcm_t *lcm) ``` in a separate thread if the dynamic properties of the protocol (joining) are needed. If the groups are static after an initial key agreement, this is not needed. Alternatively, you can use the configuration option "keyexchange_in_background" (refer to lcm.h)
* At this point, just use the craeted lcm instance as you normally would.


An Example for an application using LCM-sec can be found in examples/cpp_security (compiling it requires the toml++ library, available as a git submodule). 
This is an example on how to create a certificate which provides "alice" with the permission to send on receive on "channel1" and "channel2" of multicastgroup 239.255.76.67 and port 7667:

```bash
    step-cli certificate create alice alice.crt alice.key --san urn:lcmsec:gkexchg:239.255.76.67:7667:channel1:4 --san urn:lcmsec:gkexchg:239.255.76.67:7667:channel2:4 --san urn:lcmsec:gkexchg_g:239.255.76.67:7667:4   --profile leaf --ca ./root_ca.crt --ca-key ./root_ca.key
    # format in a way that botan can understand
    openssl pkcs8 -topk8 -in alice.key -out alice.pem
    mv alice.pem alice.key
```

# Roadmap

The LCM project is active again. The current near-term plan is to:

* Clear deprecation warnings from build for all language targets
* Flush backlog of PRs
* Cut a new release

# Quick Links

* [LCM downloads](https://github.com/lcm-proj/lcm/releases)
* [Website and documentation](https://lcm-proj.github.io/lcm)


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
      * Ubuntu (20.04 and 22.04)
      * Fedora (37)
  * macOS (11 and 12)
  * Windows (2019 and 2022) via MSYS2
* Languages
  * C
  * C++
  * Java
  * Lua
  * MATLAB
  * Python

## Unmaintained languages

The following languages are currently unmaintained. PRs for these languages are still welcome and if
you are interested in maintaining them please let us know.

 * Go
 * C#/.NET
