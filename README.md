LCMsec - Remote attestation and Security for the Lightweight Communications and Marshalling Protocol (LCM)

This repository contains code relating to a proof-of-concept integration of a group Remote Attestation mechanism into LCMsec, in the context of my masters thesis.

LCM is a set of libraries and tools for message passing and data marshalling,
targeted at real-time systems where high-bandwidth and low latency are
critical. It provides a publish/subscribe message passing model and automatic
marshalling/unmarshalling code generation with bindings for applications in a
variety of programming languages.

LCMsec, is a security extensions for LCM. It:
* provides confidentiality, integrity and authenticity to LCM messages
* provides an attribute-based acces control mechanism with multicastgroup, port and channel granularity
* aims to minimize both overhead and computational complexity - as such, LCMsec is designed to be usable in most environments in which LCM is used.
* maintains the decentralized, peer-to-peer nature of LCM: no broker, no central instance to facilitate keyexchange
* is scalable to many peers and capable of dealing with dynamic communication topologies (hosts leaving and joining a channel) efficiently* 
