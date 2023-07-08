This folder contains a program to test and demo LCMsec.

## Instructions 

* run `git submodule init && git submodule update` to fetch the toml dependency
* Make compiles the demo_instance program.
* run it: `./demo_instance instances/alice.toml`
    * demo_instance expects a config file that configures both its behaviour and which certificates to use. Some are provided in the `instances` folder.
    * You can also generate them using `gen_instances.sh`
* a sample PKI for testing is provided in the x509v3 folder
    * You can generate your own using the `gen_certificates.py` Script. It requires the openssl and step-cli commandline utilities
