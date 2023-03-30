# spaceQUIC

An implementation of the QUIC protocol as a library for the core Flight System, replacing SDLS and/or CryptoLib.
This repo provides a working demo of the library as a Docker container.

> :information_source: To use spaceQUIC standalone in an existing cFS project, take the library from `/code/libs/space_quic`.


## Requirements

Running the container requires setting [kernel parameters](https://docs.docker.com/engine/reference/commandline/run/#configure-namespaced-kernel-parameters-sysctls-at-runtime) (`--sysctl`) and [ulimits](https://docs.docker.com/engine/reference/commandline/run/#set-ulimits-in-container---ulimit) (`--ulimit`) which do not work on the Mac OS Docker host.
The container is currently untested on the Windows host; Linux is recommended.

To build natively, ensure the requirements for each of the following is met:
- [cFS](https://github.com/nasa/cFS)
- [OpenSSL + QUIC](https://github.com/quictls/openssl)
- [WolfSSL](https://github.com/wolfssl/wolfssl)
- [nghttp3](https://github.com/ngtcp2/nghttp3)
- [ngtcp2](https://github.com/ngtcp2/ngtcp2)

## Setup

The following instructions assume the use of Docker for building dependencies and compiling cFS. See the [Dockerfile](Dockerfile) for the full build process.

Clone the repo:
```bash
git clone --recurse-submodules https://github.com/ssloxford/spaceQUIC.git
cd spaceQUIC
```

> :information_source: Make sure to use the `--recurse-submodules` flag, or dependencies will be missing.

Build the container:
```bash
./build.sh
```

Generate a self-signed TLS certificate and key:
```bash
mkdir cert
cd cert
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out certificate.crt -keyout private.key
```

> :information_source: **To change the certificate/key location**: Modify the certificate info in `/code/libs/space_quic/fsw/src/quic/serv.c`.


## Usage

Run cFS and the benchmark ground system:
```bash
./run-interactive.sh
cd /code/build/exe/cpu1
./core-cpu1 &
cd /code/build/tools/benchmark
./benchmark
```

Run cFS only:
```bash
./run-sat.sh
```

Run the benchmark ground system only:
```bash
./run-ground.sh
```

Run the container with an interactive shell:
```bash
./run-interactive.sh
```

> :information_source: **To run the ground system in a separate container/machine**: Modify the `CFS_HOST` IP address in `/code/tools/benchmark/benchmark.c`.


## Contribute

Code is provided as-is, as a starting point for future work.
This project is no longer actively maintained, but pull requests for bug fixes and new features are welcomed.
We will try to review any pull requests in a timely manner.


## Planned Features

The following features have not yet been implemented:
- [x] cFS with QUIC running in Docker
- [ ] CLI ground system
- [ ] Easier OpenSSL/WolfSSL switch
- [x] Custom certificate/key files
- [ ] Remove hardcoded paths from build process (particularly `CMakeLists.txt` files)
