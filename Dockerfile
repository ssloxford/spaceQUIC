FROM ubuntu:latest

# Stop apt from asking difficult questions
ARG DEBIAN_FRONTEND=noninteractive

# Install build requirements
RUN apt update
RUN apt install -y build-essential cmake autoconf libtool pkg-config

# Install dependencies
RUN apt install -y libgcrypt-dev

ADD libs/ngtcp2 /libs/ngtcp2
ADD libs/openssl /libs/openssl
ADD libs/wolfssl /libs/wolfssl
ADD libs/nghttp3 /libs/nghttp3

# Build and install openssl
WORKDIR /libs/openssl
RUN ./config enable-tls1_3 --prefix=$PWD/build
RUN make -j$(nproc)
RUN make install_sw

# Build and install wolfssl
WORKDIR /libs/wolfssl
RUN ./autogen.sh
RUN ./configure --enable-quic
RUN make -j$(nproc)
RUN make install

# Build and install nghttp3
WORKDIR /libs/nghttp3
RUN autoreconf -i
RUN ./configure --prefix=$PWD/build --enable-lib-only
RUN make -j$(nproc) check
RUN make install

# Build and install ngtcp2
WORKDIR /libs/ngtcp2
RUN autoreconf -i
RUN ./configure PKG_CONFIG_PATH=/libs/openssl/build/lib64/pkgconfig:/libs/openssl/build/lib/pkgconfig:/libs/nghttp3/build/lib/pkgconfig LDFLAGS="-Wl,-rpath,/libs/openssl/build/lib" --with-wolfssl --with-openssl
RUN make -j$(nproc) check

# Build cFS
ADD code /code
WORKDIR /code
RUN make SIMULATION=native prep
RUN make
RUN make install

# Temporary - remove before final version
RUN apt install -y vim

WORKDIR /code
