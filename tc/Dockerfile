FROM rustlang/rust:nightly-bullseye as builder

RUN apt-get update \
    && apt-get install -y software-properties-common \
    && wget https://apt.llvm.org/llvm-snapshot.gpg.key \
    && apt-key add llvm-snapshot.gpg.key \
    && rm -f llvm-snapshot.gpg.key \
    && add-apt-repository "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main" \
    && apt-get update \
    && apt-get install -y \
    libssl-dev \
    llvm-14-dev \
    musl \
    musl-dev \
    musl-tools \
    pkg-config
RUN apt update && apt install -y libbpf0 libcli1.10 iproute2
RUN rustup component add rust-src
RUN rustup target add x86_64-unknown-linux-musl
RUN cargo install bpf-linker
COPY . /src
WORKDIR /src
RUN --mount=type=cache,target=/.root/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo xtask build-ebpf --release \
    && cargo build --release --target=x86_64-unknown-linux-musl \
    && cp /src/target/x86_64-unknown-linux-musl/release/tc /usr/bin

ARG VERSION="v1.26.0"
RUN wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
RUN tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin && rm -f crictl-$VERSION-linux-amd64.tar.gz
ENTRYPOINT ["/usr/bin/tc"]


#FROM alpine:3.15
# runc links those libraries dynamically
# RUN apk update \
#     && apk add libseccomp \
#     libselinux``

FROM debian:bullseye-slim

RUN apt-get update

RUN apt-get install -y util-linux iproute2

COPY --from=builder /usr/bin/tc /usr/sbin/
COPY --from=builder /usr/local/bin/crictl /usr/sbin/
ENTRYPOINT ["/usr/sbin/tc"]
