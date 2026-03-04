FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends e2fsprogs fuse3 util-linux \
    && rm -rf /var/lib/apt/lists/*
COPY target/x86_64-unknown-linux-musl/release/init /init
ENTRYPOINT ["/init"]
