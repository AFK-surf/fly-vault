FROM alpine:3.21
RUN apk add --no-cache e2fsprogs e2fsprogs-extra fuse3 nftables util-linux
COPY target/x86_64-unknown-linux-musl/release/init /init
ENTRYPOINT ["/init"]
