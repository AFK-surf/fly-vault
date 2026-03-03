FROM alpine:3.21
RUN apk add --no-cache e2fsprogs losetup fuse3
COPY target/x86_64-unknown-linux-musl/release/init /init
ENTRYPOINT ["/init"]
