#!/bin/bash

set -e

cd "$(dirname $0)"
tag="$(date -u +%Y%m%d-%H%M%S)"
docker build --platform linux/amd64 -t fly-vault-vmimage:$tag .
cid=$(docker create fly-vault-vmimage:$tag)
docker export $cid | gzip > ../../vmimage.tar.gz
docker rm $cid
