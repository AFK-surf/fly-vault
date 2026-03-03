#!/usr/bin/env bash
set -euo pipefail

APP="fly-vault-3112"
REGISTRY="registry.fly.io"
TAG="$(date -u +%Y%m%d%H%M)-$(openssl rand -hex 4)"
IMAGE="${REGISTRY}/${APP}:${TAG}"

echo "Building ${IMAGE}..."
cargo zigbuild --release --target x86_64-unknown-linux-musl -p init
podman build --platform linux/amd64 -t "${IMAGE}" .

echo "Authenticating with Fly registry..."
fly auth docker

echo "Pushing ${IMAGE}..."
podman push "${IMAGE}"

echo "Deploying ${IMAGE}..."
fly deploy --image "${IMAGE}"
