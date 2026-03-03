#!/usr/bin/env bash
set -euo pipefail

APP="vault-proxy-3112"
REGISTRY="registry.fly.io"
TAG="$(date -u +%Y%m%d%H%M)-$(openssl rand -hex 4)"
IMAGE="${REGISTRY}/${APP}:${TAG}"

echo "Building ${IMAGE}..."
podman build --platform linux/amd64 -t "${IMAGE}" -f ./Dockerfile.vault-proxy .

echo "Authenticating with Fly registry..."
fly auth docker

echo "Pushing ${IMAGE}..."
podman push "${IMAGE}"

echo "Deploying ${IMAGE}..."
fly deploy --image "${IMAGE}" -c ./fly.proxy.toml
