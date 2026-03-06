#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_NAME="remote-task"
SKILL_DIR="${ROOT_DIR}/skills/${SKILL_NAME}"
BIN_ROOT="${SKILL_DIR}/assets/bin"
DIST_DIR="${ROOT_DIR}/dist"
TARBALL_PATH="${DIST_DIR}/${SKILL_NAME}.tar.gz"

TARGETS=(
  "x86_64-unknown-linux-musl:linux-amd64"
  "aarch64-unknown-linux-musl:linux-arm64"
)

if [[ ! -d "${SKILL_DIR}" ]]; then
  echo "skill directory not found: ${SKILL_DIR}" >&2
  exit 1
fi

if ! command -v cargo-zigbuild >/dev/null 2>&1; then
  echo "cargo-zigbuild is required but was not found on PATH" >&2
  exit 1
fi

mkdir -p "${DIST_DIR}"
rm -rf "${BIN_ROOT}/linux-amd64" "${BIN_ROOT}/linux-arm64"

for spec in "${TARGETS[@]}"; do
  target="${spec%%:*}"
  arch_dir="${spec##*:}"
  output_dir="${BIN_ROOT}/${arch_dir}"
  output_bin="${output_dir}/fly-vault"
  source_bin="${ROOT_DIR}/target/${target}/release/fly-vault"

  echo "Building fly-vault for ${target}..."
  cargo zigbuild --release --target "${target}" -p fly-vault

  mkdir -p "${output_dir}"
  cp "${source_bin}" "${output_bin}"
  chmod 755 "${output_bin}"
done

echo "Creating ${TARBALL_PATH}..."
tar \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -C "${ROOT_DIR}/skills" \
  -czf "${TARBALL_PATH}" \
  "${SKILL_NAME}"

echo "Embedded binaries:"
for spec in "${TARGETS[@]}"; do
  arch_dir="${spec##*:}"
  echo "  ${BIN_ROOT}/${arch_dir}/fly-vault"
done

echo "Created skill tarball: ${TARBALL_PATH}"
