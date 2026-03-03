# Repository Guidelines

## Project Structure & Module Organization
This repository is a Rust workspace for a secure Fly.io vault system.

- `crates/client/`: `fly-vault` CLI (attestation verification, config verification, console, port forwarding).
- `crates/init/`: VM-side `init` binary (QUIC server, state machine, setup flow, forwarding).
- `crates/protocol/`: shared wire protocol (stream tags, framed control/console messages).
- `crates/crypto/`: AES-256-XTS sector crypto and key types.
- `docs/`: reference docs for OIDC, Machines API, FUSE, loop devices, namespaces, TLS exporter.
- Root files: `DESIGN.md` (source-of-truth design), `README.md` (usage), `Dockerfile`, `fly.toml`.

## Build, Test, and Development Commands
- `cargo build`: build all workspace crates.
- `cargo check`: fast type-check across workspace.
- `cargo test`: run all unit and integration tests.
- `cargo test -p init --bin init`: run `init` binary tests, including in-process E2E state-machine tests.
- `cargo fmt -- --check`: verify formatting.
- `cargo fmt`: apply formatting.
- `cargo run -p fly-vault -- connect <vault-name>`: run client locally.
- `cargo zigbuild --release --target x86_64-unknown-linux-musl -p init`: produce static `init` for image builds.

## Coding Style & Naming Conventions
- Follow Rust defaults (4-space indentation, `rustfmt` output, no manual alignment).
- Use `snake_case` for functions/modules/files, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for constants.
- Keep protocol constants and framing logic centralized in `crates/protocol`.
- Prefer explicit error context with `anyhow::Context` on I/O and network boundaries.

## Testing Guidelines
- Place focused unit tests near implementation (`#[cfg(test)]` modules).
- Keep cross-component behavior tests in `crates/init` test module (current E2E coverage validates `Cold/Locked/Ready` transitions).
- Test names should describe behavior, e.g. `cold_boot_to_ready_and_reconnect`.
- Run `cargo test` before opening a PR; include command output summary in PR description.

## Commit & Pull Request Guidelines
Use concise, imperative commit titles and optional scope, for example:
- `init: enforce cold flow waits for rootfs`
- `client: verify machine config mounts`

PRs should include:
- What changed and why.
- Security impact (if any), especially attestation/config checks.
- Test coverage and exact commands run.
- Linked issue(s) when applicable.
