# syntax=docker/dockerfile:1
FROM debian:trixie

ENV container=docker
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Optional: make apt non-interactive
ARG DEBIAN_FRONTEND=noninteractive

# Install systemd + a minimal, practical base userland.
# (Add/remove packages to match what you want "in the VM".)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus dbus-user-session \
      ca-certificates curl wget gnupg \
      iproute2 iputils-ping net-tools \
      openssh-server sudo \
      vim-tiny less procps kmod udev \
      locales tzdata && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Locale (optional; adjust as you like)
RUN sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
ENV LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

# systemd inside a container: reduce noise / avoid TTY gettys, etc.
# Mask a few units that are either meaningless or problematic in containers.
RUN systemctl mask \
      dev-hugepages.mount \
      sys-fs-fuse-connections.mount \
      sys-kernel-config.mount \
      sys-kernel-debug.mount \
      sys-kernel-tracing.mount \
      getty.target \
      console-getty.service \
      systemd-remount-fs.service \
      systemd-logind.service || true

CMD ["/sbin/init"]
