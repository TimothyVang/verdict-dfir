#!/usr/bin/env bash
# sift-provision.sh — minimal provisioning run by Packer inside the
# SIFT VM before snapshotting. Keep light: heavy installs belong to
# `scripts/install.sh` at Product runtime, not Packer.

set -euo pipefail

log() { printf '[sift-provision] %s\n' "$*" >&2; }

log "apt update + baseline tools (non-interactive)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  openssh-server \
  curl \
  jq \
  zstd \
  ca-certificates

# Ensure sshd starts on boot.
systemctl enable ssh
systemctl start ssh

# Disable services that would slow boot + burn no-op I/O during
# goldens. Safe to disable in L3 CI; judges' real SIFT has these.
systemctl disable \
  unattended-upgrades \
  apt-daily.service apt-daily.timer \
  apt-daily-upgrade.service apt-daily-upgrade.timer \
  snapd 2>/dev/null || true

# Pre-create the working directory the Product writes into.
mkdir -p /home/sansforensics/findevil
chown -R sansforensics:sansforensics /home/sansforensics/findevil

# Fingerprint for traceability from L3 run logs.
echo "sift-provision: $(date -u +%FT%TZ)" \
  > /etc/sift-findevil-provision-stamp

log "provision complete"
