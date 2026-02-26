#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[install_deps] $*"
}

run_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    if ! command -v sudo >/dev/null 2>&1; then
      echo "FAIL: sudo is required when running as non-root."
      exit 1
    fi
    sudo "$@"
  fi
}

if ! command -v apt-get >/dev/null 2>&1; then
  echo "FAIL: apt-get not found. Debian/Ubuntu only."
  exit 1
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" != "debian" && "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *debian* ]]; then
    log "Warning: distro ID=${ID:-unknown}; continuing with apt-get."
  fi
fi

packages=(
  ca-certificates
  curl
  git
  cmake
  build-essential
  pkg-config
  libncurses-dev
  libsndfile1-dev
  libasound2-dev
)

export DEBIAN_FRONTEND=noninteractive

log "Updating apt index"
run_root apt-get update

log "Installing required packages"
run_root apt-get install -y "${packages[@]}"

log "Done"
