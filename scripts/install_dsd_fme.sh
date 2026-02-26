#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[install_dsd_fme] $*"
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

if command -v dsd-fme >/dev/null 2>&1; then
  echo "dsd-fme present"
  exit 0
fi

for tool in git cmake; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "FAIL: missing required tool '${tool}'. Run scripts/install_deps.sh first."
    exit 1
  fi
done

workdir="$(mktemp -d)"
cleanup() {
  rm -rf "${workdir}"
}
trap cleanup EXIT

build_project() {
  local repo_url="$1"
  local project_name="$2"
  local src_dir="${workdir}/${project_name}"
  local build_dir="${src_dir}/build"

  log "Cloning ${project_name}"
  git clone --depth 1 "${repo_url}" "${src_dir}"

  log "Configuring ${project_name} (Release)"
  cmake -S "${src_dir}" -B "${build_dir}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local

  log "Building ${project_name}"
  cmake --build "${build_dir}" --parallel

  log "Installing ${project_name} to /usr/local"
  run_root cmake --install "${build_dir}"
}

build_project "https://github.com/lwvmobile/mbelib.git" "mbelib"
build_project "https://github.com/lwvmobile/dsd-fme.git" "dsd-fme"

log "Running ldconfig"
run_root ldconfig
hash -r

if ! command -v dsd-fme >/dev/null 2>&1; then
  echo "FAIL: dsd-fme not found after installation."
  exit 1
fi

log "First 10 lines of dsd-fme -h"
dsd-fme -h 2>&1 | sed -n '1,10p'
