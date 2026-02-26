#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_step() {
  local step="$1"
  echo "[install_full] Running ${step}"
  "${script_dir}/${step}"
}

run_step install_deps.sh
run_step install_dsd_fme.sh
run_step apply_overlay.sh
run_step smoke_test.sh

echo "[install_full] Done"
