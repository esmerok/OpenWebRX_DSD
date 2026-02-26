#!/usr/bin/env bash
set -euo pipefail

log() {
  echo "[apply_overlay] $*"
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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd "${script_dir}/.." && pwd)"

is_valid_overlay_dir() {
  local dir="$1"
  [[ -d "${dir}/python/owrx" && -d "${dir}/python/csdr" && -d "${dir}/htdocs/plugins/receiver" ]]
}

resolve_overlay_dir() {
  local candidate
  local found=""

  candidate="${root_dir}/overlay"
  if is_valid_overlay_dir "${candidate}"; then
    printf '%s\n' "${candidate}"
    return 0
  fi

  while IFS= read -r candidate; do
    if is_valid_overlay_dir "${candidate}"; then
      found="${candidate}"
    fi
  done < <(find "${root_dir}/releases" -maxdepth 4 -type d -name overlay 2>/dev/null | sort)

  if [[ -n "${found}" ]]; then
    printf '%s\n' "${found}"
    return 0
  fi

  return 1
}

resolve_htdocs_dir() {
  local pkg
  local index_path

  if [[ -d /usr/lib/python3/dist-packages/htdocs ]]; then
    printf '%s\n' "/usr/lib/python3/dist-packages/htdocs"
    return 0
  fi

  if ! command -v dpkg >/dev/null 2>&1; then
    return 1
  fi

  pkg="$(dpkg -S 'htdocs/index.html' 2>/dev/null | head -n1 | cut -d: -f1)"
  if [[ -z "${pkg}" ]]; then
    return 1
  fi

  index_path="$(dpkg -L "${pkg}" 2>/dev/null | awk '/\/htdocs\/index\.html$/ {print; exit}')"
  if [[ -z "${index_path}" ]]; then
    return 1
  fi

  dirname "${index_path}"
}

overlay_dir="$(resolve_overlay_dir || true)"
if [[ -z "${overlay_dir}" ]]; then
  echo "FAIL: overlay directory not found."
  exit 1
fi

log "Using overlay: ${overlay_dir}"

log "Preparing /opt/owrx-dev"
run_root rm -rf /opt/owrx-dev/owrx /opt/owrx-dev/csdr
run_root mkdir -p /opt/owrx-dev/owrx /opt/owrx-dev/csdr

log "Copying overlay/python/owrx -> /opt/owrx-dev/owrx"
run_root cp -a "${overlay_dir}/python/owrx/." /opt/owrx-dev/owrx/

log "Copying overlay/python/csdr -> /opt/owrx-dev/csdr"
run_root cp -a "${overlay_dir}/python/csdr/." /opt/owrx-dev/csdr/

log "Installing systemd override"
run_root mkdir -p /etc/systemd/system/openwebrx.service.d
tmp_override="$(mktemp)"
cat >"${tmp_override}" <<'OVERRIDE'
[Service]
Environment="PYTHONPATH=/opt/owrx-dev"
OVERRIDE
run_root install -m 0644 "${tmp_override}" /etc/systemd/system/openwebrx.service.d/override.conf
rm -f "${tmp_override}"

htdocs_dir="$(resolve_htdocs_dir || true)"
if [[ -z "${htdocs_dir}" ]]; then
  echo "FAIL: could not determine htdocs directory."
  exit 1
fi

log "Using htdocs: ${htdocs_dir}"
run_root mkdir -p "${htdocs_dir}/plugins/receiver"

log "Copying overlay/htdocs/plugins/receiver/* -> ${htdocs_dir}/plugins/receiver/"
run_root cp -a "${overlay_dir}/htdocs/plugins/receiver/." "${htdocs_dir}/plugins/receiver/"

log "Compiling Python files in /opt/owrx-dev"
run_root python3 -m compileall -q /opt/owrx-dev

log "Restarting openwebrx"
run_root systemctl daemon-reload
run_root systemctl restart openwebrx

log "Done"
