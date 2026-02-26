#!/usr/bin/env bash
set -euo pipefail

fail_count=0

ok() {
  echo "OK: $*"
}

fail() {
  echo "FAIL: $*"
  fail_count=$((fail_count + 1))
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

if command -v dsd-fme >/dev/null 2>&1; then
  ok "command -v dsd-fme"
else
  fail "command -v dsd-fme"
fi

if command -v systemctl >/dev/null 2>&1; then
  if systemctl --no-pager status openwebrx >/dev/null 2>&1; then
    ok "systemctl --no-pager status openwebrx"
  else
    fail "systemctl --no-pager status openwebrx"
  fi
else
  fail "systemctl not found"
fi

htdocs_dir="$(resolve_htdocs_dir || true)"
if [[ -z "${htdocs_dir}" ]]; then
  fail "HTDOCS directory not found"
else
  init_js="${htdocs_dir}/plugins/receiver/init.js"
  if [[ -f "${init_js}" ]]; then
    ok "${init_js}"
  else
    fail "${init_js}"
  fi

  dsdfme_auto_js="${htdocs_dir}/plugins/receiver/dsdfme_auto.js"
  dsdfme_auto_js_alt="${htdocs_dir}/plugins/receiver/dsdfme_auto/dsdfme_auto.js"
  if [[ -f "${dsdfme_auto_js}" ]]; then
    ok "${dsdfme_auto_js}"
  elif [[ -f "${dsdfme_auto_js_alt}" ]]; then
    ok "${dsdfme_auto_js_alt}"
  else
    fail "${dsdfme_auto_js}"
  fi
fi

if (( fail_count == 0 )); then
  echo "OK: smoke test passed"
else
  echo "FAIL: smoke test failed (${fail_count})"
fi

echo "Открой http://<host>:8073/ и выбери DSDFME"

if (( fail_count == 0 )); then
  exit 0
fi
exit 1
