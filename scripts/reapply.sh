#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[reapply] Running apply_overlay.sh"
"${script_dir}/apply_overlay.sh"

echo "[reapply] Running smoke_test.sh"
"${script_dir}/smoke_test.sh"

echo "Done: reapplied after upgrade."
