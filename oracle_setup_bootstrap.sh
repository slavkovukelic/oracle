#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

run_setup() {
  local interpreter=$1
  shift
  exec "$interpreter" "$SCRIPT_DIR/oracle_setup.py" "$@"
}

python3_ok=false
if command -v python3 >/dev/null 2>&1; then
  if version_tuple=$(python3 -c "import sys; print(sys.version_info[:2])" 2>/dev/null); then
    sanitized=${version_tuple//[() ]/}
    IFS=, read -r major minor <<<"$sanitized"
    if (( major > 3 || (major == 3 && minor >= 11) )); then
      python3_ok=true
    fi
  fi
fi

if [[ "$python3_ok" == true ]]; then
  run_setup python3 "$@"
fi

if command -v python3.11 >/dev/null 2>&1; then
  run_setup "$(command -v python3.11)" "$@"
fi

echo "python3.11 is required; attempting to install via dnf..." >&2
if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo command is required to install python3.11" >&2
  exit 1
fi

if ! sudo dnf install -y python3.11; then
  echo "Failed to install python3.11 via dnf" >&2
  exit 1
fi

if command -v python3.11 >/dev/null 2>&1; then
  run_setup "$(command -v python3.11)" "$@"
fi

echo "python3.11 could not be located even after installation attempt" >&2
exit 1
