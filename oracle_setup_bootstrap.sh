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

LOCAL_REPO_MODE=${ORACLE_BOOTSTRAP_REPO_MODE:-auto}
LOCAL_REPO_MODE=${LOCAL_REPO_MODE,,}
LOCAL_REPO_ROOT=${ORACLE_BOOTSTRAP_LOCAL_REPO:-/INSTALL}
REPO_DIR=/etc/yum.repos.d
REPO_FILE_NAME=oracle-setup-bootstrap.repo
LOCAL_REPO_FILE=""
LOCAL_REPO_BACKUP_DIR=""
SUDO=()

require_privileged_runner() {
  if [[ $EUID -eq 0 ]]; then
    SUDO=()
    return 0
  fi

  if command -v sudo >/dev/null 2>&1; then
    SUDO=(sudo)
    return 0
  fi

  echo "sudo command is required to install python3.11" >&2
  exit 1
}

install_with_system_repos() {
  "${SUDO[@]}" dnf install -y python3.11
}

setup_local_repo() {
  local repo_root=$1
  local appstream_dir="$repo_root/AppStream"
  local baseos_dir="$repo_root/BaseOS"

  if [[ ! -d $appstream_dir || ! -d $baseos_dir ]]; then
    echo "Local repository directories not found under $repo_root (expected AppStream and BaseOS)" >&2
    return 1
  fi

  LOCAL_REPO_BACKUP_DIR="$REPO_DIR/.oracle-setup-bootstrap-$(date +%Y%m%d%H%M%S)"
  LOCAL_REPO_FILE="$REPO_DIR/$REPO_FILE_NAME"
  local appstream_url="file://$(readlink -f "$appstream_dir")"
  local baseos_url="file://$(readlink -f "$baseos_dir")"

  "${SUDO[@]}" mkdir -p "$REPO_DIR" || return 1
  "${SUDO[@]}" mkdir -p "$LOCAL_REPO_BACKUP_DIR" || return 1

  while IFS= read -r -d '' repo_file; do
    "${SUDO[@]}" mv "$repo_file" "$LOCAL_REPO_BACKUP_DIR/" || return 1
  done < <(find "$REPO_DIR" -maxdepth 1 -type f -name '*.repo' -print0)

  "${SUDO[@]}" tee "$LOCAL_REPO_FILE" >/dev/null <<EOF || return 1
[oracle-setup-bootstrap-appstream]
name=Oracle Linux AppStream (bootstrap)
baseurl=$appstream_url
enabled=1
gpgcheck=0

[oracle-setup-bootstrap-baseos]
name=Oracle Linux BaseOS (bootstrap)
baseurl=$baseos_url
enabled=1
gpgcheck=0
EOF

  "${SUDO[@]}" chmod 644 "$LOCAL_REPO_FILE" || return 1
  "${SUDO[@]}" dnf clean metadata >/dev/null 2>&1 || true
  "${SUDO[@]}" dnf clean all >/dev/null 2>&1 || true
  return 0
}

cleanup_local_repo() {
  if [[ -n "$LOCAL_REPO_FILE" && -f "$LOCAL_REPO_FILE" ]]; then
    "${SUDO[@]}" rm -f "$LOCAL_REPO_FILE"
  fi

  if [[ -n "$LOCAL_REPO_BACKUP_DIR" && -d "$LOCAL_REPO_BACKUP_DIR" ]]; then
    while IFS= read -r -d '' repo_file; do
      "${SUDO[@]}" mv "$repo_file" "$REPO_DIR/"
    done < <(find "$LOCAL_REPO_BACKUP_DIR" -mindepth 1 -maxdepth 1 -type f -print0)
    "${SUDO[@]}" rmdir "$LOCAL_REPO_BACKUP_DIR" 2>/dev/null || true
  fi

  LOCAL_REPO_FILE=""
  LOCAL_REPO_BACKUP_DIR=""
}

install_with_local_repo() {
  if ! setup_local_repo "$1"; then
    cleanup_local_repo
    return 1
  fi

  local status=0
  if ! "${SUDO[@]}" dnf install -y python3.11; then
    status=$?
  fi

  cleanup_local_repo
  return $status
}

require_privileged_runner

try_local=false
case "$LOCAL_REPO_MODE" in
  auto)
    try_local=true
    ;;
  system)
    try_local=false
    ;;
  local)
    try_local=true
    ;;
  *)
    echo "Unknown ORACLE_BOOTSTRAP_REPO_MODE value: $LOCAL_REPO_MODE" >&2
    exit 1
    ;;
esac

if [[ "$LOCAL_REPO_MODE" != "local" ]]; then
  echo "python3.11 is required; attempting to install via system repositories..." >&2
  if install_with_system_repos; then
    if command -v python3.11 >/dev/null 2>&1; then
      run_setup "$(command -v python3.11)" "$@"
    fi
    echo "python3.11 could not be located even after installation attempt" >&2
    exit 1
  fi

  echo "Failed to install python3.11 via system repositories" >&2
fi

if [[ "$try_local" == true ]]; then
  echo "Attempting to enable local repository from $LOCAL_REPO_ROOT" >&2
  if install_with_local_repo "$LOCAL_REPO_ROOT"; then
    if command -v python3.11 >/dev/null 2>&1; then
      run_setup "$(command -v python3.11)" "$@"
    fi
    echo "python3.11 could not be located even after installation attempt" >&2
    exit 1
  fi
  echo "Failed to install python3.11 via local repository" >&2
fi

echo "python3.11 could not be located even after installation attempts" >&2
exit 1
