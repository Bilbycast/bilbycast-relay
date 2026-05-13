#!/usr/bin/env bash
# Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# uninstall-relay.sh — counterpart to install-relay.sh.
#
# By default removes the binary and systemd unit but preserves
# `/etc/bilbycast/relay.json` and `/var/lib/bilbycast/relay` so the
# operator can reinstall and pick up where they left off (registered
# node_id / node_secret survive). Pass `--purge` to wipe everything.

set -euo pipefail

INSTALL_ROOT="${INSTALL_ROOT:-/opt/bilbycast/relay}"
DATA_ROOT="${DATA_ROOT:-/var/lib/bilbycast/relay}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bilbycast}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
PURGE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --purge) PURGE=1; shift;;
        -h|--help)
            cat <<EOF
Usage: $0 [--purge]
  --purge    Remove config + state + service user (otherwise preserved for reinstall).
EOF
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 1;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "uninstall-relay.sh must run as root (sudo)." >&2
    exit 1
fi

echo "Stopping bilbycast-relay…"
systemctl disable --now bilbycast-relay 2>/dev/null || true
rm -f "${SYSTEMD_UNIT_DIR}/bilbycast-relay.service"
systemctl daemon-reload

echo "Removing binary from ${INSTALL_ROOT}…"
rm -f "${INSTALL_ROOT}/bilbycast-relay" \
      "${INSTALL_ROOT}/bilbycast-relay.previous" \
      "${INSTALL_ROOT}/bilbycast-relay.new"

if [[ "${PURGE}" -eq 1 ]]; then
    echo "--purge: removing config + data + service user…"
    rm -f "${CONFIG_DIR}/relay.json" "${CONFIG_DIR}/relay.env"
    rm -rf "${DATA_ROOT}"
    rm -f /etc/sysusers.d/bilbycast-relay.conf
    if id -u bilbycast-relay > /dev/null 2>&1; then
        userdel bilbycast-relay 2>/dev/null || true
    fi
    rmdir "${INSTALL_ROOT}" 2>/dev/null || true
    # /etc/bilbycast may be shared with bilbycast-edge or
    # bilbycast-appear-x-gateway — only remove it if it's empty.
    rmdir "${CONFIG_DIR}" 2>/dev/null || true
fi

echo "Uninstall complete."
