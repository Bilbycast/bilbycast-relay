#!/usr/bin/env bash
# Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# upgrade-relay.sh — operator-run upgrade for an installed bilbycast-relay.
#
# Usage on the relay host (as root):
#
#   curl -fsSL https://github.com/Bilbycast/bilbycast-relay/releases/latest/download/upgrade-relay.sh \
#     | sudo bash
#
# Or, with options:
#
#   sudo ./upgrade-relay.sh \
#       [--channel stable]                 # release channel (only 'stable' is published today)
#       [--service bilbycast-relay]        # systemd unit name
#       [--binary-path /usr/local/bin/bilbycast-relay]
#                                          # auto-detected from the unit's ExecStart if omitted
#       [--health-url http://127.0.0.1:4480/health]
#                                          # post-restart health probe (relay /health is
#                                          # always public — no Bearer token needed)
#       [--health-timeout 30]              # seconds to wait for /health
#       [--no-verify-cosign]               # skip Sigstore signature verification
#                                          #   (still verifies SHA-256 from the manifest;
#                                          #   only set this on air-gapped boxes that can't
#                                          #   install cosign)
#       [--no-rollback]                    # don't auto-restore the previous binary on
#                                          #   health-check failure
#       [--target-version <semver>]        # pin to a specific tag instead of latest
#       [--dry-run]                        # download + verify; print what WOULD happen,
#                                          #   then exit without touching the running service
#
# What the script does:
#   1. Resolves the running unit's binary path from `systemctl cat`.
#   2. Downloads `manifest.json` + `manifest.sig.bundle` for the requested
#      channel/version from the release.
#   3. Verifies the Sigstore signature against the production identity
#      allowlist (Fulcio cert subject = the publishing workflow at a
#      `refs/tags/v*` ref). Installs cosign on demand if missing, with
#      its own checksum verified against the upstream release page.
#   4. Reads the matching artefact's SHA-256 from the verified manifest
#      for this host's arch (x86_64-linux or aarch64-linux), downloads
#      the tarball, verifies the hash.
#   5. Compares against the running version; no-op if equal.
#   6. Stops the service, swaps the binary atomically (mv -Tf), starts
#      the service.
#   7. Polls /health. On failure, restores the previous binary and
#      restarts (unless --no-rollback).
#   8. Exits 0 only when the new version reports healthy.
#
# The relay is stateless: a restart drops connected edges, which all
# reconnect automatically. There is no graceful-drain story to worry
# about — operators who care about zero-disruption upgrades should run
# multiple relay instances behind a load balancer and rolling-upgrade
# them one at a time.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
RELEASE_REPO="${RELEASE_REPO:-Bilbycast/bilbycast-relay}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.4.1}"

CHANNEL="stable"
SERVICE_NAME="bilbycast-relay"
BINARY_PATH=""
HEALTH_URL="http://127.0.0.1:4480/health"
HEALTH_TIMEOUT=30
VERIFY_COSIGN=1
ROLLBACK=1
TARGET_VERSION=""
DRY_RUN=0

# ── Argument parsing ──────────────────────────────────────────────────
usage() {
    sed -n '4,40p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --channel) CHANNEL="$2"; shift 2;;
        --service) SERVICE_NAME="$2"; shift 2;;
        --binary-path) BINARY_PATH="$2"; shift 2;;
        --health-url) HEALTH_URL="$2"; shift 2;;
        --health-timeout) HEALTH_TIMEOUT="$2"; shift 2;;
        --no-verify-cosign) VERIFY_COSIGN=0; shift;;
        --no-rollback) ROLLBACK=0; shift;;
        --target-version) TARGET_VERSION="$2"; shift 2;;
        --dry-run) DRY_RUN=1; shift;;
        -h|--help) usage; exit 0;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
    echo "upgrade-relay.sh must run as root (sudo)." >&2
    exit 1
fi

if [[ ! "${CHANNEL}" =~ ^(stable|nightly|beta)$ ]]; then
    echo "Channel must be stable | nightly | beta; got: ${CHANNEL}" >&2
    exit 1
fi

case "$(uname -m)-$(uname -s)" in
    x86_64-Linux)  ARCH="x86_64-linux";;
    aarch64-Linux) ARCH="aarch64-linux";;
    *)
        echo "Unsupported host: $(uname -m) on $(uname -s)" >&2
        echo "bilbycast-relay is published for x86_64-linux and aarch64-linux." >&2
        exit 1
        ;;
esac

need_pkg() {
    local pkg="$1"
    command -v "${pkg}" > /dev/null 2>&1 || {
        echo "${pkg} is required but not installed. Install via your package manager." >&2
        exit 1
    }
}
need_pkg curl
need_pkg jq
need_pkg sha256sum
need_pkg systemctl

# ── Resolve the live binary path from the systemd unit ────────────────
if [[ -z "${BINARY_PATH}" ]]; then
    if ! systemctl cat "${SERVICE_NAME}" > /dev/null 2>&1; then
        echo "systemd unit '${SERVICE_NAME}' not found." >&2
        echo "Pass --service <name> if your unit has a different name," >&2
        echo "or --binary-path <path> to skip auto-detection." >&2
        exit 1
    fi
    EXEC_LINE="$(systemctl cat "${SERVICE_NAME}" | awk -F'=' '/^ExecStart=/ { sub(/^ExecStart=/, ""); print; exit }')"
    EXEC_LINE="${EXEC_LINE#[-+!]}"
    EXEC_LINE="${EXEC_LINE#[-+!]}"
    BINARY_PATH="$(awk '{ print $1 }' <<< "${EXEC_LINE}")"
fi

if [[ -z "${BINARY_PATH}" || ! -x "${BINARY_PATH}" ]]; then
    echo "Could not locate executable bilbycast-relay binary." >&2
    echo "  Resolved path: '${BINARY_PATH}'" >&2
    exit 1
fi

echo "── bilbycast-relay upgrade ──"
echo "  Release repo  : ${RELEASE_REPO}"
echo "  Channel       : ${CHANNEL}"
echo "  Arch          : ${ARCH}"
echo "  Service       : ${SERVICE_NAME}"
echo "  Binary path   : ${BINARY_PATH}"
echo "  Health URL    : ${HEALTH_URL}"
echo "  Verify cosign : $([[ ${VERIFY_COSIGN} -eq 1 ]] && echo "yes" || echo "NO (insecure)")"
echo "  Auto-rollback : $([[ ${ROLLBACK} -eq 1 ]] && echo yes || echo no)"
echo "  Dry run       : $([[ ${DRY_RUN} -eq 1 ]] && echo yes || echo no)"
echo

CURRENT_VERSION="$("${BINARY_PATH}" --version 2>/dev/null | awk '{ print $NF }' || echo unknown)"
echo "Currently installed: ${CURRENT_VERSION}"

# ── cosign (only if verifying) ────────────────────────────────────────
ensure_cosign() {
    [[ "${VERIFY_COSIGN}" -eq 1 ]] || return 0
    if command -v cosign > /dev/null 2>&1; then
        echo "Using existing cosign: $(command -v cosign)"
        return
    fi
    echo "Installing cosign ${COSIGN_VERSION} into /usr/local/bin/cosign…"
    local cosign_arch
    case "${ARCH}" in
        x86_64-linux)  cosign_arch="amd64";;
        aarch64-linux) cosign_arch="arm64";;
    esac
    local url="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${cosign_arch}"
    local checksum_url="${url}.sha256"
    curl -fsSL -o /tmp/cosign "${url}"
    local expected
    expected="$(curl -fsSL "${checksum_url}" | awk '{ print $1 }')"
    if [[ -z "${expected}" ]]; then
        echo "Could not fetch cosign checksum from ${checksum_url}" >&2
        exit 1
    fi
    local got
    got="$(sha256sum /tmp/cosign | awk '{ print $1 }')"
    if [[ "${got}" != "${expected}" ]]; then
        echo "cosign checksum mismatch: expected ${expected}, got ${got}" >&2
        exit 1
    fi
    install -m 0755 /tmp/cosign /usr/local/bin/cosign
    rm /tmp/cosign
    echo "cosign installed."
}
ensure_cosign

# ── Download manifest + signature ─────────────────────────────────────
WORK_DIR="$(mktemp -d -t bilbycast-relay-upgrade-XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT
cd "${WORK_DIR}"

if [[ -n "${TARGET_VERSION}" ]]; then
    RELEASE_BASE="https://github.com/${RELEASE_REPO}/releases/download/v${TARGET_VERSION}"
else
    RELEASE_BASE="https://github.com/${RELEASE_REPO}/releases/latest/download"
fi

echo "Downloading manifest.json + manifest.sig.bundle from ${RELEASE_BASE}…"
curl -fsSL -o manifest.json       "${RELEASE_BASE}/manifest.json"
curl -fsSL -o manifest.sig.bundle "${RELEASE_BASE}/manifest.sig.bundle"

# ── Verify Sigstore signature ─────────────────────────────────────────
if [[ "${VERIFY_COSIGN}" -eq 1 ]]; then
    echo "Verifying Sigstore signature (issuer = GitHub Actions OIDC, identity = ${RELEASE_REPO})…"
    COSIGN_EXPERIMENTAL=1 cosign verify-blob \
        --bundle manifest.sig.bundle \
        --certificate-identity-regexp "https://github\\.com/${RELEASE_REPO//\//\\/}/\\.github/workflows/nightly-release\\.yml@refs/tags/v.*" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        manifest.json
else
    echo "WARNING: Sigstore verification disabled (--no-verify-cosign). Falling back to SHA-256-only trust." >&2
fi

VERSION="$(jq -r '.version' manifest.json)"
DEVICE_TYPE="$(jq -r '.device_type' manifest.json)"
CHANNEL_IN_MANIFEST="$(jq -r '.channel' manifest.json)"

if [[ "${DEVICE_TYPE}" != "relay" ]]; then
    echo "Manifest device_type mismatch: expected 'relay', got '${DEVICE_TYPE}'." >&2
    echo "(Pointed at the wrong release repo?)" >&2
    exit 1
fi
if [[ "${CHANNEL_IN_MANIFEST}" != "${CHANNEL}" ]]; then
    echo "Manifest channel mismatch: requested ${CHANNEL}, got ${CHANNEL_IN_MANIFEST}." >&2
    exit 1
fi

echo "Manifest version: ${VERSION}"

if [[ "${VERSION}" == "${CURRENT_VERSION}" ]]; then
    echo "Already on ${VERSION}. Nothing to do."
    exit 0
fi

ARTEFACT_URL="$(jq -r --arg arch "${ARCH}" \
    '.artefacts[] | select(.arch == $arch) | .url' manifest.json | head -1)"
ARTEFACT_SHA256="$(jq -r --arg arch "${ARCH}" \
    '.artefacts[] | select(.arch == $arch) | .sha256' manifest.json | head -1)"

if [[ -z "${ARTEFACT_URL}" || "${ARTEFACT_URL}" == "null" ]]; then
    echo "No artefact for arch=${ARCH} in manifest." >&2
    echo "Available:" >&2
    jq -r '.artefacts[] | "  \(.arch) / \(.variant)"' manifest.json >&2
    exit 1
fi

# Defence-in-depth host check: even a Sigstore-signed manifest cannot
# redirect downloads outside github.com.
ARTEFACT_HOST="$(awk -F[/:] '{ print $4 }' <<< "${ARTEFACT_URL}")"
case "${ARTEFACT_HOST}" in
    github.com|objects.githubusercontent.com) ;;
    *) echo "Manifest artefact URL host '${ARTEFACT_HOST}' is not in the allowlist." >&2; exit 1;;
esac

echo "Downloading ${ARTEFACT_URL}…"
curl -fsSL -o release.tar.gz "${ARTEFACT_URL}"
GOT_SHA="$(sha256sum release.tar.gz | awk '{ print $1 }')"
if [[ "${GOT_SHA}" != "${ARTEFACT_SHA256}" ]]; then
    echo "Tarball SHA-256 mismatch: expected ${ARTEFACT_SHA256}, got ${GOT_SHA}" >&2
    exit 1
fi
echo "Tarball SHA-256 matches manifest."

# ── Extract + locate the new binary ───────────────────────────────────
mkdir staging
tar -xzf release.tar.gz -C staging
NEW_BIN="$(find staging -maxdepth 3 -name bilbycast-relay -type f | head -1)"
if [[ -z "${NEW_BIN}" || ! -x "${NEW_BIN}" ]]; then
    echo "Tarball did not contain an executable bilbycast-relay binary." >&2
    exit 1
fi

NEW_VERSION_REPORTED="$("${NEW_BIN}" --version 2>/dev/null | awk '{ print $NF }' || echo unknown)"
if [[ "${NEW_VERSION_REPORTED}" != "${VERSION}" && "${NEW_VERSION_REPORTED}" != "unknown" ]]; then
    echo "WARNING: tarball binary reports version '${NEW_VERSION_REPORTED}' but manifest claims '${VERSION}'." >&2
    echo "Continuing — the manifest is signed and authoritative." >&2
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo
    echo "── Dry run complete ──"
    echo "  Would replace : ${BINARY_PATH} (current: ${CURRENT_VERSION})"
    echo "  With          : ${NEW_BIN} (manifest: ${VERSION})"
    echo "  Then          : systemctl restart ${SERVICE_NAME}; poll ${HEALTH_URL}"
    exit 0
fi

# ── Atomic binary swap ────────────────────────────────────────────────
PREV_BACKUP="${BINARY_PATH}.previous"
NEW_STAGED="${BINARY_PATH}.new"

ORIG_OWNER="$(stat -c '%u:%g' "${BINARY_PATH}")"
ORIG_MODE="$(stat -c '%a' "${BINARY_PATH}")"

cp "${NEW_BIN}" "${NEW_STAGED}"
chown "${ORIG_OWNER}" "${NEW_STAGED}"
chmod "${ORIG_MODE}" "${NEW_STAGED}"

echo "Stopping ${SERVICE_NAME}…"
systemctl stop "${SERVICE_NAME}"

if [[ -e "${PREV_BACKUP}" ]]; then
    rm -f "${PREV_BACKUP}"
fi
cp "${BINARY_PATH}" "${PREV_BACKUP}"
mv -Tf "${NEW_STAGED}" "${BINARY_PATH}"

echo "Starting ${SERVICE_NAME}…"
systemctl start "${SERVICE_NAME}"

# ── Health check + auto-rollback ──────────────────────────────────────
echo "Waiting up to ${HEALTH_TIMEOUT}s for ${HEALTH_URL}…"
HEALTHY=0
for _ in $(seq 1 "${HEALTH_TIMEOUT}"); do
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        if curl -fsS --max-time 3 "${HEALTH_URL}" > /dev/null 2>&1; then
            HEALTHY=1
            break
        fi
    fi
    sleep 1
done

if [[ "${HEALTHY}" -eq 1 ]]; then
    NEW_RUNNING="$("${BINARY_PATH}" --version 2>/dev/null | awk '{ print $NF }' || echo unknown)"
    echo
    echo "── Upgrade complete ──"
    echo "  ${CURRENT_VERSION}  →  ${NEW_RUNNING}"
    echo "  Previous binary preserved at: ${PREV_BACKUP}"
    echo "  Logs: journalctl -u ${SERVICE_NAME} -e"
    exit 0
fi

echo
echo "Health check did not pass within ${HEALTH_TIMEOUT}s." >&2

if [[ "${ROLLBACK}" -ne 1 ]]; then
    echo "--no-rollback set; leaving the new binary in place. Investigate:" >&2
    echo "  journalctl -u ${SERVICE_NAME} -e" >&2
    exit 1
fi

echo "Rolling back to previous binary…" >&2
systemctl stop "${SERVICE_NAME}" || true
mv -Tf "${PREV_BACKUP}" "${BINARY_PATH}"
systemctl start "${SERVICE_NAME}"

echo "Waiting up to ${HEALTH_TIMEOUT}s for rollback to come up…" >&2
for _ in $(seq 1 "${HEALTH_TIMEOUT}"); do
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        if curl -fsS --max-time 3 "${HEALTH_URL}" > /dev/null 2>&1; then
            echo "Rollback healthy. Original ${CURRENT_VERSION} is back online." >&2
            exit 1
        fi
    fi
    sleep 1
done

echo "Rollback did not become healthy either. Manual intervention required:" >&2
echo "  systemctl status ${SERVICE_NAME}" >&2
echo "  journalctl -u ${SERVICE_NAME} -e" >&2
exit 2
