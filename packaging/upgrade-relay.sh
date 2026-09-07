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
# The opaque forwarder is stateless: a restart drops connected edges,
# which all reconnect automatically. Operators who care about
# zero-disruption upgrades should run multiple relay instances behind a
# load balancer and rolling-upgrade them one at a time.
#
# **A distribution relay is NOT stateless.** `OriginStore::new` clears the
# origin root at every start (src/distribution/origin.rs), so this restart
# discards the whole DVR window. The feeding edge keeps publishing a
# playlist — and a thumbnail index — naming segments that no longer exist,
# so viewers get 404s on seek until the window rolls over: at the 3600 s
# the manager provisions by default, that is an hour. Restart the edge in
# step with the relay. This script warns when it detects that case; see
# relay issues #6 and #8 for the underlying wipe.

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
# auto | distribution | default. `auto` keeps whatever is installed.
VARIANT="${VARIANT:-auto}"

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
        --variant) VARIANT="$2"; shift 2;;
        -h|--help) usage; exit 0;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1;;
    esac
done

# ── Which build is installed? ─────────────────────────────────────────
# The manifest carries two artefacts per arch — `distribution` and
# `default` — and an upgrade must keep the relay on the one it is already
# running. Picking `head -1` of the arch match (what this script used to
# do) works only because `-distribution.tar.gz.sha256` happens to sort
# before `.tar.gz.sha256` in a glob in another repo. If that ever moves,
# a working distribution relay is silently replaced by the lean forwarder:
# every WHEP viewer drops, the origin 404s, and `/health` still answers
# `ok` because it carries no variant field, so the rollback below never
# fires.
#
# THREE-VALUED ON PURPOSE. "No match" is not proof of a lean build — the
# probe also comes up empty when grep lacks `-a` (busybox), when
# ExecStart resolves to a wrapper script rather than the ELF, or when the
# file simply cannot be read. Each of those would downgrade a live
# distribution relay. So a negative is only believed once a positive
# control proves the probe can read this file at all, and anything
# ambiguous falls back to the previous behaviour.
#
# `/whep/` and `str0m` are present only in a distribution build.
# Do NOT probe for `viewer-distribution`: that string appears in BOTH
# variants (it is a config-field name compiled unconditionally), so it
# would report every lean relay as distribution.
detect_installed_variant() {   # -> distribution | default | unknown
    local bin="$1"
    [[ -r "${bin}" ]] || { echo unknown; return; }
    if grep -qa '/whep/' "${bin}" 2>/dev/null; then echo distribution; return; fi
    # Positive control: a metric name every relay binary carries, in both
    # variants. If this does not match either, the probe is not working
    # and its silence means nothing.
    if grep -qa 'bilbycast_relay_udp_sessions_total' "${bin}" 2>/dev/null; then
        echo default; return
    fi
    echo unknown
}

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
    local asset="cosign-linux-${cosign_arch}"
    local url="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${asset}"
    local checksum_url="https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign_checksums.txt"
    curl -fsSL -o /tmp/cosign "${url}"
    local expected
    expected="$(curl -fsSL "${checksum_url}" | awk -v a="${asset}" '$2 == a {print $1}')"
    if [[ -z "${expected}" ]]; then
        echo "Could not fetch cosign checksum for ${asset} from ${checksum_url}" >&2
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

# Resolve which variant to install, then select it explicitly so the
# answer no longer depends on the manifest's artefact ORDER.
if [[ "${VARIANT}" == "auto" ]]; then
    DETECTED="$(detect_installed_variant "${BINARY_PATH}")"
else
    DETECTED="${VARIANT}"
fi
case "${DETECTED}" in
    distribution|default)
        echo "  Variant       : ${DETECTED}$([[ "${VARIANT}" == "auto" ]] && echo ' (detected)' || echo ' (requested)')"
        ;;
    *)
        # Could not tell. Reproduce the previous behaviour rather than
        # guess `default` — guessing wrong here takes a live distribution
        # relay off air, and guessing wrong the other way costs nothing.
        echo "  Variant       : could not detect; keeping the previous selection rule"
        ;;
esac

ARTEFACT_URL=""
ARTEFACT_SHA256=""
if [[ "${DETECTED}" == "distribution" || "${DETECTED}" == "default" ]]; then
    ARTEFACT_URL="$(jq -r --arg arch "${ARCH}" --arg v "${DETECTED}" \
        '.artefacts[] | select(.arch == $arch and .variant == $v) | .url' manifest.json | head -1)"
    ARTEFACT_SHA256="$(jq -r --arg arch "${ARCH}" --arg v "${DETECTED}" \
        '.artefacts[] | select(.arch == $arch and .variant == $v) | .sha256' manifest.json | head -1)"
fi
# Fallback: an older manifest with no `variant` key, or a requested
# variant this release does not carry. Same rule this script always used.
if [[ -z "${ARTEFACT_URL}" || "${ARTEFACT_URL}" == "null" ]]; then
    [[ "${DETECTED}" == "distribution" || "${DETECTED}" == "default" ]] \
        && echo "  note: no '${DETECTED}' artefact in this manifest — falling back to the first for this arch" >&2
    ARTEFACT_URL="$(jq -r --arg arch "${ARCH}" \
        '.artefacts[] | select(.arch == $arch) | .url' manifest.json | head -1)"
    ARTEFACT_SHA256="$(jq -r --arg arch "${ARCH}" \
        '.artefacts[] | select(.arch == $arch) | .sha256' manifest.json | head -1)"
fi

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

# The restart discards the DVR window. Say so before doing it, because
# the symptom (viewers getting 404s on seek for the next hour) points at
# the edge rather than at this upgrade.
#
# Warn, never block: this script is a published release asset that is
# curled and run non-interactively, and a prompt here would hang an
# unattended upgrade. Every probe is `|| true`-guarded — `set -euo
# pipefail` is active, and an operator whose relay.json cannot be parsed
# must still get their upgrade rather than an exit 1 from a warning.
if [[ "${DETECTED}" == "distribution" ]] || \
   grep -qa '/whep/' "${BINARY_PATH}" 2>/dev/null; then
    ORIGIN_ROOT="$(jq -r '.distribution.origin_root // "/var/lib/bilbycast-relay/origin"' \
        /etc/bilbycast/relay.json 2>/dev/null || echo /var/lib/bilbycast-relay/origin)"
    SEG_COUNT="$(find "${ORIGIN_ROOT}" -type f -name '*.m4s' 2>/dev/null | wc -l || echo 0)"
    echo
    echo "  !! This is a distribution relay. Restarting it CLEARS the DVR origin"
    echo "     at ${ORIGIN_ROOT} (${SEG_COUNT} segment(s) held right now)."
    echo "     The feeding edge keeps publishing a playlist naming those segments,"
    echo "     so viewers get 404s on seek until the window rolls over. Restart the"
    echo "     edge in step with this relay. See relay issues #6 and #8."
    echo
fi

echo "Stopping ${SERVICE_NAME}…"
systemctl stop "${SERVICE_NAME}"

if [[ -e "${PREV_BACKUP}" ]]; then
    rm -f "${PREV_BACKUP}"
fi
cp "${BINARY_PATH}" "${PREV_BACKUP}"
mv -Tf "${NEW_STAGED}" "${BINARY_PATH}"

# ── The viewer portal, when this host runs one ────────────────────────
#
# Detected rather than flagged: an operator upgrading a relay is not choosing
# to leave its portal on an older binary, and version skew between the two is
# the kind nobody goes looking for. Silent when no portal is installed.
#
# Best-effort on purpose. The portal is not the data plane, so a portal that
# fails to swap must not roll the relay back — it is reported and left stopped,
# which is visible, rather than half-upgraded, which is not.
PORTAL_UNIT_NAME="bilbycast-portal"
PORTAL_BINARY=""
PORTAL_PREV=""
PORTAL_WAS_ACTIVE=0
if systemctl list-unit-files "${PORTAL_UNIT_NAME}.service" >/dev/null 2>&1 \
   && systemctl cat "${PORTAL_UNIT_NAME}" >/dev/null 2>&1; then
    PORTAL_EXEC="$(systemctl cat "${PORTAL_UNIT_NAME}" 2>/dev/null \
        | awk -F= '/^ExecStart=/ { sub(/^ExecStart=/, "", $0); print $0; exit }')"
    PORTAL_BINARY="$(awk '{ print $1 }' <<< "${PORTAL_EXEC}")"
    NEW_PORTAL="$(find staging -maxdepth 3 -name bilbycast-portal -type f | head -1)"

    if [[ -n "${PORTAL_BINARY}" && -x "${PORTAL_BINARY}" && -n "${NEW_PORTAL}" ]]; then
        echo "Upgrading ${PORTAL_UNIT_NAME} alongside the relay…"
        PORTAL_PREV="${PORTAL_BINARY}.previous"
        # Remember whether it was running, so the upgrade puts it back the way
        # it found it. An operator who stopped the portal deliberately — or who
        # installed it and has not finished configuring it — must not have it
        # started by a relay upgrade.
        PORTAL_WAS_ACTIVE=0
        if systemctl is-active --quiet "${PORTAL_UNIT_NAME}"; then
            PORTAL_WAS_ACTIVE=1
        fi
        systemctl stop "${PORTAL_UNIT_NAME}" || true
        cp "${PORTAL_BINARY}" "${PORTAL_PREV}"
        cp "${NEW_PORTAL}" "${PORTAL_BINARY}.new"
        chown "$(stat -c '%u:%g' "${PORTAL_BINARY}")" "${PORTAL_BINARY}.new"
        chmod "$(stat -c '%a' "${PORTAL_BINARY}")" "${PORTAL_BINARY}.new"
        mv -Tf "${PORTAL_BINARY}.new" "${PORTAL_BINARY}"
    elif [[ -n "${PORTAL_BINARY}" && -z "${NEW_PORTAL}" ]]; then
        echo "WARNING: ${PORTAL_UNIT_NAME} is installed but this tarball carries no" >&2
        echo "         portal binary — it ships in the distribution variant. The" >&2
        echo "         portal is left on its current version." >&2
    fi
fi

echo "Starting ${SERVICE_NAME}…"
systemctl start "${SERVICE_NAME}"

# ── Health check + auto-rollback ──────────────────────────────────────
# The portal comes back after the relay, and only if the relay stays up: it
# reads nothing from the relay, but bringing it up beside a relay that is about
# to be rolled back would leave the pair mismatched for the rollback window.
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
    # The relay held. Bring the portal back on the new binary.
    if [[ -n "${PORTAL_PREV}" && "${PORTAL_WAS_ACTIVE}" -eq 0 ]]; then
        echo "  ${PORTAL_UNIT_NAME}: binary upgraded, left stopped (it was not running)"
    elif [[ -n "${PORTAL_PREV}" ]]; then
        systemctl start "${PORTAL_UNIT_NAME}" || true
        if systemctl is-active --quiet "${PORTAL_UNIT_NAME}"; then
            echo "  ${PORTAL_UNIT_NAME}: upgraded and running"
        else
            # Said loudly and left stopped rather than rolled back: the portal
            # is not the data plane, and a viewer seeing nothing is a smaller
            # failure than putting the relay back a version to rescue it.
            echo "WARNING: ${PORTAL_UNIT_NAME} did not come back. Previous binary is at" >&2
            echo "         ${PORTAL_PREV}. The relay is fine; viewers cannot sign in." >&2
            echo "         journalctl -u ${PORTAL_UNIT_NAME} -e" >&2
        fi
    fi

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
# Roll the portal back with it, so the pair never straddles a version.
if [[ -n "${PORTAL_PREV}" && -e "${PORTAL_PREV}" ]]; then
    echo "Rolling the portal back too…"
    mv -Tf "${PORTAL_PREV}" "${PORTAL_BINARY}"
    systemctl start "${PORTAL_UNIT_NAME}" || true
fi

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
