#!/usr/bin/env bash
# Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# install-relay.sh — single-shot installer for bilbycast-relay.
#
# Operator usage on a fresh relay host:
#
#   # Standalone relay (no manager connection):
#   curl -fsSL https://github.com/Bilbycast/bilbycast-relay/releases/latest/download/install-relay.sh \\
#     | sudo bash
#
#   # With manager connection (relay registers itself + reports stats):
#   curl -fsSL https://github.com/Bilbycast/bilbycast-relay/releases/latest/download/install-relay.sh \\
#     | sudo bash -s -- \\
#         --manager wss://manager.example.com:8443/ws/node \\
#         --registration-token <token-from-manager-ui> \\
#         [--api-token <32-128-char-secret>] \\
#         [--require-bind-auth] \\
#         [--channel stable|nightly|beta]
#
# What the script does:
#   1. Detects the host arch (x86_64-linux / aarch64-linux).
#   2. Downloads `manifest.json` + `manifest.sig.bundle` from the
#      configured channel's GitHub release.
#   3. Verifies the Sigstore signature with cosign (installs cosign if
#      missing, with its own checksum verified against the upstream
#      release page). The verify pins the publishing workflow at a
#      `refs/tags/v*` ref.
#   4. Reads the matching artefact's SHA-256 from the verified manifest,
#      downloads the tarball, verifies the hash.
#   5. Creates the `bilbycast-relay` system user/group via
#      systemd-sysusers or useradd. Distinct from edge's `bilbycast`
#      user and the gateway's `bilbycast-gateway` user so the three
#      services can coexist on one host.
#   6. Installs the binary at `/opt/bilbycast/relay/bilbycast-relay`
#      (matches `upgrade-relay.sh`'s in-place swap design — single
#      file, no versions/ symlink).
#   7. Writes `/etc/bilbycast/relay.json`. Manager wiring + api_token
#      + require_bind_auth are filled in from CLI flags.
#   8. Installs the systemd unit, runs `systemctl daemon-reload` and
#      `systemctl enable --now`.
#   9. Polls the local relay /health endpoint for ~30 s waiting for
#      the service to settle.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
RELEASE_REPO="${RELEASE_REPO:-Bilbycast/bilbycast-relay}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/bilbycast/relay}"
DATA_ROOT="${DATA_ROOT:-/var/lib/bilbycast/relay}"
CONFIG_DIR="${CONFIG_DIR:-/etc/bilbycast}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
COSIGN_VERSION="${COSIGN_VERSION:-v2.4.1}"

CHANNEL="stable"
MANAGER_URL=""
REGISTRATION_TOKEN=""
API_TOKEN=""
QUIC_ADDR="0.0.0.0:4433"
API_ADDR="0.0.0.0:4480"
REQUIRE_BIND_AUTH=0
UPGRADE_INSTALLER=0

# ── Argument parsing ──────────────────────────────────────────────────
usage() {
    cat <<EOF
Usage: $0 [options]

Standalone install needs no flags — the relay runs with defaults.

Options:
  --manager <url>              Manager WebSocket URL (must be wss://).
                               Enables the optional manager connection.
  --registration-token <tok>   One-shot registration token from the
                               manager UI. Required if --manager is set.
  --api-token <tok>            Bearer token for REST API auth
                               (32-128 chars). Without this every
                               endpoint except /health is public.
  --require-bind-auth          Reject TunnelBind without a pre-authorised
                               HMAC token. Recommended for production.
  --quic-addr <addr>           QUIC listen address (default ${QUIC_ADDR})
  --api-addr <addr>            REST API listen address (default ${API_ADDR})
  --channel <name>             Release channel (stable | nightly | beta),
                               default stable
  --upgrade-installer          Refresh service unit + install script,
                               leave config untouched
  -h, --help                   Show this message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manager) MANAGER_URL="$2"; shift 2;;
        --registration-token) REGISTRATION_TOKEN="$2"; shift 2;;
        --api-token) API_TOKEN="$2"; shift 2;;
        --require-bind-auth) REQUIRE_BIND_AUTH=1; shift;;
        --quic-addr) QUIC_ADDR="$2"; shift 2;;
        --api-addr) API_ADDR="$2"; shift 2;;
        --channel) CHANNEL="$2"; shift 2;;
        --upgrade-installer) UPGRADE_INSTALLER=1; shift;;
        -h|--help) usage; exit 0;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1;;
    esac
done

# ── Pre-flight checks ─────────────────────────────────────────────────
if [[ "$(id -u)" -ne 0 ]]; then
    echo "install-relay.sh must run as root (sudo)." >&2
    exit 1
fi

if [[ -n "${MANAGER_URL}" ]]; then
    if [[ "${MANAGER_URL}" != wss://* ]]; then
        echo "--manager URL must use wss:// (TLS required); got: ${MANAGER_URL}" >&2
        exit 1
    fi
    if [[ -z "${REGISTRATION_TOKEN}" && "${UPGRADE_INSTALLER}" -eq 0 ]]; then
        echo "--registration-token is required when --manager is set." >&2
        exit 1
    fi
elif [[ -n "${REGISTRATION_TOKEN}" ]]; then
    echo "--registration-token requires --manager. Pass both or neither." >&2
    exit 1
fi

if [[ -n "${API_TOKEN}" ]]; then
    if (( ${#API_TOKEN} < 32 || ${#API_TOKEN} > 128 )); then
        echo "--api-token must be 32-128 characters; got length ${#API_TOKEN}." >&2
        exit 1
    fi
fi

if [[ ! "${CHANNEL}" =~ ^(stable|nightly|beta)$ ]]; then
    echo "Channel must be stable | nightly | beta; got: ${CHANNEL}" >&2
    exit 1
fi

# Detect arch.
case "$(uname -m)-$(uname -s)" in
    x86_64-Linux)   ARCH="x86_64-linux";;
    aarch64-Linux)  ARCH="aarch64-linux";;
    *)
        echo "Unsupported host: $(uname -m) on $(uname -s)" >&2
        echo "bilbycast-relay releases are published for x86_64-linux and aarch64-linux." >&2
        exit 1
        ;;
esac

echo "── bilbycast-relay installer ──"
echo "  Repo       : ${RELEASE_REPO}"
echo "  Channel    : ${CHANNEL}"
echo "  Arch       : ${ARCH}"
echo "  Install at : ${INSTALL_ROOT}/bilbycast-relay"
echo "  Manager    : ${MANAGER_URL:-<standalone>}"
echo "  Bind auth  : $([[ ${REQUIRE_BIND_AUTH} -eq 1 ]] && echo "require_bind_auth = true" || echo "permissive (default)")"
echo

# ── Idempotency guard ─────────────────────────────────────────────────
BINARY_PATH="${INSTALL_ROOT}/bilbycast-relay"
if [[ -e "${BINARY_PATH}" && "${UPGRADE_INSTALLER}" -eq 0 ]]; then
    echo "Already installed at ${BINARY_PATH}."
    echo "Use packaging/upgrade-relay.sh to advance the binary,"
    echo "or pass --upgrade-installer to refresh the service unit."
    exit 0
fi

# ── Tooling: jq + curl + cosign ───────────────────────────────────────
need_pkg() {
    local pkg="$1"
    if ! command -v "${pkg}" > /dev/null 2>&1; then
        echo "${pkg} is required but not installed. Install via your package manager." >&2
        exit 1
    fi
}
need_pkg curl
need_pkg jq
need_pkg sha256sum

ensure_cosign() {
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
    expected="$(curl -fsSL "${checksum_url}" | awk '{print $1}')"
    if [[ -z "${expected}" ]]; then
        echo "Could not fetch cosign checksum from ${checksum_url}" >&2
        exit 1
    fi
    local got
    got="$(sha256sum /tmp/cosign | awk '{print $1}')"
    if [[ "${got}" != "${expected}" ]]; then
        echo "cosign checksum mismatch: expected ${expected}, got ${got}" >&2
        exit 1
    fi
    install -m 0755 /tmp/cosign /usr/local/bin/cosign
    rm /tmp/cosign
    echo "cosign installed."
}
ensure_cosign

# ── Resolve the latest release for the chosen channel ─────────────────
RELEASE_BASE="https://github.com/${RELEASE_REPO}/releases/latest/download"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
cd "${WORK_DIR}"

echo "Downloading manifest.json + manifest.sig.bundle from ${RELEASE_BASE}…"
curl -fsSL -o manifest.json        "${RELEASE_BASE}/manifest.json"
curl -fsSL -o manifest.sig.bundle  "${RELEASE_BASE}/manifest.sig.bundle"

echo "Verifying Sigstore signature against the publishing workflow's identity…"
COSIGN_EXPERIMENTAL=1 cosign verify-blob \
    --bundle manifest.sig.bundle \
    --certificate-identity-regexp "https://github\\.com/${RELEASE_REPO//\//\\/}/\\.github/workflows/nightly-release\\.yml@refs/tags/v.*" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    manifest.json

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

# Relay manifests carry a single artefact per arch — no variant axis
# (unlike the edge's default / full split).
ARTEFACT_URL="$(jq -r --arg arch "${ARCH}" \
    '.artefacts[] | select(.arch == $arch) | .url' manifest.json | head -1)"
ARTEFACT_SHA256="$(jq -r --arg arch "${ARCH}" \
    '.artefacts[] | select(.arch == $arch) | .sha256' manifest.json | head -1)"

if [[ -z "${ARTEFACT_URL}" || "${ARTEFACT_URL}" == "null" ]]; then
    echo "No artefact for arch=${ARCH} in manifest." >&2
    echo "Available:" >&2
    jq -r '.artefacts[] | "  \(.arch)"' manifest.json >&2
    exit 1
fi

# Defence-in-depth: even a signed manifest can't redirect downloads
# outside GitHub-controlled hosts.
ARTEFACT_HOST="$(awk -F[/:] '{ print $4 }' <<< "${ARTEFACT_URL}")"
case "${ARTEFACT_HOST}" in
    github.com|objects.githubusercontent.com) ;;
    *)
        echo "Manifest artefact URL host '${ARTEFACT_HOST}' is not in the allowlist." >&2
        exit 1
        ;;
esac

echo "Downloading ${ARTEFACT_URL}…"
curl -fsSL -o release.tar.gz "${ARTEFACT_URL}"
got_sha="$(sha256sum release.tar.gz | awk '{print $1}')"
if [[ "${got_sha}" != "${ARTEFACT_SHA256}" ]]; then
    echo "Tarball checksum mismatch: expected ${ARTEFACT_SHA256}, got ${got_sha}" >&2
    exit 1
fi
echo "Tarball SHA-256 matches manifest."

# ── Extract the binary ────────────────────────────────────────────────
mkdir staging
tar -xzf release.tar.gz -C staging
NEW_BIN="$(find staging -maxdepth 3 -name bilbycast-relay -type f | head -1)"
if [[ -z "${NEW_BIN}" || ! -x "${NEW_BIN}" ]]; then
    echo "Tarball did not contain an executable bilbycast-relay binary." >&2
    exit 1
fi

# ── Create system user + group ─────────────────────────────────────────
if ! id -u bilbycast-relay > /dev/null 2>&1; then
    if command -v systemd-sysusers > /dev/null 2>&1; then
        # /etc/sysusers.d/ doesn't exist on minimal Ubuntu / Debian images
        # by default, even when systemd-sysusers is present. Pre-create it.
        mkdir -p /etc/sysusers.d
        cat > /etc/sysusers.d/bilbycast-relay.conf <<'EOF'
u bilbycast-relay - "bilbycast-relay service account" /var/lib/bilbycast/relay /usr/sbin/nologin
EOF
        systemd-sysusers
    else
        useradd --system --home /var/lib/bilbycast/relay --shell /usr/sbin/nologin bilbycast-relay
    fi
fi

# ── Lay out /opt/bilbycast/relay/ + data + config dirs ────────────────
mkdir -p "${INSTALL_ROOT}"
mkdir -p "${DATA_ROOT}"
mkdir -p "${CONFIG_DIR}"

# Atomic binary install via .new + mv -Tf — same pattern upgrade-relay.sh
# uses, so the install path and the upgrade path agree on the layout.
install -m 0755 "${NEW_BIN}" "${BINARY_PATH}.new"
mv -Tf "${BINARY_PATH}.new" "${BINARY_PATH}"

chown -R bilbycast-relay:bilbycast-relay "${INSTALL_ROOT}" "${DATA_ROOT}"

# ── Initial config ────────────────────────────────────────────────────
CONFIG_FILE="${CONFIG_DIR}/relay.json"

if [[ "${UPGRADE_INSTALLER}" -eq 0 || ! -f "${CONFIG_FILE}" ]]; then
    # Build the JSON with jq so optional sections compose cleanly and
    # values get escaped instead of string-concatenated. The relay
    # itself ignores unknown fields and uses defaults for omitted ones.
    JQ_FILTER='{ quic_addr: $quic, api_addr: $api }'
    JQ_ARGS=(--arg quic "${QUIC_ADDR}" --arg api "${API_ADDR}")

    if [[ -n "${API_TOKEN}" ]]; then
        JQ_FILTER+=' + { api_token: $token }'
        JQ_ARGS+=(--arg token "${API_TOKEN}")
    fi
    if [[ "${REQUIRE_BIND_AUTH}" -eq 1 ]]; then
        JQ_FILTER+=' + { require_bind_auth: true }'
    fi
    if [[ -n "${MANAGER_URL}" ]]; then
        JQ_FILTER+=' + { manager: { enabled: true, urls: [$mgr], registration_token: $regtok } }'
        JQ_ARGS+=(--arg mgr "${MANAGER_URL}" --arg regtok "${REGISTRATION_TOKEN}")
    fi

    jq -n "${JQ_ARGS[@]}" "${JQ_FILTER}" > "${CONFIG_FILE}.tmp"
    mv -f "${CONFIG_FILE}.tmp" "${CONFIG_FILE}"
    chown bilbycast-relay:bilbycast-relay "${CONFIG_FILE}"
    # 0640 so root can read but non-service users can't — the file holds
    # the registration token on first boot and the persisted node_secret
    # afterwards.
    chmod 0640 "${CONFIG_FILE}"
fi

# ── Install systemd unit ──────────────────────────────────────────────
UNIT_DEST="${SYSTEMD_UNIT_DIR}/bilbycast-relay.service"
# Prefer the unit shipped inside the tarball; fall back to a curl from
# the release if the tarball didn't include it (older releases).
STAGED_UNIT="$(find staging -maxdepth 4 -name bilbycast-relay.service -type f | head -1)"
if [[ -n "${STAGED_UNIT}" ]]; then
    install -m 0644 "${STAGED_UNIT}" "${UNIT_DEST}"
else
    curl -fsSL -o "${UNIT_DEST}" \
        "https://github.com/${RELEASE_REPO}/releases/latest/download/bilbycast-relay.service"
fi

# Default env file. Only seed it if missing — operators may have customised it.
ENV_FILE="${CONFIG_DIR}/relay.env"
if [[ ! -f "${ENV_FILE}" ]]; then
    cat > "${ENV_FILE}" <<'EOF'
# bilbycast-relay runtime environment.
# Tunable via systemctl restart bilbycast-relay (no daemon-reload needed).
RUST_LOG=bilbycast_relay=info
EOF
    chmod 0640 "${ENV_FILE}"
fi

systemctl daemon-reload
systemctl enable --now bilbycast-relay

# ── Wait for first /health ────────────────────────────────────────────
# /health is always public on the REST API — Bearer-token auth applies
# to every other endpoint but never to /health, so we don't need to
# thread the API token through here.
HEALTH_URL="http://127.0.0.1:${API_ADDR##*:}/health"
echo
echo "Waiting up to 60 s for bilbycast-relay to come up…"
for _ in $(seq 1 30); do
    if systemctl is-active --quiet bilbycast-relay; then
        if curl -fsS --max-time 3 "${HEALTH_URL}" > /dev/null 2>&1; then
            echo "bilbycast-relay is up. /health on ${HEALTH_URL}."
            if [[ -n "${MANAGER_URL}" ]]; then
                echo "Verify in the manager UI under /admin/nodes."
            fi
            echo
            echo "Logs : journalctl -u bilbycast-relay -f"
            echo "Cfg  : ${CONFIG_FILE}"
            echo "Env  : ${ENV_FILE}"
            exit 0
        fi
    fi
    sleep 2
done

echo
echo "bilbycast-relay didn't reach a healthy state in 60 s."
echo "Inspect:"
echo "  journalctl -u bilbycast-relay -e"
echo "  systemctl status bilbycast-relay"
exit 1
