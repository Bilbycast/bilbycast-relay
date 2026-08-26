#!/usr/bin/env bash
# Exercise the portal blocks of install-relay.sh and upgrade-relay.sh against a
# staged tarball, without touching the machine.
#
# The scripts are 400+ lines of download-and-verify that cannot run outside a
# release, so this extracts the portal blocks' *decisions* and runs them: does
# it find the binary, refuse the lean tarball, write the config only when
# absent, detect an installed portal, and leave the relay alone when there
# isn't one. Shell that only ever gets run for real is shell nobody has tested.
set -uo pipefail
cd "$(dirname "$0")"

PASS=0; FAIL=0
ok()   { printf "  ok    %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  FAIL  %s\n" "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', wanted '$3')"; fi; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ── build two tarballs the way the release workflow stages them ───────────
mk_tarball() {  # $1 = dir name, $2 = with-portal (1/0)
  local stage="$WORK/$1/bilbycast-relay-0.10.6-x86_64-linux"
  mkdir -p "$stage/packaging"
  printf '#!/bin/sh\necho relay\n' > "$stage/bilbycast-relay"; chmod +x "$stage/bilbycast-relay"
  cp ../bilbycast-relay.service "$stage/packaging/" 2>/dev/null || touch "$stage/packaging/bilbycast-relay.service"
  if [ "$2" = "1" ]; then
    printf '#!/bin/sh\necho portal\n' > "$stage/bilbycast-portal"; chmod +x "$stage/bilbycast-portal"
    cp ../bilbycast-portal.service "$stage/packaging/" 2>/dev/null || touch "$stage/packaging/bilbycast-portal.service"
    touch "$stage/portal-config.example.json"
  fi
  (cd "$WORK/$1" && tar czf ../"$1".tar.gz .)
}
mk_tarball dist 1
mk_tarball lean 0

echo "== the distribution tarball carries a portal, the lean one does not =="
for v in dist lean; do
  rm -rf "$WORK/s-$v"; mkdir -p "$WORK/s-$v"
  tar -xzf "$WORK/$v.tar.gz" -C "$WORK/s-$v"
done
check "distribution: portal binary found" \
  "$(find "$WORK/s-dist" -maxdepth 3 -name bilbycast-portal -type f | wc -l)" "1"
check "distribution: portal unit found" \
  "$(find "$WORK/s-dist" -maxdepth 4 -name bilbycast-portal.service -type f | wc -l)" "1"
check "lean: no portal binary (installer must refuse --with-portal)" \
  "$(find "$WORK/s-lean" -maxdepth 3 -name bilbycast-portal -type f | wc -l)" "0"
check "lean: relay binary still found (the default path is untouched)" \
  "$(find "$WORK/s-lean" -maxdepth 3 -name bilbycast-relay -type f | wc -l)" "1"

echo
echo "== --with-portal argument validation =="
probe() {  # run just the flag parsing + validation out of the installer
  WITH_PORTAL=1 PORTAL_MANAGER_URL="$1" bash -c '
    if [[ "${WITH_PORTAL}" -eq 1 ]]; then
        if [[ -z "${PORTAL_MANAGER_URL}" ]]; then echo reject-empty; exit 1; fi
        case "${PORTAL_MANAGER_URL}" in
            http://*|https://*) echo accept;;
            *) echo reject-scheme; exit 1;;
        esac
    fi' 2>/dev/null
}
check "https accepted"            "$(probe https://m.example)" "accept"
check "http accepted"             "$(probe http://m.example)"  "accept"
check "scheme-less refused"       "$(probe m.example)"         "reject-scheme"
check "empty refused"             "$(probe '')"                "reject-empty"

echo
echo "== config is written only when absent (an upgrade must not clobber) =="
CFG="$WORK/portal.json"
write_if_absent() {
  if [[ ! -f "$CFG" ]]; then printf '{"manager_url":"%s"}\n' "$1" > "$CFG"; fi
}
write_if_absent https://first.example
write_if_absent https://second.example
check "first write lands"         "$(python3 -c "import json;print(json.load(open('$CFG'))['manager_url'])")" "https://first.example"

echo
echo "== upgrade: detect an installed portal from its unit =="
detect() {  # $1 = fake `systemctl cat` output
  awk -F= '/^ExecStart=/ { sub(/^ExecStart=/, "", $0); print $0; exit }' <<< "$1" | awk '{ print $1 }'
}
check "binary path parsed from ExecStart" \
  "$(detect 'ExecStart=/opt/bilbycast/portal/bilbycast-portal --config /etc/bilbycast/portal.json')" \
  "/opt/bilbycast/portal/bilbycast-portal"
check "no unit -> nothing to upgrade" "$(detect '')" ""

echo
echo
echo "== --player-origin decides whether a viewing token can ever renew =="
# Run the real installer far enough to hit argument validation. Anything that
# reaches the download is "accepted" as far as this check is concerned.
porigin() {
  out=$(bash ./install-relay.sh --manager wss://m/ws --registration-token t \
        --with-portal https://m.example --player-origin "$1" 2>&1 >/dev/null </dev/null || true)
  case "$out" in
    *"must start with http"*) echo "reject-scheme";;
    *"has a path"*)           echo "reject-path";;
    *)                        echo "accept";;
  esac
}
check "player-origin scheme-less refused" "$(porigin relay.example)"               "reject-scheme"
check "player-origin with a path refused" "$(porigin https://relay.example/watch)" "reject-path"
check "player-origin https accepted"      "$(porigin https://relay.example)"       "accept"

# Absent, it must fail closed AND say so — an unrenewable token is a silent
# failure three hours later, not an error at install time.
warned=$(bash ./install-relay.sh --manager wss://m/ws --registration-token t \
         --with-portal https://m.example 2>&1 >/dev/null </dev/null || true)
case "$warned" in
  *"will not renew"*) ok "no player-origin warns that tokens will not renew";;
  *) bad "no player-origin is silent about renewal being off";;
esac

# And the config it writes must be valid JSON either way.
cfgjson() {  # $1 = what the installer substitutes
  python3 - "$1" <<'PY'
import json, sys
tpl = '{ "listen_addr": "127.0.0.1:8088", "manager_url": "https://m.example",' \
      ' "username_header": "Remote-User", "trusted_proxies": ["127.0.0.1", "::1"],' \
      ' "player_origins": [%s] }'
try:
    print(",".join(json.loads(tpl % sys.argv[1])["player_origins"]) or "empty")
except Exception:
    print("INVALID-JSON")
PY
}
check "config with an origin is valid"  "$(cfgjson '"https://relay.example"')" "https://relay.example"
check "config without one is valid"     "$(cfgjson '')"                        "empty"

echo "-- $PASS passed, $FAIL failed --"
[ "$FAIL" -eq 0 ]
