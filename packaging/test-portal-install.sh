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
  cp ./bilbycast-relay.service "$stage/packaging/"
  if [ "$2" = "1" ]; then
    printf '#!/bin/sh\necho portal\n' > "$stage/bilbycast-portal"; chmod +x "$stage/bilbycast-portal"
    cp ./bilbycast-portal.service "$stage/packaging/"
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
# The validation block is lifted OUT OF install-relay.sh at run time, not
# transcribed here. A copy would keep passing after the installer changed,
# which is the failure mode a packaging test exists to prevent.
VALIDATION="$(awk '/^# >>> portal-url-validation/,/^# <<< portal-url-validation/' install-relay.sh)"
[ -n "$VALIDATION" ] || { bad "install-relay.sh has no portal-url-validation block to lift"; }

probe() {  # run the installer's OWN validation, extracted above
  # The block prints its verdict on stderr and exits non-zero on a refusal, so
  # the trailing `echo accept` is reached only when it lets the URL through.
  WITH_PORTAL=1 PORTAL_MANAGER_URL="$1" bash -c "
    ${VALIDATION}
    echo accept" 2>&1 | head -1
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
echo "-- $PASS passed, $FAIL failed --"
[ "$FAIL" -eq 0 ]
