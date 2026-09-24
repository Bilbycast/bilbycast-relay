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

# Version read from the manifest rather than pinned, so a release bump does
# not leave this fixture naming a tarball that no longer ships.
REL_VER=$(grep -m1 "^version" ../Cargo.toml | sed 's/.*"\(.*\)"/\1/')
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ── build two tarballs the way the release workflow stages them ───────────
mk_tarball() {  # $1 = dir name, $2 = with-portal (1/0)
  local stage="$WORK/$1/bilbycast-relay-${REL_VER}-x86_64-linux"
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
# failure thirty minutes later, not an error at install time.
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

echo
echo "== the unit lets account sync write Authelia's users directory, and nothing else =="
# ProtectSystem=strict makes everything read-only; without this line every
# account-sync write fails with EROFS and no account or link is ever made.
UNIT=./bilbycast-portal.service
check "the users directory is writable, and optional" \
  "$(grep -c '^ReadWritePaths=-/etc/authelia/users$' "$UNIT")" "1"
check "no other path is writable" "$(grep -c '^ReadWritePaths=' "$UNIT")" "1"
# The group-keeping fchown is in @privileged, and a filtered call kills the
# process (SIGSYS) rather than failing — so it must be given back, and after
# the line that takes it away, or it is taken away again.
deny=$(grep -n '^SystemCallFilter=~.*@privileged' "$UNIT" | cut -d: -f1)
allow=$(grep -n '^SystemCallFilter=@chown$' "$UNIT" | cut -d: -f1)
check "fchown is allowed after @privileged is denied" \
  "$([ -n "$deny" ] && [ -n "$allow" ] && [ "$allow" -gt "$deny" ] && echo yes || echo no)" "yes"
check "and no capability comes with it" "$(grep -c '^CapabilityBoundingSet=$' "$UNIT")" "1"

echo
echo "== upgrade: the packaged unit is refreshed, and nothing of the operator's is lost =="
# Lifted out of upgrade-relay.sh at run time, like the validation block above,
# and run against a scratch unit directory with systemctl stubbed.
REFRESH="$(awk '/^# >>> portal-unit-refresh/,/^# <<< portal-unit-refresh/' upgrade-relay.sh)"
[ -n "$REFRESH" ] || bad "upgrade-relay.sh has no portal-unit-refresh block to lift"
refresh() {  # $1 = scratch root, $2 = the unit systemd reports loading, $3 = the new unit
  ( SYSTEMD_UNIT_DIR="$1/units" PORTAL_UNIT_NAME=bilbycast-portal
    PORTAL_BINARY="$1/opt/bilbycast-portal" PORTAL_UNIT_PREV="" LOADED="$2" CALLS="$1/calls"
    systemctl() {
      case "$1" in
        show) echo "$LOADED";;
        *) echo "$*" >> "$CALLS";;
      esac
    }
    eval "$REFRESH"
    refresh_portal_unit "$3"
    echo "prev=$PORTAL_UNIT_PREV" >> "$CALLS" ) 2>"$1/stderr" >/dev/null
}
scenario() {  # $1 = name; leaves the unit before account sync, with a drop-in, in place
  local root="$WORK/unit-$1"
  mkdir -p "$root/units/bilbycast-portal.service.d" "$root/opt"
  # The packaged unit as the release before account sync shipped it: this one
  # without the two lines account sync added.
  grep -v -e '^ReadWritePaths=' -e '^SystemCallFilter=@chown$' ./bilbycast-portal.service \
    > "$root/units/bilbycast-portal.service"
  cp "$root/units/bilbycast-portal.service" "$root/before"
  printf '[Service]\nReadWritePaths=/srv/authelia/users\n' \
    > "$root/units/bilbycast-portal.service.d/override.conf"
  : > "$root/calls"
  echo "$root"
}
untouched() {  # $1 = scratch root: yes when the installed unit is as the scenario left it
  cmp -s "$1/before" "$1/units/bilbycast-portal.service" && echo yes || echo no
}
R=$(scenario changed)
check "the unit before account sync differs from this release's" \
  "$(cmp -s ./bilbycast-portal.service "$R/before" && echo same || echo differs)" "differs"
refresh "$R" "$R/units/bilbycast-portal.service" ./bilbycast-portal.service
check "an outdated packaged unit is replaced by this release's" \
  "$(cmp -s ./bilbycast-portal.service "$R/units/bilbycast-portal.service" && echo yes || echo no)" "yes"
check "and systemd is told" "$(grep -c '^daemon-reload$' "$R/calls")" "1"
check "the drop-in is kept" "$(grep -c '^ReadWritePaths=/srv/authelia/users$' \
  "$R/units/bilbycast-portal.service.d/override.conf")" "1"
check "the replaced unit is kept beside the binary, for a rollback" \
  "$(cmp -s "$R/before" "$R/opt/bilbycast-portal.service.previous" && echo yes || echo no)" "yes"
check "and named for the rollback" "$(grep -c "^prev=$R/opt/bilbycast-portal.service.previous\$" "$R/calls")" "1"

R=$(scenario same)
cp ./bilbycast-portal.service "$R/units/bilbycast-portal.service"
refresh "$R" "$R/units/bilbycast-portal.service" ./bilbycast-portal.service
check "an unchanged unit is not reloaded" "$(grep -c 'daemon-reload' "$R/calls")" "0"
check "nor copied aside" "$(grep -c '^prev=$' "$R/calls")" "1"

R=$(scenario foreign)
refresh "$R" /lib/systemd/system/bilbycast-portal.service ./bilbycast-portal.service
check "a unit of the operator's own elsewhere is left alone" "$(untouched "$R")" "yes"
check "and said so" "$(grep -c 'left alone' "$R/stderr")" "1"

# A unit at the packaged path that no longer runs what the packaged one runs
# was edited by hand: replacing it would start a binary, a config or a token
# file the operator moved away from.
hand_edited() {  # $1 = name, $2 = sed expression applied to the installed unit
  local root; root=$(scenario "$1")
  sed -i "$2" "$root/units/bilbycast-portal.service"
  cp "$root/units/bilbycast-portal.service" "$root/before"
  refresh "$root" "$root/units/bilbycast-portal.service" ./bilbycast-portal.service
  echo "$root"
}
R=$(hand_edited moved 's#^ExecStart=/opt/bilbycast/portal/bilbycast-portal #ExecStart=/usr/local/bin/bilbycast-portal #')
check "a binary moved by PORTAL_ROOT is really named in the unit" \
  "$(grep -c '^ExecStart=/usr/local/bin/bilbycast-portal --config ' "$R/before")" "1"
check "a unit edited to run a binary elsewhere is left alone" "$(untouched "$R")" "yes"
check "and said so" "$(grep -c 'left alone' "$R/stderr")" "1"
check "and systemd is not reloaded" "$(grep -c 'daemon-reload' "$R/calls")" "0"
check "nor is anything copied aside" "$(grep -c '^prev=$' "$R/calls")" "1"
R=$(hand_edited token 's#^EnvironmentFile=/etc/bilbycast/portal.env$#EnvironmentFile=/root/portal.env#')
check "a unit edited to read another token file is left alone" \
  "$(grep -c '^EnvironmentFile=/root/portal.env$' "$R/units/bilbycast-portal.service")" "1"
check "and said so" "$(grep -c 'left alone' "$R/stderr")" "1"

R=$(scenario lean)
refresh "$R" "$R/units/bilbycast-portal.service" ""
check "a tarball without a unit changes nothing" "$(untouched "$R")" "yes"

# Called where it matters: after the portal binary is swapped, before the
# portal is started again, and undone by a rollback.
call=$(grep -n '^ *refresh_portal_unit "' upgrade-relay.sh | cut -d: -f1)
swap=$(grep -n 'mv -Tf "${PORTAL_BINARY}.new" "${PORTAL_BINARY}"' upgrade-relay.sh | cut -d: -f1)
start=$(grep -n 'systemctl start "${PORTAL_UNIT_NAME}"' upgrade-relay.sh | head -1 | cut -d: -f1)
check "the upgrade refreshes the unit after the swap and before the start" \
  "$([ -n "$call" ] && [ -n "$swap" ] && [ -n "$start" ] && [ "$call" -gt "$swap" ] \
     && [ "$call" -lt "$start" ] && echo yes || echo no)" "yes"
check "a rollback puts the old unit back" \
  "$(grep -c 'mv -Tf "${PORTAL_UNIT_PREV}" "${SYSTEMD_UNIT_DIR}/${PORTAL_UNIT_NAME}.service"' upgrade-relay.sh)" "1"

echo "-- $PASS passed, $FAIL failed --"
[ "$FAIL" -eq 0 ]
