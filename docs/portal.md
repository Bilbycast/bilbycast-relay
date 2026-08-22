# The viewer portal

`bilbycast-portal` is a small web service that runs beside the relay on its
VPS. A viewer signs in through **Authelia**, sees the feeds they are entitled
to, clicks one, and lands in the DVR player with a token that admits them to
that feed and nothing else.

It is the second of two ways into a gated feed. The first is a **link**, issued
per session from the manager and revocable — right for a one-off guest. The
portal is the **login**, right for staff who watch regularly, where issuing and
chasing links is the worse job. Neither replaces the other.

## What it is not

The portal holds no secret and stores no state.

* **It does not sign tokens.** It asks the manager to mint one, and the manager
  re-checks the entitlement before it does. A public-facing VPS holding the key
  that signs every viewer credential would make a compromise there a compromise
  of every feed on every relay.
* **It does not hold entitlements.** It asks the manager on each page load.
  Withdrawing someone's access therefore takes effect on their next click,
  rather than on the next successful push to a box that might be unreachable.
* **It is not the relay.** It is a separate binary and a separate systemd unit,
  under its own user. The relay terminates media for every viewer on the box; a
  bug in a public-facing web page must not be able to take that with it.

## The trust boundary

The portal learns who you are from a header — `Remote-User` by default — that
Authelia sets after it has authenticated you.

**That header is a claim, not a proof.** Anything that can reach the portal
directly can set it and become anyone. Two things stop that, and both fail
closed:

| | |
|---|---|
| `listen_addr` | Defaults to `127.0.0.1:8088`. The proxy on the same host is the only thing that can reach the port. |
| `trusted_proxies` | The addresses whose header is believed. An **empty list means nobody** — the portal refuses to start rather than treating it as "any". |

The peer address is checked *before* the header is read, so a misconfiguration
cannot silently downgrade to trusting everyone. Moving the portal off loopback
is supported (the proxy may legitimately be on another host) but it logs a
warning at startup, because at that point `trusted_proxies` is the only thing
left holding the boundary.

## Building

Not built by default — `cargo build` produces the relay alone, with no HTTP
client linked in.

```bash
cargo build --release --features portal      # -> target/release/bilbycast-portal
```

The `portal` feature is independent of `viewer-distribution`: the portal hands
out links to a relay, which need not be the one it sits beside, and building it
pulls in neither str0m nor OpenSSL.

## Installing

**There is no signed-release path for the portal yet.** `install-relay.sh` and
`upgrade-relay.sh` install from a cosign-verified release manifest, and that
manifest carries no portal artefact — adding one is release-pipeline work.
Until it exists, deploy by hand:

```bash
cargo build --release --features portal

sudo install -D -m0644 packaging/bilbycast-portal.sysusers /etc/sysusers.d/bilbycast-portal.conf
sudo systemd-sysusers

sudo install -D -m0755 target/release/bilbycast-portal /opt/bilbycast/portal/bilbycast-portal
sudo install -d -o bilbycast-portal -g bilbycast-portal /var/lib/bilbycast/portal
sudo install -D -m0644 portal-config.example.json /etc/bilbycast/portal.json
sudo install -D -m0644 packaging/bilbycast-portal.service /etc/systemd/system/bilbycast-portal.service

# The service token, from the manager (see below).
sudo install -D -m0600 /dev/null /etc/bilbycast/portal.env
sudo chgrp bilbycast-portal /etc/bilbycast/portal.env
echo 'BILBYCAST_PORTAL_TOKEN=...' | sudo tee /etc/bilbycast/portal.env >/dev/null

sudo systemctl daemon-reload && sudo systemctl enable --now bilbycast-portal
```

Edit `/etc/bilbycast/portal.json` to point at the manager before starting: the
service refuses to start without a `manager_url` and a token, which is
deliberate — a portal that came up misconfigured would fail every viewer with a
message that reads like their account being wrong.

## Configuring

Start from `portal-config.example.json`, installed at `/etc/bilbycast/portal.json`:

```json
{
  "listen_addr": "127.0.0.1:8088",
  "manager_url": "https://manager.example.com",
  "username_header": "Remote-User",
  "trusted_proxies": ["127.0.0.1", "::1"]
}
```

The service token goes in the environment, not the file — the file is what gets
copied between hosts while someone is debugging:

```
# /etc/bilbycast/portal.env   (0600 root:bilbycast-portal)
BILBYCAST_PORTAL_TOKEN=<the value the manager generated>
```

Generate that value in the manager: **DVR Sessions → Portal logins → Generate a
token** (super admin only — the token is not group-scoped, so its holder can
ask about any username in any group). It is shown once. Rotating it stops the
portal working until the new value is deployed, and the symptom on the viewer's
side is an empty feed list rather than an error, so do it deliberately.

If no token is configured in the manager, the manager refuses every portal
request. That is the intended failure: a manager that has never been set up for
a portal must not answer entitlement questions for whoever asks.

## Putting Authelia in front

Any forward-auth proxy works; the portal only needs the username header. With
Caddy:

```caddyfile
portal.example.com {
    forward_auth authelia:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
    }
    reverse_proxy 127.0.0.1:8088
}
```

Two things to get right:

1. **The proxy must strip `Remote-User` from the inbound request** before
   setting its own. A client that supplies one and has it passed through is a
   client that picked its own identity. Authelia's forward-auth response
   replaces it; make sure nothing in front re-adds it.
2. **Nothing but the proxy may reach `127.0.0.1:8088`.** On a shared host that
   means the loopback default, not a bind on the LAN address.

## Who may watch what

Entitlements live in the manager, against the **Authelia username**, spelled
exactly as Authelia spells it — `A.Smith` and `a.smith` are two different
people, because they are two different identities to the identity provider.

Administer them from the manager: **DVR Sessions → Portal logins**. Add a
username, then tick the feeds it may watch. The tick list is a *replace*: what
is on screen when you press save is what is true afterwards.

Two consequences worth stating plainly, because neither is visible from the
manager's own UI:

* The manager cannot verify a username. Adding one grants access to whoever
  Authelia later decides that name belongs to. **A username reused for a
  different person inherits the previous holder's entitlements**, and deleting a
  leaver in Authelia does not delete their rows here.
* Only sessions that are **on air** appear in the portal. A feed that is not
  running is simply absent, rather than offering a link to a black screen.

## Access lasts three hours

A token minted through the portal is good for three hours, after which the
player stops with "your viewing access has expired". The viewer returns to the
portal and opens the feed again; if their entitlement has been withdrawn in the
meantime, it is not there to open.

Removing a portal login stops them getting *new* tokens immediately. A token
already in a browser keeps working until it expires — the relay verifies a
signature and an expiry, and holds no per-viewer state to revoke. Three hours is
the outer bound on how long a withdrawal takes to bite.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | The page. |
| `GET /portal.js` | Its script — a separate route so the page can carry `script-src 'self'`. |
| `GET /api/feeds` | What the signed-in user may watch. |
| `POST /api/watch` | Mint a link for one feed. The body names the *session*; the username comes from the header and can never be supplied by the browser. |
| `GET /healthz` | Liveness. Deliberately needs no user — a health check that required one would be reporting on the proxy. |
