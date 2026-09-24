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

The portal holds no signing key and keeps no state of its own. (The optional
[account sync](#accounts-and-password-links) does write Authelia's user file,
and the optional [`mail`](#rewriting-authelias-email-mail) block gives it an
SMTP relay key — both described below.)

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

The portal ships **inside the distribution relay's release tarball** —
`bilbycast-relay-<arch>-linux-distribution.tar.gz`, the same signed artefact
`install-relay.sh` verifies. A distribution relay is the box the portal runs
beside, so they travel together; they still run as two processes under two
users.

```bash
curl -fsSL https://github.com/Bilbycast/bilbycast-relay/releases/latest/download/install-relay.sh \
  | sudo bash -s -- \
      --manager wss://manager.example.com/ws/node \
      --registration-token <token-from-the-manager-UI> \
      --with-portal https://manager.example.com
```

`--with-portal` takes the manager's **base URL** (not the WebSocket one) — the
portal talks to its REST API. It creates the `bilbycast-portal` user, installs
the binary at `/opt/bilbycast/portal/`, writes `/etc/bilbycast/portal.json` and
an empty `/etc/bilbycast/portal.env`, and installs the unit.

It does **not start the portal.** It cannot: the portal needs a service token
that only exists once you generate it in the manager, and one started without a
token does not start at all — it exits before binding its listener with
``portal config: no manager token: set BILBYCAST_PORTAL_TOKEN or `manager_token` in the config file``,
and under the unit's `Restart=always` that is a crash loop (ten attempts, three
seconds apart) until systemd's start limit trips. Generate the token (below), put
it in `portal.env`, then:

```bash
sudo systemctl enable --now bilbycast-portal
```

Passing `--with-portal` against the lean forwarder tarball is refused with a
message saying so, rather than installing a relay and quietly skipping the half
you asked for.

### Upgrading

`upgrade-relay.sh` carries the portal along automatically when the host has one
— no flag. An operator upgrading a relay is not choosing to leave its portal on
an older binary, and skew between the two is the kind nobody goes looking for.

The portal is swapped while the relay is down, then started again **only after
the relay's health probe passes**, so it never comes up beside a relay that is
about to be rolled back — and only if it was running before. If the relay fails
its probe both roll back together, unit file included. If the relay is fine but
the portal will not start, the portal is left stopped and the failure is
printed: it is not the data plane, and viewers unable to sign in is a smaller
failure than putting the relay back a version to rescue them.

Upgrading a relay with a *lean* tarball on a host that runs a portal warns and
leaves the portal alone rather than deleting it.

The script replaces the portal's **binary**, and its **unit file** when the
release's differs from the one `install-relay.sh` put at
`/etc/systemd/system/bilbycast-portal.service` — then runs
`systemctl daemon-reload`. A release can need something new from systemd (this
one does: a writable users directory and `SystemCallFilter=@chown`), and a new
binary under an old unit would fail where the new unit would not. Your own
changes belong in a drop-in (`systemctl edit bilbycast-portal`), which lives in
`bilbycast-portal.service.d/` and is kept; an edit to the unit file itself is
replaced, and the replaced file is kept at
`/opt/bilbycast/portal/bilbycast-portal.service.previous` (beside the binary).

The unit file is replaced only while it still runs what the packaged one runs:
the same `ExecStart=`, `User=`, `Group=`, `WorkingDirectory=` and
`EnvironmentFile=` lines, which no release has changed. One where any of those
was edited — a portal installed with `PORTAL_ROOT`, whose `ExecStart=` was
changed to name the binary there, or one given another config or token file —
would start something else under the packaged unit, so it is left alone, like a
portal running from a unit anywhere else, with a warning that names what this
release's unit needs. Its binary is still upgraded: the script finds it from
the unit file's own `ExecStart=`, not a drop-in's, which is why a moved binary
is named in the unit file itself.

It leaves `portal.json` and Authelia as they are, so a change that needs either
is yours to make first. A portal that already runs account sync or `mail` needs
exactly that for this release — see
[Upgrading a portal that already runs account sync or mail](#upgrading-a-portal-that-already-runs-account-sync-or-mail).

## Configuring

Start from `portal-config.example.json`, installed at `/etc/bilbycast/portal.json`:

```json
{
  "listen_addr": "127.0.0.1:8088",
  "manager_url": "https://manager.example.com",
  "username_header": "Remote-User",
  "logout_url": "https://auth.example.com/logout",
  "trusted_proxies": ["127.0.0.1", "::1"],
  "player_origins": ["https://relay.example.com"]
}
```

`player_origins` is the one that bites if you drop it. It defaults to an empty
list, which is accepted at startup and means *nobody may renew* — viewers lose
access thirty minutes in with nothing logged at either end — and nobody is counted
as watching, because the player's `POST /api/beat` is refused the same way. See
[renewal](#renewing-without-signing-in-again) below.

A `manager_url` on plain `http://` is refused at startup unless
`BILBYCAST_ALLOW_INSECURE=1` is set: the portal sends its manager token on every
request to that URL, so plaintext hands out its service identity. One carrying
a `user:password@` is refused either way. It never worked, since the manager
reads the Basic credential it becomes instead of the portal's token, and the
URL is printed in the startup log.

The portal follows no redirects, from the manager, from Authelia or from a
relay's origin. A `3xx` is handled as that service refusing; from the manager
it reaches the log as, for instance, `portal: manager refused the stream list
status=308 Permanent Redirect`. So point `manager_url` at where the manager
actually answers, not at an address that forwards to it. Following a redirect
would re-send the request, body and all (usernames, a viewer's address),
wherever `Location` pointed, to another host or over plain `http://`.

The binary takes `--config <path>` (default `portal-config.json`, which is why
the packaged unit passes `--config /etc/bilbycast/portal.json`) and `--listen
<addr>` to override `listen_addr` without editing the file.

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
side is a red "Cannot reach the manager right now" banner where the feed list
should be — the manager answers 401 and the portal reports that as the manager
being unreachable, not as a credential problem — so do it deliberately.

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

That is an Authelia served at the root. One served under a path prefix
(`server.address: 'tcp://127.0.0.1:9091/auth'`) takes the prefix in every path
the proxy calls — `uri /auth/api/authz/forward-auth` — and, with
[account sync](#accounts-and-password-links), in `accounts.authelia_url` too.

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
  leaver in Authelia does not delete their rows here. (With
  [account sync](#accounts-and-password-links) on, the opposite direction does
  work: removing a username's last portal login in the manager removes the
  Authelia account the portal created for it, at the portal's next sync.)
* Only sessions that are **on air** appear in the portal. A feed that is not
  running is simply absent, rather than offering a link to a black screen.

## Accounts and password links

Optional. With an `accounts` block in the config, the portal also **creates the
Authelia accounts** for portal logins that have an email in the manager,
**removes** them when the manager deletes the login, and sends the
**set-your-password** link an operator asks for. Without the block nothing here
happens and every account is managed in Authelia by hand, as before. The
manager must be one that serves `GET /api/v1/dvr/portal/accounts`; one without
the route answers 404, and the portal logs that the sync is failing.

```json
"accounts": {
  "users_file": "/etc/authelia/users/users.yml",
  "public_host": "watch.example.com",
  "authelia_url": "http://127.0.0.1:9091/auth",
  "managed_group": "bilbycast-portal",
  "interval_secs": 15
}
```

| Key | Default | |
|---|---|---|
| `users_file` | required | Authelia's `authentication_backend.file.path`. The file must exist before the portal starts syncing; an empty file is read as no accounts. |
| `public_host` | required | The host the emailed link names, as a bare host name — no scheme, no `/`, no spaces. See [below](#the-link-names-public_host). |
| `authelia_url` | `http://127.0.0.1:9091/auth` | Authelia itself, reached directly rather than through the public proxy. See [below](#authelia_url-and-its-path). |
| `managed_group` | `bilbycast-portal` | The Authelia group that marks an account as the portal's. Cannot be empty. See [below](#managed_group-belongs-to-the-portal-alone). |
| `interval_secs` | `15` | Seconds between syncs, 5 to 3600. |

Every `interval_secs` the portal asks the manager for
`GET /api/v1/dvr/portal/accounts?interval_secs=<interval_secs>` — one row per
username, with its email, display name, any outstanding link request and
whether a link has ever been sent to it without error, plus `removed`: each
username whose last login has been deleted, with when (`removed_at`), kept by
the manager until the portal says it has applied it. The interval rides along
on every poll so the manager can tell a portal that asks slowly from one that
has stopped asking; its Portal logins panel says which. When the previous cycle
could not read or write Authelia's user file, the poll also carries
`&sync_error=<why>` — one line, at most 300 bytes — and the manager shows it in
the Portal logins panel; a poll after a cycle that wrote, had nothing to write,
or lost only a race with Authelia's own write carries none. The portal then
reads Authelia's user file, works out what to change, writes the file if
anything did, tells the manager which removals it has applied on
`POST /api/v1/dvr/portal/accounts/removed-applied`, asks Authelia for the links
that are due, and tells the manager how each one went on
`POST /api/v1/dvr/portal/accounts/link-sent`.

### What a sync does to Authelia's file

* **A login with a usable email and no account of that name** gets one:
  `disabled: false`, `displayname` (the manager's display name, or the username
  when there is none), `email`, `groups: [<managed_group>]`, and a `password`
  that is an argon2id hash of 32 random bytes nobody ever sees — so it cannot be
  signed in to until its owner sets a password through the emailed link. The
  hash uses argon2's minimum cost parameters (`m=8,t=1,p=1`), because it guards
  256 random bits rather than a guessable password.
* **An account carrying `managed_group`** follows the manager: its `email` and
  `displayname` are rewritten when the manager's differ. Its `password`,
  `disabled` and any other groups you give it are left as they are — unless the
  username changed hands (below). An empty display name from the manager leaves
  the file's display name alone, and a `null` email leaves the file's email
  alone.
* **A hand-made account** — any entry without `managed_group`, including one
  with the same name as a manager login — is **never rewritten or removed**. A
  link asked for one is answered with a reason instead of being sent (see
  [what the manager shows](#what-the-manager-shows)), and the log says once:
  ``… is a hand-made Authelia account; its portal login's email, name and links
  are not applied to it``. That is how a hand-made `dvr-test` survives. An entry
  whose key YAML reads as something other than text — an unquoted `12345:` — is
  never the portal's, whatever its groups say.
* **A username the manager removed and gave out again** — in `removed` and in
  `accounts` at once — is a different person under the same name. Its managed
  account is **replaced**: dropped and created afresh like a new login's, in the
  same write, so no password the last holder chose survives. See
  [When an account is removed](#when-an-account-is-removed).

A login with no email, or one that is not a plausible address, simply gets no
account. Three kinds of login are held back as well, each logged once as
``portal login `<name>` was not written to Authelia: <reason>``:

* one whose email another account already has, as its email or as its username,
  compared case-insensitively — no account is made, and a managed account's
  email is not changed to it;
* one whose username another account already has in another case, or has as its
  email — no account is made;
* `<<`, which Authelia's parser reads as a YAML merge key — no account is made.
  Any other username is written as a quoted key where YAML would read it as
  something else (`'12345':`, `'true':`, `'@bob':`), so a staff or membership
  number is a username like any other. A username whose written key would not
  read back as the same text is held back too. Existing accounts are never
  judged by this rule.

Those rules exist because, with `search.email` on (which
[account sync requires](#what-authelia-needs)), Authelia refuses the whole file
when two accounts share an email or one account's email is another's username,
hand-made accounts included — and a refused file locks everyone out the next
time Authelia starts. The manager enforces the same uniqueness for new logins;
this is the check for what is already in the file.

The check is made against **the file as this cycle's write will leave it**, not
as it was, so an address one managed account is moving off can go to another
login in the same write, and two accounts can swap addresses, or three pass
them round, without Authelia ever loading a file in between. It is settled by
repetition: a login that would collide with what an untouched entry holds is
held back first, then, between two logins wanting one address, the later in
the manager's (username) order; a held-back move leaves its account on its old
address, which can hold back another login in turn. A login that lost to one
held back later in the same settling, and so has nothing left in its way, is
then written after all.

Every login held back is **refused** — its link request answered with the
reason — because something holds what it wanted in the file as written: a
hand-made account, a username, a login going ahead, or a managed account whose
own move was held back. Such an account stays on its old address for as long as
whatever blocked it does, so the way does not clear by itself: change the
logins in the manager, or the hand-made account in the file, and press **Send
password link** again. For example, pointing a login at an address a hand-made
account has, and giving its old address to a new login, refuses both.

### When an account is removed

**Only when the manager says the login is gone**: the username is in the
answer's `removed` list. The manager records that on its own, by trigger,
whenever the last login for a username is deleted by any path — a delete, a
group removal — and keeps the record until the portal acknowledges it, even
when the username is added again in the meantime. Being missing from `accounts`
is not enough: a database restored from an older backup is missing everything
created since, and deleting an account takes the password its owner chose with
it.

For each record the portal does one of three things:

* **The username is not in `accounts`**: the managed account is removed.
* **The username is in `accounts` again** — deleted and re-added, in this group
  or another, before the portal applied the removal: the managed account is
  **replaced**, dropped and made afresh with a new unusable password and the
  current email and display name, in one write. The last holder's password no
  longer works, however quickly the username was given out again; the new
  holder sets their own through the invitation, which goes out on a later cycle
  like any new account's. A session the last holder already has open is
  another matter (below).
* **There is no managed account of that name** — none at all, or a hand-made
  one: nothing is written.

**A replacement does not sign the last holder out.** Authelia ends a signed-in
session when its user has gone from the file or been disabled — and only when
that session next makes a request after its profile refresh
(`authentication_backend.refresh_interval`) finds it so. An account made afresh
under the same username is neither gone nor disabled, and a session left idle
through a plain removal is never checked while the account is gone, so it is
honoured again if the username is given out later. So a session the last holder
opened before the replacement keeps reaching the portal as that username until
it expires — up to a month with Authelia's default remember-me — and is served
the new holder's feeds. The portal cannot reach Authelia's sessions, so each
time it removes an account it logs the remedy at info level, and each time it
makes a replaced account afresh it logs at warning level ``replaced the Authelia account
`<name>` for the login's new holder; …`` with the remedy: clear Authelia's
sessions — restart Authelia when it keeps them in memory (its default, without
`session.redis`), or delete them from its Redis. Either signs every viewer out.
Where you can, give a new person a username nobody has had instead.

The portal tells the manager it has applied a record on
`POST /api/v1/dvr/portal/accounts/removed-applied` with its `username` and
`removed_at`, echoed verbatim, and the manager then forgets it, unless a newer
removal of the same username has replaced it meanwhile. It says so **only once
a later read of the file still shows the record applied** — no managed entry of
that name after a removal, none still holding the password the write dropped
after a replacement — or at once when there was nothing to write. A landed
write is not Authelia having loaded it: Authelia rewrites the whole file from
what it has loaded whenever anyone sets a password, so a password set in the
moment before it reloads puts the removed or replaced entry back, password and
all. The next cycle's read finds that, logs ``Authelia wrote back an account the
portal had removed or replaced …``, and applies the record again. A write-back
after that read is not caught; nor, for a replacement, whose check is the
password, is an entry written back after its last holder changed that password
in the same moment. A write that fails, or loses its race with Authelia, is
tried again next cycle. The portal remembers each record it has applied for as
long as it runs, so an acknowledgement that fails is retried every cycle
**without replacing the account again** — its new holder may have set a
password by then. That memory does not survive a restart: a portal restarted
between replacing an account and getting the acknowledgement through replaces
it once more, and the new holder sets their password again. The manager prunes
a record nobody acknowledges after 90 days, so a portal that does not poll for
that long never removes that account; remove it by hand.

A manager that sends `removed` but has no `removed-applied` route answers the
acknowledgement 404. The portal logs that once — ``the manager has no route to
acknowledge a removal on, so it is older than this portal; its removal records
stay until it is upgraded, and none is applied twice meanwhile`` — and carries
on; any other failure is logged once as ``could not tell the manager a removal
was applied (…); retrying without applying it again``.

**Against an older manager**, one whose answer has no `removed` key at all, the
portal falls back to the earlier rule: a managed account is removed when its
username is no longer in `accounts` — **except when `accounts` is empty**, which
removes nobody and logs ``the manager reports no portal logins at all; leaving N
Authelia account(s) alone rather than deleting every one. Remove them by hand if
that is really what was wanted.`` Under that rule the account behind the very
last login is never removed, and a login deleted and added again within one
`interval_secs` keeps its account and password. A `removed` entry without a
`username` or a `removed_at` fails the whole poll rather than being guessed at.

### Password links

An operator presses **Send password link** on a login in the manager. The
manager lists the request until the portal acknowledges it, for at most 24
hours; after that it withdraws the request and shows it as expired.

The portal asks Authelia for the link only when all of this holds:

* **The account is one the portal manages.** A hand-made account's request is
  answered with a reason.
* **Its entry already holds the manager's email when the cycle begins.**
  Authelia's reset endpoint answers OK for any username, known or not, and mails
  whatever address it has loaded. So an account created this cycle, or whose
  email this cycle rewrites, waits for the next one, by when Authelia's file
  watcher has loaded it — and the link then goes to the new address, not the one
  it replaced. A new login's first email therefore arrives within about two
  `interval_secs`.
* **This cycle's write landed**, for an account the write was going to create
  or change. A write that failed, or was abandoned because Authelia changed the
  file first, holds those accounts' links for a later cycle; everyone else's go
  ahead.
* **The manager has an email for the login.** Without one it does not list a
  request at all; an address the portal cannot use is answered with a reason.
* **Authelia is not rate-limiting** (below).

The request is Authelia's own `POST <authelia_url>/api/reset-password/identity/start`
with the username, sent with `X-Forwarded-Proto: https`,
`X-Forwarded-Host: <public_host>` and `X-Forwarded-For: 127.0.0.1`. The user
follows the emailed link to Authelia's reset page and chooses a password. Which
email they get depends on the manager's `first_link` — true until a link for
that username has been sent without error — but only with
[`mail`](#rewriting-authelias-email-mail); without it Authelia sends the same
message either way.

**What "sent" means** in the manager's list:

* **Without `mail`:** Authelia answered with a 2xx and `{"status":"OK"}`.
  Authelia reports its own failures — its notifier, its storage, a
  `public_host` outside its cookie domains — as `200` with `{"status":"KO"}`, so
  the status code alone says nothing; those come back to the manager as the
  reason, with Authelia's message. Whether the mail then reached an inbox is
  between Authelia and its SMTP relay.
* **With `mail`:** the portal's relay (Brevo, say) answered `250` to the
  message within 20 seconds — accepted for delivery, not delivered. The portal
  waits up to 30 seconds for Authelia's email to reach its listener and for the
  relay to answer, and reports whichever came first: the relay's answer or the
  timeout.

**Each request is served once per portal process.** The portal remembers each
`(username, requested_at)` it has served and what happened. A failed
acknowledgement is retried on every later cycle with the same outcome, without
asking Authelia for another email; if the manager still lists a request after
acknowledging it, the portal sends nothing and logs once. A link that failed is
not retried by the portal: press **Send password link** again, which is a new
request. The memory does not survive a restart, so a portal restarted between
sending a link and getting its acknowledgement through sends that link again.

**Authelia rate-limits these requests** per client address — by default 5 in
10 minutes, 10 in 15 minutes and 15 in 30 minutes on `reset_password_start` —
and every request the portal makes comes from 127.0.0.1. On a `429` the portal
does **not** acknowledge the request, so it stays "requested" in the manager;
it asks for no more links that cycle, and when Authelia sent a `Retry-After` in
seconds, none until then (capped at an hour). The log says once:
`Authelia is rate-limiting password links; the rest wait for a later cycle`.
A request still waiting after 24 hours is withdrawn by the manager. If you send
links in batches, raise the limit (check the key names against your Authelia
version):

```yaml
server:
  endpoints:
    rate_limits:
      reset_password_start:
        buckets:
          - period: '10 minutes'
            requests: 100
```

### What the manager shows

The Portal logins list shows `password link failed: <reason>` for a request the
portal answered with a reason. Every reason is sent on one line — control
characters become spaces — and cut to at most 300 bytes.

| When | The reason |
|---|---|
| The username is a hand-made Authelia account | `this username is an Authelia account managed by hand; the portal only sends links for accounts it created` |
| The login has no email, or one the portal cannot use | `this login has no email the portal can use, so no link was sent` |
| Another account has the email, as email or username | `another Authelia account already uses this email, or has it as its username, so the portal did not write it` |
| Another account has the username, in another case or as its email | `another Authelia account already has this username, in another case or as its email, so the portal did not create it` |
| The username cannot be a key in the file as it is | `this username cannot be written into Authelia's user file as it is, so the portal did not create it` |
| Authelia answered `{"status":"KO"}` | `Authelia could not send the link: <Authelia's message> (see Authelia's log)` |
| Authelia answered another error status | `Authelia refused the request (<status>)`, followed by `: <message>` when it gave one |
| Authelia's answer was not its JSON | `Authelia sent a reply the portal could not read` |
| Authelia could not be reached | `could not reach Authelia: <error>` |
| With `mail`: nothing came back within 30 s of the request — normally because Authelia's email never reached the listener | `timed out waiting for Authelia's email; check that Authelia's notifier points at mail.listen_addr, authenticates with mail.listen_password_file, and sends from mail.from's address` |
| With `mail`: the listener dropped the request before its email arrived | `the portal never saw the email Authelia was asked to send` |
| With `mail`: the relay refused the message | `the mail relay refused it: <the relay's error>` |
| With `mail`: the relay did not answer | `the mail relay did not answer within 20s` |

A `429` from Authelia never appears here: that request is not answered at all
until Authelia takes it. Nor does a login whose write failed: its request stays
outstanding and is tried again.

**When the portal cannot write the users file at all** — it cannot be read or
parsed, an entry in it would not survive a rewrite, replacing it would lock
Authelia out, or the write itself fails — no login's request says why, because
none has been refused. So the portal sends the reason with its next poll as
`sync_error` (the same one line, at most 300 bytes, as the log's `not rewriting
…` or `not replacing …`), and the manager shows it in the Portal logins panel
until a poll arrives without it.

### `authelia_url` and its path

The portal appends Authelia's API paths to `authelia_url`, so **its path must be
the path of Authelia's own `server.address`**. The default,
`http://127.0.0.1:9091/auth`, matches an Authelia served under `/auth`
(`server.address: 'tcp://127.0.0.1:9091/auth'`). For an Authelia served at the
root, drop the path: `http://127.0.0.1:9091`.

A trailing `/` is trimmed. The URL must be `http://` or `https://`, and plain
`http://` only to a loopback address or `localhost` — it carries the username
of everyone being invited, and whoever can read it can forge the request that
mails them a link. It cannot carry a `user:password@`, a query or a fragment.

At startup the portal asks `<authelia_url>/api/health`, and only Authelia's own
`{"status":"OK"}` counts as an answer: an Authelia served at the root answers a
path under `/auth` with its sign-in page and a `200`, which is not one. At boot
Authelia is expected to be late — with [the ordering `mail`
needs](#startup-and-ordering) it starts after the portal — so the portal asks
again every 10 seconds, quietly, and logs one error only if two minutes pass
without that answer: ``Authelia's health check did not answer at
accounts.authelia_url (<status>, and not Authelia's own OK); its path must be
the path of Authelia's own server.address, and every password link will fail
until it is``, or, when nothing is listening, ``could not reach Authelia at
accounts.authelia_url (<error>); password links will fail until it answers
there``. Syncing runs meanwhile, and neither stops the portal. The probe cannot
catch the opposite mistake — an Authelia served under `/auth` with the path
left off `authelia_url` answers its health check either way — which shows up as
links that name the wrong path.

### The link names `public_host`

Authelia builds the link from the forwarded host and its own path, so
`public_host` is **a host Authelia's pages are served on**: the portal's host
when Authelia sits under a path there (`watch.example.com`, links to
`https://watch.example.com/auth/reset-password/…`), otherwise Authelia's own
login host — the host of `session.cookies[].authelia_url`. A host outside
Authelia's cookie domains gets `{"status":"KO"}`, which the manager shows as
`Authelia could not send the link: …`. Without `public_host` the link would
name 127.0.0.1.

### `managed_group` belongs to the portal alone

Any account carrying `managed_group` is treated as the portal's: its email and
display name are overwritten from the manager, and it is removed when the
manager reports its username removed — or, against an older manager, when the
username is simply not listed. So **use the group for nothing else**, and do
not add it to an account you made by hand. It is also the natural thing to
grant the portal on in Authelia's access control; give hand-made accounts that
should reach the portal a group of their own:

```yaml
access_control:
  default_policy: deny
  rules:
    - domain: 'watch.example.com'
      subject:
        - 'group:bilbycast-portal'   # every account the portal created
        - 'group:portal-staff'       # hand-made accounts you let in yourself
      policy: one_factor
```

### The file has two writers

Authelia rewrites the file whenever someone sets a password; the portal writes
it only when something changed. There is no lock the two share, so the portal:

* reads the file and notes its inode, modification time and length;
* writes the new content to a temp file beside it (`.users.yml.portal-tmp`),
  created mode `0600` because it holds password hashes, then gives it the old
  file's permission bits and — where the directory's setgid bit has not already
  — the old file's group;
* refuses the write, with a message naming the fix, if the replacement would
  take the file from Authelia: when it would land in another group while the
  group grants something everyone else does not (a root-owned `0644` file in
  root's group is replaced as it is), or when it changes an owner other than
  root and either the mode gives the group no read-write or this host's
  `/etc/passwd` and `/etc/group` show the old owner is not in the group (an
  owner absent from those files — a directory-service user, or a container's
  uid no host user shares — is not judged);
* flushes the temp file to disk, checks the inode, time and length once more,
  renames it over the original, and flushes the directory.

If the file changed in between, the write is abandoned and the next cycle starts
again from what is there (`Authelia changed its user file mid-sync; retrying
next cycle`). A password Authelia writes in the instant between that last check
and the rename can still be lost; the window is the rename itself.

**What a rewrite keeps, and what it does not.** Every entry the portal does not
own comes back with the same values, in the same place, and so do top-level keys
other than `users`. Comments, blank lines and quoting style do not survive —
the file is parsed and written out again — and YAML anchors and aliases are
written out in full. String values survive as they were. A value the parser
would read as a number or a boolean would not: `+61412345678` comes back as
`61412345678`, `0x1F` as `31`, `True` as `true`, and an unquoted number as a
key renames the account. So an account key that is not text (an unquoted
`12345:`), or a hand-made entry holding an unquoted number, a `true` / `false`
anywhere but `disabled`, or a field name that is not text, stops **every**
write until it is quoted, and the log names the entry — for example:
``not rewriting <file>: the account `<name>` has an unquoted number or
true/false in `<field>`, which rewriting the file would change; quote it in the
file``.

The first write also changes the file's owner: the replacement belongs to the
portal's user. From then on Authelia reaches the file **only through its
group**, which is what the [permissions](#file-permissions) below arrange.

The managed mark is an Authelia **group**, not a key of the portal's own,
because Authelia keeps the fields it knows when it rewrites the file and would
drop anything else — the account would be orphaned by its owner's first
password change.

### What Authelia needs

For account sync, with or without `mail`:

```yaml
authentication_backend:
  password_reset:
    disable: false
  file:
    path: /etc/authelia/users/users.yml
    watch: true             # required: reload when the portal replaces the file
    search:
      email: true           # required: sign in with the email as well as the username

identity_validation:
  reset_password:
    jwt_lifespan: '3 days'  # how long a link lasts; the default is 5 minutes
```

* **`watch: true`** is required: without it Authelia does not see a new
  account until it restarts, and every link asked for one is answered OK and
  sent nowhere.
* **`search.email: true`** is required. The portal's emails tell people to sign
  in "with your email address or your username", and the uniqueness rules above
  — the manager's and the portal's — exist so that the file stays loadable with
  it on.
* **`jwt_lifespan`** is how long a link works. Five minutes is too short for an
  invitation somebody reads the next morning. With `mail`, `mail.link_lifetime`
  must say the same thing in words, or be left unset.
* **The rate limit** on `reset_password_start`, if you send links in batches —
  see [Password links](#password-links).

**Without a `mail` block, Authelia mails the relay itself.** Any SMTP relay
works; this example uses **Brevo**, whose relay is `smtp-relay.brevo.com` on 587
with STARTTLS (`submission://`; use `submissions://…:465` for implicit TLS):

```yaml
notifier:
  smtp:
    address: 'submission://smtp-relay.brevo.com:587'
    username: 'xxxxxxx@smtp-brevo.com'   # the SMTP login, not the account email
    sender: 'Example Notifications <noreply@example.com>'
    subject: '[Example] {title}'
```

Two credential traps: the username is the **SMTP login** Brevo shows on its SMTP
& API page (`…@smtp-brevo.com`), not the account's email address, and the
password is an **SMTP key**, not a v3 API key. Keep the key out of the config
file — Authelia reads `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE`, so put it in a
`0600` file owned by the Authelia user and point the environment at it:

```ini
# /etc/authelia/authelia.env
AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE=/etc/authelia/smtp-password
```

**With a `mail` block, Authelia mails the portal**, and the relay credentials
move to the portal — see [Authelia's notifier with `mail`](#authelias-notifier-with-mail).

Either way, **the sending domain has to be authenticated at the relay**, or the
links go to spam — and for a password link, spam is the same as broken. In
Brevo: add the sender domain under *Senders, Domains & Dedicated IPs* and
publish the DNS records it gives you (its verification code, DKIM, and a DMARC
record with a `rua` tag). Gmail, Yahoo and Microsoft all require authenticated
senders now, so this is not optional. Send a test to an address on each of the
mail providers your viewers actually use before trusting it.

### File permissions

The portal must be able to replace the file, and Authelia must be able to read
it and write it back afterwards. Replacing a file needs write permission on its
directory, so keep it in **a directory of its own**, owned by Authelia, in the
portal's group, setgid so every file made there takes that group:

```sh
install -d -o authelia -g bilbycast-portal -m 2770 /etc/authelia/users
mv /etc/authelia/users_database.yml /etc/authelia/users/users.yml   # your current users file
chown authelia:bilbycast-portal /etc/authelia/users/users.yml
chmod 660 /etc/authelia/users/users.yml
usermod -aG bilbycast-portal authelia
```

Then point `authentication_backend.file.path` at the new location, **restart
Authelia** (a process picks up a new group only when it starts), and **restart
bilbycast-portal** (its unit's `ReadWritePaths=` is applied at start). The
portal also needs to pass through `/etc/authelia` itself — execute permission
for others, or for a group it is in — but nothing else under `/etc/authelia`
needs to be readable, let alone writable, by it. Substitute the user Authelia
really runs as for `authelia`.

After the portal's first write the file belongs to `bilbycast-portal`, so
Authelia reaches it only through the group. The portal refuses a write that
would lock Authelia out, and each refusal names its own fix:

* the file's group is one the portal is not in, so the replacement could not
  keep it: ``… Give the file a group the portal is in: `chgrp <gid> <file>`, and
  put Authelia's user in that group too unless Authelia runs as root``. A
  root-owned file whose group grants nothing beyond what everyone else has —
  root's `0644`, as root makes it — is not refused: nobody reaches it through
  that group, and a root Authelia needs neither group nor mode;
* the group cannot read and write it: ``… `chmod g+rw <file>` ``;
* this host's `/etc/passwd` and `/etc/group` do not put the file's owner in its
  group: ``… `usermod -aG <gid> <Authelia's user>`, then restart Authelia. That
  check reads this host's account files only, so for an Authelia in a
  container, or one given the group by SupplementaryGroups=, add the host user
  with uid <uid> to the group as well``.

**systemd.** The packaged unit runs with `ProtectSystem=strict` and lets the
portal write one place: `ReadWritePaths=-/etc/authelia/users`. The leading `-`
lets a portal without account sync start when the directory does not exist; it
also means a directory created after the portal started stays read-only until
the portal restarts. A `users_file` anywhere else needs its own drop-in, never an
edit to the unit, which `install-relay.sh --with-portal` replaces with the
packaged one, and `upgrade-relay.sh` too unless what it runs was edited (see
[Upgrading](#upgrading)); both keep drop-ins:

```sh
systemctl edit bilbycast-portal
#   [Service]
#   ReadWritePaths=/srv/authelia/users
systemctl restart bilbycast-portal
```

A write blocked this way fails with a read-only-file-system error whose message
names that drop-in. Nothing under `/home` or `/tmp` can work: the unit's
`ProtectHome=` and `PrivateTmp=` hide them. The unit also carries
`SystemCallFilter=@chown` after its `SystemCallFilter=~@privileged @resources`:
keeping the file's group is an `fchown`, which is in `@privileged`, and a call
the filter denies does not fail — it kills the process with `SIGSYS`. **Any
custom unit that denies `@privileged` must add `SystemCallFilter=@chown` after
the deny**, or the portal dies the first time a group has to be restored. With
the unit's empty `CapabilityBoundingSet=` it can only hand a file the portal
owns to a group the portal is already in.

**Docker.** An Authelia container that runs with `user:` needs the
`bilbycast-portal` group's numeric id in its `group_add:`; one running as root
needs none. **Mount the directory, not the file**: the portal replaces the
file by renaming a new one over it, and a bind mount of a single file keeps
showing the file it was made with, so Authelia would never see a change — and
its own writes would go to the orphan. The `/etc/passwd` check does not judge a
container's uid the host does not know, but it judges one a host user shares
as that host user — typically uid 1000 — so with `group_add:` also add that
host user to the `bilbycast-portal` group, or the portal refuses the write.

## Rewriting Authelia's email (`mail`)

Optional, and only useful alongside `accounts`. Authelia sends one email for
"set your first password" and "I forgot my password" — one subject, one body,
one link lifetime — because it cannot tell the two apart. The manager can: it
knows whether a link for this person has ever been sent. So with a `mail` block,
Authelia is pointed at an **SMTP listener inside the portal** on loopback
instead of at the relay, and a message the portal has just asked for is
rewritten — an **invitation** for a first link, a **password reset** otherwise —
around Authelia's own link, then sent through the relay named here.

The portal cannot mint the link itself: it is a JWT Authelia signs *and*
records, and a token minted anywhere else is refused because the record behind
it does not exist. Taking Authelia's message is the only way to put other words
around it.

```json
"mail": {
  "listen_addr": "127.0.0.1:2525",
  "listen_password_file": "/etc/bilbycast/portal-mail-listener",
  "relay_host": "smtp-relay.brevo.com",
  "relay_username": "xxxxxxx@smtp-brevo.com",
  "relay_password_file": "/etc/bilbycast/portal-smtp-key",
  "from": "Example Notifications <noreply@example.com>",
  "sign_in_url": "https://watch.example.com",
  "brand": "Example",
  "link_lifetime": "three days"
}
```

| Key | Default | |
|---|---|---|
| `listen_addr` | `127.0.0.1:2525` | Where Authelia delivers: `host:port` on `127.0.0.1` or `[::1]`. The listener speaks no TLS, and Authelia's SMTP client sends its password without TLS only to `127.0.0.1`, `::1` or `localhost`, so any other address — `127.0.0.2` included — is refused: Authelia could never authenticate there. |
| `listen_password_file` | required | A file holding the secret Authelia authenticates with. Read once at startup and trimmed; it must be one line with no control characters and at least 32 characters (`openssl rand -hex 32`). Both the portal and Authelia read it. |
| `relay_host` | required | The relay that delivers, e.g. `smtp-relay.brevo.com`. |
| `relay_port` | `587`, or `465` with `implicit_tls` | `0` is refused, and so is `465` without `implicit_tls: true` — a relay there speaks TLS from the first byte and never sends the greeting STARTTLS waits for. |
| `relay_username` | required | The relay login — Brevo's SMTP login, not the account email. |
| `relay_password_file` | required | A file holding the relay password (Brevo's SMTP key). Read once at startup, trimmed. |
| `from` | required | The From on every rewritten email: `Name <address>`, with the name in double quotes if it contains any of `, ( ) : ; @ [ ] \ "`. Its address must be Authelia's `notifier.smtp.sender` address, and its domain authenticated at the relay. |
| `sign_in_url` | required | Where a viewer signs in, named in the emails. `http://` or `https://`; a trailing `/` is trimmed. |
| `brand` | `Bilbycast` | 1 to 64 characters, one line. Used in "access to *brand* live and recorded video", "your *brand* account", the header bar, the "*brand* Notifications" sign-off and the default subjects. |
| `link_lifetime` | unset | Up to 64 characters, one line; blank means unset. When set, the emails say "This link lasts *link_lifetime*." — so it must agree with Authelia's `identity_validation.reset_password.jwt_lifespan`, which the portal cannot read. Unset, the emails make no claim about how long the link lasts. |
| `invite_subject` | `Your <brand> account` | Up to 200 characters, one line; blank means the default. |
| `reset_subject` | `<brand> password reset` | Up to 200 characters, one line; blank means the default. |
| `starttls` | on, unless `implicit_tls` | STARTTLS to the relay. `false` is accepted only when `relay_host` is a loopback IP literal or `localhost`: it sends the relay password in clear. |
| `implicit_tls` | `false` | TLS from the first byte (`submissions`, port 465) instead of STARTTLS. Refused together with `starttls: true`. |

`from` is checked at startup the way the rewrite will use it, so a From that
could never be sent stops the portal with
``mail.from `…` is not an address to send from: write `Name <noreply@example.com>`,
with the name in double quotes if it contains any of , ( ) : ; @ [ ] \ "``.

Both secret files sit under `/etc/bilbycast`, which the unit mounts read-only
for the portal. Something like:

```sh
openssl rand -hex 32 > /etc/bilbycast/portal-mail-listener
chown root:bilbycast-portal /etc/bilbycast/portal-mail-listener
chmod 0640 /etc/bilbycast/portal-mail-listener   # Authelia reads it through the group

install -m 0640 -o root -g bilbycast-portal /dev/null /etc/bilbycast/portal-smtp-key
# then write the Brevo SMTP key into it
```

The listener secret has to be readable by both services. With Authelia's user
already in `bilbycast-portal` for the users file, mode `0640` in that group does
it; otherwise keep two files holding the same secret.

### Authelia's notifier with `mail`

```yaml
notifier:
  smtp:
    address: 'smtp://127.0.0.1:2525'
    username: 'authelia'
    sender: 'Example Notifications <noreply@example.com>'
    disable_require_tls: true
```

```ini
# /etc/authelia/authelia.env
AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE=/etc/bilbycast/portal-mail-listener   # = mail.listen_password_file
```

* **`address`** must name `mail.listen_addr` — `127.0.0.1` or `::1` as it is
  written there, or `localhost` where that resolves to it — and its port.
  Authelia's SMTP client sends a password without TLS only to those names,
  which is why the portal accepts no other listen address.
* **`username`** can be any non-empty name; the listener checks only the
  password. Without a username Authelia does not authenticate at all, and the
  listener refuses its mail.
* **The password** is the secret in `mail.listen_password_file`, through
  `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE`. A trailing newline in the file is
  fine; the listener ignores it.
* **`sender`'s address must equal `mail.from`'s address** (compared without
  regard to case; the display names may differ). Any other sender is refused at
  `MAIL FROM` with `550`, and the portal logs ``refused mail from a sender other
  than mail.from; Authelia's notifier.smtp.sender must carry the same address``.
* **`disable_require_tls: true`** is needed because the listener offers no
  STARTTLS; the conversation never leaves the host.
* **`subject`**, if you keep one, applies only to mail the portal passes through
  unchanged.
* **The relay login and key move** from Authelia into `mail.relay_username` and
  `mail.relay_password_file`. Remove Authelia's old relay address and password
  file.

Authelia's notifier startup check connects to the listener and runs the whole
exchange — `EHLO`, `AUTH`, `MAIL FROM` with its sender, `RCPT` to its
`startup_check_address`, `RSET` — and a failure there stops Authelia. So an
Authelia that starts is one whose notifier the listener accepts, and a wrong
password (`535`) or sender (`550`) shows up in Authelia's own log at once. A
failed `AUTH` is also logged by the portal: ``a client failed to authenticate to
the notification mail listener; if it was Authelia, its notifier.smtp password
is not the secret in mail.listen_password_file``.

### What is rewritten, and what is not

Only a message to somebody the portal has just asked a link for, matched by
recipient address (case-insensitively) within 30 seconds of the request.
Before asking Authelia, the portal registers the address Authelia's user file
holds for the account — the one Authelia will mail — and forgets it again if
Authelia refuses the request. Everything else Authelia sends — a viewer using the "reset password" link on
the sign-in page, one of Authelia's own notices — is relayed byte for byte.

The rewritten email is plain text with an HTML alternative, addressed to the
display name the manager has for the login (the username when it has none),
greeting them by it. The invitation says they have been given access to *brand*
live and recorded video, asks them to choose a password, and tells them to sign
in at `sign_in_url` "with your email address or your username". The reset says
somebody asked to reset the password on their *brand* account. Both carry
Authelia's link unchanged, the lifetime sentence when `link_lifetime` is set,
and sign off "*brand* Notifications". A name or brand is escaped in the HTML,
and control characters in a name become spaces.

If the rewrite cannot be composed, or Authelia's message holds no link the
portal can find, Authelia's message is relayed unchanged instead — the person
still gets their link, in Authelia's words — and "sent" in the manager reflects
the relay's answer to that.

**What "sent" means with `mail`.** Authelia believes a message is sent the
moment the listener answers `250`, and it will not send it again; the relay is
tried afterwards, for at most 20 seconds. For a link the portal asked for, the
relay's answer is what the manager is told. Mail nobody here asked for has
nobody to report to, so a relay failure on it is only an ERROR in the portal's
journal: ``could not relay an email Authelia sent; Authelia was told it was
accepted and will not send it again``.

### The listener's limits

It speaks enough SMTP for Authelia and nothing more:

* `AUTH PLAIN` and `AUTH LOGIN` only; `MAIL`, `RCPT` and `DATA` before a
  successful `AUTH` get `530`. Three failed `AUTH`s, or three unrecognised
  commands, close the connection. No STARTTLS is offered.
* Before `AUTH` succeeds: 10 seconds, and 6 commands (`EHLO` and `AUTH`
  included), then `421` and the connection is closed. Authelia authenticates in
  its first two round trips.
* 16 connections at once. When all 16 are taken, the oldest connection that has
  not authenticated is closed to make room, so sockets that connect and say
  nothing cannot keep Authelia out; only when all 16 have authenticated is a
  newcomer told `421` and closed.
* 60 seconds per session, however it is going, and 30 seconds idle.
* One recipient per message (`452` for a second).
* 64 KiB per line (`500`) and 1 MiB per message (`552`).
* 8 messages accepted and still waiting on the relay; past that, `DATA` is
  answered `451` and Authelia's send fails.
* A line that looks like HTTP closes the connection: a browser, or a request
  something was steered into making, is not Authelia.

### Startup and ordering

The portal binds the mail listener before it serves anything. A port someone
else holds (`portal mail listener 127.0.0.1:2525: …`), a listener secret that
cannot be read or is too short (`portal mail listener: …`), a relay key that
cannot be read (`portal mail relay: …`) or a config without
`listen_password_file` (``portal config: mail.listen_password_file is required:
…``) makes it exit non-zero at startup, and the unit's `Restart=always` with its
start limit makes that visible in `systemctl status`. If the listener or the
account sync ever stops or panics afterwards, the whole portal exits non-zero
and systemd restarts it, rather than serving viewers while links quietly stop.

Authelia's startup check needs the listener up, so **start Authelia after the
portal**:

```sh
systemctl edit authelia
#   [Unit]
#   After=bilbycast-portal.service
#   Wants=bilbycast-portal.service
```

The portal's unit is `Type=simple`, so `After=` waits only for it to be
launched; it binds within moments of that. A restart of the portal leaves a few
seconds in which Authelia's mail — a viewer's own reset included — has nowhere
to go.

## Upgrading a portal that already runs account sync or mail

Earlier builds of account sync and `mail` took a config this build refuses, and
wrote emails this build words differently. `upgrade-relay.sh` swaps the portal
**binary**, refreshes the packaged **unit file** (see [Upgrading](#upgrading))
and restarts it; it does not touch `portal.json` or Authelia. Do all of this
before the upgrade. Steps 1, 4 and 5 decide whether the new binary starts at
all — when it does not, the script prints that the portal did not come back and
leaves it stopped — and the rest decide whether it goes on working as it did:

1. **Create the listener secret** and add it to the `mail` block — it is now
   required, and without it the portal refuses to start with
   ``mail.listen_password_file is required: …``:

   ```sh
   openssl rand -hex 32 > /etc/bilbycast/portal-mail-listener
   chown root:bilbycast-portal /etc/bilbycast/portal-mail-listener
   chmod 0640 /etc/bilbycast/portal-mail-listener   # Authelia, in the group, reads it too
   ```

   ```json
   "listen_password_file": "/etc/bilbycast/portal-mail-listener"
   ```

2. **Keep the wording you have.** The earlier emails said "GRS" and used the
   subjects `GRS New User` and `GRS password reset`; the defaults are now
   "Bilbycast", `Your Bilbycast account` and `Bilbycast password reset`. Set
   them explicitly:

   ```json
   "brand": "GRS",
   "invite_subject": "GRS New User",
   "reset_subject": "GRS password reset"
   ```

3. **Say how long a link lasts only if it is true.** The earlier emails said
   "This link lasts three days" whatever Authelia did. Set
   `"link_lifetime": "three days"` only if Authelia's
   `identity_validation.reset_password.jwt_lifespan` really is three days;
   otherwise set it to what that value is, or leave it out and the emails make
   no claim.

4. **Check `mail.from`, `mail.listen_addr` and `mail.relay_port`.** `from`
   must now parse as `Name <address>`, with a name containing
   `, ( ) : ; @ [ ] \ "` in double quotes; `listen_addr` must be on
   `127.0.0.1` or `[::1]`; and `relay_port: 465` needs `"implicit_tls": true`.

5. **Check `accounts.authelia_url`.** The default is unchanged,
   `http://127.0.0.1:9091/auth`, and so is the rule that `http://` is for this
   host only; a URL carrying credentials, a query or a fragment is now refused.

6. **Give Authelia's notifier a username and the password**, as in
   [Authelia's notifier with `mail`](#authelias-notifier-with-mail):
   `username`, `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE` set to the file from
   step 1, `sender` with `mail.from`'s address, `disable_require_tls: true`,
   `address` on `127.0.0.1`. Turn on `search.email: true` if it is not already;
   Authelia then refuses a file in which two accounts share an email, or one's
   email is another's username, so check the hand-made ones first. Add the `After=` / `Wants=` drop-in to
   `authelia.service`.

7. **Move edits of the unit file into a drop-in.** The new unit adds
   `ReadWritePaths=-/etc/authelia/users` and `SystemCallFilter=@chown`, and
   `upgrade-relay.sh` now installs it over the packaged
   `/etc/systemd/system/bilbycast-portal.service` — earlier versions of the
   script did not — keeping drop-ins and the file it replaced. A change made in
   the unit file itself belongs in `systemctl edit bilbycast-portal` first —
   except a moved binary's `ExecStart=`, which the script reads from the unit
   file to find the binary it upgrades. On a unit the script leaves alone — one
   of your own elsewhere, or one whose `ExecStart=`, `User=`, `Group=`,
   `WorkingDirectory=` or `EnvironmentFile=` you edited — add `ReadWritePaths=`
   for the users directory and `SystemCallFilter=@chown` after any line denying
   `@privileged`, then `systemctl daemon-reload`.

8. **Check the users file's permissions** against
   [File permissions](#file-permissions). The portal now refuses a write that
   would leave Authelia unable to reach the file, where the earlier build made
   it.

Then upgrade, and **restart Authelia once the new portal is running**: the
earlier listener offered no `AUTH`, so an Authelia configured to authenticate
fails its startup check against it, and an Authelia still running the old
notifier config has its mail refused by the new one with `530`. The window
between the two restarts is the only time mail fails.

Three behaviours change without any config:

* **Removal needs the manager's word.** Against a manager that sends `removed`,
  an account is removed only when its username is listed there; absence alone
  no longer removes anything. Against an older manager the earlier rule still
  applies. See [When an account is removed](#when-an-account-is-removed).
* **Links go only to accounts the portal made**, and only once the file holds
  the manager's address. A request for a hand-made account is answered with
  `this username is an Authelia account managed by hand; the portal only sends
  links for accounts it created`.
* **A username given out again is a new account.** Against a manager that keeps
  removal records until they are acknowledged, a login removed and added again
  before the portal applied the removal gets its account replaced, with a new
  unusable password; the earlier build kept the account and its password. A
  session the last holder has open is not ended — see
  [When an account is removed](#when-an-account-is-removed).

## Clips

A viewer marks a moment in the DVR player and asks for a clip; it is cut on the
edge and lands here, under the feed list, once it is ready. Each row offers a
**Download** and a **Delete**.

**Entitlement is the same one that governs watching.** `GET /api/clips` asks the
manager which sessions the signed-in user is entitled to and lists the clips of
those, so a clip is visible to everyone entitled to the feed it came from — not
only whoever pressed export. The only widening is in *when*, never *who*: a feed
that has stopped is gone from the feed list above on the next page load, but its
clips stay here — listed, downloadable and deletable — for the 24 h of clip
retention that starts when the session stops. That is deliberate: clips are a
working artefact of an event, and a gallery only its author can see is the wrong
shape for a crew.

**Failure is shown, not hidden.** A clip the edge cannot produce reads
**Failed**, with the edge's reason on its own line underneath, rather than
sitting as "Cutting…" for ever. The common one is a mark that spans a recorder
restart, where the media either side is two separate timelines; the message
says to move the mark.

**Delete is offered on failed clips too.** Clips are exempt from the relay's
retention sweep — they are removed with the session, not with the window they
came from — so neither retention nor the free-space floor reclaims their space.
The relay does reclaim on its own account, as a backstop for a manager that
never comes back: anything under `clips/` — media or record, finished or
failed — is removed seven days after it was last written, whatever the session
is doing, well past the day the manager allows after a stop; an abandoned
`.part`, or media with no record beside it, goes after an hour. Short of that, a
failed export still holds a record until somebody clears it.

**The list is best-effort.** A relay too old to know about clips, or one that
cannot be reached, leaves the section hidden rather than putting an error in
front of a viewer whose feeds loaded perfectly well. The page exists to get
someone watching.

## Signing out

The portal cannot end a session — it never authenticated anyone. Authelia holds
the cookie and only Authelia can clear it, so `logout_url` in `portal.json`
points at the identity provider's own logout (`https://auth.example.com/logout`
for Authelia). Leave it unset and no button is shown, which is better than one
that appears to work and leaves the viewer signed in.

## Access lasts thirty minutes

A token minted through the portal is good for thirty minutes
(`PORTAL_TOKEN_TTL_SECS` on the manager; a link grant is a separate, three-hour
token), after which the player stops with "your viewing access has expired". The viewer returns to the
portal and opens the feed again; if their entitlement has been withdrawn in the
meantime, it is not there to open.

A viewer whose token runs out is offered a link straight back to **that
feed** — `{portal}/watch?stream={id}` — not to the portal's front page. The
portal already knows who they are, so recovering is one tap. A stream they are
not entitled to and one that does not exist both land back on the front page
with no hint of which, exactly as the mint endpoint refuses.

The player keeps its token in `sessionStorage` for the life of the tab, because
it strips it from the URL on load. Stripping is right — a viewer copying the
address bar should not hand out their credential — but without somewhere to
keep it the page became a one-shot: a reload, a back-navigation or a restored
tab lost the token and reported "your viewing access has expired", which was
false. A refused token is forgotten, so one refusal cannot become a loop that
survives every reload.

### Renewing without signing in again

Thirty minutes does not cover a match plus its build-up, and the failure arrives
mid-second-half. So the player renews itself about ten minutes before its token
runs out, by calling `GET /api/renew?stream=…` here.

That renewal goes back through the manager exactly as the first mint did, and
**the manager re-checks the entitlement before it signs**. This is what keeps a
short expiry meaningful: it is revocation latency, not a countdown. A renewal
that skipped the check would quietly turn "access lasts thirty minutes" into
"access lasts as long as the tab is open", and withdrawing access would stop
working.

`install-relay.sh` takes `--player-origin https://relay.example.com` alongside
`--with-portal` and writes it for you. Without it the installer warns, because
the failure is otherwise silent: the portal installs, viewers sign in, and thirty
minutes later their access ends mid-event with nothing to say why.

Renewal needs **two** settings, on two different services, and the second is
easy to miss.

**On the relay: `distribution.portal_url` must be set.** The player's
`scheduleRenewal()` returns immediately when it is empty, so a blank
`portal_url` turns the thirty minutes into a hard limit however the portal is
configured. Nothing reports it at either end — the viewer simply loses access
mid-event. The manager's Distribution tab labels the field "Optional", which is
true of the sign-in-again link and false of renewal.

**On the portal: renewal is off until you name the player's origin,** because it
is a cross-origin request carrying the viewer's session cookie — the shape a
CSRF wants:

```json
"player_origins": ["https://relay.example.com"]
```

Exact matches only, and `*` is refused at startup: a response carrying
`Access-Control-Allow-Credentials` may not answer a wildcard origin, so a
portal configured that way would look right and never renew.

The origin is checked **before anything is done**, so an unlisted one cannot
even cause a mint. Past that check every exit carries the CORS headers,
including the refusals — the origin is already trusted by then, and withholding
them only turns a clear 403 into an opaque browser error. The answer is
`Cache-Control: no-store`: the body is a credential.

Only a viewer who came through the portal can renew — they hold the session
cookie. **A guest with a one-off link cannot, and should not:** their three
hours are the point of the link.

Removing a portal login stops them getting *new* tokens immediately. A token
already in a browser keeps working until it expires — the relay verifies a
signature and an expiry, and holds no per-viewer state to revoke. Thirty minutes
is the outer bound on how long a withdrawal takes to bite for a portal viewer —
three hours for a link grant, which cannot renew.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /` | The page. |
| `GET /portal.js` | Its script — a separate route so the page can carry `script-src 'self'`. |
| `GET /api/feeds` | What the signed-in user may watch. |
| `POST /api/watch` | Mint a link for one feed. The body names the *session*; the username comes from the header and can never be supplied by the browser. |
| `GET /watch?stream=…` | One tap back to a feed whose credential ran out — re-mints and redirects. This is where the player's expired-access link points, not the front page. |
| `GET /api/renew?stream=…` | Background renewal before the thirty minutes are up. Cross-origin, so it answers only origins named in `player_origins`; an empty list means no renewal at all. |
| `POST /api/beat?stream=…&held=…` | "Still watching", once a minute from a visible portal-viewer tab, so the manager's DVR page can count who is watching *now* rather than who last renewed. Carries no token and grants nothing — it moves one timestamp on the row this device already holds. Cross-origin like `/api/renew`, so it too answers only `player_origins`, and the failure is just as silent: with the origin missing the count simply stays empty. A manager that refuses the beats (one without the route, or one whose service token has been rotated) is logged at `warn` once per episode, not per beat. |
| `GET /api/clips` | Clips cut from the feeds this user is entitled to — including a feed that has finished, for the day its clips are kept — with a download link for each one that is ready. |
| `GET /api/clips/download?session=…&name=…` | Hand a finished clip to the viewer, proxied from the relay so no viewer token appears in a link somebody is told to save. Entitlement is re-checked by the same mint the listing uses. |
| `DELETE /api/clips` | Remove one clip on the viewer's behalf. The body names the session and the clip; the portal mints against the manager as the permission check and deletes on the relay from here, because the page's `connect-src 'self'` never lets the browser reach the origin itself. |
| `GET /healthz` | Liveness. Deliberately needs no user — a health check that required one would be reporting on the proxy. |
