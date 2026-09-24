// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portal logins become Authelia accounts.
//!
//! The manager decides who has a login — an operator adds a username and an
//! email in the Portal logins modal. Authelia holds the password. This loop is
//! the bridge: it asks the manager for the login list, keeps Authelia's user
//! file in step with it, and asks Authelia to email a set-your-password link
//! when an operator requests one.
//!
//! # What it owns, and what it leaves alone
//!
//! Only accounts it created. Every account this loop writes carries
//! [`AccountSyncConfig::managed_group`] in its Authelia `groups`, and only an
//! account carrying it, under a plain string key, is ever updated, removed or
//! sent a link. An account somebody wrote by hand — `dvr-test` on the first
//! production install — keeps its entry as it is, even when the manager has a
//! login of the same name; a link requested for one is answered with the
//! reason instead of being sent. A group is used as the mark rather than a key
//! of our own because Authelia rewrites this file whenever a user sets a
//! password, and it keeps the fields it knows: a custom key would vanish on the
//! first password change and the account would be orphaned.
//!
//! An account is removed only when the manager says its login is gone — the
//! username is in the answer's `removed`. Missing from the list is not enough:
//! a database restored from an older backup is missing everything created
//! since, and a deleted account takes the password its owner chose with it. A
//! manager too old to send `removed` gets the previous rule, removal by
//! absence, except that an empty list removes nobody.
//!
//! The manager keeps each removal until the portal acknowledges it, even when
//! the username is given out again meanwhile, so a username in `removed` *and*
//! in `accounts` has changed hands: its entry is replaced — dropped and made
//! afresh in the same write — or the old holder's password would open the new
//! holder's feeds. A removal is acknowledged only once the write that applied
//! it has landed, and the process remembers what it has applied, so a failed
//! acknowledgement is retried without replacing the account a second time,
//! perhaps after its new owner has set a password.
//!
//! # Passwords are Authelia's
//!
//! A new account gets an argon2id hash of 32 random bytes that nobody ever
//! sees, so it cannot be signed in to until its owner sets a password through
//! the emailed link. An existing account's `password` is never rewritten: the
//! user may have set it a second ago. A replaced one is a new account.
//!
//! # One address, one account
//!
//! With `search.email` on, Authelia refuses the whole file when two accounts
//! share an email, or one's email is another's username — hand-made accounts
//! included — and a refused file is a lockout for everyone at its next
//! restart. So an account is not created, and an email not changed, when the
//! file this cycle writes would hold such a pair; the login is reported
//! instead. That is judged against the file as it will be, not as it was, so
//! an address one account gives up can go to another in the same write, and
//! two accounts can swap theirs. A login whose address is held only by an
//! account the manager is moving off it, which could not move this cycle,
//! waits rather than being refused.
//!
//! # Two things Authelia will not tell us
//!
//! `POST /api/reset-password/identity/start` answers OK for any username,
//! known or not — it will not reveal who exists — and mails whatever address it
//! has loaded. So a link is requested only for an account whose entry already
//! holds the address the manager has when the cycle begins. One created this
//! cycle, or whose email this cycle rewrites, waits for the next, by when
//! Authelia's file watcher has loaded it: asking sooner would send nothing, or
//! send the link to the address the operator just replaced.
//!
//! And whether the mail was delivered: that is between Authelia and its SMTP
//! relay. What the manager is told is whether Authelia took the request — or,
//! with [`mail`](super::mail) rewriting it, whether the relay took the email —
//! and the reason when it did not.
//!
//! # The file has two writers
//!
//! This loop and Authelia. A write here is therefore rare (only when something
//! changed), whole-file by temp-then-rename, and abandoned if the file changed
//! between reading it and replacing it — the next cycle starts again from what
//! is there. A link for an account a write would have changed waits until that
//! write lands. There is no lock the two share, so a password Authelia writes
//! in the instant between the last check and the rename can still be lost.
//!
//! Rewriting re-serialises the file. Comments are dropped and quoting is
//! normalised; string values come back as they were. A hand-made entry holding
//! an unquoted number or boolean would come back as different text — a
//! username or an email changed under its owner — so such an entry stops every
//! write until it is quoted, and the log names it.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};

use super::PortalState;
use super::mail::{LinkKind, PendingLinks};

/// The `accounts` block of the portal config. Absent means the portal does not
/// manage accounts at all, which is how every portal ran before this existed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSyncConfig {
    /// Authelia's `authentication_backend.file.path`. Authelia must have
    /// `watch: true` on it, and this service must be able to replace the file.
    pub users_file: PathBuf,

    /// Authelia itself, reached directly on loopback rather than through the
    /// public proxy. Its path must be the path of Authelia's own
    /// `server.address`: `/auth` here by default, because that is how the
    /// portal's Authelia has been deployed since account sync shipped, and a
    /// changed default would silently break it; set it without the path for
    /// an Authelia served at the root. Checked once at startup against
    /// Authelia's health endpoint, so a wrong one is said then rather than on
    /// every link.
    #[serde(default = "default_authelia_url")]
    pub authelia_url: String,

    /// The public host the emailed link names, e.g. `watch.example.com`.
    /// Authelia builds the link from the forwarded host and its own path, so
    /// this is a host Authelia's pages are served on: the portal's, when
    /// Authelia sits under a path there, or Authelia's own login host. Without
    /// it the link would name 127.0.0.1.
    pub public_host: String,

    /// The Authelia group that marks an account as this loop's to manage.
    #[serde(default = "default_group")]
    pub managed_group: String,

    /// Seconds between syncs. A requested link goes out within about one of
    /// these, or two for an account created, or given a new email, in the same
    /// request. Told to the manager on every poll, so it can tell a portal that
    /// has stopped asking from one that asks slowly.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
}

fn default_authelia_url() -> String {
    "http://127.0.0.1:9091/auth".to_string()
}
fn default_group() -> String {
    "bilbycast-portal".to_string()
}
fn default_interval() -> u64 {
    15
}

impl AccountSyncConfig {
    pub fn normalise(&mut self) {
        while self.authelia_url.ends_with('/') {
            self.authelia_url.pop();
        }
        self.public_host = self.public_host.trim().to_string();
        self.managed_group = self.managed_group.trim().to_string();
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.users_file.as_os_str().is_empty() {
            return Err("accounts.users_file is required".into());
        }
        // Parsed the way the HTTP client will parse it: a hand-rolled reading
        // that ends the host somewhere else is a check that can be spelled
        // around (`http://evil#@127.0.0.1`).
        let url = reqwest::Url::parse(&self.authelia_url)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https"))
            .ok_or("accounts.authelia_url must be an http(s) URL")?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err("accounts.authelia_url cannot carry credentials".into());
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(
                "accounts.authelia_url cannot have a query or a fragment: Authelia's API \
                 paths are appended to it"
                    .into(),
            );
        }
        // Plain HTTP carries the username of everyone being invited, and
        // anyone who can read it can also forge the request that emails them a
        // password link. On loopback that is the documented deployment —
        // Authelia listens there without TLS — and anywhere else it is a
        // mistake nobody would see, so it is refused rather than warned about.
        if url.scheme() == "http" && !authelia_is_local(&url) {
            return Err(
                "accounts.authelia_url may only be http:// on this host; use https:// \
                        for an Authelia anywhere else"
                    .into(),
            );
        }
        // A host, not a URL: it becomes the `X-Forwarded-Host` header.
        if self.public_host.is_empty()
            || self.public_host.contains('/')
            || self.public_host.contains(char::is_whitespace)
        {
            return Err(
                "accounts.public_host must be a bare host name, e.g. watch.example.com".into(),
            );
        }
        if self.managed_group.is_empty() {
            return Err("accounts.managed_group cannot be empty".into());
        }
        if !(5..=3600).contains(&self.interval_secs) {
            return Err("accounts.interval_secs must be between 5 and 3600".into());
        }
        Ok(())
    }
}

/// Is this Authelia on the same host? A loopback address, or `localhost`.
fn authelia_is_local(url: &reqwest::Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

/// One login, as the manager reports it: one row per username, however many
/// groups have granted that username something.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ManagerAccount {
    pub username: String,
    /// No email means the manager has no way to reach this person, so no
    /// account is created for them and no link is sent — they sign in however
    /// they did before.
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// An outstanding request for a set-your-password link, as the manager
    /// stamped it. Echoed back verbatim when acknowledging, so the manager
    /// clears exactly the request that was served.
    #[serde(default)]
    pub link_requested_at: Option<String>,
    /// No link has ever been sent for this login, so the next one is an
    /// invitation rather than a password reset. The manager decides this
    /// because only it remembers; Authelia cannot tell the two apart.
    #[serde(default)]
    pub first_link: bool,
}

#[derive(Debug, Deserialize)]
struct AccountsResponse {
    #[serde(default)]
    accounts: Vec<ManagerAccount>,
    /// Usernames whose last login was deleted, each kept by the manager until
    /// the portal acknowledges it — a username given out again since included.
    /// Absent from a manager older than this list, which is the one case
    /// removal falls back to absence from `accounts`.
    #[serde(default)]
    removed: Option<Vec<Removal>>,
}

/// The manager's record that a username's last login was deleted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct Removal {
    pub username: String,
    /// The manager's stamp, echoed back verbatim when acknowledging: the
    /// manager forgets the record only while it still carries this stamp, so
    /// acknowledging an older removal never loses a newer one.
    pub removed_at: String,
}

/// A managed account's entry, brought back in line with the manager.
#[derive(Debug, Clone, PartialEq)]
pub struct Update {
    pub username: String,
    /// The new email, when it changed and no other account holds it.
    pub email: Option<String>,
    /// The new display name, when it changed.
    pub display_name: Option<String>,
}

/// A link to ask Authelia for.
#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub username: String,
    /// The manager's stamp, echoed back verbatim.
    pub requested_at: String,
    /// The address in Authelia's file — the one it will mail, and so the one
    /// the rewriting listener must expect.
    pub email: String,
    pub kind: LinkKind,
    /// What the rewritten email calls them.
    pub name: String,
}

/// A link request answered with a reason instead of a link.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub username: String,
    pub requested_at: String,
    pub reason: &'static str,
}

/// What one sync would change. Worked out from the file and the manager's
/// answer alone, so every decision here is testable without Authelia or a
/// network.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Plan {
    /// Accounts to create.
    pub add: Vec<ManagerAccount>,
    /// Managed accounts whose email or display name has changed.
    pub update: Vec<Update>,
    /// Managed accounts whose login the manager has deleted — or, from a
    /// manager too old to say, no longer lists.
    pub remove: Vec<String>,
    /// Managed accounts whose username was deleted and given out again: the
    /// entry is dropped, and made afresh in `add` when the new login can have
    /// an account at all, so nothing set on the old one survives.
    pub replace: Vec<String>,
    /// The manager's removal records this plan settles, each with whether
    /// settling it takes this cycle's write. One that needs no write — no
    /// managed account of that name — is settled already.
    pub removals: Vec<(Removal, bool)>,
    /// Links to ask Authelia for now.
    pub links: Vec<Link>,
    /// Link requests to answer with a reason.
    pub refused: Vec<Refusal>,
    /// Logins the manager has that are hand-made accounts in the file. Left
    /// alone, and logged so the operator can be told why an edit did nothing.
    pub foreign: Vec<String>,
    /// Logins that were not written, and why: an email or a username another
    /// account already holds, a username the file cannot hold as it is, or an
    /// address still on an account that is moving off it.
    pub conflicts: Vec<(String, &'static str)>,
    /// Removals held back because the manager, too old to say what it deleted,
    /// reported no logins at all.
    pub held_back: usize,
}

impl Plan {
    pub fn changes_file(&self) -> bool {
        !(self.add.is_empty()
            && self.update.is_empty()
            && self.remove.is_empty()
            && self.replace.is_empty())
    }
}

/// What the manager is told for a link to an account the portal did not make.
const HAND_MADE_LINK: &str = "this username is an Authelia account managed by hand; the portal \
                             only sends links for accounts it created";
/// … and for a login it has no address for.
const NO_EMAIL: &str = "this login has no email the portal can use, so no link was sent";
const EMAIL_TAKEN: &str = "another Authelia account already uses this email, or has it as its \
                           username, so the portal did not write it";
const NAME_TAKEN: &str = "another Authelia account already has this username, in another case \
                          or as its email, so the portal did not create it";
const UNWRITABLE_NAME: &str = "this username cannot be written into Authelia's user file as it \
                               is, so the portal did not create it";
/// Logged, never sent to the manager: the login's request stays outstanding
/// and is tried again next cycle.
const WAITING: &str = "another Authelia account still holds its email or username, and the \
                       manager is moving that account off it; it is written once that has \
                       happened";

fn is_managed(entry: &Value, group: &str) -> bool {
    entry
        .get("groups")
        .and_then(Value::as_sequence)
        .is_some_and(|g| g.iter().any(|v| v.as_str() == Some(group)))
}

fn str_field<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
}

/// A key as the text Authelia's parser reads it as. An unquoted `12345:` is a
/// number to ours and the username "12345" to Authelia's.
fn key_text(k: &Value) -> Option<String> {
    match k {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// An email the manager accepted is still checked here: it goes into a file
/// another service parses, and becomes the address a login link is sent to.
fn plausible_email(e: &str) -> bool {
    e.len() <= 254
        && !e.chars().any(|c| c.is_control() || c.is_whitespace())
        && e.split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'))
}

/// And a username: it becomes a YAML key and the name someone signs in with.
fn plausible_username(u: &str) -> bool {
    !u.is_empty() && u.len() <= 256 && !u.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// The login's email, when it is one the portal will write.
fn usable_email(a: &ManagerAccount) -> Option<&str> {
    a.email.as_deref().filter(|e| plausible_email(e))
}

/// Can this username be a new key that Authelia reads back as the same text?
///
/// A new key is written as a string, and serde_yaml_ng quotes one wherever
/// the bare text would read as something else — `'12345':`, `'true':`,
/// `'@bob':` — so a staff number is as good a username as any. The exception
/// is `<<`, which it writes bare and Authelia's parser takes as a merge key.
/// That is refused by name, and anything else whose emitted key does not
/// parse back as the same string is refused too, so a change in the emitter
/// cannot turn into a renamed account. Asked only before creating an
/// account: an existing one is never judged by it, or a stricter rule would
/// remove it.
fn creatable_key(u: &str) -> bool {
    if u == "<<" {
        return false;
    }
    let key = Value::String(u.to_string());
    let mut probe = Mapping::new();
    probe.insert(key.clone(), Value::Null);
    serde_yaml_ng::to_string(&probe)
        .ok()
        .and_then(|text| serde_yaml_ng::from_str::<Mapping>(&text).ok())
        .is_some_and(|back| back.len() == 1 && back.contains_key(&key))
}

/// What a login asks of the file this cycle: an address, and for a new
/// account its username as well.
struct Claim<'a> {
    name: &'a str,
    email: &'a str,
    /// A new entry. Otherwise an existing managed entry taking a new address;
    /// its username it holds already.
    new: bool,
}

/// One holder of a lower-cased username or address in the file a plan would
/// write.
struct Hold<'a> {
    /// The account's name.
    owner: &'a str,
    /// Held as its email rather than its username.
    as_email: bool,
    /// The claim it comes from; `None` for what an entry keeps as it is.
    claim: Option<usize>,
}

type Holds<'a> = HashMap<String, Vec<Hold<'a>>>;

/// Everything the file would hold with the claims still `alive` written:
/// every kept entry's username, its email — or, for a managed entry whose
/// move is going ahead, the address it moves to — and each new account's
/// username and email.
fn holds<'a>(
    kept: &'a [(String, Option<&'a str>)],
    claims: &[Claim<'a>],
    alive: &[bool],
) -> Holds<'a> {
    let moving: HashSet<&str> = claims
        .iter()
        .zip(alive)
        .filter(|(c, alive)| **alive && !c.new)
        .map(|(c, _)| c.name)
        .collect();
    let mut holds = Holds::new();
    for (name, email) in kept {
        holds.entry(name.to_lowercase()).or_default().push(Hold {
            owner: name,
            as_email: false,
            claim: None,
        });
        if let Some(email) = email.filter(|_| !moving.contains(name.as_str())) {
            holds.entry(email.to_lowercase()).or_default().push(Hold {
                owner: name,
                as_email: true,
                claim: None,
            });
        }
    }
    for (i, c) in claims.iter().enumerate().filter(|(i, _)| alive[*i]) {
        holds.entry(c.email.to_lowercase()).or_default().push(Hold {
            owner: c.name,
            as_email: true,
            claim: Some(i),
        });
        if c.new {
            holds.entry(c.name.to_lowercase()).or_default().push(Hold {
                owner: c.name,
                as_email: false,
                claim: Some(i),
            });
        }
    }
    holds
}

/// The holders of `key` other than `c` itself.
fn others<'h, 'a>(holds: &'h Holds<'a>, key: &str, c: &Claim) -> Vec<&'h Hold<'a>> {
    holds
        .get(&key.to_lowercase())
        .into_iter()
        .flatten()
        .filter(|h| h.owner != c.name)
        .collect()
}

/// Which claims can be written together, and who holds what once they are.
///
/// Judged against the file as the write would leave it, so a managed account
/// moving off an address frees it for another login in the same write, and
/// two accounts can swap theirs. Repeated until nothing changes: a claim that
/// collides with what a kept entry holds is dropped first, then, between two
/// claims on one name, the later in the manager's order. A dropped move leaves
/// its account on its old address, which can drop another claim in turn.
/// Every round drops something or ends, so it ends.
fn resolve<'a>(
    kept: &'a [(String, Option<&'a str>)],
    claims: &[Claim<'a>],
) -> (Vec<bool>, Holds<'a>) {
    let keys = |c: &Claim<'a>| {
        let name = c.new.then_some(c.name);
        std::iter::once(c.email).chain(name)
    };
    let mut alive = vec![true; claims.len()];
    loop {
        let held = holds(kept, claims, &alive);
        let mut next = alive.clone();
        for (i, c) in claims.iter().enumerate().filter(|(i, _)| alive[*i]) {
            if keys(c).any(|k| others(&held, k, c).iter().any(|h| h.claim.is_none())) {
                next[i] = false;
            }
        }
        if next == alive {
            for (i, c) in claims.iter().enumerate() {
                let beaten = |k| {
                    others(&held, k, c)
                        .iter()
                        .any(|h| h.claim.is_some_and(|j| j < i && next[j]))
                };
                if next[i] && keys(c).any(beaten) {
                    next[i] = false;
                }
            }
        }
        if next == alive {
            return (alive, held);
        }
        alive = next;
    }
}

/// Why a claim `resolve` dropped was not written: the reason to answer its
/// link request with, or `None` when it should wait. It waits when every
/// holder in its way is a managed account the manager lists with another
/// address — one that could not move this cycle, and may next — or when
/// nobody holds it once the write is done.
fn refusal_for(c: &Claim, held: &Holds, moving_to: &HashMap<&str, &str>) -> Option<&'static str> {
    // Held for good: by a claim going ahead, by a username, or as an address
    // its account is not being moved off.
    let fixed = |key: &str| {
        others(held, key, c).iter().any(|h| {
            h.claim.is_some()
                || !h.as_email
                || moving_to
                    .get(h.owner)
                    .is_none_or(|to| to.to_lowercase() == key.to_lowercase())
        })
    };
    if fixed(c.email) {
        Some(EMAIL_TAKEN)
    } else if c.new && fixed(c.name) {
        Some(NAME_TAKEN)
    } else {
        None
    }
}

pub fn plan(
    users: &Mapping,
    accounts: &[ManagerAccount],
    removed: Option<&[Removal]>,
    group: &str,
) -> Plan {
    let mut p = Plan::default();

    // Every entry by the name Authelia knows it by. A key that is not a plain
    // string is never this loop's, whatever its groups say.
    let mut by_name: HashMap<String, (&Value, bool)> = HashMap::new();
    for (k, v) in users {
        if let Some(name) = key_text(k) {
            by_name
                .entry(name)
                .and_modify(|e| e.1 &= k.is_string())
                .or_insert((v, k.is_string()));
        }
    }
    let ours =
        |name: &str| matches!(by_name.get(name), Some(&(entry, true)) if is_managed(entry, group));

    // Removals first, so an address a deleted login frees can go to a new one
    // in the same cycle.
    let listed: HashSet<&str> = accounts.iter().map(|a| a.username.as_str()).collect();
    match removed {
        Some(removed) => {
            // Written only where there is a managed account to take away. A
            // username listed again has changed hands, so its entry is
            // replaced rather than kept. No entry, or a hand-made one, is
            // settled with nothing to write.
            let mut acted = HashSet::new();
            for r in removed {
                let write = ours(&r.username);
                if write && acted.insert(r.username.as_str()) {
                    if listed.contains(r.username.as_str()) {
                        p.replace.push(r.username.clone());
                    } else {
                        p.remove.push(r.username.clone());
                    }
                }
                p.removals.push((r.clone(), write));
            }
        }
        None => {
            let managed_names = users
                .iter()
                .filter(|(_, v)| is_managed(v, group))
                .filter_map(|(k, _)| k.as_str());
            let wanted: HashSet<&str> = accounts
                .iter()
                .map(|a| a.username.as_str())
                .filter(|u| plausible_username(u))
                .collect();
            p.remove = managed_names
                .filter(|n| !wanted.contains(n))
                .map(str::to_string)
                .collect();
            // An empty list removes nobody.
            //
            // To a manager that cannot say what it deleted, "it knows of no
            // logins at all" and "every login was deleted" are the same answer,
            // and the first one has causes that have nothing to do with
            // intent: a database restored from a backup taken before these
            // rows existed, a migration half-applied, a regression in the
            // query. Acting on it locks every viewer out of an event, and
            // re-creating the accounts does not give them their passwords back.
            if accounts.is_empty() {
                p.held_back = std::mem::take(&mut p.remove).len();
            }
        }
    }
    p.remove.sort();
    p.replace.sort();

    // What each login is to the file. A replaced entry is gone, so its
    // username makes a new account.
    enum Slot<'v> {
        New,
        Ours(&'v Value),
        Foreign,
    }
    let replaced: HashSet<String> = p.replace.iter().cloned().collect();
    let slot = |name: &str| match by_name.get(name) {
        _ if replaced.contains(name) => Slot::New,
        None => Slot::New,
        Some(&(entry, true)) if is_managed(entry, group) => Slot::Ours(entry),
        Some(_) => Slot::Foreign,
    };

    // Every entry the write leaves in place, with the address it holds now.
    let gone: HashSet<&str> = p
        .remove
        .iter()
        .chain(&p.replace)
        .map(String::as_str)
        .collect();
    let kept: Vec<(String, Option<&str>)> = users
        .iter()
        .filter(|(k, _)| !k.as_str().is_some_and(|n| gone.contains(n)))
        .filter_map(|(k, v)| {
            Some((
                key_text(k)?,
                str_field(v, "email").filter(|e| !e.is_empty()),
            ))
        })
        .collect();

    // What each login would write: a new account with an address, or a
    // managed account's new address. Settled together, against the file as
    // it will be.
    let mut claims = Vec::new();
    let mut claim_of = vec![None; accounts.len()];
    // The address the manager wants each managed account on.
    let mut moving_to: HashMap<&str, &str> = HashMap::new();
    for (i, a) in accounts.iter().enumerate() {
        let Some(email) = usable_email(a).filter(|_| plausible_username(&a.username)) else {
            continue;
        };
        let new = match slot(&a.username) {
            Slot::New if creatable_key(&a.username) => true,
            Slot::Ours(entry) => {
                moving_to.insert(&a.username, email);
                if str_field(entry, "email") == Some(email) {
                    continue;
                }
                false
            }
            Slot::New | Slot::Foreign => continue,
        };
        claim_of[i] = Some(claims.len());
        claims.push(Claim {
            name: &a.username,
            email,
            new,
        });
    }
    let (alive, held) = resolve(&kept, &claims);
    // A claim that was not written: answered with the reason, or left to wait.
    let dropped = |p: &mut Plan, a: &ManagerAccount, c: usize| {
        let why = refusal_for(&claims[c], &held, &moving_to);
        p.conflicts
            .push((a.username.clone(), why.unwrap_or(WAITING)));
        why
    };

    for (i, a) in accounts.iter().enumerate() {
        if !plausible_username(&a.username) {
            continue;
        }
        let email = usable_email(a);
        let mut refusal = None;
        let mut link_email = None;
        match slot(&a.username) {
            // Nothing to mail yet: a new account's link waits a cycle.
            Slot::New => match (email, claim_of[i]) {
                (None, _) => refusal = Some(NO_EMAIL),
                (Some(_), None) => {
                    p.conflicts.push((a.username.clone(), UNWRITABLE_NAME));
                    refusal = Some(UNWRITABLE_NAME);
                }
                (Some(_), Some(c)) if alive[c] => p.add.push(a.clone()),
                (Some(_), Some(c)) => refusal = dropped(&mut p, a, c),
            },
            Slot::Ours(entry) => {
                let mut update = Update {
                    username: a.username.clone(),
                    email: None,
                    display_name: a
                        .display_name
                        .clone()
                        .filter(|n| !n.is_empty() && str_field(entry, "displayname") != Some(n)),
                };
                match (email, claim_of[i]) {
                    (None, _) => refusal = Some(NO_EMAIL),
                    (Some(_), None) => link_email = str_field(entry, "email"),
                    // A new address: written now, mailed next cycle, once
                    // Authelia has loaded it rather than the one it replaces.
                    (Some(e), Some(c)) if alive[c] => update.email = Some(e.to_string()),
                    (Some(_), Some(c)) => refusal = dropped(&mut p, a, c),
                }
                if update.email.is_some() || update.display_name.is_some() {
                    p.update.push(update);
                }
            }
            Slot::Foreign => {
                p.foreign.push(a.username.clone());
                refusal = Some(HAND_MADE_LINK);
            }
        }
        let Some(at) = &a.link_requested_at else {
            continue;
        };
        if let Some(reason) = refusal {
            p.refused.push(Refusal {
                username: a.username.clone(),
                requested_at: at.clone(),
                reason,
            });
        } else if let Some(email) = link_email {
            p.links.push(Link {
                username: a.username.clone(),
                requested_at: at.clone(),
                email: email.to_string(),
                kind: if a.first_link {
                    LinkKind::Invite
                } else {
                    LinkKind::Reset
                },
                name: a
                    .display_name
                    .clone()
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| a.username.clone()),
            });
        }
    }
    p
}

/// A hash nobody holds the password for.
///
/// At argon2's minimum cost: the cost of a hash is what protects a guessable
/// password from a stolen file, and this one hides 256 random bits nobody has,
/// so the default's 19 MiB and two passes would buy nothing but a stalled
/// sync. Still an argon2id PHC string, which is all Authelia checks for.
fn unusable_password_hash() -> anyhow::Result<String> {
    use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let params = Params::new(
        Params::MIN_M_COST,
        Params::MIN_T_COST,
        Params::MIN_P_COST,
        None,
    )
    .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    let hash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(&secret)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(hash.to_string())
}

/// Why rewriting the file would change an entry this loop does not own, if it
/// would.
///
/// Authelia's parser reads a scalar into a string field as the text it was
/// written as; ours reads `+61412345678` as a number and writes it back as
/// `61412345678`, `True` as `true`, `0x1F` as `31`. On a key that renames the
/// account, and in an email it changes the address. Which text was written is
/// lost by the time the file is parsed, so any such scalar stops the write —
/// quoting it costs the operator one edit, guessing wrong costs the account.
fn unrewritable(users: &Mapping, group: &str) -> Option<String> {
    for (k, v) in users {
        let Some(name) = k.as_str() else {
            let shown = key_text(k).unwrap_or_else(|| format!("{k:?}"));
            return Some(format!(
                "the account key `{shown}` is not quoted text; quote it in the file ('{shown}':)"
            ));
        };
        if is_managed(v, group) {
            continue;
        }
        let Some(fields) = v.as_mapping() else {
            continue;
        };
        for (f, fv) in fields {
            let Some(field) = f.as_str() else {
                return Some(format!(
                    "the account `{name}` has a field whose name is not quoted text; quote it in \
                     the file"
                ));
            };
            let odd = |s: &Value| s.is_number() || (s.is_bool() && field != "disabled");
            if odd(fv) || fv.as_sequence().is_some_and(|s| s.iter().any(odd)) {
                return Some(format!(
                    "the account `{name}` has an unquoted number or true/false in `{field}`, \
                     which rewriting the file would change; quote it in the file"
                ));
            }
        }
    }
    None
}

/// Apply `p` to the parsed file. Leaves every entry it does not own as it was
/// read, and where it was: removal shifts rather than swaps.
pub fn apply(
    doc: &mut Value,
    p: &Plan,
    group: &str,
    mut new_hash: impl FnMut() -> anyhow::Result<String>,
) -> anyhow::Result<()> {
    if !doc.is_mapping() {
        *doc = Value::Mapping(Mapping::new());
    }
    let root = doc.as_mapping_mut().expect("just made a mapping");
    let users_key = Value::String("users".into());
    if !root.get(&users_key).is_some_and(Value::is_mapping) {
        root.insert(users_key.clone(), Value::Mapping(Mapping::new()));
    }
    let users = root
        .get_mut(&users_key)
        .and_then(Value::as_mapping_mut)
        .expect("just made a mapping");

    for name in p.remove.iter().chain(&p.replace) {
        users.shift_remove(Value::String(name.clone()));
    }
    for a in &p.add {
        let mut e = Mapping::new();
        e.insert("disabled".into(), Value::Bool(false));
        e.insert(
            "displayname".into(),
            Value::String(
                a.display_name
                    .clone()
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| a.username.clone()),
            ),
        );
        e.insert("password".into(), Value::String(new_hash()?));
        e.insert(
            "email".into(),
            Value::String(a.email.clone().unwrap_or_default()),
        );
        e.insert(
            "groups".into(),
            Value::Sequence(vec![Value::String(group.to_string())]),
        );
        users.insert(Value::String(a.username.clone()), Value::Mapping(e));
    }
    for u in &p.update {
        if let Some(Value::Mapping(e)) = users.get_mut(Value::String(u.username.clone())) {
            if let Some(email) = &u.email {
                e.insert("email".into(), Value::String(email.clone()));
            }
            if let Some(n) = &u.display_name {
                e.insert("displayname".into(), Value::String(n.clone()));
            }
        }
    }
    Ok(())
}

/// The file as read, with what is needed to tell whether it changed since.
struct Snapshot {
    doc: Value,
    ino: u64,
    modified: Option<SystemTime>,
    len: u64,
}

impl Snapshot {
    fn users(&self) -> Option<&Mapping> {
        self.doc.get("users").and_then(Value::as_mapping)
    }

    /// Is `meta` still the file this was read from, unchanged?
    fn matches(&self, meta: &std::fs::Metadata) -> bool {
        meta.ino() == self.ino && meta.modified().ok() == self.modified && meta.len() == self.len
    }
}

fn read_users_file(path: &Path) -> anyhow::Result<Snapshot> {
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("cannot stat {}: {e}", path.display()))?;
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    let doc: Value = if text.trim().is_empty() {
        Value::Mapping(Mapping::new())
    } else {
        serde_yaml_ng::from_str(&text)
            .map_err(|e| anyhow::anyhow!("cannot parse {}: {e}", path.display()))?
    };
    Ok(Snapshot {
        doc,
        ino: meta.ino(),
        modified: meta.modified().ok(),
        len: meta.len(),
    })
}

/// A failed write to the users directory, with the fix when there is an
/// obvious one. The loop logs a failure once, so that one line has to say
/// what to do.
fn cannot_write(what: &Path, dir: &Path, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::ReadOnlyFilesystem {
        anyhow::anyhow!(
            "cannot write {}: {e}. This service may not write {}: add \
             `ReadWritePaths={}` to bilbycast-portal.service with `systemctl edit \
             bilbycast-portal`, then restart it",
            what.display(),
            dir.display(),
            dir.display(),
        )
    } else {
        anyhow::anyhow!("cannot write {}: {e}", what.display())
    }
}

/// Whether `uid` belongs to group `gid`, as `passwd` and `group` (the text of
/// /etc/passwd and /etc/group) say. `None` when `uid` is not in them — one
/// from a directory service, or a container's that no host user shares —
/// which cannot be judged from here. A container uid that a host user does
/// share is judged as that host user, which is why a refusal says so.
fn in_group(passwd: &str, group: &str, uid: u32, gid: u32) -> Option<bool> {
    let fields = |l: &str| l.split(':').map(str::to_string).collect::<Vec<_>>();
    let id = |f: &str| f.parse::<u32>().ok();
    let user = passwd
        .lines()
        .map(fields)
        .find(|f| f.len() >= 4 && id(&f[2]) == Some(uid))?;
    if id(&user[3]) == Some(gid) {
        return Some(true);
    }
    let listed = group
        .lines()
        .map(fields)
        .any(|f| f.len() >= 4 && id(&f[2]) == Some(gid) && f[3].split(',').any(|m| m == user[0]));
    Some(listed)
}

/// Does a file's group reach it in a way everyone else does not? Only then
/// does handing the file to another group take anything from anyone.
fn group_matters(mode: u32) -> bool {
    ((mode >> 3) & 0o7) & !(mode & 0o7) != 0
}

/// Why putting a file owned `new_uid:new_gid` in place of `path`, owned
/// `old_uid:old_gid`, both with `mode`, would take the file away from someone
/// who can use it now — with what to do about it — or `None` when it would
/// not.
///
/// Authelia must still read the file, and write it when someone sets a
/// password. A rename replaces the owner, and the old one keeps the file only
/// through its group; once this process owns the file, Authelia reaches it only
/// that way too. So the group must not change while it grants anything
/// `other` does not, and when the owner changes, it must grant read-write and
/// have the old owner in it. A root owner needs none of that — root is kept out
/// by no mode bit — so a root-owned `0644` file, in root's group, is replaced
/// as it is.
fn lockout(
    path: &Path,
    (old_uid, old_gid): (u32, u32),
    (new_uid, new_gid): (u32, u32),
    mode: u32,
    owner_in_group: impl FnOnce(u32, u32) -> Option<bool>,
) -> Option<String> {
    let file = path.display();
    if new_gid != old_gid && group_matters(mode) {
        return Some(format!(
            "the replacement would belong to group {new_gid}, not the file's group {old_gid}, \
             which the portal is not in and so cannot keep. Give the file a group the portal \
             is in: `chgrp {new_gid} {file}`, and put Authelia's user in that group too unless \
             Authelia runs as root"
        ));
    }
    if old_uid == new_uid || old_uid == 0 {
        return None;
    }
    if mode & 0o060 != 0o060 {
        return Some(format!(
            "it is owned by uid {old_uid}, who could reach the replacement only through its \
             group, and its mode {:o} gives the group no read-write: `chmod g+rw {file}`",
            mode & 0o777
        ));
    }
    if owner_in_group(old_uid, old_gid) == Some(false) {
        return Some(format!(
            "it is owned by uid {old_uid}, who could reach the replacement only through its \
             group, and this host's /etc/passwd and /etc/group do not put that user in group \
             {old_gid}: `usermod -aG {old_gid} <Authelia's user>`, then restart Authelia. \
             That check reads this host's account files only, so for an Authelia in a \
             container, or one given the group by SupplementaryGroups=, add the host user \
             with uid {old_uid} to the group as well"
        ));
    }
    None
}

/// Replace the file, unless somebody else changed it since `snap` was taken.
///
/// Returns `Ok(false)` for the lost race, which is not an error: Authelia has
/// just written a password, and the next cycle re-plans from that.
fn write_users_file(path: &Path, snap: &Snapshot, doc: &Value) -> anyhow::Result<bool> {
    let body = serde_yaml_ng::to_string(doc)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.portal-tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("users.yml")
    ));
    let written = replace_file(path, dir, &tmp, snap, body.as_bytes());
    if !matches!(written, Ok(true)) {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Write `body` to `tmp` and rename it over `path`: the file's mode and group,
/// on disk before it is visible, and only if `path` is still what `snap` read.
fn replace_file(
    path: &Path,
    dir: &Path,
    tmp: &Path,
    snap: &Snapshot,
    body: &[u8],
) -> anyhow::Result<bool> {
    let old = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => anyhow::bail!("cannot stat {}: {e}", path.display()),
    };
    // Owner-only until it is the file's own mode: it holds password hashes. A
    // temp file left by a crash is removed rather than reused, so it cannot
    // carry permissions of its own into the new file.
    let _ = std::fs::remove_file(tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .map_err(|e| cannot_write(tmp, dir, e))?;
    f.write_all(body).map_err(|e| cannot_write(tmp, dir, e))?;

    // Authelia keeps the file only through its group once this process owns
    // it. The directory's setgid bit normally gives the new file the old
    // group; where it does not, give it explicitly, which needs no privilege
    // for a group this process is in.
    if f.metadata()?.gid() != old.gid() {
        let _ = std::os::unix::fs::fchown(&f, None, Some(old.gid()));
    }
    f.set_permissions(std::fs::Permissions::from_mode(old.mode() & 0o777))
        .map_err(|e| anyhow::anyhow!("cannot set the mode of {}: {e}", tmp.display()))?;
    let new = f.metadata()?;
    let membership = |uid, gid| {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        let group = std::fs::read_to_string("/etc/group").ok()?;
        in_group(&passwd, &group, uid, gid)
    };
    if let Some(why) = lockout(
        path,
        (old.uid(), old.gid()),
        (new.uid(), new.gid()),
        old.mode(),
        membership,
    ) {
        anyhow::bail!("not replacing {}: {why}", path.display());
    }
    f.sync_all()
        .map_err(|e| anyhow::anyhow!("cannot flush {}: {e}", tmp.display()))?;
    drop(f);

    // As late as it can be: the window this leaves is the rename itself.
    match std::fs::metadata(path) {
        Ok(now) if snap.matches(&now) => {}
        _ => return Ok(false),
    }
    std::fs::rename(tmp, path)
        .map_err(|e| anyhow::anyhow!("cannot replace {}: {e}", path.display()))?;
    // The rename is only durable once the directory is: without this, a crash
    // soon after can leave an empty users file, and Authelia will not start.
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(true)
}

/// The most of a link error the manager keeps. A current one truncates to it;
/// an older one refuses anything longer, which would leave the request
/// outstanding for ever, so it is cut here too.
const MAX_ACK_ERROR: usize = 300;

/// A reason as the manager will store it: one line, at most
/// [`MAX_ACK_ERROR`] bytes, cut on a character boundary. SMTP rejections run
/// to several hundred bytes over several lines.
fn bound_error(e: &str) -> String {
    let mut s: String = e
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let mut end = s.len().min(MAX_ACK_ERROR);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

/// A link request, as far as it got.
#[derive(Debug)]
enum LinkError {
    /// Authelia's reset rate limit, with how long it asked for.
    RateLimited(Option<Duration>),
    Failed(String),
}

/// A request served, remembered until the manager stops asking for it.
struct Served {
    /// What the manager is told: `None` for sent.
    outcome: Option<String>,
    acked: bool,
    /// Said in the log already, so the next cycle stays quiet.
    warned: bool,
}

/// What the loop remembers between cycles, for as long as the process runs.
#[derive(Default)]
struct Memory {
    /// Every link request served, by `(username, requested_at)`. An email
    /// cannot be unsent, so an acknowledgement that fails is retried from
    /// here, never by asking Authelia for another.
    served: HashMap<(String, String), Served>,
    /// Removal records a landed write has applied, kept until the manager
    /// stops listing them. Never applied twice: a replaced account may have a
    /// password its new owner set since, so an acknowledgement that fails is
    /// retried from here, never by replacing the account again.
    applied: HashSet<Removal>,
    /// A removal acknowledgement has failed, and the log has said so.
    removal_ack_failing: bool,
    /// Authelia's rate limit: no link is asked for before then.
    paused_until: Option<Instant>,
    /// Authelia has rate-limited a link, and the log has said so. Cleared by
    /// any other answer from Authelia, or when the pause it asked for is
    /// over, so the next episode is said too.
    limited: bool,
    /// Plan notes already logged.
    noted: HashSet<String>,
    /// Why the last cycle could not read or write Authelia's file, bounded
    /// like a link error. Sent with the next poll, so the manager can say why
    /// its logins are not reaching Authelia; `None` once nothing stood in the
    /// way of a write, or nothing needed writing.
    sync_error: Option<String>,
}

impl Memory {
    /// Log what this plan says that the last one did not.
    fn note(&mut self, p: &Plan) {
        let mut now = HashSet::new();
        for u in &p.foreign {
            let line = format!(
                "`{u}` is a hand-made Authelia account; its portal login's email, name and links \
                 are not applied to it"
            );
            if !self.noted.contains(&line) {
                tracing::warn!("{line}");
            }
            now.insert(line);
        }
        for (u, why) in &p.conflicts {
            let line = format!("portal login `{u}` was not written to Authelia: {why}");
            if !self.noted.contains(&line) {
                tracing::warn!("{line}");
            }
            now.insert(line);
        }
        if p.held_back > 0 {
            let line = format!(
                "the manager reports no portal logins at all; leaving {} Authelia account(s) \
                 alone rather than deleting every one. Remove them by hand if that is really \
                 what was wanted.",
                p.held_back
            );
            if !self.noted.contains(&line) {
                tracing::warn!("{line}");
            }
            now.insert(line);
        }
        self.noted = now;
    }
}

/// What one cycle did, for the log.
#[derive(Debug, Default)]
struct Outcome {
    added: usize,
    updated: usize,
    removed: usize,
    replaced: usize,
    links_sent: usize,
    links_refused: usize,
    lost_race: bool,
    /// The file was not written, and why. Links for accounts it would have
    /// changed wait; everyone else's go ahead.
    write_error: Option<String>,
}

/// One sync: fetch, plan, write, acknowledge removals, request links,
/// acknowledge those.
async fn sync_once(
    state: &PortalState,
    cfg: &AccountSyncConfig,
    memory: &mut Memory,
) -> anyhow::Result<Outcome> {
    let mut poll = state
        .http
        .get(format!(
            "{}/api/v1/dvr/portal/accounts",
            state.cfg.manager_url
        ))
        .query(&[("interval_secs", cfg.interval_secs)]);
    // Only here does the manager hear that its logins are not reaching
    // Authelia; the portal's journal is not somewhere an operator looks.
    if let Some(e) = &memory.sync_error {
        poll = poll.query(&[("sync_error", e)]);
    }
    let resp = poll.bearer_auth(&state.cfg.manager_token).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("manager answered {} for the account list", resp.status());
    }
    let answer = resp.json::<AccountsResponse>().await?;
    let accounts = answer.accounts;
    let removed = answer.removed;
    let unapplied: Option<Vec<Removal>> = removed.as_ref().map(|r| {
        r.iter()
            .filter(|r| !memory.applied.contains(*r))
            .cloned()
            .collect()
    });

    let path = cfg.users_file.clone();
    let snap = match tokio::task::spawn_blocking(move || read_users_file(&path)).await? {
        Ok(snap) => snap,
        Err(e) => {
            memory.sync_error = Some(bound_error(&format!("{e:#}")));
            return Err(e);
        }
    };
    let empty = Mapping::new();
    let p = plan(
        snap.users().unwrap_or(&empty),
        &accounts,
        unapplied.as_deref(),
        &cfg.managed_group,
    );
    memory.note(&p);

    let mut out = Outcome::default();
    // Whether this cycle's changes are in the file — trivially so when there
    // were none.
    let mut landed = true;
    if p.changes_file() {
        let (path, group, changes) = (cfg.users_file.clone(), cfg.managed_group.clone(), p.clone());
        // Hashing included: it is CPU, and this runtime also serves viewers.
        let written = tokio::task::spawn_blocking(move || {
            if let Some(why) = unrewritable(snap.users().unwrap_or(&Mapping::new()), &group) {
                anyhow::bail!("not rewriting {}: {why}", path.display());
            }
            let mut doc = snap.doc.clone();
            apply(&mut doc, &changes, &group, unusable_password_hash)?;
            write_users_file(&path, &snap, &doc)
        })
        .await?;
        match written {
            Ok(true) => {
                out.added = p.add.len();
                out.updated = p.update.len();
                out.removed = p.remove.len();
                out.replaced = p.replace.len();
                memory.sync_error = None;
            }
            // Authelia wrote first, after every check that could have stopped
            // the write had passed: nothing is blocked, so nothing is
            // reported. The next cycle re-plans from Authelia's file.
            Ok(false) => {
                out.lost_race = true;
                memory.sync_error = None;
                landed = false;
            }
            Err(e) => {
                let e = format!("{e:#}");
                memory.sync_error = Some(bound_error(&e));
                out.write_error = Some(e);
                landed = false;
            }
        }
    } else {
        memory.sync_error = None;
    }
    // Accounts this cycle would have changed are as they were if the write
    // did not land; their links wait for one that does.
    let unsettled: HashSet<&str> = if landed {
        HashSet::new()
    } else {
        p.add
            .iter()
            .map(|a| a.username.as_str())
            .chain(p.update.iter().map(|u| u.username.as_str()))
            .collect()
    };

    for (r, needs_write) in &p.removals {
        if landed || !needs_write {
            memory.applied.insert(r.clone());
        }
    }
    if let Some(removed) = &removed {
        memory.applied.retain(|r| removed.contains(r));
        for r in removed.iter().filter(|r| memory.applied.contains(*r)) {
            let failed = match acknowledge_removal(state, r).await {
                Ok(true) => None,
                Ok(false) => Some(
                    "the manager has no route to acknowledge a removal on, so it is older than \
                     this portal; its removal records stay until it is upgraded, and none is \
                     applied twice meanwhile"
                        .to_string(),
                ),
                Err(e) => Some(format!(
                    "could not tell the manager a removal was applied ({e:#}); retrying without \
                     applying it again"
                )),
            };
            match failed {
                None => memory.removal_ack_failing = false,
                Some(why) if !memory.removal_ack_failing => {
                    memory.removal_ack_failing = true;
                    tracing::warn!(username = %r.username, "{why}");
                }
                Some(_) => {}
            }
        }
    }

    let pending = state.cfg.mail.is_some().then_some(&*state.links);
    // A pause that has run out ends the episode, so the next 429 is said.
    if memory.paused_until.is_some_and(|t| Instant::now() >= t) {
        memory.paused_until = None;
        memory.limited = false;
    }
    let mut asking = memory.paused_until.is_none();
    let mut planned = HashSet::new();
    for r in &p.refused {
        let key = (r.username.clone(), r.requested_at.clone());
        planned.insert(key.clone());
        if !memory.served.contains_key(&key) {
            out.links_refused += 1;
        }
        serve(state, memory, key, || Some(r.reason.to_string())).await;
    }
    for l in &p.links {
        let key = (l.username.clone(), l.requested_at.clone());
        planned.insert(key.clone());
        if unsettled.contains(l.username.as_str()) {
            continue;
        }
        if !memory.served.contains_key(&key) {
            if !asking {
                continue;
            }
            match send_link(state, cfg, pending, l).await {
                Ok(()) => {
                    out.links_sent += 1;
                    memory.limited = false;
                    memory.served.insert(key.clone(), Served::new(None));
                }
                // Authelia answered, and not with its limit: that episode is
                // over.
                Err(LinkError::Failed(e)) => {
                    memory.limited = false;
                    memory.served.insert(key.clone(), Served::new(Some(e)));
                }
                // Not acknowledged, so it stays outstanding, and no further
                // link is asked for this cycle: each would be refused the same
                // way, and counts against the limit.
                Err(LinkError::RateLimited(after)) => {
                    asking = false;
                    memory.paused_until = after.map(|d| Instant::now() + d);
                    if !memory.limited {
                        memory.limited = true;
                        tracing::warn!(
                            "Authelia is rate-limiting password links; the rest wait for a \
                             later cycle"
                        );
                    }
                    continue;
                }
            }
        }
        serve(state, memory, key, || None).await;
    }
    memory.served.retain(|k, _| planned.contains(k));
    Ok(out)
}

impl Served {
    fn new(outcome: Option<String>) -> Self {
        Served {
            outcome: outcome.map(|e| bound_error(&e)),
            acked: false,
            warned: false,
        }
    }
}

/// Tell the manager how `key` went, remembering it so the manager is never
/// answered twice and the person never mailed twice.
///
/// `fresh` is the outcome when there is none on record yet. A failed
/// acknowledgement is logged once and retried next cycle; it never stops the
/// requests after it.
async fn serve(
    state: &PortalState,
    memory: &mut Memory,
    key: (String, String),
    fresh: impl FnOnce() -> Option<String>,
) {
    let served = memory
        .served
        .entry(key.clone())
        .or_insert_with(|| Served::new(fresh()));
    if served.acked {
        if !served.warned {
            served.warned = true;
            tracing::warn!(
                username = %key.0,
                "the manager still lists a link request it acknowledged; not sending it again"
            );
        }
        return;
    }
    match acknowledge(state, &key.0, &key.1, served.outcome.as_deref()).await {
        Ok(()) => {
            served.acked = true;
            served.warned = false;
        }
        Err(e) => {
            if !served.warned {
                served.warned = true;
                tracing::warn!(
                    username = %key.0, error = %e,
                    "could not tell the manager how a password link went; retrying without \
                     sending it again"
                );
            }
        }
    }
}

/// How long to wait for the rewritten email to reach the relay.
///
/// Authelia mails during the request that asks it to, so this is normally
/// already done by the time it answers. The wait exists so the manager is told
/// what actually happened rather than that the request was accepted.
const RELAY_WAIT: Duration = Duration::from_secs(30);

// The listener forgets an expectation no later than this wait gives up on it,
// and its relay gives up before either, so a slow relay is reported as the
// relay's answer and a stale expectation never rewrites a later email.
const _: () = assert!(
    super::mail::PENDING_TTL.as_secs() <= RELAY_WAIT.as_secs()
        && super::mail::RELAY_TIMEOUT.as_secs() < RELAY_WAIT.as_secs()
);

/// Ask Authelia for a link, and report whether the email really went.
///
/// With [`mail`](super::mail) rewriting it, `pending` is its list of links to
/// expect: the link's address is registered there first — the address in
/// Authelia's file, which is the one it will mail — and that registration is
/// also what tells the listener whether to write an invitation or a password
/// reset.
async fn send_link(
    state: &PortalState,
    cfg: &AccountSyncConfig,
    pending: Option<&PendingLinks>,
    link: &Link,
) -> Result<(), LinkError> {
    let waiter = match pending {
        Some(p) => Some(p.expect(&link.email, link.kind, &link.name).await),
        None => None,
    };

    if let Err(e) = request_link(state, cfg, &link.username).await {
        if let Some(p) = pending {
            p.forget(&link.email).await;
        }
        return Err(e);
    }

    let Some(waiter) = waiter else { return Ok(()) };
    match tokio::time::timeout(RELAY_WAIT, waiter).await {
        Ok(Ok(result)) => result.map_err(LinkError::Failed),
        // The listener dropped the expectation without reporting, which should
        // not happen; say so rather than claiming success.
        Ok(Err(_)) => Err(LinkError::Failed(
            "the portal never saw the email Authelia was asked to send".into(),
        )),
        Err(_) => Err(LinkError::Failed(
            "timed out waiting for Authelia's email; check that Authelia's notifier points at \
             mail.listen_addr, authenticates with mail.listen_password_file, and sends from \
             mail.from's address"
                .into(),
        )),
    }
}

/// Authelia's JSON envelope: `{"status":"OK"}`, or `"KO"` with a message.
#[derive(Deserialize)]
struct AutheliaReply {
    status: String,
    #[serde(default)]
    message: Option<String>,
}

/// The most of Authelia's `Retry-After` honoured. Its buckets are half an
/// hour at most; a larger value is a mistake that would stop every link.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3600);

/// Ask Authelia to email `username` a set-your-password link.
///
/// Authelia reports a failed send — its notifier, a host outside its cookie
/// domains, its storage — as `200` with `{"status":"KO"}`, so the status code
/// alone says nothing. Only an `OK` in the body is success.
async fn request_link(
    state: &PortalState,
    cfg: &AccountSyncConfig,
    username: &str,
) -> Result<(), LinkError> {
    let resp = state
        .http
        .post(format!(
            "{}/api/reset-password/identity/start",
            cfg.authelia_url
        ))
        // Authelia builds the link from these. Straight to loopback, so
        // nothing else sets them, and the link names the public host.
        .header("X-Forwarded-Proto", "https")
        .header("X-Forwarded-Host", &cfg.public_host)
        .header("X-Forwarded-For", "127.0.0.1")
        .json(&serde_json::json!({ "username": username }))
        .send()
        .await
        .map_err(|e| LinkError::Failed(format!("could not reach Authelia: {e}")))?;
    let status = resp.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|s| Duration::from_secs(s).min(MAX_RETRY_AFTER));
        return Err(LinkError::RateLimited(after));
    }
    let reply = resp
        .bytes()
        .await
        .ok()
        .and_then(|b| serde_json::from_slice::<AutheliaReply>(&b).ok());
    if !status.is_success() {
        return Err(LinkError::Failed(match reply.and_then(|r| r.message) {
            Some(m) => format!("Authelia refused the request ({status}): {m}"),
            None => format!("Authelia refused the request ({status})"),
        }));
    }
    match reply {
        Some(r) if r.status == "OK" => Ok(()),
        Some(r) => Err(LinkError::Failed(format!(
            "Authelia could not send the link: {} (see Authelia's log)",
            r.message.as_deref().unwrap_or("no reason given")
        ))),
        None => Err(LinkError::Failed(
            "Authelia sent a reply the portal could not read".into(),
        )),
    }
}

async fn acknowledge(
    state: &PortalState,
    username: &str,
    requested_at: &str,
    error: Option<&str>,
) -> anyhow::Result<()> {
    let resp = state
        .http
        .post(format!(
            "{}/api/v1/dvr/portal/accounts/link-sent",
            state.cfg.manager_url
        ))
        .bearer_auth(&state.cfg.manager_token)
        .json(&serde_json::json!({
            "username": username,
            "requested_at": requested_at,
            "error": error,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "manager answered {} to a link acknowledgement",
            resp.status()
        );
    }
    Ok(())
}

/// Tell the manager a removal is applied, so it forgets the record.
///
/// `Ok(false)` when the manager has no such route: one older than removal
/// acknowledgements, which lists its records until it is upgraded and is
/// otherwise unaffected.
async fn acknowledge_removal(state: &PortalState, r: &Removal) -> anyhow::Result<bool> {
    let resp = state
        .http
        .post(format!(
            "{}/api/v1/dvr/portal/accounts/removed-applied",
            state.cfg.manager_url
        ))
        .bearer_auth(&state.cfg.manager_token)
        .json(&serde_json::json!({
            "username": r.username,
            "removed_at": r.removed_at,
        }))
        .send()
        .await?;
    match resp.status() {
        s if s.is_success() => Ok(true),
        reqwest::StatusCode::NOT_FOUND => Ok(false),
        s => anyhow::bail!("manager answered {s} to a removal acknowledgement"),
    }
}

/// How often the startup probe asks, and for how long before it says so. At
/// boot Authelia starts after the portal — its notifier needs the portal's
/// mail listener — so the first answers are expected to fail.
const PROBE_EVERY: Duration = Duration::from_secs(10);
const PROBE_WITHIN: Duration = Duration::from_secs(120);

/// Does Authelia answer its health check at `authelia_url`? Only its own
/// `{"status":"OK"}` counts: an Authelia at the root serves its sign-in page,
/// with a 200, for a path under a `/auth` it does not have.
async fn authelia_health(state: &PortalState, cfg: &AccountSyncConfig) -> Result<(), String> {
    let resp = state
        .http
        .get(format!("{}/api/health", cfg.authelia_url))
        .send()
        .await
        .map_err(|e| {
            format!(
                "could not reach Authelia at accounts.authelia_url ({e}); password links will \
                 fail until it answers there"
            )
        })?;
    let status = resp.status();
    let healthy = status.is_success()
        && resp
            .bytes()
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<AutheliaReply>(&b).ok())
            .is_some_and(|r| r.status == "OK");
    if healthy {
        return Ok(());
    }
    Err(format!(
        "Authelia's health check did not answer at accounts.authelia_url ({status}, and not \
         Authelia's own OK); its path must be the path of Authelia's own server.address, and \
         every password link will fail until it is"
    ))
}

/// Is Authelia where `authelia_url` says? Asked at startup, every `every`
/// until it answers or `within` has passed, and only then reported: a wrong
/// path prefix otherwise shows up only as a refusal against every link, one
/// login at a time.
async fn probe_authelia(
    state: &PortalState,
    cfg: &AccountSyncConfig,
    every: Duration,
    within: Duration,
) -> Result<(), String> {
    let until = Instant::now() + within;
    loop {
        match authelia_health(state, cfg).await {
            Ok(()) => return Ok(()),
            Err(e) if Instant::now() + every > until => return Err(e),
            Err(_) => tokio::time::sleep(every).await,
        }
    }
}

/// The loop, with the startup probe beside it rather than ahead of it: a
/// sync does not wait two minutes for an Authelia that is still starting.
pub async fn run(state: PortalState, cfg: AccountSyncConfig) {
    let probe = async {
        if let Err(e) = probe_authelia(&state, &cfg, PROBE_EVERY, PROBE_WITHIN).await {
            tracing::error!(authelia_url = %cfg.authelia_url, "{e}");
        }
    };
    tokio::join!(probe, sync_loop(&state, &cfg));
}

/// A problem is logged when it starts, changes or clears, rather than every
/// fifteen seconds for as long as it lasts.
async fn sync_loop(state: &PortalState, cfg: &AccountSyncConfig) {
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut memory = Memory::default();
    let mut problem: Option<String> = None;
    loop {
        ticker.tick().await;
        let now = match sync_once(state, cfg, &mut memory).await {
            Ok(o) => {
                if o.added + o.updated + o.removed + o.replaced + o.links_sent + o.links_refused > 0
                {
                    tracing::info!(
                        added = o.added,
                        updated = o.updated,
                        removed = o.removed,
                        replaced = o.replaced,
                        links_sent = o.links_sent,
                        links_refused = o.links_refused,
                        "portal accounts synced to Authelia"
                    );
                }
                if o.lost_race {
                    tracing::info!("Authelia changed its user file mid-sync; retrying next cycle");
                }
                o.write_error
            }
            Err(e) => Some(format!("{e:#}")),
        };
        if now != problem {
            match &now {
                Some(e) => tracing::warn!(
                    error = %e,
                    "portal account sync failing; logins in the manager are not reaching Authelia"
                ),
                None => tracing::info!("portal account sync recovered"),
            }
            problem = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: &str = "bilbycast-portal";

    fn acct(u: &str, email: Option<&str>) -> ManagerAccount {
        ManagerAccount {
            username: u.into(),
            email: email.map(Into::into),
            display_name: None,
            link_requested_at: None,
            first_link: false,
        }
    }

    fn asking(mut a: ManagerAccount, at: &str) -> ManagerAccount {
        a.link_requested_at = Some(at.into());
        a
    }

    /// The manager's removal records for `names`.
    fn gone(names: &[&str]) -> Vec<Removal> {
        names
            .iter()
            .map(|n| Removal {
                username: n.to_string(),
                removed_at: "2026-09-24T08:00:00.123456Z".into(),
            })
            .collect()
    }

    fn file(yaml: &str) -> Value {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    fn users(doc: &Value) -> Mapping {
        doc.get("users")
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_default()
    }

    fn names(v: &[ManagerAccount]) -> Vec<&str> {
        v.iter().map(|a| a.username.as_str()).collect()
    }

    /// `(username, the address it goes to)` for every planned link.
    fn links(p: &Plan) -> Vec<(&str, &str)> {
        p.links
            .iter()
            .map(|l| (l.username.as_str(), l.email.as_str()))
            .collect()
    }

    fn refused(p: &Plan) -> Vec<(&str, &str)> {
        p.refused
            .iter()
            .map(|r| (r.username.as_str(), r.reason))
            .collect()
    }

    const HAND_MADE: &str = r#"
users:
  dvr-test:
    disabled: false
    displayname: "DVR Test"
    password: "$argon2id$v=19$m=65536,t=3,p=4$handmade"
    email: dvr-test@example.com
    groups: []
  a.smith:
    disabled: false
    displayname: "Alex Smith"
    password: "$argon2id$v=19$m=19456,t=2,p=1$chosen-by-alex"
    email: alex@example.com
    groups: [bilbycast-portal, editors]
"#;

    #[test]
    fn a_login_with_an_email_becomes_an_account_and_one_without_does_not() {
        let doc = file("users: {}");
        let p = plan(
            &users(&doc),
            &[acct("new", Some("new@example.com")), acct("noemail", None)],
            Some(&[]),
            G,
        );
        assert_eq!(names(&p.add), ["new"]);
        assert!(p.remove.is_empty() && p.update.is_empty());
    }

    #[test]
    fn a_hand_made_account_is_never_rewritten_and_never_sent_a_link() {
        let doc = file(HAND_MADE);
        // The manager has a login called dvr-test, with a different email, and
        // somebody pressed "send link" on it.
        let mut a = asking(
            acct("dvr-test", Some("someone-else@example.com")),
            "2026-09-22T08:00:00Z",
        );
        a.display_name = Some("Renamed".into());
        let p = plan(
            &users(&doc),
            &[a, acct("a.smith", Some("alex@example.com"))],
            Some(&[]),
            G,
        );
        assert!(
            p.update.is_empty(),
            "a hand-made account would be rewritten: {p:?}"
        );
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign, ["dvr-test"]);
        assert!(p.links.is_empty(), "a hand-made account was sent a link");
        assert_eq!(
            refused(&p),
            [(
                "dvr-test",
                "this username is an Authelia account managed by hand; the portal only sends \
                 links for accounts it created"
            )],
            "the manager must be told why, in the words it expects"
        );

        // And its entry survives an apply with the same content.
        let mut doc2 = doc.clone();
        let p = plan(
            &users(&doc),
            &[acct("x", Some("x@example.com"))],
            Some(&[]),
            G,
        );
        apply(&mut doc2, &p, G, || Ok("$argon2id$fake".into())).unwrap();
        assert_eq!(doc2["users"]["dvr-test"], doc["users"]["dvr-test"]);
    }

    #[test]
    fn an_account_goes_only_when_the_manager_says_its_login_was_deleted() {
        let doc = file(HAND_MADE);
        let someone = || acct("someone.else", Some("s@example.com"));

        // Missing from the list is not deleted: a manager restored from an
        // older backup lists nothing created since.
        let p = plan(&users(&doc), &[someone()], Some(&[]), G);
        assert!(p.remove.is_empty(), "absence alone removed an account");

        let removed = gone(&["a.smith", "dvr-test"]);
        let p = plan(&users(&doc), &[someone()], Some(&removed), G);
        assert_eq!(
            p.remove,
            ["a.smith"],
            "only the managed account goes, never a hand-made one of the same name"
        );
        assert_eq!(
            p.removals,
            [(removed[0].clone(), true), (removed[1].clone(), false)],
            "the hand-made one's record is settled with nothing to write"
        );

        // The last login deleted is deleted too: the list says so outright.
        let p = plan(&users(&doc), &[], Some(&removed), G);
        assert_eq!(p.remove, ["a.smith"]);
        assert_eq!(p.held_back, 0);
    }

    /// Removed and added again before the portal saw the removal: the same
    /// username, but a different person, who must not inherit a password the
    /// last one chose.
    #[test]
    fn a_username_given_out_again_is_made_afresh_not_kept() {
        let doc = file(HAND_MADE);
        let mut sam = asking(
            acct("a.smith", Some("sam@example.com")),
            "2026-09-24T08:05:00Z",
        );
        sam.display_name = Some("Sam Smith".into());
        sam.first_link = true;
        let removed = gone(&["a.smith"]);
        let p = plan(&users(&doc), std::slice::from_ref(&sam), Some(&removed), G);
        assert_eq!(p.replace, ["a.smith"]);
        assert!(p.remove.is_empty() && p.update.is_empty(), "{p:?}");
        assert_eq!(names(&p.add), ["a.smith"]);
        assert_eq!(p.removals, [(removed[0].clone(), true)]);
        assert!(
            p.links.is_empty() && p.refused.is_empty(),
            "a new account's link waits a cycle, and is not refused: {p:?}"
        );

        let mut doc2 = doc.clone();
        apply(&mut doc2, &p, G, || Ok("$argon2id$fresh".into())).unwrap();
        let e = &doc2["users"]["a.smith"];
        assert_eq!(
            e["password"].as_str(),
            Some("$argon2id$fresh"),
            "Alex's password survived"
        );
        assert_eq!(e["email"].as_str(), Some("sam@example.com"));
        assert_eq!(e["displayname"].as_str(), Some("Sam Smith"));
        assert_eq!(
            e["groups"],
            file("[bilbycast-portal]"),
            "Alex's own groups came along"
        );
        assert_eq!(doc2["users"]["dvr-test"], doc["users"]["dvr-test"]);

        // A username given out again with no address the portal can use is
        // still taken from the last holder: it just gets no new account.
        let p = plan(&users(&doc), &[acct("a.smith", None)], Some(&removed), G);
        assert_eq!(p.replace, ["a.smith"]);
        assert!(p.add.is_empty());
    }

    #[test]
    fn an_older_manager_still_removes_by_absence() {
        let doc = file(HAND_MADE);
        let p = plan(
            &users(&doc),
            &[acct("someone.else", Some("s@example.com"))],
            None,
            G,
        );
        assert_eq!(p.remove, ["a.smith"], "only the managed account goes");
    }

    #[test]
    fn an_empty_list_from_an_older_manager_deletes_nobody() {
        let doc = file(HAND_MADE);
        let p = plan(&users(&doc), &[], None, G);
        assert!(
            p.remove.is_empty(),
            "a manager that answered with no logins at all emptied Authelia: {p:?}"
        );
        assert_eq!(p.held_back, 1, "and the log is told what was held back");
    }

    #[test]
    fn an_email_change_updates_the_account_but_never_its_password() {
        let doc = file(HAND_MADE);
        let p = plan(
            &users(&doc),
            &[acct("a.smith", Some("alex@new.example.com"))],
            Some(&[]),
            G,
        );
        assert_eq!(p.update.len(), 1);
        let mut doc2 = doc.clone();
        apply(&mut doc2, &p, G, || {
            panic!("an update must not mint a password")
        })
        .unwrap();
        assert_eq!(
            doc2["users"]["a.smith"]["email"].as_str(),
            Some("alex@new.example.com")
        );
        assert_eq!(
            doc2["users"]["a.smith"]["password"], doc["users"]["a.smith"]["password"],
            "the password Alex chose was overwritten"
        );
        // Their other groups are theirs.
        assert_eq!(
            doc2["users"]["a.smith"]["groups"],
            doc["users"]["a.smith"]["groups"]
        );
    }

    #[test]
    fn a_link_waits_while_the_address_it_would_go_to_is_being_replaced() {
        let doc = file(HAND_MADE);
        let at = "2026-09-22T08:00:00Z";
        let fixed = asking(acct("a.smith", Some("alex@fixed.example.com")), at);
        let p = plan(&users(&doc), std::slice::from_ref(&fixed), Some(&[]), G);
        assert_eq!(p.update.len(), 1);
        assert!(
            p.links.is_empty() && p.refused.is_empty(),
            "Authelia still holds the old address and would mail the link there: {p:?}"
        );

        // Next cycle the file holds the new address, and the link goes to it.
        let mut doc2 = doc.clone();
        apply(&mut doc2, &p, G, || panic!("no account is new")).unwrap();
        let p = plan(&users(&doc2), &[fixed], Some(&[]), G);
        assert!(p.update.is_empty());
        assert_eq!(links(&p), [("a.smith", "alex@fixed.example.com")]);
        assert_eq!(p.links[0].requested_at, at, "echoed back verbatim");
    }

    #[test]
    fn a_new_name_does_not_hold_a_link_back() {
        let doc = file(HAND_MADE);
        let mut a = asking(
            acct("a.smith", Some("alex@example.com")),
            "2026-09-22T08:00:00Z",
        );
        a.display_name = Some("Alexandra Smith".into());
        let p = plan(&users(&doc), &[a], Some(&[]), G);
        assert_eq!(p.update.len(), 1);
        assert_eq!(links(&p), [("a.smith", "alex@example.com")]);
    }

    #[test]
    fn a_login_whose_email_was_cleared_gets_no_link() {
        let doc = file(HAND_MADE);
        let p = plan(
            &users(&doc),
            &[asking(acct("a.smith", None), "2026-09-22T08:00:00Z")],
            Some(&[]),
            G,
        );
        assert!(
            p.links.is_empty(),
            "the link would go to the address the operator took away"
        );
        assert_eq!(refused(&p), [("a.smith", NO_EMAIL)]);
    }

    #[test]
    fn a_new_account_carries_the_mark_and_an_unusable_password() {
        let mut doc = file("users: {}");
        let mut a = acct("b.jones", Some("b@example.com"));
        a.display_name = Some("Bea Jones".into());
        let p = plan(&users(&doc), &[a], Some(&[]), G);
        apply(&mut doc, &p, G, unusable_password_hash).unwrap();
        let e = &doc["users"]["b.jones"];
        assert_eq!(e["email"].as_str(), Some("b@example.com"));
        assert_eq!(e["displayname"].as_str(), Some("Bea Jones"));
        assert!(is_managed(e, G));
        let hash = e["password"].as_str().unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=8,t=1,p=1$"),
            "not an argon2id hash at the minimum cost: {hash}"
        );
        // Two accounts never share a hash.
        let mut doc2 = file("users: {}");
        apply(&mut doc2, &p, G, unusable_password_hash).unwrap();
        assert_ne!(doc2["users"]["b.jones"]["password"], e["password"]);
    }

    #[test]
    fn a_link_waits_for_an_account_authelia_has_loaded() {
        let doc = file(HAND_MADE);
        let fresh = asking(acct("fresh", Some("f@example.com")), "2026-09-22T08:00:00Z");
        let mut known = asking(
            acct("a.smith", Some("alex@example.com")),
            "2026-09-22T08:00:01Z",
        );
        known.first_link = true;
        let p = plan(&users(&doc), &[fresh, known], Some(&[]), G);
        assert_eq!(
            links(&p),
            [("a.smith", "alex@example.com")],
            "a link for an account written this cycle would be answered OK and send nothing"
        );
        assert_eq!(p.links[0].kind, LinkKind::Invite);
        assert_eq!(p.links[0].name, "a.smith");
        assert!(p.refused.is_empty(), "a deferred link is left outstanding");
        assert_eq!(p.add.len(), 1);
    }

    #[test]
    fn nothing_changed_writes_nothing() {
        let doc = file(HAND_MADE);
        let p = plan(
            &users(&doc),
            &[acct("a.smith", Some("alex@example.com"))],
            Some(&[]),
            G,
        );
        assert!(!p.changes_file(), "{p:?}");
    }

    #[test]
    fn junk_from_the_manager_does_not_reach_the_file() {
        let doc = file("users: {}");
        let p = plan(
            &users(&doc),
            &[
                acct("has space", Some("a@example.com")),
                acct("ok", Some("not-an-email")),
                acct("ok2", Some("a@b.c\nemail: evil@x.y")),
            ],
            Some(&[]),
            G,
        );
        assert!(p.add.is_empty(), "{p:?}");
    }

    #[test]
    fn an_address_or_name_another_account_holds_is_never_written() {
        let doc = file(HAND_MADE);
        let at = "2026-09-22T08:00:00Z";
        let p = plan(
            &users(&doc),
            &[
                // dvr-test's address, in another case.
                asking(acct("ops2", Some("DVR-Test@Example.com")), at),
                // A username that is someone's email.
                acct("alex@example.com", Some("other@example.com")),
                // A username that is an existing one in another case.
                acct("DVR-TEST", Some("third@example.com")),
            ],
            Some(&[]),
            G,
        );
        assert!(
            p.add.is_empty(),
            "Authelia refuses a file where two accounts share a name: {p:?}"
        );
        assert_eq!(
            p.conflicts,
            [
                ("ops2".to_string(), EMAIL_TAKEN),
                ("alex@example.com".to_string(), NAME_TAKEN),
                ("DVR-TEST".to_string(), NAME_TAKEN),
            ]
        );
        assert_eq!(
            refused(&p),
            [("ops2", EMAIL_TAKEN)],
            "an outstanding link is answered with the reason"
        );
    }

    #[test]
    fn two_new_logins_with_one_address_make_one_account() {
        let doc = file("users: {}");
        let p = plan(
            &users(&doc),
            &[
                acct("bob", Some("bob@example.com")),
                acct("bob2", Some("BOB@example.com")),
            ],
            Some(&[]),
            G,
        );
        assert_eq!(names(&p.add), ["bob"]);
        assert_eq!(p.conflicts, [("bob2".to_string(), EMAIL_TAKEN)]);
    }

    #[test]
    fn a_new_address_another_account_holds_is_not_written_and_not_mailed() {
        let doc = file(HAND_MADE);
        let mut a = asking(
            acct("a.smith", Some("dvr-test@example.com")),
            "2026-09-22T08:00:00Z",
        );
        a.display_name = Some("Alexandra Smith".into());
        let p = plan(&users(&doc), &[a], Some(&[]), G);
        assert_eq!(
            p.update,
            [Update {
                username: "a.smith".into(),
                email: None,
                display_name: Some("Alexandra Smith".into()),
            }],
            "the name still changes; the address does not"
        );
        assert!(p.links.is_empty());
        assert_eq!(refused(&p), [("a.smith", EMAIL_TAKEN)]);
    }

    #[test]
    fn an_address_a_deleted_login_frees_can_go_to_a_new_one() {
        let doc = file(HAND_MADE);
        let p = plan(
            &users(&doc),
            &[acct("alex2", Some("alex@example.com"))],
            Some(&gone(&["a.smith"])),
            G,
        );
        assert_eq!(p.remove, ["a.smith"]);
        assert_eq!(names(&p.add), ["alex2"]);
        assert!(p.conflicts.is_empty());
    }

    fn managed(entries: &[(&str, &str)]) -> Value {
        let mut yaml = String::from("users:\n");
        for (name, email) in entries {
            yaml.push_str(&format!(
                "  '{name}':\n    password: chosen\n    email: '{email}'\n    groups: [bilbycast-portal]\n"
            ));
        }
        file(&yaml)
    }

    /// `(username, the email it would be written with)` for every update.
    fn moves(p: &Plan) -> Vec<(&str, &str)> {
        p.update
            .iter()
            .filter_map(|u| Some((u.username.as_str(), u.email.as_deref()?)))
            .collect()
    }

    /// An address one account gives up goes to another in the same write,
    /// whichever sorts first — the manager answers in username order.
    #[test]
    fn an_address_a_moved_account_frees_can_go_to_a_new_one() {
        let doc = managed(&[("b-old", "x@example.com")]);
        let at = "2026-09-24T08:00:00Z";
        let p = plan(
            &users(&doc),
            &[
                asking(acct("a-new", Some("x@example.com")), at),
                acct("b-old", Some("y@example.com")),
            ],
            Some(&[]),
            G,
        );
        assert_eq!(names(&p.add), ["a-new"]);
        assert_eq!(moves(&p), [("b-old", "y@example.com")]);
        assert!(
            p.conflicts.is_empty() && p.refused.is_empty(),
            "the invitation was used up on a refusal: {p:?}"
        );
    }

    /// Two accounts trading addresses, or three passing them round, land in
    /// one write: Authelia never loads the file in between.
    #[test]
    fn a_swap_or_a_rotation_lands_in_one_write() {
        let at = "2026-09-24T08:00:00Z";
        let doc = managed(&[("alpha", "a@example.com"), ("beta", "b@example.com")]);
        let p = plan(
            &users(&doc),
            &[
                asking(acct("alpha", Some("B@example.com")), at),
                asking(acct("beta", Some("a@example.com")), at),
            ],
            Some(&[]),
            G,
        );
        assert_eq!(
            moves(&p),
            [("alpha", "B@example.com"), ("beta", "a@example.com")]
        );
        assert!(p.conflicts.is_empty() && p.refused.is_empty(), "{p:?}");
        let mut doc2 = doc.clone();
        apply(&mut doc2, &p, G, || panic!("no account is new")).unwrap();
        assert_eq!(
            doc2["users"]["alpha"]["email"].as_str(),
            Some("B@example.com")
        );
        assert_eq!(
            doc2["users"]["beta"]["email"].as_str(),
            Some("a@example.com")
        );

        let doc = managed(&[
            ("one", "x@example.com"),
            ("two", "y@example.com"),
            ("three", "z@example.com"),
        ]);
        let p = plan(
            &users(&doc),
            &[
                acct("one", Some("y@example.com")),
                acct("three", Some("x@example.com")),
                acct("two", Some("z@example.com")),
            ],
            Some(&[]),
            G,
        );
        assert_eq!(p.update.len(), 3, "{p:?}");
        assert!(p.conflicts.is_empty());
    }

    /// A move a hand-made account blocks keeps its old address, so a login
    /// that wanted that address waits — unrefused, its request outstanding —
    /// while the blocked one is refused: the hand-made holder is going nowhere.
    #[test]
    fn a_blocked_move_keeps_its_address_and_whoever_wanted_it_waits() {
        let at = "2026-09-24T08:00:00Z";
        let doc = file(
            "users:\n  alpha:\n    email: a@example.com\n    groups: [bilbycast-portal]\n  \
             hand:\n    email: h@example.com\n    groups: []\n",
        );
        let p = plan(
            &users(&doc),
            &[
                asking(acct("alpha", Some("h@example.com")), at),
                asking(acct("newbie", Some("a@example.com")), at),
            ],
            Some(&[]),
            G,
        );
        assert!(p.add.is_empty() && p.update.is_empty(), "{p:?}");
        assert_eq!(
            refused(&p),
            [("alpha", EMAIL_TAKEN)],
            "newbie's request was used up on an address that is still moving"
        );
        assert_eq!(
            p.conflicts,
            [
                ("alpha".to_string(), EMAIL_TAKEN),
                ("newbie".to_string(), WAITING)
            ]
        );
    }

    /// When the account holding an address is one the manager really lists
    /// with it, the request is answered — there is nothing to wait for.
    #[test]
    fn an_address_the_manager_still_gives_its_holder_is_refused() {
        let at = "2026-09-24T08:00:00Z";
        let doc = managed(&[("zed", "ann@example.com")]);
        let p = plan(
            &users(&doc),
            &[
                asking(acct("ann", Some("ann@example.com")), at),
                acct("zed", Some("ann@example.com")),
            ],
            Some(&[]),
            G,
        );
        assert!(p.add.is_empty());
        assert_eq!(refused(&p), [("ann", EMAIL_TAKEN)]);
    }

    /// A username that is an address keeps holding that address as a name
    /// when the account's email moves: the name does not move with it.
    #[test]
    fn an_account_named_after_its_address_keeps_the_name_when_the_address_moves() {
        let doc = managed(&[("a@example.com", "a@example.com")]);
        let p = plan(
            &users(&doc),
            &[
                acct("a@example.com", Some("new@example.com")),
                acct("zed", Some("A@example.com")),
            ],
            Some(&[]),
            G,
        );
        assert_eq!(moves(&p), [("a@example.com", "new@example.com")]);
        assert!(
            p.add.is_empty(),
            "zed's email would be another account's username: {p:?}"
        );
        assert_eq!(p.conflicts, [("zed".to_string(), EMAIL_TAKEN)]);
    }

    /// Membership numbers, handles, words YAML has a meaning for: written as
    /// quoted keys, they read back as themselves. Only `<<`, which goes out
    /// bare and is a merge key to Authelia's parser, cannot be a username.
    #[test]
    fn a_username_is_refused_only_when_its_key_would_not_read_back() {
        let mut doc = file("users: {}");
        let usernames = [
            "12345", "0x3039", "@bob", "true", "null", "~", "yes", "-", "a:b", "#tag", "*x",
        ];
        let logins: Vec<_> = usernames
            .iter()
            .enumerate()
            .map(|(i, u)| acct(u, Some(&format!("n{i}@example.com"))))
            .chain([acct("<<", Some("m@example.com"))])
            .collect();
        let p = plan(&users(&doc), &logins, Some(&[]), G);
        assert_eq!(names(&p.add), usernames);
        assert_eq!(p.conflicts, [("<<".to_string(), UNWRITABLE_NAME)]);

        // And what is written reads back with every one of them as text.
        apply(&mut doc, &p, G, || Ok("$argon2id$fake".into())).unwrap();
        let text = serde_yaml_ng::to_string(&doc).unwrap();
        let back: Value = serde_yaml_ng::from_str(&text).unwrap();
        let keys: Vec<_> = users(&back).keys().cloned().collect();
        let expected: Vec<_> = usernames
            .iter()
            .map(|u| Value::String(u.to_string()))
            .collect();
        assert_eq!(keys, expected, "{text}");
        assert_eq!(unrewritable(&users(&back), G), None, "{text}");
    }

    #[test]
    fn an_unquoted_numeric_account_is_found_and_left_alone() {
        // Hand-written staff IDs. To Authelia this is the username "12345".
        let doc = file(
            "users:\n  12345:\n    displayname: Staff\n    password: x\n    email: s@example.com\n    groups: [bilbycast-portal]\n",
        );
        let p = plan(
            &users(&doc),
            &[acct("12345", Some("new@example.com"))],
            Some(&[]),
            G,
        );
        assert!(
            p.add.is_empty() && p.update.is_empty(),
            "a second '12345' key would be a duplicate to Authelia: {p:?}"
        );
        assert_eq!(p.foreign, ["12345"]);
        let p = plan(&users(&doc), &[], Some(&gone(&["12345"])), G);
        assert!(p.remove.is_empty(), "a key that is not text is never ours");
        assert!(!p.removals[0].1, "and its record needs no write");
    }

    #[test]
    fn an_entry_rewriting_would_change_stops_the_write() {
        let doc = file(
            "users:\n  phone:\n    displayname: True\n    password: x\n    email: +61412345678\n    groups: []\n",
        );
        let why = unrewritable(&users(&doc), G).expect("the number would be rewritten");
        assert!(why.contains("`phone`"), "{why}");

        let doc = file("users:\n  12345:\n    displayname: Staff\n    groups: []\n");
        assert!(unrewritable(&users(&doc), G).is_some(), "an unquoted key");

        // What the portal writes itself, and a hand-made entry's own flag,
        // round-trip unchanged.
        let doc = file(HAND_MADE);
        assert_eq!(unrewritable(&users(&doc), G), None);
    }

    #[test]
    fn a_removal_keeps_everyone_else_where_they_were() {
        let mut doc = file(
            "users:\n  a: {groups: [bilbycast-portal]}\n  b: {groups: []}\n  c: {groups: []}\n",
        );
        let p = Plan {
            remove: vec!["a".into()],
            ..Plan::default()
        };
        apply(&mut doc, &p, G, || panic!("nothing is added")).unwrap();
        let left = users(&doc);
        let order: Vec<&str> = left.keys().filter_map(Value::as_str).collect();
        assert_eq!(
            order,
            ["b", "c"],
            "the last account was swapped into the gap"
        );
    }

    #[test]
    fn a_file_changed_underneath_is_not_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("users.yml");
        std::fs::write(&path, HAND_MADE).unwrap();
        let snap = read_users_file(&path).unwrap();
        // Authelia writes a new password for a.smith in the meantime.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(
            &path,
            HAND_MADE.replace("chosen-by-alex", "changed-just-now"),
        )
        .unwrap();
        let mut doc = snap.doc.clone();
        let p = plan(
            &users(&doc),
            &[acct("x", Some("x@example.com"))],
            Some(&[]),
            G,
        );
        apply(&mut doc, &p, G, || Ok("$argon2id$fake".into())).unwrap();
        assert!(
            !write_users_file(&path, &snap, &doc).unwrap(),
            "the race was not noticed"
        );
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("changed-just-now")
        );
        assert!(
            !tmp.path().join(".users.yml.portal-tmp").exists(),
            "the temp file was left behind"
        );
    }

    #[test]
    fn a_file_replaced_with_the_same_size_and_time_is_still_noticed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("users.yml");
        std::fs::write(&path, HAND_MADE).unwrap();
        let snap = read_users_file(&path).unwrap();
        // Replaced by rename, as a writer that does it properly would: same
        // length, and the old modification time put back.
        let other = tmp.path().join("other.yml");
        std::fs::write(
            &other,
            HAND_MADE.replace("chosen-by-alex", "chosen-by-ALEX"),
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&other)
            .unwrap()
            .set_modified(snap.modified.unwrap())
            .unwrap();
        std::fs::rename(&other, &path).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (meta.len(), meta.modified().ok()),
            (snap.len, snap.modified)
        );

        let mut doc = snap.doc.clone();
        let p = plan(
            &users(&doc),
            &[acct("x", Some("x@example.com"))],
            Some(&[]),
            G,
        );
        apply(&mut doc, &p, G, || Ok("$argon2id$fake".into())).unwrap();
        assert!(
            !write_users_file(&path, &snap, &doc).unwrap(),
            "a different file under the same name was overwritten"
        );
    }

    #[test]
    fn a_write_round_trips_and_keeps_the_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("users.yml");
        std::fs::write(&path, HAND_MADE).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let snap = read_users_file(&path).unwrap();
        let mut doc = snap.doc.clone();
        let p = plan(
            &users(&doc),
            &[
                acct("x", Some("x@example.com")),
                acct("a.smith", Some("alex@example.com")),
            ],
            Some(&[]),
            G,
        );
        apply(&mut doc, &p, G, || Ok("$argon2id$fake".into())).unwrap();
        assert!(write_users_file(&path, &snap, &doc).unwrap());
        let back = read_users_file(&path).unwrap().doc;
        assert!(back["users"]["x"].is_mapping());
        assert_eq!(back["users"]["dvr-test"], snap.doc["users"]["dvr-test"]);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o660);
        // Written by the file's owner, so neither owner nor group moved.
        assert_eq!((meta.uid(), meta.gid()), (before.uid(), before.gid()));
    }

    #[test]
    fn a_replacement_that_would_lock_the_owner_out_is_refused() {
        const AUTHELIA: u32 = 990;
        const PORTAL: u32 = 991;
        const SHARED: u32 = 995;
        let f = Path::new("/etc/authelia/users/users.yml");
        let member = |_, _| Some(true);
        let outsider = |_, _| Some(false);
        let unknown = |_, _| None;
        // The documented layout, with Authelia in the group: fine.
        assert_eq!(
            lockout(f, (AUTHELIA, SHARED), (PORTAL, SHARED), 0o660, member),
            None
        );
        // The same, before anyone added Authelia to the group.
        assert!(lockout(f, (AUTHELIA, SHARED), (PORTAL, SHARED), 0o660, outsider).is_some());
        // A group that cannot write.
        assert!(lockout(f, (AUTHELIA, SHARED), (PORTAL, SHARED), 0o640, member).is_some());
        // A group the portal could not give the new file.
        assert!(lockout(f, (AUTHELIA, SHARED), (PORTAL, PORTAL), 0o660, member).is_some());
        // Once the portal owns it, Authelia is in the group, so the group
        // cannot change either.
        assert!(lockout(f, (PORTAL, SHARED), (PORTAL, PORTAL), 0o660, member).is_some());
        // Unless it granted nothing; and root is locked out of nothing.
        assert_eq!(
            lockout(f, (PORTAL, SHARED), (PORTAL, PORTAL), 0o600, outsider),
            None
        );
        assert_eq!(lockout(f, (0, 0), (PORTAL, PORTAL), 0o600, outsider), None);
        // A user the account files do not list is not judged.
        assert_eq!(
            lockout(f, (AUTHELIA, SHARED), (PORTAL, SHARED), 0o660, unknown),
            None
        );
    }

    /// What root with umask 022 makes: root:root 0644. Its group grants
    /// nothing everyone else does not have, so a new group takes nothing from
    /// anyone — and a root Authelia needs neither group nor mode.
    #[test]
    fn a_group_that_grants_nothing_extra_may_change() {
        const PORTAL: u32 = 991;
        const AUTHELIA_GROUP: u32 = 990;
        let f = Path::new("/etc/authelia/users/users.yml");
        let outsider = |_, _| Some(false);
        assert_eq!(lockout(f, (0, 0), (PORTAL, PORTAL), 0o644, outsider), None);
        // A root-owned file whose group is how a non-root Authelia reaches it
        // is another matter.
        assert!(lockout(f, (0, AUTHELIA_GROUP), (PORTAL, PORTAL), 0o664, outsider).is_some());
    }

    /// Each refusal says what clears it, and the membership check says whose
    /// account files it read.
    #[test]
    fn a_refusal_names_its_remedy() {
        let f = Path::new("/etc/authelia/users/users.yml");
        let group = lockout(f, (990, 995), (991, 991), 0o660, |_, _| Some(true)).unwrap();
        assert!(
            group.contains("`chgrp 991 /etc/authelia/users/users.yml`"),
            "{group}"
        );
        let mode = lockout(f, (990, 995), (991, 995), 0o640, |_, _| Some(true)).unwrap();
        assert!(
            mode.contains("`chmod g+rw /etc/authelia/users/users.yml`"),
            "{mode}"
        );
        let member = lockout(f, (990, 995), (991, 995), 0o660, |_, _| Some(false)).unwrap();
        assert!(member.contains("`usermod -aG 995"), "{member}");
        assert!(
            member.contains("this host's account files only") && member.contains("container"),
            "{member}"
        );
    }

    #[test]
    fn group_membership_is_read_from_the_account_files() {
        let passwd = "root:x:0:0::/root:/bin/sh\nauthelia:x:990:990::/:/usr/sbin/nologin\n";
        let group =
            "authelia:x:990:\nbilbycast-portal:x:995:bilbycast-portal,authelia\nother:x:996:\n";
        assert_eq!(
            in_group(passwd, group, 990, 995),
            Some(true),
            "supplementary"
        );
        assert_eq!(in_group(passwd, group, 990, 990), Some(true), "primary");
        assert_eq!(in_group(passwd, group, 990, 996), Some(false));
        assert_eq!(in_group(passwd, group, 4242, 995), None, "not a local user");
    }

    #[test]
    fn a_read_only_directory_is_named_with_its_fix() {
        let e = cannot_write(
            Path::new("/etc/authelia/users/.users.yml.portal-tmp"),
            Path::new("/etc/authelia/users"),
            std::io::Error::from_raw_os_error(30),
        )
        .to_string();
        assert!(
            e.contains("ReadWritePaths=/etc/authelia/users") && e.contains("systemctl edit"),
            "{e}"
        );
    }

    #[test]
    fn an_error_is_one_line_the_manager_will_take() {
        let long = format!(
            "550-5.7.1 rejected\r\n550 {}é{}",
            // The `é` straddles byte 300.
            "x".repeat(275),
            "y".repeat(700)
        );
        let e = bound_error(&long);
        assert!(e.len() <= MAX_ACK_ERROR, "{} bytes", e.len());
        assert!(!e.contains(['\r', '\n']));
        assert!(e.starts_with("550-5.7.1 rejected  550 xxx"));
        assert_eq!(bound_error("short"), "short");
    }

    fn account_cfg(url: &str) -> AccountSyncConfig {
        let mut c = AccountSyncConfig {
            users_file: "/etc/authelia/users.yml".into(),
            authelia_url: url.into(),
            public_host: "watch.example.com".into(),
            managed_group: default_group(),
            interval_secs: 15,
        };
        c.normalise();
        c
    }

    #[test]
    fn plain_http_to_authelia_is_this_host_only() {
        for ok in [
            "http://127.0.0.1:9091",
            "http://127.0.0.1:9091/auth",
            "http://localhost:9091/auth",
            "http://[::1]:9091/auth",
            "https://auth.example.com",
        ] {
            assert!(account_cfg(ok).validate().is_ok(), "{ok} was refused");
        }
        for bad in [
            "http://auth.example.com/auth",
            // The host is what counts, not what is written before the `@`,
            // and nothing that ends the host earlier for the client than for
            // the check.
            "http://127.0.0.1@evil.example.com/auth",
            "http://evil.example.com#@127.0.0.1:9091/auth",
            "http://evil.example.com\\@127.0.0.1:9091/auth",
            "http://127.0.0.1.evil.example.com/auth",
            "https://user:pass@auth.example.com",
            "http://127.0.0.1:9091/auth?x=1",
        ] {
            assert!(
                account_cfg(bad).validate().is_err(),
                "{bad} would send every invited username somewhere else"
            );
        }
    }

    #[test]
    fn the_config_refuses_what_would_break_the_link() {
        let ok = account_cfg(&default_authelia_url());
        assert!(ok.validate().is_ok());
        let mut bad = ok.clone();
        bad.public_host = "https://watch.example.com/".into();
        assert!(
            bad.validate().is_err(),
            "a URL where a host belongs names the wrong link"
        );
        let mut bad = ok.clone();
        bad.interval_secs = 1;
        assert!(bad.validate().is_err());
    }

    // ── One whole cycle, against a stub manager and a stub Authelia ─────────

    use axum::extract::{RawQuery, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Stub {
        /// What the manager answers for the account list.
        answer: serde_json::Value,
        queries: Vec<String>,
        /// Acknowledgements received, and the usernames to refuse them for.
        acks: Vec<serde_json::Value>,
        refuse_ack: HashSet<String>,
        /// Usernames Authelia was asked about, and how it answers.
        asked: Vec<String>,
        authelia: (u16, String),
        retry_after: Option<&'static str>,
        /// Removal acknowledgements received; the status to answer them
        /// with, when not 200.
        removal_acks: Vec<serde_json::Value>,
        removal_ack_status: Option<u16>,
        /// How Authelia's health check answers, each time it is asked in
        /// turn, the last answer repeating.
        health: Vec<(u16, &'static str)>,
        health_asked: usize,
    }
    type Shared = Arc<Mutex<Stub>>;

    async fn stub_removal_ack(
        State(s): State<Shared>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let mut s = s.lock().unwrap();
        s.removal_acks.push(body);
        StatusCode::from_u16(s.removal_ack_status.unwrap_or(200)).unwrap()
    }

    async fn stub_health(State(s): State<Shared>) -> (StatusCode, &'static str) {
        let mut s = s.lock().unwrap();
        let i = s.health_asked.min(s.health.len() - 1);
        s.health_asked += 1;
        let (code, body) = s.health[i];
        (StatusCode::from_u16(code).unwrap(), body)
    }

    async fn stub_accounts(State(s): State<Shared>, RawQuery(q): RawQuery) -> impl IntoResponse {
        let mut s = s.lock().unwrap();
        s.queries.push(q.unwrap_or_default());
        axum::Json(s.answer.clone())
    }

    async fn stub_ack(
        State(s): State<Shared>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> StatusCode {
        let mut s = s.lock().unwrap();
        let refused = s
            .refuse_ack
            .contains(body["username"].as_str().unwrap_or(""));
        s.acks.push(body);
        if refused {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::OK
        }
    }

    async fn stub_identity_start(
        State(s): State<Shared>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::response::Response {
        let mut s = s.lock().unwrap();
        s.asked
            .push(body["username"].as_str().unwrap_or("").to_string());
        let (code, body) = s.authelia.clone();
        let mut r = (StatusCode::from_u16(code).unwrap(), body).into_response();
        if let Some(after) = s.retry_after {
            r.headers_mut()
                .insert(reqwest::header::RETRY_AFTER, after.parse().unwrap());
        }
        r
    }

    struct Rig {
        stub: Shared,
        state: PortalState,
        cfg: AccountSyncConfig,
        _dir: tempfile::TempDir,
    }

    async fn rig(
        users_yaml: &str,
        answer: serde_json::Value,
        mail: Option<serde_json::Value>,
    ) -> Rig {
        let stub: Shared = Arc::new(Mutex::new(Stub {
            answer,
            authelia: (200, r#"{"status":"OK"}"#.into()),
            health: vec![(200, r#"{"status":"OK"}"#)],
            ..Stub::default()
        }));
        let app = axum::Router::new()
            .route("/api/v1/dvr/portal/accounts", get(stub_accounts))
            .route("/api/v1/dvr/portal/accounts/link-sent", post(stub_ack))
            .route(
                "/api/v1/dvr/portal/accounts/removed-applied",
                post(stub_removal_ack),
            )
            .route("/api/health", get(stub_health))
            .route(
                "/api/reset-password/identity/start",
                post(stub_identity_start),
            )
            .with_state(stub.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let dir = tempfile::tempdir().unwrap();
        let users_file = dir.path().join("users.yml");
        std::fs::write(&users_file, users_yaml).unwrap();
        let mut portal = serde_json::json!({ "manager_url": base, "manager_token": "t" });
        if let Some(mail) = mail {
            portal["mail"] = mail;
        }
        // Bare clients need a provider installed; the binary installs its own.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let state = PortalState {
            cfg: Arc::new(serde_json::from_value(portal).unwrap()),
            http: reqwest::Client::new(),
            media: reqwest::Client::new(),
            last_beat_answer: Default::default(),
            links: Default::default(),
        };
        let mut cfg = account_cfg(&base);
        cfg.users_file = users_file;
        Rig {
            stub,
            state,
            cfg,
            _dir: dir,
        }
    }

    const TWO_MANAGED: &str = r#"
users:
  a.smith:
    displayname: Alex
    password: x
    email: alex@example.com
    groups: [bilbycast-portal]
  b.jones:
    displayname: Bea
    password: x
    email: bea@example.com
    groups: [bilbycast-portal]
"#;

    fn requesting(users: &[&str]) -> serde_json::Value {
        serde_json::json!({
            "accounts": users.iter().map(|u| serde_json::json!({
                "username": u,
                "email": if *u == "a.smith" { "alex@example.com" } else { "bea@example.com" },
                "link_requested_at": "2026-09-22T08:00:00.123456Z",
            })).collect::<Vec<_>>(),
            "removed": [],
        })
    }

    #[tokio::test]
    async fn a_failed_acknowledgement_stops_nobody_and_is_retried_without_a_second_email() {
        let r = rig(TWO_MANAGED, requesting(&["a.smith", "b.jones"]), None).await;
        r.stub.lock().unwrap().refuse_ack.insert("a.smith".into());
        let mut memory = Memory::default();

        let out = sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(out.links_sent, 2);
        {
            let s = r.stub.lock().unwrap();
            assert_eq!(
                s.asked,
                ["a.smith", "b.jones"],
                "a refused acknowledgement stopped the links after it"
            );
            assert_eq!(s.acks.len(), 2);
            assert_eq!(
                s.queries,
                ["interval_secs=15"],
                "the poll names its interval"
            );
        }

        // The manager still has a.smith outstanding, b.jones not.
        {
            let mut s = r.stub.lock().unwrap();
            s.answer = requesting(&["a.smith"]);
            s.refuse_ack.clear();
        }
        let out = sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(out.links_sent, 0);
        {
            let s = r.stub.lock().unwrap();
            assert_eq!(
                s.asked,
                ["a.smith", "b.jones"],
                "a.smith was mailed a second link because an acknowledgement failed"
            );
            let last = s.acks.last().unwrap();
            assert_eq!(last["username"], "a.smith");
            assert_eq!(last["requested_at"], "2026-09-22T08:00:00.123456Z");
            assert!(
                last["error"].is_null(),
                "the retry reports what happened: {last}"
            );
        }

        // Once the manager stops asking, the memory lets go of it.
        r.stub.lock().unwrap().answer = requesting(&[]);
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert!(memory.served.is_empty());
    }

    #[tokio::test]
    async fn authelia_answering_ko_is_a_failure_with_its_reason() {
        let r = rig(TWO_MANAGED, requesting(&["a.smith"]), None).await;
        r.stub.lock().unwrap().authelia = (
            200,
            r#"{"status":"KO","message":"Operation failed"}"#.into(),
        );
        let out = sync_once(&r.state, &r.cfg, &mut Memory::default())
            .await
            .unwrap();
        assert_eq!(out.links_sent, 0);
        let s = r.stub.lock().unwrap();
        let error = s.acks[0]["error"].as_str().expect("reported as sent");
        assert!(error.contains("Operation failed"), "{error}");
    }

    #[tokio::test]
    async fn a_rate_limit_leaves_the_links_for_later_and_stops_asking() {
        let r = rig(TWO_MANAGED, requesting(&["a.smith", "b.jones"]), None).await;
        {
            let mut s = r.stub.lock().unwrap();
            s.authelia = (429, String::new());
            s.retry_after = Some("60");
        }
        let mut memory = Memory::default();
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        {
            let s = r.stub.lock().unwrap();
            assert_eq!(s.asked, ["a.smith"], "kept asking into the limit");
            assert!(s.acks.is_empty(), "a rate-limited link was cleared");
        }
        // Authelia asked for a minute; the next cycle does not ask at all.
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(r.stub.lock().unwrap().asked, ["a.smith"]);
    }

    /// The warning is said once per episode, and an episode ends with any
    /// other answer from Authelia, or with the pause it asked for — not only
    /// with a link it took, which may be days away.
    #[tokio::test]
    async fn the_rate_limit_warning_is_rearmed_by_any_other_answer_or_the_end_of_the_pause() {
        let r = rig(TWO_MANAGED, requesting(&["a.smith"]), None).await;
        r.stub.lock().unwrap().authelia = (
            200,
            r#"{"status":"KO","message":"Operation failed"}"#.into(),
        );
        let mut memory = Memory {
            limited: true,
            ..Memory::default()
        };
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert!(!memory.limited, "a failed send left the warning latched");

        r.stub.lock().unwrap().answer = requesting(&[]);
        let mut memory = Memory {
            limited: true,
            paused_until: Some(Instant::now() - Duration::from_secs(1)),
            ..Memory::default()
        };
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert!(
            !memory.limited && memory.paused_until.is_none(),
            "a pause that is over left the warning latched"
        );
    }

    /// At boot Authelia comes up after the portal, so the probe keeps asking
    /// quietly; and only Authelia's own OK counts, not any 200.
    #[tokio::test]
    async fn the_startup_probe_waits_for_authelia_and_wants_its_own_ok() {
        let r = rig(TWO_MANAGED, requesting(&[]), None).await;
        r.stub.lock().unwrap().health = vec![(503, ""), (503, ""), (200, r#"{"status":"OK"}"#)];
        let every = Duration::from_millis(10);
        let got = probe_authelia(&r.state, &r.cfg, every, Duration::from_secs(5)).await;
        assert_eq!(got, Ok(()));
        assert_eq!(r.stub.lock().unwrap().health_asked, 3);

        // An Authelia at the root answers a path under `/auth` with its
        // sign-in page, and a 200.
        r.stub.lock().unwrap().health = vec![(200, "<!DOCTYPE html><html></html>")];
        let err = probe_authelia(&r.state, &r.cfg, every, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.contains("its path must be the path"), "{err}");
    }

    #[tokio::test]
    async fn a_write_that_fails_holds_back_only_the_links_it_would_have_changed() {
        // A hand-made entry the portal cannot rewrite faithfully, so the write
        // is refused while it stands.
        let yaml = format!(
            "{TWO_MANAGED}  phone:\n    password: x\n    email: +61412345678\n    groups: []\n"
        );
        let mut answer = requesting(&["a.smith", "b.jones"]);
        answer["accounts"][0]["display_name"] = "Alexandra".into();
        let r = rig(&yaml, answer, None).await;
        let out = sync_once(&r.state, &r.cfg, &mut Memory::default())
            .await
            .unwrap();
        assert!(
            out.write_error
                .as_deref()
                .is_some_and(|e| e.contains("`phone`")),
            "{out:?}"
        );
        let s = r.stub.lock().unwrap();
        assert_eq!(
            s.asked,
            ["b.jones"],
            "the file failing stopped a link it had nothing to do with, or sent one for an \
             account it did not write"
        );
        assert_eq!(s.acks.len(), 1);
    }

    fn password(r: &Rig, user: &str) -> String {
        let doc = read_users_file(&r.cfg.users_file).unwrap().doc;
        doc["users"][user]["password"].as_str().unwrap().to_string()
    }

    /// A username removed and given out again is replaced once. If telling
    /// the manager fails, the retry tells it again and replaces nothing: the
    /// new holder may have chosen a password in the meantime.
    #[tokio::test]
    async fn a_removal_is_applied_once_and_acknowledged_until_the_manager_forgets_it() {
        let answer = serde_json::json!({
            "accounts": [{ "username": "a.smith", "email": "sam@example.com" }],
            "removed": [
                { "username": "a.smith", "removed_at": "2026-09-24T08:00:00.123456Z" },
                { "username": "never.made", "removed_at": "2026-09-24T08:00:01.5Z" },
            ],
        });
        let r = rig(TWO_MANAGED, answer, None).await;
        r.stub.lock().unwrap().removal_ack_status = Some(500);
        let mut memory = Memory::default();

        let out = sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(out.replaced, 1);
        let fresh = password(&r, "a.smith");
        assert_ne!(fresh, "x", "the last holder's password survived");
        {
            let s = r.stub.lock().unwrap();
            let acked: Vec<_> = s
                .removal_acks
                .iter()
                .map(|a| a["username"].clone())
                .collect();
            assert_eq!(acked, ["a.smith", "never.made"]);
            assert_eq!(
                s.removal_acks[0]["removed_at"], "2026-09-24T08:00:00.123456Z",
                "echoed verbatim"
            );
        }

        // Sam sets a password; the manager still lists both, as neither
        // acknowledgement got through.
        let text = std::fs::read_to_string(&r.cfg.users_file)
            .unwrap()
            .replace(&fresh, "set-by-sam");
        std::fs::write(&r.cfg.users_file, text).unwrap();
        r.stub.lock().unwrap().removal_ack_status = None;
        let out = sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(out.replaced, 0);
        assert_eq!(
            password(&r, "a.smith"),
            "set-by-sam",
            "a retried acknowledgement replaced the account a second time"
        );
        assert_eq!(r.stub.lock().unwrap().removal_acks.len(), 4);

        // Forgotten by the manager, forgotten here.
        r.stub.lock().unwrap().answer["removed"] = serde_json::json!([]);
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert!(memory.applied.is_empty());
        assert_eq!(r.stub.lock().unwrap().removal_acks.len(), 4);
    }

    /// Not acknowledged until it is in the file: the manager would forget a
    /// removal that never happened.
    #[tokio::test]
    async fn a_removal_the_write_did_not_carry_is_not_acknowledged() {
        let yaml = format!(
            "{TWO_MANAGED}  phone:\n    password: x\n    email: +61412345678\n    groups: []\n"
        );
        let answer = serde_json::json!({
            "accounts": [{ "username": "b.jones", "email": "bea@example.com" }],
            "removed": [{ "username": "a.smith", "removed_at": "2026-09-24T08:00:00Z" }],
        });
        let r = rig(&yaml, answer, None).await;
        let out = sync_once(&r.state, &r.cfg, &mut Memory::default())
            .await
            .unwrap();
        assert!(out.write_error.is_some());
        assert!(r.stub.lock().unwrap().removal_acks.is_empty());
    }

    /// A manager from before acknowledgements answers them 404. That is not
    /// the cycle's failure, and the removal is still applied only once.
    #[tokio::test]
    async fn a_manager_without_the_acknowledgement_route_is_tolerated() {
        let answer = serde_json::json!({
            "accounts": [],
            "removed": [{ "username": "a.smith", "removed_at": "2026-09-24T08:00:00Z" }],
        });
        let r = rig(TWO_MANAGED, answer, None).await;
        r.stub.lock().unwrap().removal_ack_status = Some(404);
        assert!(
            acknowledge_removal(&r.state, &gone(&["a.smith"])[0])
                .await
                .is_ok_and(|a| !a)
        );
        let mut memory = Memory::default();
        let out = sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(out.removed, 1);
        assert!(memory.removal_ack_failing);
        let out = sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(out.removed, 0);

        r.stub.lock().unwrap().removal_ack_status = Some(503);
        assert!(
            acknowledge_removal(&r.state, &gone(&["a.smith"])[0])
                .await
                .is_err()
        );
    }

    fn sync_errors(r: &Rig) -> Vec<Option<String>> {
        r.stub
            .lock()
            .unwrap()
            .queries
            .iter()
            .map(|q| {
                reqwest::Url::parse(&format!("http://manager/?{q}"))
                    .unwrap()
                    .query_pairs()
                    .find(|(k, _)| k == "sync_error")
                    .map(|(_, v)| v.into_owned())
            })
            .collect()
    }

    /// A file the portal will not rewrite is said on the next poll, so the
    /// manager can show why its logins go nowhere — and no longer once it
    /// writes.
    #[tokio::test]
    async fn a_blocked_write_is_reported_on_the_next_poll() {
        let yaml = format!(
            "{TWO_MANAGED}  phone:\n    password: x\n    email: +61412345678\n    groups: []\n"
        );
        let mut answer = requesting(&["a.smith", "b.jones"]);
        answer["accounts"][0]["display_name"] = "Alexandra".into();
        let r = rig(&yaml, answer, None).await;
        let mut memory = Memory::default();
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        let errors = sync_errors(&r);
        assert_eq!(errors[0], None);
        let said = errors[1]
            .as_deref()
            .expect("the blocked write was not reported");
        assert!(
            said.starts_with("not rewriting ") && said.contains("`phone`"),
            "{said}"
        );
        assert!(said.len() <= MAX_ACK_ERROR);

        // Quoted, the entry no longer stops the write.
        std::fs::write(
            &r.cfg.users_file,
            yaml.replace("+61412345678", "'+61412345678'"),
        )
        .unwrap();
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        sync_once(&r.state, &r.cfg, &mut memory).await.unwrap();
        assert_eq!(sync_errors(&r)[3], None);
    }

    #[tokio::test]
    async fn a_refused_request_forgets_the_email_it_expected() {
        use crate::portal::mail::{self, Incoming, Relay};
        use lettre::address::Envelope;

        struct Captured(Mutex<Vec<Vec<u8>>>);
        #[async_trait::async_trait]
        impl Relay for Captured {
            async fn send(&self, _: Envelope, body: Vec<u8>) -> Result<(), String> {
                self.0.lock().unwrap().push(body);
                Ok(())
            }
        }

        let mail_cfg = serde_json::json!({
            "relay_host": "127.0.0.1",
            "relay_username": "u",
            "relay_password_file": "/dev/null",
            "listen_password_file": "/dev/null",
            "from": "Portal <noreply@example.com>",
            "sign_in_url": "https://watch.example.com",
        });
        let r = rig(TWO_MANAGED, requesting(&["a.smith"]), Some(mail_cfg)).await;
        r.stub.lock().unwrap().authelia = (500, String::new());
        sync_once(&r.state, &r.cfg, &mut Memory::default())
            .await
            .unwrap();

        // The viewer then resets their own password from the sign-in page.
        let own = Incoming {
            from: "noreply@example.com".into(),
            recipients: vec!["alex@example.com".into()],
            data: b"Subject: Reset your password\r\n\r\nhttps://watch.example.com/reset-password/step2?token=abc\r\n".to_vec(),
        };
        let relay = Captured(Mutex::new(Vec::new()));
        mail::handle(
            r.state.cfg.mail.as_ref().unwrap(),
            &r.state.links,
            &relay,
            own.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            relay.0.lock().unwrap()[0],
            own.data,
            "a refused link's expectation rewrote the viewer's own email as ours"
        );
    }
}
