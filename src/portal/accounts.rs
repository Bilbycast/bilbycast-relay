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
//! account carrying it is ever updated or removed. An account somebody wrote by
//! hand — `dvr-test` on the first production install — is never touched, even
//! when the manager has a login of the same name. A group is used as the mark
//! rather than a key of our own because Authelia rewrites this file whenever a
//! user sets a password, and it keeps the fields it knows: a custom key would
//! vanish on the first password change and the account would be orphaned.
//!
//! # Passwords are Authelia's
//!
//! A new account gets an argon2id hash of 32 random bytes that nobody ever
//! sees, so it cannot be signed in to until its owner sets a password through
//! the emailed link. An existing account's `password` is never rewritten: the
//! user may have set it a second ago.
//!
//! # Two things Authelia will not tell us
//!
//! `POST /api/reset-password/identity/start` answers `200` for any username,
//! known or not — it will not reveal who exists. So a link is requested only
//! for an account that was already in the file when this cycle began, and a
//! link for an account created this cycle waits for the next one, by when
//! Authelia's file watcher has loaded it. Asking sooner would be answered `200`
//! and send nothing.
//!
//! And whether the mail was delivered: that is between Authelia and its SMTP
//! relay. What the manager is told is that the portal asked, and when.
//!
//! # The file has two writers
//!
//! This loop and Authelia. A write here is therefore rare (only when something
//! changed), whole-file by temp-then-rename, and abandoned if the file changed
//! between reading it and writing it — the next cycle starts again from what
//! is there.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use serde_yaml_ng::{Mapping, Value};

use super::PortalState;

/// The `accounts` block of the portal config. Absent means the portal does not
/// manage accounts at all, which is how every portal ran before this existed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSyncConfig {
    /// Authelia's `authentication_backend.file.path`. Authelia must have
    /// `watch: true` on it, and this service must be able to replace the file.
    pub users_file: PathBuf,

    /// Authelia's own address and path prefix, reached directly on loopback
    /// rather than through the public proxy.
    #[serde(default = "default_authelia_url")]
    pub authelia_url: String,

    /// The public host the emailed link must point at, e.g.
    /// `watch.example.com`. Authelia builds the link from the forwarded host,
    /// so without it the link would name 127.0.0.1.
    pub public_host: String,

    /// The Authelia group that marks an account as this loop's to manage.
    #[serde(default = "default_group")]
    pub managed_group: String,

    /// Seconds between syncs. A requested link goes out within about one of
    /// these, or two for an account created in the same request.
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
        if !(self.authelia_url.starts_with("http://") || self.authelia_url.starts_with("https://"))
        {
            return Err("accounts.authelia_url must be an http(s) URL".into());
        }
        // Plain HTTP carries the username of everyone being invited, and
        // anyone who can read it can also forge the request that emails them a
        // password link. On loopback that is the documented deployment —
        // Authelia listens there without TLS — and anywhere else it is a
        // mistake nobody would see, so it is refused rather than warned about.
        if self.authelia_url.starts_with("http://") && !authelia_is_local(&self.authelia_url) {
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

/// Is this Authelia on the same host?
///
/// Host only: a port, a path prefix and credentials are all allowed around it.
fn authelia_is_local(url: &str) -> bool {
    let rest = url.trim_start_matches("http://");
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host.rfind(':') {
        // Not a port when it is inside `[::1]`.
        Some(i) if !host[i..].contains(']') => &host[..i],
        _ => host,
    };
    matches!(
        host.trim_matches(|c| c == '[' || c == ']'),
        "127.0.0.1" | "localhost" | "::1"
    )
}

/// One login, as the manager reports it: one row per username, however many
/// groups have granted that username something.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ManagerAccount {
    pub username: String,
    /// No email means the manager has no way to reach this person, so no
    /// account is created for them — they sign in however they did before.
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
}

/// What one sync would change. Worked out from the file and the manager's list
/// alone, so every decision here is testable without Authelia or a network.
#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    /// Accounts to create.
    pub add: Vec<ManagerAccount>,
    /// Managed accounts whose email or display name has changed.
    pub update: Vec<ManagerAccount>,
    /// Managed accounts the manager no longer knows.
    pub remove: Vec<String>,
    /// `(username, requested_at)` — links to ask Authelia for now.
    pub links: Vec<(String, String)>,
    /// Logins the manager has that are hand-made accounts in the file. Left
    /// alone; counted so the operator can be told why an edit did nothing.
    pub foreign: Vec<String>,
}

impl Plan {
    pub fn changes_file(&self) -> bool {
        !(self.add.is_empty() && self.update.is_empty() && self.remove.is_empty())
    }
}

fn is_managed(entry: &Value, group: &str) -> bool {
    entry
        .get("groups")
        .and_then(Value::as_sequence)
        .is_some_and(|g| g.iter().any(|v| v.as_str() == Some(group)))
}

fn str_field<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry.get(key).and_then(Value::as_str)
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

pub fn plan(users: &Mapping, accounts: &[ManagerAccount], group: &str) -> Plan {
    let mut p = Plan::default();
    let mut wanted = std::collections::HashSet::new();
    for a in accounts {
        if !plausible_username(&a.username) {
            continue;
        }
        wanted.insert(a.username.as_str());
        let existing = users.get(Value::String(a.username.clone()));
        let email = a.email.as_deref().filter(|e| plausible_email(e));
        match existing {
            None => {
                if email.is_some() {
                    p.add.push(a.clone());
                }
            }
            Some(entry) if is_managed(entry, group) => {
                let email_changed = email.is_some_and(|e| str_field(entry, "email") != Some(e));
                let name_changed = a
                    .display_name
                    .as_deref()
                    .is_some_and(|n| !n.is_empty() && str_field(entry, "displayname") != Some(n));
                if email_changed || name_changed {
                    p.update.push(a.clone());
                }
            }
            Some(_) => p.foreign.push(a.username.clone()),
        }
        // Only for an account already loaded — see the module note on why
        // asking about one written this cycle would silently send nothing.
        // Hand-made accounts included: resending a link to whatever address
        // Authelia holds is exactly what the button is for.
        if let (Some(at), Some(_)) = (a.link_requested_at.as_ref(), existing) {
            p.links.push((a.username.clone(), at.clone()));
        }
    }
    for (k, v) in users {
        if let Some(name) = k.as_str()
            && is_managed(v, group)
            && !wanted.contains(name)
        {
            p.remove.push(name.to_string());
        }
    }
    p.remove.sort();
    // An empty list removes nothing.
    //
    // "The manager knows of no logins at all" and "every login was deleted"
    // are the same answer on the wire, and the first one has causes that have
    // nothing to do with intent: a database restored from a backup taken
    // before these rows existed, a migration half-applied, a regression in the
    // query. Acting on it locks every viewer out of an event, and re-creating
    // the accounts does not give them their passwords back.
    //
    // So the last account is never swept automatically. Deleting the final
    // login leaves one account to remove by hand, and the log says so — a far
    // cheaper failure than the other direction.
    if accounts.is_empty() && !p.remove.is_empty() {
        tracing::warn!(
            would_remove = p.remove.len(),
            "the manager reports no portal logins at all; leaving the Authelia accounts \
             alone rather than deleting every one. Remove them by hand if that is really \
             what was wanted."
        );
        p.remove.clear();
    }
    p
}

/// A hash nobody holds the password for. argon2 draws the salt itself.
fn unusable_password_hash() -> anyhow::Result<String> {
    use argon2::PasswordHasher;
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let hash = argon2::Argon2::default()
        .hash_password(&secret)
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))?;
    Ok(hash.to_string())
}

/// Apply `p` to the parsed file. Leaves every entry it does not own exactly as
/// it was read.
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

    for name in &p.remove {
        users.remove(Value::String(name.clone()));
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
    for a in &p.update {
        if let Some(Value::Mapping(e)) = users.get_mut(Value::String(a.username.clone())) {
            if let Some(email) = a.email.as_deref().filter(|e| plausible_email(e)) {
                e.insert("email".into(), Value::String(email.to_string()));
            }
            if let Some(n) = a.display_name.as_deref().filter(|n| !n.is_empty()) {
                e.insert("displayname".into(), Value::String(n.to_string()));
            }
        }
    }
    Ok(())
}

/// The file as read, with what is needed to tell whether it changed since.
struct Snapshot {
    doc: Value,
    modified: Option<SystemTime>,
    len: u64,
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
        modified: meta.modified().ok(),
        len: meta.len(),
    })
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
    std::fs::write(&tmp, body.as_bytes())
        .map_err(|e| anyhow::anyhow!("cannot write {}: {e}", tmp.display()))?;
    // Same permissions as the file it replaces: Authelia must still be able to
    // read it, and to write it back when someone sets a password.
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    let now = std::fs::metadata(path).ok();
    let unchanged = now
        .as_ref()
        .is_some_and(|m| m.modified().ok() == snap.modified && m.len() == snap.len);
    if !unchanged {
        let _ = std::fs::remove_file(&tmp);
        return Ok(false);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("cannot replace {}: {e}", path.display());
    }
    Ok(true)
}

/// What one cycle did, for the log.
#[derive(Debug, Default)]
pub struct Outcome {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub links_sent: usize,
    pub lost_race: bool,
}

/// One sync: fetch, plan, write, request links, acknowledge.
pub async fn sync_once(state: &PortalState, cfg: &AccountSyncConfig) -> anyhow::Result<Outcome> {
    let resp = state
        .http
        .get(format!(
            "{}/api/v1/dvr/portal/accounts",
            state.cfg.manager_url
        ))
        .bearer_auth(&state.cfg.manager_token)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("manager answered {} for the account list", resp.status());
    }
    let accounts = resp.json::<AccountsResponse>().await?.accounts;

    let path = cfg.users_file.clone();
    let snap = tokio::task::spawn_blocking(move || read_users_file(&path)).await??;
    let empty = Mapping::new();
    let users = snap
        .doc
        .get("users")
        .and_then(Value::as_mapping)
        .unwrap_or(&empty);
    let p = plan(users, &accounts, &cfg.managed_group);

    let mut out = Outcome::default();
    if p.changes_file() {
        let mut doc = snap.doc.clone();
        apply(&mut doc, &p, &cfg.managed_group, unusable_password_hash)?;
        let path = cfg.users_file.clone();
        let wrote =
            tokio::task::spawn_blocking(move || write_users_file(&path, &snap, &doc)).await??;
        if wrote {
            out.added = p.add.len();
            out.updated = p.update.len();
            out.removed = p.remove.len();
        } else {
            out.lost_race = true;
        }
    }

    for (username, requested_at) in &p.links {
        let account = accounts.iter().find(|a| &a.username == username);
        let error = send_link(state, cfg, username, account).await.err();
        if error.is_none() {
            out.links_sent += 1;
        }
        acknowledge(state, username, requested_at, error.as_deref()).await?;
    }
    Ok(out)
}

/// How long to wait for the rewritten email to reach the relay.
///
/// Authelia mails during the request that asks it to, so this is normally
/// already done by the time it answers. The wait exists so the manager is told
/// what actually happened rather than that the request was accepted.
const RELAY_WAIT: Duration = Duration::from_secs(30);

/// Ask Authelia for a link, and report whether the email really went.
///
/// With [`mail`](super::mail) configured the portal rewrites that email, so it
/// says in advance who to expect one for — that registration is also what tells
/// it whether to write an invitation or a password reset.
async fn send_link(
    state: &PortalState,
    cfg: &AccountSyncConfig,
    username: &str,
    account: Option<&ManagerAccount>,
) -> Result<(), String> {
    let intercepting = state.cfg.mail.is_some();
    let waiter = match (intercepting, account.and_then(|a| a.email.as_deref())) {
        (true, Some(email)) => {
            let kind = if account.is_some_and(|a| a.first_link) {
                super::mail::LinkKind::Invite
            } else {
                super::mail::LinkKind::Reset
            };
            let name = account
                .and_then(|a| a.display_name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| username.to_string());
            Some(state.links.expect(email, kind, &name).await)
        }
        _ => None,
    };

    request_link(state, cfg, username)
        .await
        .map_err(|e| e.to_string())?;

    let Some(waiter) = waiter else { return Ok(()) };
    match tokio::time::timeout(RELAY_WAIT, waiter).await {
        Ok(Ok(result)) => result,
        // The listener dropped the expectation without reporting, which should
        // not happen; say so rather than claiming success.
        Ok(Err(_)) => Err("the portal never saw the email Authelia was asked to send".into()),
        Err(_) => Err("timed out waiting for the email to reach the relay".into()),
    }
}

/// Ask Authelia to email `username` a set-your-password link.
async fn request_link(
    state: &PortalState,
    cfg: &AccountSyncConfig,
    username: &str,
) -> anyhow::Result<()> {
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
        .map_err(|e| anyhow::anyhow!("could not reach Authelia: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("Authelia refused the request ({})", resp.status());
    }
    Ok(())
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

/// The loop. Logs an error once when it starts failing and once when it
/// recovers, rather than every fifteen seconds for as long as it lasts.
pub async fn run(state: PortalState, cfg: AccountSyncConfig) {
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing = false;
    loop {
        ticker.tick().await;
        match sync_once(&state, &cfg).await {
            Ok(o) => {
                if failing {
                    tracing::info!("portal account sync recovered");
                    failing = false;
                }
                if o.added + o.updated + o.removed + o.links_sent > 0 {
                    tracing::info!(
                        added = o.added,
                        updated = o.updated,
                        removed = o.removed,
                        links_sent = o.links_sent,
                        "portal accounts synced to Authelia"
                    );
                }
                if o.lost_race {
                    tracing::info!("Authelia changed its user file mid-sync; retrying next cycle");
                }
            }
            Err(e) => {
                if !failing {
                    tracing::warn!(error = %e, "portal account sync failing; logins in the manager are not reaching Authelia");
                    failing = true;
                }
            }
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

    fn file(yaml: &str) -> Value {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    fn users(doc: &Value) -> Mapping {
        doc.get("users")
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_default()
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
            G,
        );
        assert_eq!(
            p.add
                .iter()
                .map(|a| a.username.as_str())
                .collect::<Vec<_>>(),
            ["new"]
        );
        assert!(p.remove.is_empty() && p.update.is_empty());
    }

    #[test]
    fn a_hand_made_account_is_never_touched() {
        let doc = file(HAND_MADE);
        // The manager has a login called dvr-test, with a different email.
        let mut a = acct("dvr-test", Some("someone-else@example.com"));
        a.display_name = Some("Renamed".into());
        let p = plan(
            &users(&doc),
            &[a, acct("a.smith", Some("alex@example.com"))],
            G,
        );
        assert!(
            p.update.is_empty(),
            "a hand-made account would be rewritten: {p:?}"
        );
        assert!(p.remove.is_empty());
        assert_eq!(p.foreign, ["dvr-test"]);

        // And it survives an apply byte-for-byte in content.
        let mut doc2 = doc.clone();
        let p = plan(&users(&doc), &[acct("x", Some("x@example.com"))], G);
        apply(&mut doc2, &p, G, || Ok("$argon2id$fake".into())).unwrap();
        assert_eq!(doc2["users"]["dvr-test"], doc["users"]["dvr-test"]);
    }

    #[test]
    fn a_managed_account_the_manager_forgot_is_removed() {
        let doc = file(HAND_MADE);
        // Another login still exists, so this is a deletion and not the
        // "manager knows nothing" case guarded against below.
        let p = plan(
            &users(&doc),
            &[acct("someone.else", Some("s@example.com"))],
            G,
        );
        assert_eq!(p.remove, ["a.smith"], "only the managed account goes");
    }

    #[test]
    fn an_empty_list_from_the_manager_deletes_nobody() {
        let doc = file(HAND_MADE);
        let p = plan(&users(&doc), &[], G);
        assert!(
            p.remove.is_empty(),
            "a manager that answered with no logins at all emptied Authelia: {p:?}"
        );
    }

    #[test]
    fn an_email_change_updates_the_account_but_never_its_password() {
        let doc = file(HAND_MADE);
        let p = plan(
            &users(&doc),
            &[acct("a.smith", Some("alex@new.example.com"))],
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
    fn a_new_account_carries_the_mark_and_an_unusable_password() {
        let mut doc = file("users: {}");
        let mut a = acct("b.jones", Some("b@example.com"));
        a.display_name = Some("Bea Jones".into());
        let p = plan(&users(&doc), &[a], G);
        apply(&mut doc, &p, G, unusable_password_hash).unwrap();
        let e = &doc["users"]["b.jones"];
        assert_eq!(e["email"].as_str(), Some("b@example.com"));
        assert_eq!(e["displayname"].as_str(), Some("Bea Jones"));
        assert!(is_managed(e, G));
        let hash = e["password"].as_str().unwrap();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        // Two accounts never share a hash.
        let mut doc2 = file("users: {}");
        apply(&mut doc2, &p, G, unusable_password_hash).unwrap();
        assert_ne!(doc2["users"]["b.jones"]["password"], e["password"]);
    }

    #[test]
    fn a_link_waits_for_an_account_authelia_has_loaded() {
        let doc = file(HAND_MADE);
        let mut fresh = acct("fresh", Some("f@example.com"));
        fresh.link_requested_at = Some("2026-09-22T08:00:00Z".into());
        let mut known = acct("a.smith", Some("alex@example.com"));
        known.link_requested_at = Some("2026-09-22T08:00:01Z".into());
        let mut hand = acct("dvr-test", Some("x@example.com"));
        hand.link_requested_at = Some("2026-09-22T08:00:02Z".into());
        let p = plan(&users(&doc), &[fresh, known, hand], G);
        assert_eq!(
            p.links,
            [
                ("a.smith".to_string(), "2026-09-22T08:00:01Z".to_string()),
                ("dvr-test".to_string(), "2026-09-22T08:00:02Z".to_string()),
            ],
            "a link for an account written this cycle would be answered 200 and send nothing"
        );
        assert_eq!(p.add.len(), 1);
    }

    #[test]
    fn nothing_changed_writes_nothing() {
        let doc = file(HAND_MADE);
        let p = plan(
            &users(&doc),
            &[acct("a.smith", Some("alex@example.com"))],
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
            G,
        );
        assert!(p.add.is_empty(), "{p:?}");
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
        let p = plan(&users(&doc), &[acct("x", Some("x@example.com"))], G);
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
    fn a_write_round_trips_and_keeps_the_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("users.yml");
        std::fs::write(&path, HAND_MADE).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        }
        let snap = read_users_file(&path).unwrap();
        let mut doc = snap.doc.clone();
        let p = plan(
            &users(&doc),
            &[
                acct("x", Some("x@example.com")),
                acct("a.smith", Some("alex@example.com")),
            ],
            G,
        );
        apply(&mut doc, &p, G, || Ok("$argon2id$fake".into())).unwrap();
        assert!(write_users_file(&path, &snap, &doc).unwrap());
        let back = read_users_file(&path).unwrap().doc;
        assert!(back["users"]["x"].is_mapping());
        assert_eq!(back["users"]["dvr-test"], snap.doc["users"]["dvr-test"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o660);
        }
    }

    #[test]
    fn plain_http_to_authelia_is_this_host_only() {
        for ok in [
            "http://127.0.0.1:9091/auth",
            "http://localhost:9091/auth",
            "http://[::1]:9091/auth",
            "https://auth.example.com",
        ] {
            let mut c = AccountSyncConfig {
                users_file: "/etc/authelia/users.yml".into(),
                authelia_url: ok.into(),
                public_host: "watch.example.com".into(),
                managed_group: default_group(),
                interval_secs: 15,
            };
            c.normalise();
            assert!(c.validate().is_ok(), "{ok} was refused");
        }
        for bad in [
            "http://auth.example.com/auth",
            // The host is what counts, not what is written before the `@`.
            "http://127.0.0.1@evil.example.com/auth",
        ] {
            let mut c = AccountSyncConfig {
                users_file: "/etc/authelia/users.yml".into(),
                authelia_url: bad.into(),
                public_host: "watch.example.com".into(),
                managed_group: default_group(),
                interval_secs: 15,
            };
            c.normalise();
            assert!(
                c.validate().is_err(),
                "{bad} would send every invited username over the network in clear"
            );
        }
    }

    #[test]
    fn the_config_refuses_what_would_break_the_link() {
        let ok = AccountSyncConfig {
            users_file: "/etc/authelia/users.yml".into(),
            authelia_url: default_authelia_url(),
            public_host: "watch.example.com".into(),
            managed_group: default_group(),
            interval_secs: 15,
        };
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
}
