// Behavioural tests for the viewer portal page.
//
// `portal.js` holds the whole of what the portal does in the browser — the
// "Coming up" refresh and its pacing, the back-off, the pause while hidden,
// the guarded sign-in reload, and a Watch press with its give-up timer — and
// no cargo command executes it: `mod.rs` only serves it. This drives the real
// `portal.html` and `portal.js` in jsdom against a fake network, a virtual
// clock that the test advances by hand, a `document.hidden` the test sets,
// and a `location` whose reloads and navigations are counted rather than
// followed, so a regression in any of those fails here rather than on a
// viewer's tablet.
//
// CI runs it in the `portal-page` job with `PORTAL_PAGE_REQUIRE_JSDOM=1`,
// which makes a missing jsdom a failure rather than a skip. Locally it still
// skips without jsdom, so `node --test` works anywhere:
//
//   cd src/portal && docker run --rm -e PORTAL_PAGE_REQUIRE_JSDOM=1 \
//     -v "$PWD:/w" -w /w node:22-alpine \
//     sh -c 'npm i --no-save --silent jsdom@30 && node --test tests/portal_page.test.cjs'
//
// The page script is run inside a function whose `window`, `fetch`,
// `setTimeout`, `clearTimeout` and `Date` are the test's. Everything else it
// touches — `document`, `sessionStorage`, events — is jsdom's own.

// Start times are told in the browser's own zone; the tests read them in UTC.
process.env.TZ = "UTC";

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

let JSDOM, VirtualConsole;
try {
  ({ JSDOM, VirtualConsole } = require("jsdom"));
} catch (e) {
  // Where the suite is meant to run, a skip would be a green run that tested
  // nothing.
  if (process.env.PORTAL_PAGE_REQUIRE_JSDOM === "1") throw e;
  test("portal page (skipped: jsdom not installed)", () => {});
  return;
}

const HTML = fs.readFileSync(path.join(__dirname, "..", "portal.html"), "utf8");
const JS = fs.readFileSync(path.join(__dirname, "..", "portal.js"), "utf8");

const ORIGIN = "https://watch.test";
/// The virtual clock's start. Fixed, so nothing here depends on the day the
/// suite runs.
const T0 = Date.UTC(2026, 9, 28, 1, 0, 0);
const SEC = 1000;
const MIN = 60 * SEC;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
/// What `signInAgain()` keeps its last reload under.
const RELOAD_KEY = "bilbycast-portal-reloaded-at";
const SIGNED_OUT = "Your sign-in has ended.";
const COULD_NOT_OPEN = "Could not open that feed";

const feed = (name, id) => ({ session_id: id || "s-" + name, name });
/// An upcoming entry starting `inMs` after the clock's start.
const soon = (name, inMs) => ({ name, starts_at: new Date(T0 + inMs).toISOString() });
const until = () => new Promise((r) => setImmediate(r));

/// Every promise the page has chained runs to its end. The page's promises and
/// the test's share one microtask queue, so a macrotask turn drains them all;
/// two, for a chain that schedules another.
async function flush() {
  await until();
  await until();
}

/// The portal page, loaded with:
/// - `opts.answer`: what `/api/feeds` answers, `{feeds, upcoming}` (the
///   default route reads `page.answer` at the time of each request, so a test
///   changes what the next refresh sees by changing that);
/// - `opts.first`: a one-off answer for the first `/api/feeds` instead;
/// - `opts.now`: the clock at load (default `T0`);
/// - `opts.session`: `sessionStorage` before the script runs, which is how a
///   test stands for the page a reload brings up.
///
/// While `page.signedOut` is set, every `/api/feeds` not queued otherwise is
/// answered 401, as a proxy does once the session has ended.
///
/// `/api/watch` is left unanswered unless queued: a test answers each press
/// itself, in whatever order it wants. `/api/clips` answers an empty shelf.
async function loadPortal(opts = {}) {
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e) => {
    // jsdom's CSS parser does not know every property the page uses.
    if (!/Could not parse CSS stylesheet/.test(e.message)) console.error(e.message);
  });
  const dom = new JSDOM(HTML, { runScripts: "outside-only", virtualConsole, url: ORIGIN + "/" });
  const { window } = dom;
  for (const [k, v] of Object.entries(opts.session || {})) window.sessionStorage.setItem(k, v);

  const clock = { now: opts.now ?? T0, seq: 0, timers: new Map() };
  const setT = (fn, ms) => {
    const id = ++clock.seq;
    clock.timers.set(id, { at: clock.now + Math.max(0, Number(ms) || 0), ms, fn });
    return id;
  };
  const clearT = (id) => {
    clock.timers.delete(id);
  };
  class FakeDate extends Date {
    constructor(...a) {
      if (a.length === 0) super(clock.now);
      else super(...a);
    }
    static now() {
      return clock.now;
    }
  }

  let hidden = false;
  Object.defineProperty(window.document, "hidden", { get: () => hidden, configurable: true });
  Object.defineProperty(window.document, "visibilityState", {
    get: () => (hidden ? "hidden" : "visible"),
    configurable: true,
  });

  // jsdom's `location` cannot be replaced or navigated, so the page gets this
  // one: `reload()` and an `href` assignment are recorded, nothing more.
  const loc = {
    origin: ORIGIN,
    reloads: 0,
    navigations: [],
    reload() {
      loc.reloads += 1;
    },
    get href() {
      return ORIGIN + "/";
    },
    set href(v) {
      loc.navigations.push(String(v));
    },
  };
  const win = new Proxy(window, {
    get(t, k) {
      if (k === "location") return loc;
      const v = t[k];
      return typeof v === "function" ? v.bind(t) : v;
    },
  });

  const net = { requests: [], queued: { "/api/feeds": [], "/api/watch": [] } };
  if (opts.first) net.queued["/api/feeds"].push(opts.first);
  const page = {
    window, document: window.document, clock, loc, net,
    answer: opts.answer || { feeds: [], upcoming: [] },
    signedOut: false,
  };

  net.settle = (req, spec) => {
    assert.ok(!req.done, "a request was answered twice: " + req.url);
    req.done = true;
    if (spec.error) {
      req.reject(new TypeError("Failed to fetch"));
      return;
    }
    if (spec.redirect) {
      req.resolve({
        status: 0, ok: false, type: "opaqueredirect",
        json: async () => {
          throw new SyntaxError("an opaque redirect has no body");
        },
      });
      return;
    }
    const status = spec.status ?? 200;
    req.resolve({ status, ok: status >= 200 && status < 300, type: "basic", json: async () => spec.body });
  };
  const route = (req) => {
    const q = net.queued[req.path];
    if (q && q.length) return q.shift();
    if (req.path === "/api/feeds" && page.signedOut) return { status: 401, body: {} };
    if (req.path === "/api/feeds") {
      return {
        body: {
          username: "a.smith",
          feeds: page.answer.feeds,
          upcoming: page.answer.upcoming,
          logout_url: null,
        },
      };
    }
    if (req.path === "/api/clips") return { body: { clips: [] } };
    return null;
  };
  const fakeFetch = (url, init = {}) =>
    new Promise((resolve, reject) => {
      const req = {
        url, path: String(url).split("?")[0], init, at: clock.now,
        body: init.body ? JSON.parse(init.body) : null, resolve, reject, done: false,
      };
      net.requests.push(req);
      const spec = route(req);
      if (spec) net.settle(req, spec);
    });

  const run = window.eval(
    "(function (window, fetch, setTimeout, clearTimeout, Date) {\n" + JS + "\n})"
  );
  run(win, fakeFetch, setT, clearT, FakeDate);

  Object.assign(page, {
    /// Requests to `p` made so far.
    asked: (p) => net.requests.filter((r) => r.path === p),
    /// The newest unanswered `/api/watch`.
    pendingWatch: () => net.requests.filter((r) => r.path === "/api/watch" && !r.done).pop(),
    /// Pending timers of one kind — `feed`, `nav` or `clips` — told by what
    /// they call, which every version of the page agrees on.
    timers(kind) {
      const re = { feed: /loadFeeds/, nav: /reopen/, clips: /loadClips/ }[kind];
      return [...clock.timers.values()].filter((t) => re.test(String(t.fn)));
    },
    /// The waits of the pending feed timers, as armed.
    feedWaits: () => page.timers("feed").map((t) => t.ms),
    /// The time left on the one pending feed timer.
    feedDue() {
      const ts = page.timers("feed");
      assert.equal(ts.length, 1, "expected one refresh timer, found " + ts.length);
      return ts[0].at - clock.now;
    },
    /// Run the clock forward, firing every timer due on the way in order.
    async advance(ms) {
      const end = clock.now + ms;
      for (;;) {
        let next = null;
        for (const [id, t] of clock.timers) {
          if (t.at <= end && (!next || t.at < next[1].at)) next = [id, t];
        }
        if (!next) break;
        clock.timers.delete(next[0]);
        clock.now = next[1].at;
        next[1].fn();
        await flush();
      }
      clock.now = end;
      await flush();
    },
    async setHidden(h) {
      hidden = h;
      window.document.dispatchEvent(new window.Event("visibilitychange"));
      await flush();
    },
    async pageshow(persisted) {
      const ev = new window.Event("pageshow");
      Object.defineProperty(ev, "persisted", { value: persisted });
      window.dispatchEvent(ev);
      await flush();
    },
    async pagehide() {
      window.dispatchEvent(new window.Event("pagehide"));
      await flush();
    },
    /// The Watch button for the feed called `name`.
    button(name) {
      const row = [...window.document.querySelectorAll("#body .feed")].find(
        (r) => !r.classList.contains("upcoming") && r.querySelector(".name").textContent === name
      );
      return row ? row.querySelector("button") : null;
    },
    async press(name) {
      const b = page.button(name);
      assert.ok(b, "no Watch button for " + name + " on: " + page.text());
      b.dispatchEvent(new window.Event("click", { bubbles: true }));
      await flush();
    },
    async answerWatch(req, spec) {
      net.settle(req, spec);
      await flush();
    },
    live: () =>
      [...window.document.querySelectorAll("#body .feed:not(.upcoming) .name")].map((n) => n.textContent),
    upcoming: () =>
      [...window.document.querySelectorAll("#body .feed.upcoming")].map(
        (r) => r.querySelector(".name").textContent + " | " + r.querySelector(".when").textContent
      ),
    text: () => window.document.getElementById("body").textContent,
    close: () => window.close(),
  });
  await flush();
  return page;
}

const minted = (token) => ({ body: { watch_url: "https://origin.test/dvr/show?token=" + token } });

// ── the refresh and its pacing ──────────────────────────────────────────────

test("a refresh is paced by the soonest start", async (t) => {
  const cases = [
    ["three days out: every quarter hour", [soon("Final", 3 * DAY)], 15 * MIN],
    ["five minutes out: at the start", [soon("Final", 5 * MIN)], 5 * MIN],
    ["passed two minutes ago: every half minute", [soon("Final", -2 * MIN)], 30 * SEC],
    ["passed twenty minutes ago: every five minutes", [soon("Final", -20 * MIN)], 5 * MIN],
    ["the soonest of several", [soon("Late", 2 * DAY), soon("Early", 7 * MIN)], 7 * MIN],
  ];
  for (const [what, upcoming, wait] of cases) {
    const page = await loadPortal({ answer: { feeds: [feed("Live")], upcoming } });
    t.after(page.close);
    assert.deepEqual(page.feedWaits(), [wait], what);
    // And it does ask when that comes.
    await page.advance(wait);
    assert.equal(page.asked("/api/feeds").length, 2, what + ": no refresh at the due time");
  }
});

test("with nothing coming up the page does not poll at all", async (t) => {
  const page = await loadPortal({ answer: { feeds: [feed("Live")], upcoming: [] } });
  t.after(page.close);
  assert.deepEqual(page.feedWaits(), []);
  await page.advance(3 * HOUR);
  assert.equal(page.asked("/api/feeds").length, 1, "the page polled with nothing coming up");
});

test("a failed refresh backs off, doubling to the quarter hour, and a good one resets it", async (t) => {
  const page = await loadPortal({
    answer: { feeds: [feed("Live")], upcoming: [soon("Final", 3 * DAY)] },
  });
  t.after(page.close);
  const backoff = [30 * SEC, 1 * MIN, 2 * MIN, 4 * MIN, 8 * MIN, 15 * MIN, 15 * MIN];
  for (const [i, wait] of backoff.entries()) {
    // A portal's 502 and a request that never got an answer, by turns.
    const fail = i % 2 ? { error: true } : { status: 502, body: { error: "Cannot reach the manager right now." } };
    page.net.queued["/api/feeds"].push(fail);
    await page.advance(page.feedDue());
    assert.deepEqual(page.feedWaits(), [wait], "after failure " + (i + 1));
    // What was on screen stays there: a failed refresh is not an error page.
    assert.deepEqual(page.live(), ["Live"], "a failed refresh took the list away");
  }
  // A good answer goes back to the list's own pace...
  await page.advance(page.feedDue());
  assert.deepEqual(page.feedWaits(), [15 * MIN], "a good answer did not reset the pace");
  // ...and the next failure starts the back-off again from the bottom.
  page.net.queued["/api/feeds"].push({ status: 502, body: {} });
  await page.advance(page.feedDue());
  assert.deepEqual(page.feedWaits(), [30 * SEC], "the back-off was not reset by a good answer");
});

test("nothing is asked while the tab is hidden, and showing it asks at once", async (t) => {
  const page = await loadPortal({
    answer: { feeds: [feed("Live")], upcoming: [soon("Final", 10 * MIN)] },
  });
  t.after(page.close);
  await page.setHidden(true);
  assert.deepEqual(page.feedWaits(), [], "a refresh timer ran on in a hidden tab");
  await page.advance(2 * HOUR);
  assert.equal(page.asked("/api/feeds").length, 1, "a hidden tab asked");

  await page.setHidden(false);
  assert.equal(page.asked("/api/feeds").length, 2, "showing the tab did not ask at once");
  // And the refresh goes on from there: the start is long past, so every five
  // minutes.
  assert.deepEqual(page.feedWaits(), [5 * MIN]);

  // A tab hidden while backing off resumes too.
  page.net.queued["/api/feeds"].push({ error: true });
  await page.advance(page.feedDue());
  await page.setHidden(true);
  await page.advance(HOUR);
  const before = page.asked("/api/feeds").length;
  await page.setHidden(false);
  assert.equal(page.asked("/api/feeds").length, before + 1, "a backing-off refresh did not resume on show");
});

test("a refresh answered after the tab is hidden sets no timer there", async (t) => {
  const page = await loadPortal({
    answer: { feeds: [feed("Live")], upcoming: [soon("Final", 10 * MIN)] },
  });
  t.after(page.close);
  // The refresh goes out while the tab is shown, and its answer is held...
  page.net.queued["/api/feeds"].push(null);
  await page.advance(page.feedDue());
  const held = page.net.requests.filter((r) => r.path === "/api/feeds" && !r.done).pop();
  assert.ok(held, "the refresh did not go out");
  // ...until the viewer has switched tabs.
  await page.setHidden(true);
  page.net.settle(held, {
    body: { username: "a.smith", feeds: [feed("Live")], upcoming: [soon("Final", 10 * MIN)], logout_url: null },
  });
  await flush();
  assert.deepEqual(page.feedWaits(), [], "an answer landing in a hidden tab set a refresh timer");
  const asked = page.asked("/api/feeds").length;
  await page.advance(2 * HOUR);
  assert.equal(page.asked("/api/feeds").length, asked, "a hidden tab asked");
  await page.setHidden(false);
  assert.equal(page.asked("/api/feeds").length, asked + 1, "showing the tab did not ask at once");
});

test("an unchanged answer keeps the very same Watch button", async (t) => {
  const page = await loadPortal({
    answer: { feeds: [feed("Live")], upcoming: [soon("Final", 3 * DAY)] },
  });
  t.after(page.close);
  const btn = page.button("Live");
  await page.advance(page.feedDue());
  assert.equal(page.asked("/api/feeds").length, 2);
  assert.strictEqual(page.button("Live"), btn, "an unchanged answer rebuilt the Watch button");

  // A changed one is drawn.
  page.answer = { feeds: [feed("Live"), feed("Second")], upcoming: [soon("Final", 3 * DAY)] };
  await page.advance(page.feedDue());
  assert.deepEqual(page.live(), ["Live", "Second"]);

  // But never under a press in progress.
  await page.press("Live");
  const pressed = page.button("Live");
  page.answer = { feeds: [feed("Live")], upcoming: [soon("Final", 3 * DAY)] };
  await page.advance(page.feedDue());
  assert.strictEqual(page.button("Live"), pressed, "a refresh redrew under a Watch press");
  assert.equal(pressed.textContent, "Opening…");

  // Nor one whose upcoming half failed, with a live list that changed.
  page.answer = { feeds: [feed("Live"), feed("Third")], upcoming: null };
  await page.advance(page.feedDue());
  assert.strictEqual(page.button("Live"), pressed, "a refresh with no upcoming list redrew under a Watch press");
  assert.equal(pressed.textContent, "Opening…");
});

// ── signing in again ─────────────────────────────────────────────────────────

test("a 401 reloads once, then offers a link within 30 s, then reloads again", async (t) => {
  const page = await loadPortal({ first: { status: 401, body: {} } });
  t.after(page.close);
  assert.equal(page.loc.reloads, 1, "a 401 on the first load did not reload");
  const stamp = page.window.sessionStorage.getItem(RELOAD_KEY);
  assert.equal(stamp, String(T0), "the reload was not stamped");

  // The page that reload brings up, 5 s later, is refused too.
  const again = await loadPortal({
    now: T0 + 5 * SEC,
    session: { [RELOAD_KEY]: stamp },
    first: { status: 401, body: {} },
  });
  t.after(again.close);
  assert.equal(again.loc.reloads, 0, "the page reloaded twice within 30 s");
  assert.ok(again.text().includes(SIGNED_OUT), again.text());
  const a = again.document.querySelector("#body a");
  assert.ok(a && a.textContent === "Sign in again" && a.getAttribute("href") === "/", "no Sign in again link");
  // A first load refused has never set a refresh, so this is no test of the
  // link stopping one (the redirect case below and the held-back one past the
  // guard are); it is that the 401 itself does not set one.
  assert.deepEqual(again.feedWaits(), [], "a first load refused set a refresh");

  // Past the 30 s, another 401 reloads again.
  const later = await loadPortal({
    now: T0 + 31 * SEC,
    session: { [RELOAD_KEY]: stamp },
    first: { status: 401, body: {} },
  });
  t.after(later.close);
  assert.equal(later.loc.reloads, 1, "a 401 past the 30 s guard did not reload");
});

test("a refresh redirected to the sign-in host is a sign-in, not a failure", async (t) => {
  const page = await loadPortal({
    answer: { feeds: [feed("Live")], upcoming: [soon("Final", 3 * DAY)] },
  });
  t.after(page.close);
  // Neither fetch follows redirects, which is what makes one visible at all.
  assert.equal(page.asked("/api/feeds")[0].init.redirect, "manual");
  page.net.queued["/api/feeds"].push({ redirect: true });
  await page.advance(page.feedDue());
  assert.equal(page.loc.reloads, 1, "an opaque redirect on a refresh did not reload");

  // Within 30 s of that, the link.
  page.net.queued["/api/feeds"].push({ redirect: true });
  await page.setHidden(true);
  await page.advance(10 * SEC);
  await page.setHidden(false);
  assert.equal(page.loc.reloads, 1, "reloaded twice within 30 s");
  assert.ok(page.text().includes(SIGNED_OUT), page.text());

  // Behind the link nothing is wanted any more: the tab put away and brought
  // back again does not ask.
  page.signedOut = true;
  const asked = page.asked("/api/feeds").length;
  await page.setHidden(true);
  await page.setHidden(false);
  assert.equal(page.asked("/api/feeds").length, asked, "showing the tab asked again behind the link");
  assert.equal(page.loc.reloads, 1);
});

// ── a Watch press ────────────────────────────────────────────────────────────

test("Watch opens the feed in this tab, then gives the button back if nothing happens", async (t) => {
  const page = await loadPortal({ answer: { feeds: [feed("Live", "s1")], upcoming: [] } });
  t.after(page.close);
  await page.press("Live");
  const btn = page.button("Live");
  assert.equal(btn.textContent, "Opening…");
  assert.ok(btn.disabled);
  const req = page.pendingWatch();
  assert.deepEqual(req.body, { session_id: "s1" });
  assert.equal(req.init.method, "POST");
  assert.equal(req.init.redirect, "manual");

  await page.answerWatch(req, minted("t1"));
  assert.deepEqual(page.loc.navigations, [
    "https://origin.test/dvr/show?token=t1&from=" + encodeURIComponent(ORIGIN),
  ]);
  assert.deepEqual(page.timers("nav").map((x) => x.ms), [45 * SEC]);

  // The navigation never happens. At 45 s the button comes back, and nothing
  // else: no refresh that could reload over a navigation still arriving.
  const asked = page.asked("/api/feeds").length;
  await page.advance(45 * SEC);
  assert.equal(btn.textContent, "Watch");
  assert.ok(!btn.disabled);
  assert.equal(page.asked("/api/feeds").length, asked, "the give-up refreshed");
  assert.equal(page.loc.reloads, 0);
});

test("back from the cache, the button is given back and the list asked afresh", async (t) => {
  const page = await loadPortal({ answer: { feeds: [feed("Live")], upcoming: [] } });
  t.after(page.close);
  await page.press("Live");
  await page.answerWatch(page.pendingWatch(), minted("t1"));
  // The navigation went ahead: no give-up timer is left behind.
  await page.pagehide();
  assert.deepEqual(page.timers("nav"), [], "pagehide left the give-up timer");

  const asked = page.asked("/api/feeds").length;
  await page.pageshow(true);
  assert.equal(page.asked("/api/feeds").length, asked + 1, "a cache restore did not refresh");
  const btn = page.button("Live");
  assert.equal(btn.textContent, "Watch");
  assert.ok(!btn.disabled);

  // A first-time pageshow is not a restore.
  await page.pageshow(false);
  assert.equal(page.asked("/api/feeds").length, asked + 1);
});

test("a press answered after a cache restore gave it back does nothing", async (t) => {
  for (const [what, spec] of [
    ["a 502", { status: 502, body: { error: "Cannot reach the manager right now." } }],
    ["a 401", { status: 401, body: {} }],
    ["a redirect", { redirect: true }],
    ["a network error", { error: true }],
    ["a link", minted("stale")],
  ]) {
    const page = await loadPortal({ answer: { feeds: [feed("Live")], upcoming: [] } });
    t.after(page.close);
    await page.press("Live");
    const req = page.pendingWatch();
    await page.pageshow(true);
    await page.answerWatch(req, spec);
    assert.deepEqual(page.live(), ["Live"], what + ": a stale press's answer wiped the reloaded list");
    assert.ok(!page.text().includes("Cannot reach"), what + ": " + page.text());
    assert.ok(!page.text().includes(COULD_NOT_OPEN), what + ": " + page.text());
    assert.equal(page.loc.reloads, 0, what + ": a stale press signed in again");
    assert.deepEqual(page.loc.navigations, [], what + ": a stale press navigated");
  }
});

test("a superseded press answered 401, redirected or failing does nothing", async (t) => {
  for (const [what, spec] of [
    ["a 401", { status: 401, body: {} }],
    ["a redirect", { redirect: true }],
    ["a network error", { error: true }],
  ]) {
    // Superseded by a press on another button, and by one on its own button
    // again, which only the press's number tells apart from it.
    for (const last of ["B", "A"]) {
      const how = what + ", then Watch " + (last === "A" ? "B, A" : "B");
      const page = await loadPortal({ answer: { feeds: [feed("A"), feed("B")], upcoming: [] } });
      t.after(page.close);
      await page.press("A");
      const stale = page.pendingWatch();
      await page.press("B");
      if (last === "A") await page.press("A");
      const latest = page.pendingWatch();
      await page.answerWatch(stale, spec);
      assert.equal(page.loc.reloads, 0, how + ": a superseded press signed in again");
      assert.ok(!page.text().includes(COULD_NOT_OPEN), how + ": " + page.text());
      assert.deepEqual(page.live(), ["A", "B"], how + ": the list was taken away");
      assert.equal(page.button(last).textContent, "Opening…", how + ": the latest press was given back");
      await page.answerWatch(latest, minted("latest"));
      assert.equal(page.loc.navigations.length, 1, how + ": the latest press did not navigate");
      assert.ok(page.loc.navigations[0].includes("token=latest"), page.loc.navigations[0]);
    }
  }
});

test("Watch A, then B, then A again: only the last press is followed", async (t) => {
  for (const order of ["in order", "the last first"]) {
    const page = await loadPortal({
      answer: { feeds: [feed("A"), feed("B"), feed("C")], upcoming: [] },
    });
    t.after(page.close);
    await page.press("A");
    const first = page.pendingWatch();
    await page.press("B");
    const second = page.pendingWatch();
    assert.equal(page.button("A").textContent, "Watch", "B's press did not give A back");
    await page.press("A");
    const third = page.pendingWatch();
    assert.equal(page.button("B").textContent, "Watch");

    const answers = [[first, "first"], [second, "second"], [third, "third"]];
    if (order !== "in order") answers.reverse();
    for (const [req, token] of answers) await page.answerWatch(req, minted(token));
    assert.deepEqual(
      page.loc.navigations,
      ["https://origin.test/dvr/show?token=third&from=" + encodeURIComponent(ORIGIN)],
      order + ": a superseded press navigated"
    );
    assert.equal(page.timers("nav").length, 1, order + ": a give-up timer was left behind");

    // The navigation stalls. A press on C, 40 s on, is not undone by a timer
    // some earlier press left behind.
    await page.advance(40 * SEC);
    await page.press("C");
    const c = page.pendingWatch();
    await page.advance(6 * SEC);
    assert.equal(page.button("C").textContent, "Opening…", order + ": C's press was given back by a stale timer");
    await page.answerWatch(c, minted("c"));
    assert.equal(page.loc.navigations.length, 2, order + ": C's answer was thrown away");
    assert.ok(page.loc.navigations[1].includes("token=c"));
  }
});

test("a failed press says why, and neither reloads nor navigates", async (t) => {
  for (const [spec, why] of [
    [{ status: 403, body: { error: "That feed is not available to you." } }, "That feed is not available to you."],
    [{ status: 200, body: {} }, COULD_NOT_OPEN],
    [{ error: true }, COULD_NOT_OPEN],
  ]) {
    const page = await loadPortal({ answer: { feeds: [feed("Live")], upcoming: [] } });
    t.after(page.close);
    await page.press("Live");
    await page.answerWatch(page.pendingWatch(), spec);
    assert.ok(page.text().includes(why), JSON.stringify(spec) + ": " + page.text());
    assert.equal(page.loc.reloads, 0);
    assert.deepEqual(page.loc.navigations, []);
    assert.deepEqual(page.timers("nav"), []);
  }
});

test("a press answered 401 or redirected signs in again", async (t) => {
  for (const spec of [{ status: 401, body: {} }, { redirect: true }]) {
    const page = await loadPortal({ answer: { feeds: [feed("Live")], upcoming: [] } });
    t.after(page.close);
    await page.press("Live");
    await page.answerWatch(page.pendingWatch(), spec);
    assert.equal(page.loc.reloads, 1, JSON.stringify(spec));
    assert.ok(!page.text().includes(COULD_NOT_OPEN), page.text());
  }
});

// ── a sign-in held back by a press ───────────────────────────────────────────

/// Feeds A and B on air, X an hour out, so a refresh is due at 15 min, and a
/// press on A made just before it. The refresh is refused, and so is every
/// one after it: the session has ended while the press is out. Returns the
/// page and A's request.
async function pressThenRefreshRefused(t) {
  const page = await loadPortal({
    answer: { feeds: [feed("A"), feed("B")], upcoming: [soon("X", HOUR)] },
  });
  t.after(page.close);
  await page.advance(page.feedDue() - 2 * SEC);
  await page.press("A");
  const req = page.pendingWatch();
  page.signedOut = true;
  await page.advance(2 * SEC);
  assert.equal(page.asked("/api/feeds").length, 2, "the refresh did not go out");
  assert.equal(page.loc.reloads, 0, "a refresh reloaded over a press in progress");
  return { page, req };
}

test("a sign-in held back by a press is done when the press fails", async (t) => {
  const failures = [
    ["a 502", { status: 502, body: { error: "Cannot reach the manager right now. Try again in a moment." } }],
    ["a 403", { status: 403, body: { error: "That feed is not available to you." } }],
    ["a network error", { error: true }],
  ];
  for (const [what, spec] of failures) {
    const { page, req } = await pressThenRefreshRefused(t);
    await page.answerWatch(req, spec);
    assert.equal(page.loc.reloads, 1, what + ": the held-back sign-in was dropped");
  }
});

test("a sign-in held back by a press is done when a later press fails", async (t) => {
  const { page, req } = await pressThenRefreshRefused(t);
  await page.press("B");
  // Not done over the new press, which may yet navigate.
  assert.equal(page.loc.reloads, 0, "the sign-in was done over a press still out");
  const b = page.pendingWatch();
  await page.answerWatch(b, { status: 403, body: { error: "That feed is not available to you." } });
  assert.equal(page.loc.reloads, 1, "a superseding press's failure dropped the sign-in");
  // A's answer, landing late, changes nothing.
  await page.answerWatch(req, minted("a"));
  assert.deepEqual(page.loc.navigations, []);
  assert.equal(page.loc.reloads, 1);
});

test("a sign-in held back by a press, past the reload guard, is the link", async (t) => {
  const page = await loadPortal({
    answer: { feeds: [feed("A")], upcoming: [soon("X", HOUR)] },
    session: { [RELOAD_KEY]: String(T0 + 15 * MIN - 10 * SEC) },
  });
  t.after(page.close);
  await page.advance(page.feedDue() - 2 * SEC);
  await page.press("A");
  const req = page.pendingWatch();
  page.signedOut = true;
  await page.advance(2 * SEC);
  // Held back, the refresh goes on every half minute behind the press.
  assert.deepEqual(page.feedWaits(), [30 * SEC]);
  await page.answerWatch(req, { status: 502, body: { error: "Cannot reach the manager right now." } });
  assert.equal(page.loc.reloads, 0);
  assert.ok(page.text().includes(SIGNED_OUT), page.text());
  assert.ok(!page.text().includes("Cannot reach"), "the press's own error stood over the sign-in");

  // The link ends that refresh. Left running, it was refused past the guard
  // and reloaded the page out from under the link.
  assert.deepEqual(page.feedWaits(), [], "the held-back refresh was left running behind the link");
  const asked = page.asked("/api/feeds").length;
  await page.advance(2 * MIN);
  await page.setHidden(true);
  await page.setHidden(false);
  assert.equal(page.asked("/api/feeds").length, asked, "refreshed behind the link");
  assert.equal(page.loc.reloads, 0, "reloaded under the link");
  assert.ok(page.document.querySelector("#body a"), "the Sign in again link went");
});

test("a sign-in held back by a press is done when the press is given up", async (t) => {
  const { page, req } = await pressThenRefreshRefused(t);
  await page.answerWatch(req, minted("a"));
  assert.equal(page.loc.navigations.length, 1);
  assert.equal(page.loc.reloads, 0, "reloaded over the navigation");
  await page.advance(45 * SEC);
  assert.equal(page.loc.reloads, 1, "the give-up did not do the held-back sign-in");
});

test("while a sign-in is held back the refresh keeps going, and not as a failure", async (t) => {
  const { page } = await pressThenRefreshRefused(t);
  assert.deepEqual(page.feedWaits(), [30 * SEC], "nothing was left scheduled behind the press");
  // Refused again, still behind the press: the same half minute, not a
  // back-off, and still no reload over the press.
  await page.advance(30 * SEC);
  assert.equal(page.asked("/api/feeds").length, 3);
  assert.deepEqual(page.feedWaits(), [30 * SEC], "a held-back sign-in was backed off as a failure");
  assert.equal(page.loc.reloads, 0);
});

test("a refresh that gets past the proxy drops a held-back sign-in", async (t) => {
  const { page, req } = await pressThenRefreshRefused(t);
  // The tab is put away and brought back; the refresh that sends is let
  // through, so the session is good after all.
  page.signedOut = false;
  await page.setHidden(true);
  await page.setHidden(false);
  assert.equal(page.asked("/api/feeds").length, 3);
  await page.answerWatch(req, minted("a"));
  await page.advance(45 * SEC);
  assert.equal(page.loc.reloads, 0, "a stale held-back sign-in reloaded a signed-in page");
});

// ── an upcoming list the manager could not give ──────────────────────────────

test("with no upcoming list yet, nothing on air says so and backs off", async (t) => {
  const page = await loadPortal({ answer: { feeds: [], upcoming: null } });
  t.after(page.close);
  assert.ok(page.text().includes("could not be loaded"), page.text());
  assert.deepEqual(page.feedWaits(), [30 * SEC]);
  await page.advance(30 * SEC);
  assert.deepEqual(page.feedWaits(), [1 * MIN], "an unknown list was not backed off");
});

test("an answer missing only its upcoming list ends a back-off", async (t) => {
  const page = await loadPortal({
    answer: { feeds: [feed("Live")], upcoming: [soon("Final", 3 * DAY)] },
  });
  t.after(page.close);
  for (const wait of [30 * SEC, 1 * MIN]) {
    page.net.queued["/api/feeds"].push({ status: 502, body: {} });
    await page.advance(page.feedDue());
    assert.deepEqual(page.feedWaits(), [wait]);
  }
  // The portal answers again; only the manager's upcoming half is missing.
  page.answer = { feeds: [feed("Live")], upcoming: null };
  await page.advance(page.feedDue());
  assert.deepEqual(page.feedWaits(), [15 * MIN], "the remembered list's pace was not taken up");
  // So the next failure is the first of a new back-off.
  page.net.queued["/api/feeds"].push({ status: 502, body: {} });
  await page.advance(page.feedDue());
  assert.deepEqual(page.feedWaits(), [30 * SEC], "the back-off was not reset by an answer missing its upcoming list");
});

test("an upcoming list that stops coming keeps the refresh going and draws a feed that starts", async (t) => {
  const page = await loadPortal({ answer: { feeds: [], upcoming: [soon("X", 10 * MIN)] } });
  t.after(page.close);
  assert.ok(page.text().includes("once they start"), page.text());
  assert.equal(page.upcoming().length, 1);
  assert.deepEqual(page.feedWaits(), [10 * MIN]);

  // From here on the upcoming question fails; the live one does not.
  page.answer = { feeds: [], upcoming: null };
  await page.advance(page.feedDue());
  assert.deepEqual(page.upcoming().map((u) => u.split(" | ")[0]), ["X"], "the last list was not kept");
  assert.deepEqual(page.feedWaits(), [30 * SEC], "the refresh did not keep the list's pace");

  // X starts.
  page.answer = { feeds: [feed("X")], upcoming: null };
  await page.advance(page.feedDue());
  assert.deepEqual(page.live(), ["X"], "a feed that started was not drawn");
  assert.deepEqual(page.upcoming(), [], "a feed on air was still listed as coming up");
  assert.deepEqual(page.feedWaits(), [15 * MIN], "the refresh stopped");
});

test("a feed seen on air does not come back as coming up once it ends", async (t) => {
  const page = await loadPortal({ answer: { feeds: [], upcoming: [soon("X", 10 * MIN)] } });
  t.after(page.close);
  page.answer = { feeds: [feed("X")], upcoming: null };
  await page.advance(10 * MIN);
  assert.deepEqual(page.live(), ["X"]);

  // X ends, and the upcoming question is still failing. X has started, so it
  // is not coming up: the page says nothing is available, as a manager that
  // answered would, and goes on asking every quarter hour — not every five
  // minutes for a start long past.
  page.answer = { feeds: [], upcoming: null };
  await page.advance(page.feedDue());
  assert.deepEqual(page.upcoming(), [], "an ended feed came back as coming up");
  assert.ok(!page.text().includes("Starting shortly"), page.text());
  assert.ok(page.text().includes("Nothing is available"), page.text());
  assert.deepEqual(page.feedWaits(), [15 * MIN]);
  // And it stays gone.
  await page.advance(HOUR);
  assert.deepEqual(page.upcoming(), []);
});

test("a later session of the same name is not the one that went on air", async (t) => {
  // A name is all an upcoming entry carries, so "seen on air" is by name; a
  // session whose start is still more than ten minutes off when a feed of
  // its name is on air is a different one, and stays listed. Here it is a
  // day off; the two cases below pin the ten minutes from either side.
  const page = await loadPortal({
    answer: { feeds: [], upcoming: [soon("Training", 10 * MIN), soon("Training", DAY)] },
  });
  t.after(page.close);
  page.answer = { feeds: [feed("Training")], upcoming: null };
  await page.advance(10 * MIN);
  assert.deepEqual(page.live(), ["Training"]);
  // While one of the name is on air, none is listed as coming up.
  assert.deepEqual(page.upcoming(), []);

  page.answer = { feeds: [], upcoming: null };
  await page.advance(page.feedDue());
  const rows = page.upcoming();
  assert.equal(rows.length, 1, "expected tomorrow's Training only: " + rows);
  assert.ok(rows[0].startsWith("Training | Tomorrow"), rows[0]);
  assert.deepEqual(page.feedWaits(), [15 * MIN]);
});

test("a feed on air five minutes before its start does not come back as coming up", async (t) => {
  // An operator may start a feed ahead of its slot: seen on air up to ten
  // minutes early, it is the entry of its name, and has run.
  const page = await loadPortal({ answer: { feeds: [], upcoming: [soon("X", 10 * MIN)] } });
  t.after(page.close);
  await page.advance(5 * MIN);
  page.answer = { feeds: [feed("X")], upcoming: null };
  await page.setHidden(true);
  await page.setHidden(false);
  assert.equal(page.asked("/api/feeds").length, 2, "no refresh five minutes before the start");
  assert.deepEqual(page.live(), ["X"]);

  // X ends after its start, with the upcoming question still failing.
  page.answer = { feeds: [], upcoming: null };
  await page.advance(page.feedDue());
  assert.deepEqual(page.upcoming(), [], "a feed started early came back as coming up");
  assert.ok(!page.text().includes("Starting shortly"), page.text());
  assert.deepEqual(page.feedWaits(), [15 * MIN]);
});

test("a same-named session twelve minutes off is not the one on air", async (t) => {
  const later = soon("Training", 22 * MIN);
  const page = await loadPortal({
    answer: { feeds: [], upcoming: [soon("Training", 10 * MIN), later] },
  });
  t.after(page.close);
  page.answer = { feeds: [feed("Training")], upcoming: null };
  await page.advance(10 * MIN);
  assert.deepEqual(page.live(), ["Training"]);

  // It ends two minutes in, before the later one is due.
  page.answer = { feeds: [], upcoming: null };
  await page.advance(2 * MIN);
  await page.setHidden(true);
  await page.setHidden(false);
  const rows = page.upcoming();
  assert.equal(rows.length, 1, "expected the later Training only: " + rows);
  assert.ok(rows[0].startsWith("Training | Today"), rows[0]);
  assert.equal(
    page.document.querySelector("#body .feed.upcoming .when").getAttribute("data-starts"),
    later.starts_at
  );
});
