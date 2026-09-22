// Smoke test for the DVR player page.
//
// `dvr.html` is ~770 lines of hand-written transport logic that nothing in CI
// parses or executes. This drives the real page in jsdom against stubbed media
// elements and a stubbed hls.js, so a typo'd identifier, a wrong arity, or a
// transport-state regression fails here rather than on a tablet.
//
// Skips (does not fail) when jsdom is absent, so it stays opt-in:
//
//   cd src/distribution && docker run --rm -v "$PWD:/w" -w /w node:22-alpine \
//     sh -c 'npm i --no-save --silent jsdom && node --test tests/dvr_page.test.cjs'

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

let JSDOM;
try {
  ({ JSDOM } = require("jsdom"));
} catch {
  test("dvr page (skipped: jsdom not installed)", () => {});
  return;
}

/// The wall clock at media time 0 in a page loaded with `clock`. Recent, so
/// the day-old cut-off on carrying local marks into the shared list is
/// decided by the test and not by the date it runs on.
const T0 = Math.floor(Date.now() / 1000) * 1000 - 120_000;

const HTML = fs
  .readFileSync(path.join(__dirname, "..", "dvr.html"), "utf8")
  .replace(/__STREAM_ID__/g, "bigshow")
  .replace(/__HLS_JS_VERSION__/g, "1.6.16");

/// A page with the media elements stubbed into something inspectable.
///
/// jsdom implements no media pipeline: `play()` rejects, `currentTime` does not
/// advance, `seekable` is empty. The transport only ever reads those through a
/// few accessors, so replacing them is enough to exercise every branch.
///
/// `opts.clock` gives main a playlist with a published date on every one-second
/// fragment — `T0` at media time 0 — which is what marks and loops convert
/// through. `opts.fetch` stands in for the network; without it the page has no
/// `fetch` at all, as jsdom ships none. `opts.storage` is in `localStorage`
/// before the page's script runs.
function loadPage(opts = {}) {
  const dom = new JSDOM(HTML, {
    runScripts: "outside-only",
    pretendToBeVisual: true,
    // An origin, so `localStorage` exists: marks fall back to it.
    url: "https://relay.test/dvr/bigshow",
  });
  const { window } = dom;
  for (const [k, v] of Object.entries(opts.storage || {})) window.localStorage.setItem(k, v);

  const levels = opts.clock
    ? [{
        details: {
          fragments: Array.from({ length: 100 }, (_, i) => ({
            start: i,
            duration: 1,
            programDateTime: T0 + i * 1000,
          })),
        },
      }]
    : undefined;
  window.Hls = function () {
    return {
      loadSource() {},
      attachMedia() {},
      on() {},
      destroy() {},
      liveSyncPosition: 100,
      levels,
      currentLevel: 0,
    };
  };
  if (opts.fetch) window.fetch = opts.fetch;
  window.Hls.isSupported = () => true;
  window.Hls.Events = { ERROR: "hlsError", MANIFEST_PARSED: "hlsManifestParsed" };

  for (const id of ["main", "proxy"]) {
    const v = window.document.getElementById(id);
    let t = 50;
    Object.defineProperty(v, "currentTime", {
      get: () => t,
      set: (x) => {
        t = x;
      },
      configurable: true,
    });
    Object.defineProperty(v, "seekable", {
      get: () => ({ length: 1, start: () => 0, end: () => 100 }),
      configurable: true,
    });
    Object.defineProperty(v, "readyState", { get: () => 4, configurable: true });
    let paused = true;
    Object.defineProperty(v, "paused", {
      get: () => paused,
      configurable: true,
    });
    v.play = () => {
      paused = false;
      return Promise.resolve();
    };
    v.pause = () => {
      paused = true;
    };
    v.playbackRate = 1;
  }

  // The shuttle is a requestAnimationFrame loop. jsdom drives no frames, so
  // counting the requests is how a test sees the loop start or restart.
  window.rafCalls = 0;
  window.requestAnimationFrame = () => {
    window.rafCalls += 1;
    return window.rafCalls;
  };
  window.cancelAnimationFrame = () => {};

  const script = [...window.document.querySelectorAll("script")]
    .filter((s) => !s.src)
    .map((s) => s.textContent)
    .join("\n");
  window.eval(script);
  return window;
}

/// The page installs a 200 ms `setInterval`, which keeps jsdom's timer queue —
/// and therefore node's event loop — alive forever. Every test must close its
/// window or `node --test` hangs after the last assertion.
function closePage(w) {
  try {
    w.close();
  } catch {
    /* already closed */
  }
}

const click = (w, sel) => w.document.querySelector(sel).dispatchEvent(
  new w.Event("click", { bubbles: true })
);

test("the page loads and wires its controls", (t) => {
  const w = loadPage();
  t.after(() => closePage(w));
  assert.ok(w.document.getElementById("main"), "no main video element");
  assert.ok(w.document.getElementById("proxy"), "no proxy video element");
  assert.ok(
    w.document.querySelector('script[src^="/dvr/hls.js?v="]'),
    "hls.js is loaded from an unversioned URL"
  );
  assert.ok(!HTML.includes("__STREAM_ID__"), "stream id placeholder left in page");
});

test("play after a forward shuttle resumes at a playback rate, not the shuttle rate", (t) => {
  const w = loadPage();
  t.after(() => closePage(w));
  const main = w.document.getElementById("main");

  // Fast-forward: two presses take the shuttle to 4x.
  click(w, "#btnFf");
  click(w, "#btnFf");
  assert.equal(w.document.body.dataset.mode, "shuttle", "FF did not enter shuttle");

  click(w, "#btnPlay");
  assert.ok(
    main.playbackRate <= 1,
    `play resumed at ${main.playbackRate}x — a shuttle seek rate was used as a playbackRate`
  );
});

test("scrubbing during a forward shuttle leaves a running transport", (t) => {
  const w = loadPage();
  t.after(() => closePage(w));
  const scrub = w.document.getElementById("scrub");

  click(w, "#btnFf");
  assert.equal(w.document.body.dataset.mode, "shuttle");

  // A forward shuttle leaves BOTH elements paused, so "is it playing?" cannot
  // be answered by asking the element.
  scrub.dispatchEvent(new w.Event("pointerdown", { bubbles: true }));
  scrub.value = "500";
  scrub.dispatchEvent(new w.Event("input", { bubbles: true }));
  const rafBefore = w.rafCalls;
  w.dispatchEvent(new w.Event("pointerup"));

  const main = w.document.getElementById("main");
  // The shuttle must resume as a shuttle. Resuming it through the playback
  // path instead would set `main.playbackRate` to the seek rate, which is the
  // 16x-playback bug wearing a different hat.
  assert.ok(
    w.rafCalls > rafBefore,
    "releasing the scrub bar did not restart the shuttle loop"
  );
  assert.equal(
    w.document.body.dataset.mode,
    "shuttle",
    "releasing the scrub bar left the shuttle stopped"
  );
  assert.ok(
    main.playbackRate <= 1,
    `resuming the shuttle set playbackRate to ${main.playbackRate}x`
  );
});

// ── shared marks ─────────────────────────────────────────────────────────────

/// The relay's marks surface, in memory, with the same contract: one list per
/// stream, ids minted here, a repeated instant is the same mark, and a `GET`
/// with the current validator answers 304.
function fakeRelay() {
  const relay = { marks: [], rev: 0, calls: [], seq: 0 };
  const etag = () => '"marks-test-' + relay.rev + '"';
  const json = (status, body) => ({
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (h) => (h.toLowerCase() === "etag" ? etag() : null) },
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
  const list = (status, extra = {}) =>
    json(status, { rev: relay.rev, marks: relay.marks.map((m) => ({ ...m })), ...extra });
  relay.fetch = async (url, init = {}) => {
    const method = init.method || "GET";
    relay.calls.push(method + " " + url);
    const m = /^\/origin\/bigshow\/marks(?:\/([0-9a-f]+))?$/.exec(url);
    if (!m) return json(404, {});
    const id = m[1];
    const body = init.body ? JSON.parse(init.body) : null;
    if (method === "GET") {
      if ((init.headers || {})["If-None-Match"] === etag()) return json(304, null);
      return list(200);
    }
    if (method === "POST") {
      assert.ok(Number.isInteger(body.at), "a mark was sent with a fractional instant: " + body.at);
      let mark = relay.marks.find((x) => x.at === body.at);
      if (!mark) {
        relay.seq += 1;
        mark = { id: "a" + relay.seq.toString(16), at: body.at, name: body.name,
                 colour: body.colour, exported: !!body.exported };
        relay.marks.push(mark);
        relay.marks.sort((a, b) => a.at - b.at);
        relay.rev += 1;
      }
      return list(201, { id: mark.id });
    }
    const mark = relay.marks.find((x) => x.id === id);
    if (method === "PATCH") {
      if (!mark) return json(404, {});
      Object.assign(mark, body);
      relay.rev += 1;
      return list(200);
    }
    if (method === "DELETE") {
      relay.marks = relay.marks.filter((x) => x.id !== id);
      relay.rev += 1;
      return list(200);
    }
    return json(405, {});
  };
  return relay;
}

/// Let every promise the page has in flight settle.
const settle = async () => {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  // And a real timer: the page defers some redraws with setTimeout(0).
  await new Promise((r) => setTimeout(r, 10));
  for (let i = 0; i < 5; i++) await new Promise((r) => setImmediate(r));
};
const key = (w, k) =>
  w.document.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true }));
/// A poll now, rather than in three seconds: the page fetches on becoming visible.
const poll = (w) => w.document.dispatchEvent(new w.Event("visibilitychange"));
const rows = (w) => [...w.document.querySelectorAll("#markList li")];

test("a mark made by one viewer appears for another watching the same feed", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, fetch: relay.fetch });
  const b = loadPage({ clock: true, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();

  key(a, "m");
  assert.equal(rows(a).length, 1, "the mark is not drawn until the relay answers");
  await settle();
  assert.equal(relay.marks.length, 1, "the mark never reached the relay");
  assert.equal(relay.marks[0].at, T0 + 50_000, "the mark is not the wall clock at the playhead");

  poll(b);
  await settle();
  assert.equal(rows(b).length, 1, "the second viewer does not see the first viewer's mark");
  const flags = [...b.document.querySelectorAll("#markbar i")].filter((i) => i.style.display === "block");
  assert.equal(flags.length, 1, "no flag on the second viewer's bar");

  // And nothing is doubled once the first viewer's own poll comes round.
  poll(a);
  await settle();
  assert.equal(rows(a).length, 1, "the maker's pending copy and the relay's copy both show");
});

test("a rename, and then a delete, reach the other viewer", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, fetch: relay.fetch });
  const b = loadPage({ clock: true, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();

  const name = a.document.querySelector("#markList li input[type=text]");
  name.value = "Keeper's save";
  name.dispatchEvent(new a.Event("input", { bubbles: true }));
  name.dispatchEvent(new a.Event("change", { bubbles: true }));
  await settle();
  assert.equal(relay.marks[0].name, "Keeper's save", "the rename was not sent");

  poll(b);
  await settle();
  assert.equal(
    rows(b)[0].querySelector("input[type=text]").value,
    "Keeper's save",
    "the second viewer still shows the old name"
  );

  click(b, "#markList li .del");
  await settle();
  assert.equal(relay.marks.length, 0, "the delete was not sent");
  poll(a);
  await settle();
  assert.equal(rows(a).length, 0, "the first viewer still shows a deleted mark");
});

test("a list arriving mid-word does not move the cursor or the name", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, fetch: relay.fetch });
  const b = loadPage({ clock: true, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();

  const name = a.document.querySelector("#markList li input[type=text]");
  name.focus();
  name.value = "Goa";
  name.dispatchEvent(new a.Event("input", { bubbles: true }));
  // Someone else marks something while this is being typed.
  b.document.getElementById("main").currentTime = 20;
  key(b, "m");
  await settle();
  poll(a);
  await settle();
  assert.equal(a.document.activeElement, name, "a poll redrew the list under the cursor");
  assert.equal(name.value, "Goa", "a poll put the old name back mid-word");
  const flags = [...a.document.querySelectorAll("#markbar i")].filter((i) => i.style.display === "block");
  assert.equal(flags.length, 2, "the other viewer's mark did not reach the bar");

  name.blur();
  await settle();
  assert.equal(rows(a).length, 2, "leaving the field did not bring the list up to date");
});

test("an older relay leaves marks on this device, as before", async (t) => {
  const w = loadPage({
    clock: true,
    fetch: async () => ({ status: 404, ok: false, headers: { get: () => null } }),
  });
  t.after(() => closePage(w));
  await settle();
  key(w, "m");
  await settle();
  assert.equal(rows(w).length, 1);
  const stored = JSON.parse(w.localStorage.getItem("bilbycast.dvr.marks.bigshow") || "[]");
  assert.equal(stored.length, 1, "with no shared list the mark was not kept locally");
});

test("marks already on the device are carried into the shared list once", async (t) => {
  const relay = fakeRelay();
  const stored = JSON.stringify([
    // Written by the previous page, with the fraction `wallClockAt` gives.
    { id: 1, at: T0 + 20_000.4, name: "Earlier", colour: "#ffb020" },
    // Two days old: no window reaches it.
    { id: 2, at: T0 - 2 * 86_400_000, name: "Last week", colour: "#ff4d4f" },
  ]);
  const w = loadPage({
    clock: true,
    fetch: relay.fetch,
    storage: { "bilbycast.dvr.marks.bigshow": stored },
  });
  t.after(() => closePage(w));
  await settle();
  assert.deepEqual(
    relay.marks.map((m) => [m.at, m.name, m.colour]),
    [[T0 + 20_000, "Earlier", "#ffb020"]],
    "the device's recent mark was not carried over, or the old one was"
  );
  assert.equal(w.localStorage.getItem("bilbycast.dvr.marks.bigshow"), null,
    "the local list is still live, so it would be carried again");
  assert.equal(w.localStorage.getItem("bilbycast.dvr.marks.bigshow.migrated"), stored,
    "the local list was thrown away rather than kept aside");
});

// ── loop around a mark ───────────────────────────────────────────────────────

test("a loop plays the span around a mark at its own speed, and wraps", (t) => {
  const w = loadPage({ clock: true });
  t.after(() => closePage(w));
  const main = w.document.getElementById("main");
  key(w, "m");                        // a mark at media time 50

  click(w, "#btnLoop");
  assert.equal(w.document.body.dataset.loop, "1", "the loop did not start");
  assert.equal(main.currentTime, 47, "the loop does not start three seconds before the mark");
  assert.equal(main.playbackRate, 0.5, "the loop is not at its own default speed");
  assert.equal(main.paused, false, "the loop is not playing");
  assert.equal(
    w.document.querySelector('.grp.left [aria-pressed="true"]'),
    null,
    "an ordinary playback rate is lit while the loop sets the speed"
  );

  // Reaching the out point goes back to the in point.
  main.currentTime = 53.1;
  main.dispatchEvent(new w.Event("timeupdate"));
  assert.equal(main.currentTime, 47, "the loop ran past its out point");

  // The speed changes without leaving the loop, and is remembered.
  click(w, '#loopBar [data-loop-rate="0.25"]');
  assert.equal(main.playbackRate, 0.25);
  assert.equal(w.document.body.dataset.loop, "1", "changing the loop's speed ended it");
  assert.equal(w.localStorage.getItem("bilbycast.dvr.loop.rate"), "0.25");

  // Any other transport control leaves it, at that control's own rate.
  click(w, "#btnPlay");
  assert.equal(w.document.body.dataset.loop, "0", "play did not end the loop");
  assert.equal(main.playbackRate, 1, "play after a loop kept the loop's speed");
});

test("the loop's length comes from settings, and O toggles it", (t) => {
  const w = loadPage({ clock: true });
  t.after(() => closePage(w));
  const main = w.document.getElementById("main");
  const pre = w.document.getElementById("loopPre");
  pre.value = "10";
  pre.dispatchEvent(new w.Event("change"));
  const post = w.document.getElementById("loopPost");
  post.value = "2";
  post.dispatchEvent(new w.Event("change"));
  key(w, "m");
  key(w, "o");
  assert.equal(main.currentTime, 40, "the in point ignores the seconds-before setting");
  main.currentTime = 52;
  main.dispatchEvent(new w.Event("timeupdate"));
  assert.equal(main.currentTime, 40, "the out point ignores the seconds-after setting");
  key(w, "o");
  assert.equal(w.document.body.dataset.loop, "0", "O did not stop the loop");
  assert.equal(main.paused, true, "stopping the loop did not hold the picture");
});

test("another viewer deleting the looped mark ends the loop", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, fetch: relay.fetch });
  const b = loadPage({ clock: true, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();
  poll(b);
  await settle();
  click(b, "#markList li .loop");
  assert.equal(b.document.body.dataset.loop, "1", "the row's loop button did not start a loop");

  click(a, "#markList li .del");
  await settle();
  poll(b);
  await settle();
  assert.equal(b.document.body.dataset.loop, "0", "the loop outlived its mark");
});
