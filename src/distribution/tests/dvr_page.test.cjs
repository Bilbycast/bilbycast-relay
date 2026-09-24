// Behavioural tests for the DVR player page.
//
// `dvr.html` is thousands of lines of hand-written transport, marks and loop
// logic, and the Rust tests in `mod.rs` can only read it as text. This drives
// the real page in jsdom against stubbed media elements, a stubbed hls.js and
// an in-memory relay, so a typo'd identifier, a wrong arity, or a regression
// in the transport or the shared marks fails here rather than on a tablet.
//
// CI runs it in the `dvr-page` job with `DVR_PAGE_REQUIRE_JSDOM=1`, which
// makes a missing jsdom a failure rather than a skip. Locally it still skips
// without jsdom, so `node --test` works anywhere:
//
//   cd src/distribution && docker run --rm -e DVR_PAGE_REQUIRE_JSDOM=1 \
//     -v "$PWD:/w" -w /w node:22-alpine \
//     sh -c 'npm i --no-save --silent jsdom && node --test tests/dvr_page.test.cjs'

const { test } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

let JSDOM;
try {
  ({ JSDOM } = require("jsdom"));
} catch (e) {
  // Where the suite is meant to run, a skip would be a green run that tested
  // nothing.
  if (process.env.DVR_PAGE_REQUIRE_JSDOM === "1") throw e;
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
/// before the page's script runs, and `opts.blockStorage` makes every access
/// to it throw, as a browser with site data blocked does. `opts.token` is the
/// viewer token in the page's URL, as the portal hands it out.
/// `opts.nativeHls` leaves hls.js unsupported, so the page plays the way
/// Safari on iOS does: no request headers, the token in the query instead.
///
/// hls.js's event handlers are kept on `window.hlsHandlers`, so a test can
/// raise the errors the real one would.
function loadPage(opts = {}) {
  const dom = new JSDOM(HTML, {
    runScripts: "outside-only",
    pretendToBeVisual: true,
    // An origin, so `localStorage` exists: marks fall back to it.
    url: "https://relay.test/dvr/bigshow" +
      (opts.token ? "?token=" + encodeURIComponent(opts.token) : ""),
  });
  const { window } = dom;
  for (const [k, v] of Object.entries(opts.storage || {})) window.localStorage.setItem(k, v);
  if (opts.blockStorage) {
    Object.defineProperty(window, "localStorage", {
      get() { throw new window.DOMException("blocked", "SecurityError"); },
      configurable: true,
    });
  }

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
  window.hlsHandlers = {};
  window.Hls = function () {
    return {
      loadSource() {},
      attachMedia() {},
      on(ev, cb) { (window.hlsHandlers[ev] = window.hlsHandlers[ev] || []).push(cb); },
      destroy() {},
      liveSyncPosition: 100,
      levels,
      currentLevel: 0,
    };
  };
  if (opts.fetch) window.fetch = opts.fetch;
  window.Hls.isSupported = () => !opts.nativeHls;
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

/// The viewer token the shared-marks pages are opened with.
const TOKEN = "tkn";

/// The relay's marks surface, in memory, with the same contract: one list per
/// stream, ids minted here, a repeated instant is the same mark, a `GET` with
/// the current validator answers 304, a name is refused on the relay's own
/// rule, and every verb wants the viewer token — `Authorization: Bearer`, or
/// `?token=` where the page cannot set a header — or answers 401. A list never
/// written has no file behind it, and its validator says so: `"marks-none"`,
/// where every later one names the list's lifetime and revision.
///
/// Replies can be made to arrive out of turn. A verb in `relay.hold` is acted
/// on at once but its reply — the list as it stood then — is parked until
/// `relay.release()`. A verb in `relay.lose` is acted on and its reply never
/// arrives: the fetch rejects, as a dropped connection does.
///
/// `opts.refuseNames` refuses every name, for the one path a name is sent on.
function fakeRelay(opts = {}) {
  const relay = {
    marks: [], rev: 0, seq: 0, calls: [], auth: [],
    hold: new Set(), held: [], lose: new Set(), failNext: 0,
  };
  const etag = () => (relay.rev === 0 ? '"marks-none"' : '"marks-7e57-' + relay.rev + '"');
  // The validator is taken when the reply is made, so a held reply carries
  // the one it was made with.
  const json = (status, body) => {
    const tag = etag();
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: { get: (h) => (h.toLowerCase() === "etag" ? tag : null) },
      json: async () => body,
      text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
    };
  };
  const list = (status, extra = {}) =>
    json(status, { rev: relay.rev, marks: relay.marks.map((m) => ({ ...m })), ...extra });
  const nameRefused = (n) =>
    (opts.refuseNames && n) || [...n].length > 120 || /[\u0000-\u001f\u007f-\u009f]/.test(n);
  const NAME_REFUSED = "a mark's name must be at most 120 characters of plain text";

  function act(method, id, body, headers) {
    if (method === "GET") {
      if (headers["If-None-Match"] === etag()) return json(304, null);
      return list(200);
    }
    if (method === "POST") {
      assert.ok(Number.isInteger(body.at), "a mark was sent with a fractional instant: " + body.at);
      if (nameRefused(body.name || "")) return json(400, NAME_REFUSED);
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
      if (!mark) return json(404, "no such mark");
      if (body.name !== undefined && nameRefused(body.name)) return json(400, NAME_REFUSED);
      Object.assign(mark, body);
      relay.rev += 1;
      return list(200);
    }
    if (method === "DELETE") {
      relay.marks = relay.marks.filter((x) => x.id !== id);
      relay.rev += 1;
      return list(200);
    }
    return json(405, "");
  }

  relay.fetch = async (url, init = {}) => {
    const method = init.method || "GET";
    const headers = init.headers || {};
    relay.calls.push(method + " " + url);
    relay.auth.push(headers.Authorization || null);
    const [path, query = ""] = url.split("?");
    const m = /^\/origin\/bigshow\/marks(?:\/([0-9a-f]+))?$/.exec(path);
    if (!m) return json(404, {});
    const viaQuery = new URLSearchParams(query).get("token");
    if (headers.Authorization !== "Bearer " + TOKEN && viaQuery !== TOKEN) {
      return json(401, "viewer token required");
    }
    if (relay.failNext) {
      const status = relay.failNext;
      relay.failNext = 0;
      return json(status, "could not read or write the marks");
    }
    const reply = act(method, m[1], init.body ? JSON.parse(init.body) : null, headers);
    if (relay.lose.has(method)) throw new TypeError("the connection dropped before the reply");
    if (relay.hold.has(method)) return new Promise((resolve) => relay.held.push(() => resolve(reply)));
    return reply;
  };
  relay.release = () => {
    const held = relay.held;
    relay.held = [];
    held.forEach((go) => go());
  };
  return relay;
}

/// A relay from before the list, answering as its router did: `marks` falls
/// through to the object route, whose name check wants a `.` (400 to a GET)
/// and which has no POST (405), and nothing routes three segments after
/// `/origin` (404).
function olderRelay() {
  const relay = { calls: [] };
  relay.fetch = async (url, init = {}) => {
    const method = init.method || "GET";
    relay.calls.push(method + " " + url);
    const path = url.split("?")[0];
    const status = /^\/origin\/bigshow\/marks$/.test(path) ? (method === "GET" ? 400 : 405) : 404;
    return {
      status,
      ok: false,
      headers: { get: () => null },
      text: async () => (status === 400 ? "invalid object name" : ""),
    };
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
const flags = (w) =>
  [...w.document.querySelectorAll("#markbar i")].filter((i) => i.style.display === "block");
const typeName = (w, input, text) => {
  input.value = text;
  input.dispatchEvent(new w.Event("input", { bubbles: true }));
};
const MARKS_KEY = "bilbycast.dvr.marks.bigshow";

test("a mark made by one viewer appears for another watching the same feed", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();

  // The POST lands, and its reply is held: the maker's next poll sees the
  // relay's copy while its own is still pending.
  relay.hold.add("POST");
  key(a, "m");
  assert.equal(rows(a).length, 1, "the mark is not drawn until the relay answers");
  await settle();
  assert.equal(relay.marks.length, 1, "the mark never reached the relay");
  assert.equal(relay.marks[0].at, T0 + 50_000, "the mark is not the wall clock at the playhead");
  poll(a);
  await settle();
  assert.equal(rows(a).length, 1, "the maker's pending copy and the relay's copy both show");
  relay.hold.clear();
  relay.release();
  await settle();
  assert.equal(rows(a).length, 1, "the POST's reply doubled the mark");

  poll(b);
  await settle();
  assert.equal(rows(b).length, 1, "the second viewer does not see the first viewer's mark");
  assert.equal(flags(b).length, 1, "no flag on the second viewer's bar");
});

test("a rename, and then a delete, reach the other viewer", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();

  const name = a.document.querySelector("#markList li input[type=text]");
  typeName(a, name, "Keeper's save");
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
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();

  // The rename stays owed for the whole test, so the only thing that can
  // keep "Goa" on screen is the page laying it over the relay's lists.
  relay.hold.add("PATCH");
  const name = a.document.querySelector("#markList li input[type=text]");
  name.focus();
  typeName(a, name, "Goa");
  // Someone else marks something while this is being typed.
  b.document.getElementById("main").currentTime = 20;
  key(b, "m");
  await settle();
  poll(a);
  await settle();
  assert.equal(a.document.activeElement, name, "a poll redrew the list under the cursor");
  assert.equal(flags(a).length, 2, "the other viewer's mark did not reach the bar");
  assert.ok(
    flags(a).some((f) => f.title === "Goa"),
    "the list put the old name back on the bar mid-word"
  );

  name.blur();
  await settle();
  assert.equal(rows(a).length, 2, "leaving the field did not bring the list up to date");
  assert.equal(relay.marks.find((m) => m.at === T0 + 50_000).name, "", "fixture: the rename landed");
  assert.equal(
    rows(a)[1].querySelector("input[type=text]").value,
    "Goa",
    "the redrawn row shows the relay's old name, not the one still being sent"
  );
});

test("a list is held back for a name being typed, not for a button that kept focus", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();
  poll(b);
  await settle();

  // Chrome leaves focus on a pressed button.
  const lp = b.document.querySelector("#markList li .loop");
  lp.focus();
  click(b, "#markList li .loop");
  assert.equal(b.document.activeElement, lp, "fixture: the loop button should hold focus");

  click(a, "#markList li .del");
  await settle();
  poll(b);
  await settle();
  assert.equal(rows(b).length, 0, "a deleted mark's row stayed because a button in the list had focus");

  // Held back for a name field, the rows are stale — and a stale row's loop
  // button must not loop around a mark that has gone.
  b.document.getElementById("main").currentTime = 30;
  key(b, "m");
  await settle();
  poll(a);
  await settle();
  const name = b.document.querySelector("#markList li input[type=text]");
  name.focus();
  click(a, "#markList li .del");
  await settle();
  poll(b);
  await settle();
  assert.equal(rows(b).length, 1, "fixture: the list should wait for the name field");
  click(b, "#markList li .loop");
  assert.equal(b.document.body.dataset.loop, "0", "a stale row started a loop around a deleted mark");
  const main = b.document.getElementById("main");
  main.currentTime = 70;
  click(b, "#markList li .at");
  assert.equal(main.currentTime, 70, "a stale row went to a mark that has been deleted");
});

/// Two viewers of one list, `b` with a colour palette open on its one row, and
/// a list waiting for `b` that the palette is holding back: `a` has deleted
/// the mark the row is for and made one at media time 20.
///
/// The palette is opened the way Safari and iOS open it — a tap that moves no
/// focus, because neither ever focuses a button — so nothing here can lean on
/// focus to decide whether the palette is in use.
async function paletteHoldingAList(t) {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();
  poll(b);
  await settle();

  click(b, "#markList li .swatch");
  assert.ok(b.document.querySelector("#markList li.picking"), "fixture: the palette did not open");
  assert.notEqual(b.document.activeElement.className, "swatch", "fixture: the swatch took focus");

  click(a, "#markList li .del");
  await settle();
  a.document.getElementById("main").currentTime = 20;
  key(a, "m");
  await settle();
  poll(b);
  await settle();
  return { relay, a, b };
}

/// The instants `b`'s rows are for, relative to `T0`.
const rowAts = (w) => rows(w).map((li) => Number(li.querySelector(".loop").dataset.at) - T0);

test("a list is held back for a colour palette that is open, and moves the flags", async (t) => {
  const { b } = await paletteHoldingAList(t);
  // A redraw would take the palette away under the operator's finger.
  assert.ok(b.document.querySelector("#markList li.picking"), "a poll closed a palette in use");
  assert.deepEqual(rowAts(b), [50_000], "a poll redrew the rows under an open palette");
  assert.equal(flags(b).length, 1, "the bar did not move to the new list");
});

test("a tap outside the open palette closes it and brings the list up to date", async (t) => {
  const { b } = await paletteHoldingAList(t);
  b.document.body.dispatchEvent(new b.Event("pointerdown", { bubbles: true }));
  assert.equal(b.document.querySelector("#markList li.picking"), null, "the palette stayed open");
  assert.deepEqual(rowAts(b), [20_000], "the list stayed held back after the palette was left");
});

test("a tap inside the palette's own row does not close it", async (t) => {
  const { b } = await paletteHoldingAList(t);
  const colour = b.document.querySelector("#markList li .palette button");
  colour.dispatchEvent(new b.Event("pointerdown", { bubbles: true }));
  assert.ok(b.document.querySelector("#markList li.picking"), "pressing a colour closed the palette first");
  colour.dispatchEvent(new b.Event("click", { bubbles: true }));
  assert.ok(b.document.querySelector("#markList li.picking"), "choosing a colour was taken as a tap elsewhere");
});

/// jsdom lays nothing out, so it cannot show a tap landing on the wrong row;
/// what it can pin is the class that lays the palette out. A palette closed
/// on the press lifts every row below it before the tap's click is aimed, and
/// in Chrome a tap on the next row's × then deleted the row below that. The
/// tap itself was checked in headless Chrome over the DevTools protocol.
test("a tap on another row closes the palette once its click is aimed, and the next poll redraws", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  a.document.getElementById("main").currentTime = 30;
  key(a, "m");
  await settle();
  poll(b);
  await settle();
  assert.deepEqual(rowAts(b), [30_000, 50_000], "fixture");

  click(b, "#markList li:nth-child(1) .swatch");
  a.document.querySelectorAll("#markList li .del")[1].dispatchEvent(new a.Event("click", { bubbles: true }));
  await settle();
  a.document.getElementById("main").currentTime = 20;
  key(a, "m");
  await settle();
  poll(b);
  await settle();
  assert.deepEqual(rowAts(b), [30_000, 50_000], "fixture: the palette should hold the list");

  // The row below the open palette.
  const tapped = rows(b)[1];
  const name = tapped.querySelector("input[type=text]");
  name.dispatchEvent(new b.Event("pointerdown", { bubbles: true }));
  assert.ok(
    rows(b)[0].classList.contains("picking"),
    "the palette closed on the press, lifting the row under the finger before the click was aimed"
  );
  name.dispatchEvent(new b.Event("click", { bubbles: true }));
  assert.equal(b.document.querySelector("#markList li.picking"), null, "the palette stayed open");
  assert.equal(rows(b)[1], tapped, "the rows were redrawn under the tap, taking the row it landed on");

  poll(b);
  await settle();
  assert.deepEqual(rowAts(b), [20_000, 30_000], "the list stayed held back once the palette had closed");
});

test("a press in the drawer outside the list closes the palette and leaves the list to the next poll", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();
  poll(b);
  await settle();
  click(b, "#markList li .swatch");
  // The only mark goes, so the list the palette holds back is an empty one.
  click(a, "#markList li .del");
  await settle();
  poll(b);
  await settle();
  assert.deepEqual(rowAts(b), [50_000], "fixture: the palette should hold the list");

  b.document.getElementById("btnExport").dispatchEvent(new b.Event("pointerdown", { bubbles: true }));
  assert.equal(b.document.querySelector("#markList li.picking"), null, "the palette stayed open");
  // Drawn now, the empty list would give its place to the shorter note and
  // lift the export button from under the finger.
  assert.equal(b.document.body.dataset.marks, "1", "the list was drawn under a press on the export controls");
  assert.deepEqual(rowAts(b), [50_000], "the list was drawn under a press on the export controls");
  poll(b);
  await settle();
  assert.equal(b.document.body.dataset.marks, "0", "the list stayed held back once the palette had closed");
});

/// A palette opened on a list already held back — here for a name field, as
/// holding MARK leaves one focused (and Android keeps it focused with the
/// keyboard put away) — is timed from its own opening. Timed from the list's
/// arrival, it was closed by the first poll after it opened, lifting the rows
/// below under a finger on its way to a colour.
test("a palette opened on a list held back for long is not closed by the next poll", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => { closePage(a); closePage(b); });
  await settle();
  key(a, "m");
  await settle();
  poll(b);
  await settle();
  const real = b.performance.now.bind(b.performance);
  let skew = 0;
  b.performance.now = () => real() + skew;

  rows(b)[0].querySelector("input[type=text]").focus();
  a.document.getElementById("main").currentTime = 20;
  key(a, "m");
  await settle();
  poll(b);
  await settle();
  skew = 40_000;
  poll(b);
  await settle();
  assert.deepEqual(rowAts(b), [50_000], "fixture: the list should wait for the name field");

  // Chrome on Android moves focus to a tapped button.
  const swatch = rows(b)[0].querySelector(".swatch");
  swatch.dispatchEvent(new b.Event("pointerdown", { bubbles: true }));
  swatch.focus();
  swatch.dispatchEvent(new b.Event("click", { bubbles: true }));
  await settle();
  assert.ok(b.document.querySelector("#markList li.picking"), "fixture: the palette did not open");

  skew = 41_000;
  poll(b);
  await settle();
  assert.ok(b.document.querySelector("#markList li.picking"), "the first poll after the palette opened closed it");
  assert.deepEqual(rowAts(b), [50_000], "the first poll after the palette opened redrew the rows");

  skew = 71_000;
  poll(b);
  await settle();
  assert.equal(b.document.querySelector("#markList li.picking"), null, "the palette was never closed");
  assert.deepEqual(rowAts(b), [20_000, 50_000], "a palette left open held the list back indefinitely");
});

test("closing the drawer closes an open palette and brings the list up to date", async (t) => {
  const { b } = await paletteHoldingAList(t);
  b.document.body.dataset.drawer = "1";
  key(b, "Escape");
  assert.equal(b.document.body.dataset.drawer, "0", "fixture: Escape did not close the drawer");
  assert.equal(b.document.querySelector("#markList li.picking"), null, "the palette outlived the drawer");
  assert.deepEqual(rowAts(b), [20_000], "the drawer reopens on the list from before");
});

test("a palette nobody touches for half a minute stops holding the list back", async (t) => {
  const { b } = await paletteHoldingAList(t);
  const real = b.performance.now.bind(b.performance);
  let skew = 0;
  b.performance.now = () => real() + skew;

  skew = 10_000;
  poll(b);
  await settle();
  assert.deepEqual(rowAts(b), [50_000], "the list was released while the palette might be in use");

  skew = 31_000;
  poll(b);
  await settle();
  assert.equal(b.document.querySelector("#markList li.picking"), null, "the palette was never closed");
  assert.deepEqual(rowAts(b), [20_000], "a palette left open held the list back indefinitely");
});

test("opening one palette closes any other", async (t) => {
  const relay = fakeRelay();
  const w = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => closePage(w));
  await settle();
  key(w, "m");
  w.document.getElementById("main").currentTime = 20;
  key(w, "m");
  await settle();
  const swatches = w.document.querySelectorAll("#markList li .swatch");
  // By keyboard: a click with no pointerdown before it.
  swatches[0].dispatchEvent(new w.Event("click", { bubbles: true }));
  swatches[1].dispatchEvent(new w.Event("click", { bubbles: true }));
  const open = [...w.document.querySelectorAll("#markList li.picking")];
  assert.deepEqual(open.map((li) => rows(w).indexOf(li)), [1], "two palettes were open at once");
  assert.equal(swatches[0].getAttribute("aria-expanded"), "false");
});

test("a mark whose POST landed but whose reply was lost keeps what was typed into it", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => closePage(a));
  await settle();

  relay.lose.add("POST");
  key(a, "m");
  await settle();
  relay.lose.clear();
  assert.equal(relay.marks.length, 1, "fixture: the POST should have landed");

  // Named and recoloured while the page still holds it as pending.
  typeName(a, a.document.querySelector("#markList li input[type=text]"), "Goal");
  click(a, "#markList li .palette button[aria-label=Blue]");
  await settle();
  poll(a);
  await settle();
  assert.deepEqual(
    [relay.marks.length, relay.marks[0].name, relay.marks[0].colour],
    [1, "Goal", "#4da3ff"],
    "what was typed while the reply was lost never reached the relay"
  );
  assert.equal(rows(a).length, 1);
  assert.equal(rows(a)[0].querySelector("input[type=text]").value, "Goal");
});

test("a pending mark deleted after its POST landed unseen is deleted on the relay", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => closePage(a));
  await settle();

  relay.lose.add("POST");
  key(a, "m");
  await settle();
  relay.lose.clear();
  click(a, "#markList li .del");
  await settle();
  assert.equal(rows(a).length, 0);

  poll(a);
  await settle();
  assert.equal(relay.marks.length, 0, "the relay kept a mark deleted while its POST's reply was lost");
  poll(a);
  await settle();
  assert.equal(rows(a).length, 0, "the deleted mark came back");
});

test("a list older than the one drawn does not bring a deleted mark back", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => closePage(a));
  await settle();
  key(a, "m");
  await settle();

  // A poll leaves before the delete, and its reply arrives after the delete's.
  relay.rev += 1;
  relay.hold.add("GET");
  poll(a);
  await settle();
  relay.hold.clear();
  click(a, "#markList li .del");
  await settle();
  assert.equal(relay.marks.length, 0, "fixture: the delete should have landed");
  relay.release();
  await settle();
  assert.equal(rows(a).length, 0, "a late reply put a deleted mark back");
  assert.equal(flags(a).length, 0, "a late reply put a deleted mark back on the bar");
});

test("a list from before the feed's first mark does not wipe that mark or its loop", async (t) => {
  const relay = fakeRelay();
  // Something between the page and the relay that does not pass the
  // validator on. The relay itself answers a poll carrying `"marks-none"`
  // with a 304 while it has no list, so without this a poll from before the
  // first mark could not come back as a list at all.
  const noValidator = (u, init = {}) => {
    const headers = { ...(init.headers || {}) };
    delete headers["If-None-Match"];
    return relay.fetch(u, { ...init, headers });
  };
  const a = loadPage({ clock: true, token: TOKEN, fetch: noValidator });
  t.after(() => closePage(a));
  await settle();

  // A poll the relay answers while it still has no list at all, delivered
  // after the reply to the feed's first mark.
  relay.hold.add("GET");
  poll(a);
  await settle();
  relay.hold.clear();
  key(a, "m");
  await settle();
  assert.equal(relay.marks.length, 1, "fixture: the mark should have landed");
  click(a, "#markList li .loop");
  assert.equal(a.document.body.dataset.loop, "1", "fixture: the loop should have started");

  relay.release();
  await settle();
  assert.equal(rows(a).length, 1, "a list from before the first mark wiped it");
  assert.equal(flags(a).length, 1, "a list from before the first mark took its flag off the bar");
  assert.equal(a.document.body.dataset.loop, "1", "a list from before the first mark ended its loop");
});

test("marks travel with the viewer token, in a header where hls.js is in play", async (t) => {
  const relay = fakeRelay();
  const w = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => closePage(w));
  await settle();
  key(w, "m");
  await settle();
  assert.equal(relay.marks.length, 1, "the mark did not reach the relay with the token");
  assert.ok(relay.auth.every((a) => a === "Bearer " + TOKEN), "a marks request went without the header");
  assert.ok(relay.calls.every((c) => !c.includes("token=")), "the token went into a URL as well");
});

test("marks travel with the viewer token in the query where the page plays native HLS", async (t) => {
  const relay = fakeRelay();
  relay.marks.push({ id: "a1", at: T0 + 10_000, name: "Kick-off", colour: "#ffb020", exported: false });
  relay.rev = 1;
  const w = loadPage({ token: TOKEN, fetch: relay.fetch, nativeHls: true });
  t.after(() => closePage(w));
  await settle();
  assert.equal(rows(w).length, 1, "the shared list was not read");
  assert.ok(relay.calls.length > 0 && relay.calls.every((c) => c.includes("?token=" + TOKEN)),
    "a marks request went without the token in its query: " + relay.calls);
  assert.ok(relay.auth.every((a) => a === null), "a header was sent where the page cannot set one");
});

test("a page with no token keeps its marks on the device", async (t) => {
  const relay = fakeRelay();
  const w = loadPage({ clock: true, fetch: relay.fetch });
  t.after(() => closePage(w));
  await settle();
  key(w, "m");
  await settle();
  assert.equal(relay.marks.length, 0, "a mark was sent without a token");
  assert.equal(JSON.parse(w.localStorage.getItem(MARKS_KEY) || "[]").length, 1,
    "refused the shared list, the mark was not kept locally");
});

test("an older relay leaves marks on this device, and is not asked every poll", async (t) => {
  const relay = olderRelay();
  const w = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => closePage(w));
  await settle();
  key(w, "m");
  await settle();
  assert.equal(rows(w).length, 1);
  const stored = JSON.parse(w.localStorage.getItem(MARKS_KEY) || "[]");
  assert.equal(stored.length, 1, "with no shared list the mark was not kept locally");
  poll(w);
  await settle();
  poll(w);
  await settle();
  assert.deepEqual(
    relay.calls,
    ["GET /origin/bigshow/marks"],
    "a relay without the list was asked again on the next poll, or sent a mark"
  );
});

test("a page on its own marks asks again now and then, and joins a list that appears", async (t) => {
  const older = olderRelay();
  const relay = fakeRelay();
  let upgraded = false;
  const w = loadPage({
    clock: true,
    token: TOKEN,
    fetch: (u, i) => (upgraded ? relay.fetch(u, i) : older.fetch(u, i)),
  });
  t.after(() => closePage(w));
  await settle();
  key(w, "m");
  await settle();

  upgraded = true;
  for (let i = 0; i < 19; i++) poll(w);
  await settle();
  assert.equal(relay.calls.length, 0, "a relay without the list was asked again on every poll");
  poll(w);
  await settle();
  assert.equal(relay.marks.length, 1, "the list the relay now has was never joined");
  assert.equal(relay.marks[0].at, T0 + 50_000);
});

test("joining a list mid-session keeps the export selection, the mark to name, and a loop", async (t) => {
  const older = olderRelay();
  const relay = fakeRelay();
  let upgraded = false;
  const w = loadPage({
    clock: true,
    token: TOKEN,
    fetch: (u, i) => (upgraded ? relay.fetch(u, i) : older.fetch(u, i)),
    // Written by the previous page, with the fraction `wallClockAt` gives.
    storage: { [MARKS_KEY]: JSON.stringify([{ id: 1, at: T0 + 20_000.4, name: "", colour: "#ffb020" }]) },
  });
  t.after(() => closePage(w));
  await settle();
  key(w, "m");                          // at media time 50: the one to name
  await settle();

  // Looping around the older mark, both ticked for export.
  click(w, "#markList li .loop");
  assert.equal(w.document.body.dataset.loop, "1", "fixture: the loop should have started");
  click(w, "#btnExport");
  for (const pick of w.document.querySelectorAll("#markList li .pick")) {
    pick.checked = true;
    pick.dispatchEvent(new w.Event("change", { bubbles: true }));
  }
  const exportCount = w.document.getElementById("exportCount");
  assert.equal(exportCount.textContent, "2 selected", "fixture: both marks should be ticked");

  // The relay is upgraded, and the next ask joins its list.
  upgraded = true;
  for (let i = 0; i < 20; i++) poll(w);
  await settle();
  assert.equal(relay.marks.length, 2, "fixture: both marks should have been carried");
  assert.equal(exportCount.textContent, "2 selected", "joining the list cleared the export selection");
  assert.ok(
    [...w.document.querySelectorAll("#markList li .pick")].every((p) => p.checked),
    "joining the list unticked the rows"
  );
  assert.equal(w.document.body.dataset.loop, "1", "joining the list ended a loop around a carried mark");

  // Holding MARK opens the list on the mark just made, ready to name.
  w.document.getElementById("btnMark").dispatchEvent(new w.Event("pointerdown", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 500));
  const named = w.document.activeElement;
  assert.equal(named.tagName, "INPUT", "the list opened with no row to name");
  assert.equal(
    Number(named.closest("li").querySelector(".loop").dataset.at),
    T0 + 50_000,
    "the list opened on the wrong mark"
  );
});

test("a relay that fails a read is asked again on the next poll", async (t) => {
  const relay = fakeRelay();
  relay.failNext = 503;
  const w = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  t.after(() => closePage(w));
  await settle();
  poll(w);
  await settle();
  key(w, "m");
  await settle();
  assert.equal(relay.marks.length, 1, "one failed read left the page on its own marks for good");
});

test("marks already on the device are carried into the shared list once", async (t) => {
  const relay = fakeRelay();
  const stored = JSON.stringify([
    // Written by the previous page, with the fraction `wallClockAt` gives.
    { id: 1, at: T0 + 20_000.4, name: "Earlier", colour: "#ffb020" },
    // Two days old: no window reaches it.
    { id: 2, at: T0 - 2 * 86_400_000, name: "Last week", colour: "#ff4d4f" },
    // Names the old page never limited, which the relay would refuse.
    { id: 3, at: T0 + 30_000, name: "Goal\tscored", colour: "#ffb020" },
    { id: 4, at: T0 + 40_000, name: "y".repeat(150), colour: "#ffb020" },
  ]);
  const w = loadPage({
    clock: true,
    token: TOKEN,
    fetch: relay.fetch,
    storage: { [MARKS_KEY]: stored },
  });
  t.after(() => closePage(w));
  await settle();
  assert.deepEqual(
    relay.marks.map((m) => [m.at, m.name, m.colour]),
    [
      [T0 + 20_000, "Earlier", "#ffb020"],
      [T0 + 30_000, "Goal scored", "#ffb020"],
      [T0 + 40_000, "y".repeat(120), "#ffb020"],
    ],
    "the device's recent marks were not carried over as the relay takes them, or the old one was"
  );
  assert.equal(w.localStorage.getItem(MARKS_KEY), null,
    "the local list is still live, so it would be carried again");
  assert.equal(w.localStorage.getItem(MARKS_KEY + ".migrated"), stored,
    "the local list was thrown away rather than kept aside");
});

test("a later carry never replaces the list first kept aside", async (t) => {
  const relay = fakeRelay();
  const first = JSON.stringify([{ id: 1, at: T0 - 3 * 86_400_000, name: "Old", colour: "#ffb020" }]);
  const later = JSON.stringify([{ id: 1, at: T0 + 20_000, name: "", colour: "#ff4d4f" }]);
  const w = loadPage({
    clock: true,
    token: TOKEN,
    fetch: relay.fetch,
    storage: { [MARKS_KEY + ".migrated"]: first, [MARKS_KEY]: later },
  });
  t.after(() => closePage(w));
  await settle();
  assert.equal(relay.marks.length, 1, "fixture: the later mark should have been carried");
  assert.equal(w.localStorage.getItem(MARKS_KEY + ".migrated"), first,
    "the device's original list was overwritten");
  const beside = Object.keys(w.localStorage).filter((k) => k.startsWith(MARKS_KEY + ".migrated."));
  assert.deepEqual(beside.map((k) => w.localStorage.getItem(k)), [later],
    "the later list was not kept beside the first");
});

test("a name the relay refuses costs the name, not the mark", async (t) => {
  const relay = fakeRelay({ refuseNames: true });
  const w = loadPage({
    clock: true,
    token: TOKEN,
    fetch: relay.fetch,
    storage: { [MARKS_KEY]: JSON.stringify([{ id: 1, at: T0 + 20_000, name: "Earlier", colour: "#ffb020" }]) },
  });
  t.after(() => closePage(w));
  await settle();
  assert.deepEqual(relay.marks.map((m) => [m.at, m.name]), [[T0 + 20_000, ""]],
    "a refused name took its mark with it");
  assert.equal(rows(w).length, 1);
  assert.match(w.document.getElementById("err").textContent, /kept without its name/);
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

test("with site data blocked, the loop's speed and length still take effect", (t) => {
  const w = loadPage({ clock: true, blockStorage: true });
  t.after(() => closePage(w));
  const main = w.document.getElementById("main");
  const pre = w.document.getElementById("loopPre");
  pre.value = "10";
  pre.dispatchEvent(new w.Event("change"));
  key(w, "m");
  key(w, "o");
  assert.equal(main.currentTime, 40, "the seconds-before setting did nothing without storage");
  click(w, '#loopBar [data-loop-rate="0.25"]');
  main.dispatchEvent(new w.Event("timeupdate"));
  assert.equal(main.playbackRate, 0.25, "the speed buttons did nothing without storage");
  assert.equal(
    w.document.querySelector('#loopBar [data-loop-rate="0.25"]').getAttribute("aria-pressed"),
    "true"
  );
});

test("a loop started during a shuttle ends into normal speed, not back into the shuttle", (t) => {
  const w = loadPage({ clock: true });
  t.after(() => closePage(w));
  key(w, "m");
  click(w, "#btnFf");
  click(w, "#btnFf");                  // 4x
  key(w, "o");
  assert.equal(w.document.body.dataset.loop, "1", "fixture: the loop should have started");

  const scrub = w.document.getElementById("scrub");
  scrub.dispatchEvent(new w.Event("pointerdown", { bubbles: true }));
  scrub.value = "500";
  scrub.dispatchEvent(new w.Event("input", { bubbles: true }));
  w.dispatchEvent(new w.Event("pointerup"));
  assert.notEqual(
    w.document.body.dataset.mode,
    "shuttle",
    "leaving the loop by the scrub bar started a shuttle nobody asked for"
  );
  assert.ok(w.document.getElementById("main").playbackRate <= 1);
});

test("deleting the looped mark on this device ends the loop", (t) => {
  const w = loadPage({ clock: true });          // no fetch: marks are local
  t.after(() => closePage(w));
  key(w, "m");
  key(w, "o");
  assert.equal(w.document.body.dataset.loop, "1", "fixture: the loop should have started");
  click(w, "#markList li .del");
  w.document.getElementById("main").dispatchEvent(new w.Event("timeupdate"));
  assert.equal(w.document.body.dataset.loop, "0", "the loop outlived its mark");
});

test("another viewer deleting the looped mark ends the loop", async (t) => {
  const relay = fakeRelay();
  const a = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
  const b = loadPage({ clock: true, token: TOKEN, fetch: relay.fetch });
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

test("a loop ends when access does, and cannot be started again", (t) => {
  const w = loadPage({ clock: true, token: TOKEN });
  t.after(() => closePage(w));
  const main = w.document.getElementById("main");
  key(w, "m");
  key(w, "o");
  assert.equal(w.document.body.dataset.loop, "1", "fixture: the loop should have started");

  // The relay refuses the credential, as it does once access is withdrawn.
  for (const cb of w.hlsHandlers.hlsError || []) {
    cb("hlsError", { details: "fragLoadError", fatal: false, response: { code: 403 } });
  }
  assert.match(w.document.getElementById("err").textContent, /expired/, "fixture: no expiry notice");
  assert.equal(w.document.body.dataset.loop, "0", "the loop played on after access ended");
  main.dispatchEvent(new w.Event("timeupdate"));
  assert.equal(main.paused, true, "the picture restarted under the expiry notice");
  key(w, "o");
  assert.equal(w.document.body.dataset.loop, "0", "a loop started after access ended");
});

test("the self-test ends a loop before it drives the player", (t) => {
  const w = loadPage({ clock: true });
  t.after(() => closePage(w));
  key(w, "m");
  key(w, "o");
  assert.equal(w.document.body.dataset.loop, "1", "fixture: the loop should have started");
  click(w, "#stRun");
  assert.equal(w.document.body.dataset.loop, "0", "the self-test ran with a loop fencing the transport");
});
