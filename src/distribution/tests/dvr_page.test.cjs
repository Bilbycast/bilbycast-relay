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

const HTML = fs
  .readFileSync(path.join(__dirname, "..", "dvr.html"), "utf8")
  .replace(/__STREAM_ID__/g, "bigshow")
  .replace(/__HLS_JS_VERSION__/g, "1.6.16");

/// A page with the media elements stubbed into something inspectable.
///
/// jsdom implements no media pipeline: `play()` rejects, `currentTime` does not
/// advance, `seekable` is empty. The transport only ever reads those through a
/// few accessors, so replacing them is enough to exercise every branch.
function loadPage() {
  const dom = new JSDOM(HTML, { runScripts: "outside-only", pretendToBeVisual: true });
  const { window } = dom;

  window.Hls = function () {
    return {
      loadSource() {},
      attachMedia() {},
      on() {},
      destroy() {},
      liveSyncPosition: 100,
    };
  };
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
