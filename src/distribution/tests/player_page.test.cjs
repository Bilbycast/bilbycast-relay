// Behavioural tests for the `/watch` player page.
//
// `player.html` holds the WHEP player's whole reconnect logic — come back for
// the stream when the relay closes the session or the connection fails, back
// off 1 s doubling to 30 s, start over after a session that stayed up 10 s,
// stop on a refusal asking again will not change, let Stop cancel a pending
// retry — and no cargo command executes it: `mod.rs` only serves it. This
// runs the page's real script in jsdom against a fake `RTCPeerConnection`
// whose transport and connection states the test sets, a fake `fetch` the
// test answers, and a virtual clock the test advances by hand.
//
// CI runs it in the `dvr-page` job, beside the DVR page's suite (it is the
// job that installs jsdom in this directory), with
// `PLAYER_PAGE_REQUIRE_JSDOM=1`, which makes a missing jsdom a failure rather
// than a skip. Locally it still skips without jsdom, so `node --test` works
// anywhere:
//
//   cd src/distribution && docker run --rm -e PLAYER_PAGE_REQUIRE_JSDOM=1 \
//     -v "$PWD:/w" -w /w node:22-alpine \
//     sh -c 'npm i --no-save --silent jsdom@30 && node --test tests/player_page.test.cjs'
//
// The page script runs inside a function whose `fetch`, `setTimeout`,
// `clearTimeout`, `Date`, `RTCPeerConnection` and `MediaStream` are the
// test's. Everything else it touches — `document`, `location`, events — is
// jsdom's own.

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
  if (process.env.PLAYER_PAGE_REQUIRE_JSDOM === "1") throw e;
  test("player page (skipped: jsdom not installed)", () => {});
  return;
}

const HTML = fs
  .readFileSync(path.join(__dirname, "..", "player.html"), "utf8")
  .replace(/__STREAM_ID__/g, "live");
const SCRIPT = (() => {
  const m = HTML.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(m, "player.html has one inline script");
  return m[1];
})();
const SEC = 1000;
const until = () => new Promise((r) => setImmediate(r));

/// Every promise the page has chained runs to its end: `start()` awaits
/// several in a row, so a few macrotask turns.
async function flush() {
  for (let i = 0; i < 6; i++) await until();
}

/// The player page, with:
/// - `page.pcs`: every `RTCPeerConnection` it made, newest last, each with
///   `ice(state)`, `conn(state)` and `dtls(state)` to move it;
/// - `page.posts` / `page.deletes`: the WHEP requests it made, each POST
///   answered by `page.answer(post, {status, body})` (201 with a resource
///   and an answer unless told otherwise) or `page.fail(post)`;
/// - `page.advance(ms)`: the clock moved on, firing every timer due.
async function loadPlayer(opts = {}) {
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", (e) => console.error(e.message));
  const dom = new JSDOM(HTML, {
    runScripts: "outside-only",
    virtualConsole,
    url: "https://relay.test/watch/live" + (opts.token ? "?token=" + opts.token : ""),
  });
  const { window } = dom;

  const clock = { now: 1_000_000, seq: 0, timers: new Map() };
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

  const pcs = [];
  class FakePC {
    constructor(config) {
      this.config = config;
      this.closed = false;
      this.iceConnectionState = "new";
      this.connectionState = "new";
      this.receivers = [];
      // Like a browser's: no DTLS transport until the answer is applied.
      this.transport = null;
      pcs.push(this);
    }
    addTransceiver(kind, init) {
      this.receivers.push({ kind, init, get transport() { return this.pc.transport; }, pc: this });
    }
    getReceivers() {
      return this.receivers;
    }
    async createOffer() {
      return { type: "offer", sdp: "v=0 offer " + pcs.length };
    }
    async setLocalDescription(d) {
      this.local = d;
    }
    async setRemoteDescription(d) {
      this.remote = d;
      this.transport = { state: "new", onstatechange: null };
    }
    close() {
      this.closed = true;
    }
    ice(state) {
      this.iceConnectionState = state;
      if (this.oniceconnectionstatechange) this.oniceconnectionstatechange();
    }
    conn(state) {
      this.connectionState = state;
      if (this.onconnectionstatechange) this.onconnectionstatechange();
    }
    dtls(state) {
      this.transport.state = state;
      if (this.transport.onstatechange) this.transport.onstatechange();
    }
  }
  class FakeMediaStream {
    addTrack() {}
  }

  const posts = [];
  const deletes = [];
  const fakeFetch = (url, init = {}) => {
    if (init.method === "DELETE") {
      deletes.push({ url, init });
      return Promise.resolve({ ok: true, status: 200 });
    }
    return new Promise((resolve, reject) => {
      posts.push({ url, init, resolve, reject, at: clock.now });
    });
  };

  const run = window.eval(
    "(function (fetch, setTimeout, clearTimeout, Date, RTCPeerConnection, MediaStream) {\n" +
      SCRIPT +
      "\n})"
  );
  run(fakeFetch, setT, clearT, FakeDate, FakePC, FakeMediaStream);

  const $ = (id) => window.document.getElementById(id);
  const page = {
    window, clock, pcs, posts, deletes,
    status: () => $("status").textContent,
    isError: () => $("status").classList.contains("err"),
    button: () => $("play").textContent,
    async click() {
      $("play").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
      await flush();
    },
    /// The pending retry timers, as armed.
    retries: () => [...clock.timers.values()].filter((t) => /start\(\)/.test(String(t.fn))),
    /// The wait of the one pending retry.
    retryWait() {
      const ts = page.retries();
      assert.equal(ts.length, 1, "expected one pending retry, found " + ts.length);
      return ts[0].ms;
    },
    /// Answer `post` (default: the newest).
    async answer(spec = {}, post = posts[posts.length - 1]) {
      const status = spec.status ?? 201;
      const n = posts.indexOf(post) + 1;
      post.resolve({
        ok: status >= 200 && status < 300,
        status,
        headers: { get: (h) => (h === "Location" ? "/whep/live/resource-" + n : null) },
        text: async () => spec.body ?? "v=0 answer " + n,
      });
      await flush();
    },
    async fail(post = posts[posts.length - 1]) {
      post.reject(new TypeError("Failed to fetch"));
      await flush();
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
    /// Press Watch, and have the relay answer and the session connect.
    async watchAndConnect() {
      await page.click();
      await page.answer();
      page.pcs[page.pcs.length - 1].ice("connected");
    },
    close: () => window.close(),
  };
  return page;
}

test("a session the relay closes is asked for again after 1 s", async () => {
  const page = await loadPlayer({ token: "tok" });
  await page.watchAndConnect();
  assert.equal(page.posts.length, 1);
  assert.equal(page.posts[0].url, "/whep/live");
  assert.equal(page.posts[0].init.headers.Authorization, "Bearer tok");
  assert.equal(page.button(), "Stop");

  // The relay ends the session with its stream: a DTLS close_notify.
  const first = page.pcs[0];
  first.dtls("closed");
  assert.equal(page.status(), "stream ended — reconnecting in 1 s");
  assert.equal(page.isError(), false);
  assert.ok(first.closed, "the dropped session is closed");
  assert.deepEqual(page.deletes.map((d) => d.url), ["/whep/live/resource-1"]);
  assert.equal(page.retryWait(), 1 * SEC);

  await page.advance(999);
  assert.equal(page.posts.length, 1, "not before the back-off");
  await page.advance(1);
  assert.equal(page.posts.length, 2, "and then asked for again");
  assert.equal(page.pcs.length, 2, "on a new peer connection");
  await page.answer();
  page.pcs[1].ice("connected");
  assert.equal(page.status(), "connected");
  page.close();
});

test("a failed connection is asked for again, shown as an error", async () => {
  for (const fail of [(pc) => pc.dtls("failed"), (pc) => pc.conn("failed")]) {
    const page = await loadPlayer();
    await page.watchAndConnect();
    fail(page.pcs[0]);
    assert.equal(page.status(), "connection lost — reconnecting in 1 s");
    assert.equal(page.isError(), true);
    await page.advance(1 * SEC);
    assert.equal(page.posts.length, 2);
    page.close();
  }
});

test("the back-off doubles to 30 s and stays there", async () => {
  const page = await loadPlayer();
  await page.click();
  const waits = [];
  for (let i = 0; i < 8; i++) {
    // Each attempt is answered, and its session closes before it connects.
    await page.answer();
    page.pcs[page.pcs.length - 1].dtls("closed");
    waits.push(page.retryWait());
    await page.advance(page.retryWait());
  }
  assert.deepEqual(waits, [1, 2, 4, 8, 16, 30, 30, 30].map((s) => s * SEC));
  assert.equal(page.posts.length, 9, "one request per back-off, never in a loop");
  page.close();
});

test("a session that stayed up 10 s starts the back-off over; a shorter one does not", async () => {
  const page = await loadPlayer();
  await page.watchAndConnect();
  // Two quick failures: 1 s, then 2 s.
  page.pcs[0].dtls("closed");
  await page.advance(1 * SEC);
  await page.answer();
  page.pcs[1].dtls("closed");
  assert.equal(page.retryWait(), 2 * SEC);
  await page.advance(2 * SEC);

  // Connected for 9.999 s: not long enough.
  await page.answer();
  page.pcs[2].ice("connected");
  await page.advance(9999);
  page.pcs[2].dtls("closed");
  assert.equal(page.retryWait(), 4 * SEC);
  await page.advance(4 * SEC);

  // Connected for 10 s: the next wait is 1 s again.
  await page.answer();
  page.pcs[3].ice("connected");
  await page.advance(10 * SEC);
  page.pcs[3].dtls("closed");
  assert.equal(page.retryWait(), 1 * SEC);
  page.close();
});

test("Stop cancels a pending retry", async () => {
  const page = await loadPlayer();
  await page.watchAndConnect();
  page.pcs[0].dtls("closed");
  assert.equal(page.retries().length, 1);

  await page.click();
  assert.equal(page.button(), "Watch");
  assert.equal(page.status(), "stopped");
  assert.equal(page.retries().length, 0, "the retry is cancelled");
  await page.advance(60 * SEC);
  assert.equal(page.posts.length, 1, "and nothing is asked for");

  // Watch again starts at once, with the back-off from the start.
  await page.click();
  assert.equal(page.posts.length, 2);
  await page.answer();
  page.pcs[1].dtls("closed");
  assert.equal(page.retryWait(), 1 * SEC);
  page.close();
});

test("a refusal that asking again will not change stops; 429, 5xx and a network error retry", async () => {
  for (const status of [400, 401, 403, 404]) {
    const page = await loadPlayer();
    await page.click();
    await page.answer({ status, body: "no" });
    assert.equal(page.status(), "WHEP " + status + ": no");
    assert.equal(page.isError(), true);
    assert.equal(page.button(), "Watch");
    assert.equal(page.retries().length, 0, status + " is not retried");
    await page.advance(60 * SEC);
    assert.equal(page.posts.length, 1);
    page.close();
  }
  for (const status of [429, 500, 503]) {
    const page = await loadPlayer();
    await page.click();
    await page.answer({ status, body: "busy" });
    assert.equal(page.status(), "WHEP " + status + ": busy — reconnecting in 1 s");
    assert.equal(page.button(), "Stop");
    await page.advance(1 * SEC);
    assert.equal(page.posts.length, 2, status + " is retried");
    page.close();
  }
  const page = await loadPlayer();
  await page.click();
  await page.fail();
  assert.equal(page.status(), "network error — reconnecting in 1 s");
  await page.advance(1 * SEC);
  assert.equal(page.posts.length, 2, "a network error is retried");
  page.close();
});

test("events from a session the page has dropped are not its own", async () => {
  const page = await loadPlayer();
  await page.watchAndConnect();
  const old = page.pcs[0];
  old.dtls("closed");
  await page.advance(1 * SEC);
  await page.answer();
  page.pcs[1].ice("connected");

  // The old connection reports its end late: nothing changes.
  old.conn("failed");
  old.dtls("failed");
  old.ice("disconnected");
  assert.equal(page.retries().length, 0, "no retry for a dropped session");
  assert.equal(page.status(), "connected");
  assert.equal(page.pcs.length, 2);
  page.close();
});
