/* The viewer portal.
 *
 * Two calls and a redirect. The page asks what the signed-in user may watch,
 * and when they pick one it asks for a link and follows it.
 *
 * Nothing here decides anything. The list is the manager's answer, and the
 * manager re-checks the entitlement when the link is minted — so a feed still
 * showing on a stale tab cannot be opened after access is withdrawn.
 *
 * Served as its own file rather than inlined so the page can carry
 * `script-src 'self'`.
 */
(function () {
  'use strict';

  var body = document.getElementById('body');
  var note = document.getElementById('note');

  function msg(text, bad) {
    /* Whatever was drawn is gone, so the next answer is drawn whatever it
     * says. */
    shown = null;
    body.textContent = '';
    var d = document.createElement('div');
    d.className = bad ? 'msg bad' : 'msg';
    d.textContent = text;
    body.appendChild(d);
  }

  /* The proxy in front of us handles sign-in, so the fix for a session that
   * has ended is to land on it again: reload. At most once in half a minute,
   * though — a proxy that refuses `/api/*` while still serving this page would
   * otherwise have it reload for ever — and past that, a link to do it by
   * hand. The time is kept in sessionStorage, which outlives the reload;
   * where that cannot be read or written the link is offered at once, since a
   * reload that cannot be counted cannot be bounded either. */
  var RELOAD_GUARD_MS = 30 * 1000;
  var RELOAD_KEY = 'bilbycast-portal-reloaded-at';

  function signInAgain() {
    /* Whatever sign-in a refresh held back is this one. */
    signInDeferred = false;
    var now = Date.now();
    try {
      var since = now - (Number(window.sessionStorage.getItem(RELOAD_KEY)) || 0);
      if (since < 0 || since >= RELOAD_GUARD_MS) {
        window.sessionStorage.setItem(RELOAD_KEY, String(now));
        window.location.reload();
        return;
      }
    } catch (e) { /* the link, below */ }
    stopFeeds();
    msg('Your sign-in has ended.', true);
    var a = document.createElement('a');
    a.href = '/';
    a.textContent = 'Sign in again';
    body.firstChild.appendChild(document.createTextNode(' '));
    body.firstChild.appendChild(a);
  }

  /* Built with createElement + textContent rather than innerHTML. Feed names
   * come from an operator, not a viewer, but that is an assumption about
   * today's product rather than a property of this code. */
  function render(data) {
    var who = document.getElementById('who');
    who.textContent = 'Signed in as ' + data.username;

    /* Sign out belongs to whoever holds the session, which is not us: the
     * portal never authenticated anyone and cannot clear Authelia's cookie.
     * All it can do is point at the right place, so with no `logout_url`
     * configured there is no button — better than one that appears to work
     * and leaves the viewer signed in. */
    var out = document.getElementById('signout');
    if (out && data.logout_url) {
      out.href = data.logout_url;
      out.hidden = false;
    }

    var upcoming = data.upcoming || [];
    if (!data.feeds || !data.feeds.length) {
      /* Distinguishing "you have none" from "none are on air" would need the
       * manager to report entitlements for feeds it has decided not to show,
       * which is the oracle the API deliberately does not provide. So this
       * says what the viewer can act on. */
      note.hidden = true;
      if (!upcoming.length && data.upcomingUnknown) {
        msg('Nothing is on air right now, and the list of feeds coming up could '
          + 'not be loaded. This page tries again shortly.');
        return;
      }
      if (!upcoming.length) {
        msg('Nothing is available to you right now. Feeds appear here once they '
          + 'are on air. If you are expecting one, check with whoever set it up.');
        return;
      }
      msg('Nothing is on air right now. The feeds below can be opened here '
        + 'once they start.');
      body.appendChild(renderUpcoming(upcoming));
      return;
    }
    note.hidden = false;

    var list = document.createElement('div');
    list.className = 'feeds';
    data.feeds.forEach(function (f) {
      var row = document.createElement('div');
      row.className = 'feed';

      var name = document.createElement('div');
      name.className = 'name';
      name.textContent = f.name;
      row.appendChild(name);

      var btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Watch';
      btn.addEventListener('click', function () { open(f, btn); });
      row.appendChild(btn);

      list.appendChild(row);
    });
    body.textContent = '';
    body.appendChild(list);
    if (upcoming.length) body.appendChild(renderUpcoming(upcoming));
  }

  /* Scheduled feeds starting within the week. A name and a time, and nothing
   * to press: there is nothing to watch until it starts, and the manager
   * would refuse the link if asked. */
  function renderUpcoming(upcoming) {
    var section = document.createDocumentFragment();
    var h = document.createElement('h2');
    h.textContent = 'Coming up';
    section.appendChild(h);

    var list = document.createElement('div');
    list.className = 'feeds';
    upcoming.forEach(function (f) {
      var row = document.createElement('div');
      row.className = 'feed upcoming';

      var name = document.createElement('div');
      name.className = 'name';
      name.textContent = f.name;
      row.appendChild(name);

      var when = document.createElement('div');
      when.className = 'when';
      when.setAttribute('data-starts', f.starts_at);
      when.textContent = startsText(f.starts_at);
      row.appendChild(when);

      list.appendChild(row);
    });
    section.appendChild(list);
    return section;
  }

  /* In the viewer's own time zone, which is the browser's. A start that has
   * passed is one the system is still bringing up, so it says so rather than
   * showing a time in the past. */
  function startsText(iso) {
    var t = new Date(iso);
    if (isNaN(t.getTime())) return '';
    var now = new Date();
    if (t <= now) return 'Starting shortly';
    var time = t.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    var day = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    var days = Math.round(
      (new Date(t.getFullYear(), t.getMonth(), t.getDate()) - day) / 86400000);
    if (days === 0) return 'Today, ' + time;
    if (days === 1) return 'Tomorrow, ' + time;
    return t.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' })
      + ', ' + time;
  }

  /* The link is followed in THIS tab, not opened in a new one. A token in a
   * URL that window.open() produced gets blocked as a popup often enough that
   * the failure would read as the feed being broken. */
  function open(feed, btn) {
    /* One press at a time. A second Watch press supersedes the first: its
     * button is given back, its give-up timer cleared, and whatever its
     * request answers is ignored — the press the viewer made last is the one
     * that is followed.
     *
     * A press is told apart by its number, not by its button: Watch A, then
     * B, then A again is three presses on two buttons, and the first A's
     * answer is as stale as B's. Keyed on the button, it navigated and armed
     * a second give-up timer, which later gave back whatever press was out
     * when it fired, so that one did nothing at all. The button still has to
     * be the one opening as well: a give-up or a return from the
     * back-forward cache hands a press back without a newer one, and its
     * answer, landing after that, must not act either. */
    clearTimeout(navTimer);
    navTimer = null;
    if (opening && opening !== btn) giveBack(opening);
    var press = ++pressSeq;
    function current() { return opening === btn && pressSeq === press; }
    opening = btn;
    btn.disabled = true;
    btn.textContent = 'Opening…';
    /* Redirects are not followed, as for the feed list: a session that has
     * ended answered with the proxy's sign-in redirect is refused by
     * `connect-src 'self'` once followed, and read as the feed failing. */
    fetch('/api/watch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: feed.session_id }),
      redirect: 'manual'
    }).then(function (r) {
      if (!current()) throw new Error('superseded');
      if (r.status === 401 || r.type === 'opaqueredirect') {
        giveBack(btn);
        signInAgain();
        throw new Error('unauthenticated');
      }
      return r.json().then(function (d) { return { ok: r.ok, data: d }; });
    }).then(function (res) {
      if (!current()) return;
      if (!res.ok || !res.data.watch_url) {
        giveBack(btn);
        if (takeDeferredSignIn()) return;
        msg(res.data && res.data.error
            ? res.data.error
            : 'Could not open that feed. Try again in a moment.', true);
        return;
      }
      // Tell the player where to send them back to.
      //
      // The player is served from the origin — a different host and port to
      // this page — so it has no way to work out where the portal is. This
      // page does: it is running on it. Without this the viewer reaches the
      // player and has no route back to the page their clips appear on.
      var url = res.data.watch_url;
      url += (url.indexOf("?") === -1 ? "?" : "&")
           + "from=" + encodeURIComponent(window.location.origin);
      window.location.href = url;
      /* Cleared first, and owned by this press: no give-up timer is ever left
       * running for a press that is no longer the latest. */
      clearTimeout(navTimer);
      navTimer = setTimeout(function () {
        navTimer = null;
        if (pressSeq === press) reopen(false);
      }, NAV_GIVE_UP_MS);
    }).catch(function (e) {
      if (e && (e.message === 'unauthenticated' || e.message === 'superseded')) return;
      if (!current()) return;
      giveBack(btn);
      if (takeDeferredSignIn()) return;
      msg('Could not open that feed. Try again in a moment.', true);
    });
  }

  /* A sign-in that a refresh held back while a press was opening, done now
   * that the press has ended without navigating — given up, or failed. A
   * failed press used to drop it: the page was left with an error, no button
   * and nothing scheduled, for good. True when there was one to do, which
   * then speaks for the page in place of the press's own error. */
  function takeDeferredSignIn() {
    if (!signInDeferred) return false;
    signInAgain();
    return true;
  }

  /* A pressed Watch button back as it was, and no longer the one opening. */
  function giveBack(btn) {
    btn.disabled = false;
    btn.textContent = 'Watch';
    if (opening === btn) opening = false;
  }

  /* Clips are fetched after the feeds, and their failure is silent.
   *
   * The page exists to get someone watching. A relay too old to know about
   * clips, or one that cannot be reached, must not put an error in front of a
   * viewer whose feeds loaded perfectly well. */
  /* While anything is still being cut, come back and look again.
   *
   * A cut takes seconds to a minute, and this page is where it lands — so
   * loading once meant an operator who exported and stayed put never learned
   * their clip was ready. They had to know to reload, which is knowledge the
   * page should not require.
   *
   * Only while something is pending, and only for a bounded spell: a tab left
   * open all day must not poll a relay for the rest of the afternoon. A clip
   * that is still not ready after that is one the operator will find on their
   * next visit, and the edge gives up long before it. */
  var clipPollTimer = null;
  var clipPollUntil = 0;
  var clipPollSeq = 0;
  var CLIP_POLL_MS = 5000;
  var CLIP_POLL_MAX_MS = 10 * 60 * 1000;

  /* Re-arm from one place, on every outcome.
   *
   * The only `setTimeout` used to sit inside the success branch, past an early
   * `return` for a null body — so one 502 from a reverse proxy, one relay
   * restart, one dropped connection ended the poller for the life of the page
   * load. The clip finished cutting and the page never said so, and the
   * operator concluded the export had failed. `keepGoing` is false only when
   * the server says nothing is pending; a failed poll knows nothing and must
   * therefore keep asking. */
  function schedulePoll(keepGoing) {
    if (clipPollTimer) { clearTimeout(clipPollTimer); clipPollTimer = null; }
    if (keepGoing && Date.now() < clipPollUntil) {
      clipPollTimer = setTimeout(function () { loadClips(true); }, CLIP_POLL_MS);
    }
  }

  function loadClips(isPoll) {
    if (!isPoll) clipPollUntil = Date.now() + CLIP_POLL_MAX_MS;
    /* Numbered when sent, so a tombstone left by a finished delete can tell
     * an answer that predates it from one that post-dates it. */
    var seq = ++clipPollSeq;
    fetch('/api/clips', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.clips) { schedulePoll(true); return; }
        renderClips(d.clips, seq);
        /* Nothing pending means nothing to wait for. Note this is decided on
         * the server's answer, not on what was drawn — a row removed by a
         * delete must not keep the timer alive. */
        schedulePoll(d.clips.some(function (c) { return !c.ready && !c.failed; }));
      })
      .catch(function () { schedulePoll(true); });
  }

  /* A clip-scoped message, in the clips section.
   *
   * Not `msg()`: that one empties #body, which holds the feed list and its
   * Watch buttons, and nothing rebuilds it — so a failed delete took away the
   * only thing on the page that gets someone watching. */
  function clipMsg(text) {
    var el = document.getElementById('clipnote');
    if (!el) return;
    el.textContent = text || '';
    el.hidden = !text;
  }

  /* Rows being deleted right now, keyed the way renderClips keys them.
   *
   * A poll lands every five seconds while anything is being cut, and it used to
   * rebuild the table unconditionally — so a DELETE in flight had its captured
   * row replaced by a clone, `tr.remove()` became a no-op on a detached node,
   * and the clip the viewer had just deleted came back with its Delete button
   * enabled until the next poll dropped it. Clicking that clone raised a
   * spurious error for a clip that was already gone.
   *
   * `true` while the DELETE is in flight. Once it has succeeded the entry
   * becomes the number of the first poll that can be trusted to know — a poll
   * already on the wire when the delete finished can still list the clip — and
   * it is dropped when such a poll lands. It must not outlive that: a clip's
   * file name is deterministic, so deleting a clip and exporting the same
   * moment again yields the same key, and a tombstone that stood for the life
   * of the page hid the new clip from every poll. The viewer saw a silent
   * no-op Export, and if it was the only clip the whole panel stayed hidden. */
  var deleting = Object.create(null);

  function clipKey(c) { return c.session_id + '\u0000' + c.name; }

  function renderClips(clips, seq) {
    var section = document.getElementById('clips');
    var list = document.getElementById('cliplist');
    var shown = clips.filter(function (c) {
      var t = deleting[clipKey(c)];
      return !(t === true || (typeof t === 'number' && seq < t));
    });
    Object.keys(deleting).forEach(function (k) {
      if (deleting[k] !== true && deleting[k] <= seq) delete deleting[k];
    });
    if (!shown.length) {
      list.textContent = '';
      section.hidden = true;
      return;
    }
    list.textContent = '';
    shown.forEach(function (c) { list.appendChild(clipRow(c, list)); });
    section.hidden = false;
  }

  /* One clip, as a table row.
   *
   * Built with createElement + textContent rather than innerHTML: a clip name
   * is an operator's free text, and it reaches this page having been round a
   * filename. */
  function clipRow(c, list) {
    var tr = document.createElement('tr');

    var name = document.createElement('td');
    name.className = 'name';
    name.textContent = c.name;
    tr.appendChild(name);

    var feed = document.createElement('td');
    feed.className = 'feed';
    feed.textContent = c.feed;
    tr.appendChild(feed);

    /* Size, or what is standing in for it. A clip still being cut has no size
     * yet and one that failed never will, so the column says which. */
    var size = document.createElement('td');
    size.className = 'num';
    if (c.ready && c.bytes) {
      size.textContent = (c.bytes / 1048576).toFixed(1) + ' MB';
    } else if (c.failed) {
      size.className = 'num failed';
      size.textContent = 'Failed';
    } else {
      size.className = 'num pending';
      size.textContent = 'Cutting…';
    }
    tr.appendChild(size);

    var act = document.createElement('td');
    act.className = 'act';
    if (c.ready && c.url) {
      var a = document.createElement('a');
      a.className = 'btn';
      a.href = c.url;
      /* The filename the operator was promised, not the URL's last segment:
       * browsers percent-decode inconsistently. */
      a.setAttribute('download', c.name + '.mp4');
      a.textContent = 'Download';
      act.appendChild(a);
    }

    /* Clips sit outside the retention sweep, so nothing reclaims their space
     * until the session ends. Offered on failed ones too — that is exactly
     * what somebody wants to clear.
     *
     * Deleted through THIS page, not by reaching for the relay: the portal
     * carries `connect-src 'self'`, so a cross-origin fetch never leaves the
     * browser and the button failed every time with nothing in any log. */
    var del = document.createElement('button');
    del.className = 'btn quiet';
    del.textContent = 'Delete';
    del.addEventListener('click', function () {
      del.disabled = true;
      del.textContent = 'Deleting…';
      clipMsg('');
      var key = clipKey(c);
      deleting[key] = true;
      fetch('/api/clips', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: c.session_id, name: c.name })
      }).then(function (r) {
        if (r.ok) {
          var reason = tr.nextSibling;
          if (reason && reason.classList && reason.classList.contains('reasonrow')) {
            reason.remove();
          }
          tr.remove();
          /* The last one going takes the empty table with it. */
          if (!list.children.length) document.getElementById('clips').hidden = true;
          /* Gone on the server: hide it only from polls sent before now. */
          deleting[key] = clipPollSeq + 1;
          return;
        }
        delete deleting[key];
        del.disabled = false;
        del.textContent = 'Delete';
        return r.json().catch(function () { return null; }).then(function (e) {
          clipMsg(e && e.error ? e.error : 'Could not delete that clip.');
        });
      }).catch(function () {
        delete deleting[key];
        del.disabled = false;
        del.textContent = 'Delete';
        clipMsg('Could not delete that clip.');
      });
    });
    act.appendChild(del);
    tr.appendChild(act);

    /* The reason a clip failed gets its own row underneath, full width. It is
     * a sentence, not a cell, and squeezing it into the size column would
     * either truncate it or wreck the table. */
    if (!c.failed || !c.error) return tr;

    var extra = document.createElement('tr');
    extra.className = 'reasonrow';
    var td = document.createElement('td');
    td.className = 'reason';
    td.colSpan = 4;
    td.textContent = c.error;
    extra.appendChild(td);

    /* Both rows go back together in a fragment, so the reason cannot end up
     * anywhere but directly under the clip it belongs to. */
    var pair = document.createDocumentFragment();
    pair.appendChild(tr);
    pair.appendChild(extra);
    return pair;
  }

  /* While something is coming up, look again, so a feed turns into a Watch
   * button when it starts without the viewer having to know to reload.
   *
   * Paced by the soonest start rather than a fixed tick: a game three days
   * out is re-checked every quarter hour, which also picks up anything newly
   * scheduled. One whose start has passed is checked every half minute for
   * ten minutes, then every five: it stays listed until its slot ends, which
   * can be hours, and a start that late is as likely never to come. With
   * nothing coming up the page does not poll at all.
   *
   * Never while the tab is hidden. Each refresh passes the sign-in proxy, so
   * a tab left open and unwatched would keep its session alive for as long
   * as anything was scheduled. Shown again, it refreshes at once. */
  var feedTimer = null;
  /* A refresh is due: the timer is running, or would be if the tab were shown. */
  var feedWanted = false;
  var feedFailures = 0;
  /* Numbered when sent: only the latest answer is acted on, so a refresh the
   * tab being shown or restored sends while another is out does not have the
   * older one schedule over it. */
  var feedSeq = 0;
  /* The Watch button whose feed is being opened, or false. While set, no
   * refresh redraws under it. */
  var opening = false;
  /* The number of the latest Watch press: only its answer is acted on. */
  var pressSeq = 0;
  /* What the list on screen was drawn from, or null when it was not. */
  var shown = null;
  /* The upcoming list of the last answer that had one, or null before any
   * did: what a refresh whose upcoming half failed shows meanwhile. */
  var lastUpcoming = null;
  /* A refresh found the session ended while a Watch press was opening, and
   * left it so as not to reload over the navigation. Acted on when the press
   * ends without navigating (it fails, or is given up); dropped when a later
   * refresh gets past the proxy, which shows the session is good after all. */
  var signInDeferred = false;
  var FEED_POLL_MIN_MS = 30 * 1000;
  var FEED_POLL_MAX_MS = 15 * 60 * 1000;
  var FEED_OVERDUE_FAST_MS = 10 * 60 * 1000;
  var FEED_POLL_OVERDUE_MS = 5 * 60 * 1000;

  function pollIn(wait) {
    clearTimeout(feedTimer);
    feedTimer = null;
    feedWanted = true;
    if (document.hidden) return;
    feedTimer = setTimeout(function () {
      feedTimer = null;
      if (!document.hidden) loadFeeds(false);
    }, wait);
  }

  function stopFeeds() {
    clearTimeout(feedTimer);
    feedTimer = null;
    feedWanted = false;
  }

  function scheduleFeeds(upcoming) {
    if (!upcoming || !upcoming.length) {
      stopFeeds();
      return;
    }
    pollIn(nextPoll(upcoming));
  }

  function nextPoll(upcoming) {
    var now = Date.now();
    var wait = FEED_POLL_MAX_MS;
    upcoming.forEach(function (f) {
      var t = new Date(f.starts_at).getTime();
      if (isNaN(t)) return;
      var w = t > now ? t - now
        : now - t < FEED_OVERDUE_FAST_MS ? FEED_POLL_MIN_MS
        : FEED_POLL_OVERDUE_MS;
      if (w < wait) wait = w;
    });
    return Math.max(wait, FEED_POLL_MIN_MS);
  }

  /* A refresh that fails keeps what is on screen and tries again, half a
   * minute later and twice as long each time after, up to the quarter hour:
   * a relay or manager that is down is not asked every half minute until it
   * comes back. */
  function retryFeeds() {
    feedFailures++;
    pollIn(Math.min(FEED_POLL_MIN_MS * Math.pow(2, feedFailures - 1), FEED_POLL_MAX_MS));
  }

  /* Redrawn only when the answer changed. Rebuilt on every refresh, the Watch
   * buttons lost focus, and a press that landed before the swap and was let
   * go after it was no click at all. Unchanged, only the start times move,
   * since they are told relative to now. */
  function draw(data) {
    var key = JSON.stringify([data.username, data.logout_url || null,
      data.feeds || [], data.upcoming || [], !!data.upcomingUnknown]);
    if (key === shown) {
      var whens = body.querySelectorAll('.feed.upcoming .when');
      for (var i = 0; i < whens.length; i++) {
        whens[i].textContent = startsText(whens[i].getAttribute('data-starts'));
      }
      return;
    }
    render(data);
    shown = key;
  }

  /* Only the first load reports a failure, since that is the one with nothing
   * to show. A refresh never redraws under a viewer who has just pressed
   * Watch. */
  function loadFeeds(first) {
    var seq = ++feedSeq;
    /* Redirects are not followed. A proxy that answers an expired session
     * with a redirect to its sign-in host, rather than a 401, would have the
     * fetch follow it to another origin, which `connect-src 'self'` refuses
     * — a network failure, retried for good, while the page never signed
     * the viewer back in. Not followed, it arrives as an opaque redirect. */
    fetch('/api/feeds', { headers: { 'Accept': 'application/json' }, redirect: 'manual' })
      .then(function (r) {
        if (r.status === 401 || r.type === 'opaqueredirect') {
          /* Not while a Watch press is navigating away: a reload would cancel
           * it, and the player's own load passes the proxy, which signs the
           * viewer in. If the press ends without navigating, it is done then.
           * The refresh keeps going meanwhile, at its shortest step and not
           * counted as a failure, so a press that ends some way nothing here
           * foresaw still meets a refresh that signs the viewer in. */
          if (opening) {
            signInDeferred = true;
            pollIn(FEED_POLL_MIN_MS);
          } else {
            signInAgain();
          }
          throw new Error('unauthenticated');
        }
        /* Past the proxy, so the session is good: a sign-in an earlier
         * refresh held back is not wanted any more. Any answer counts, a
         * portal's own 502 included — it identified the viewer first. */
        if (seq === feedSeq) signInDeferred = false;
        return r.json().then(function (d) { return { ok: r.ok, data: d }; });
      })
      .then(function (res) {
        if (!res.ok) {
          failed(res.data && res.data.error ? res.data.error : 'Could not load your feeds.');
          return;
        }
        if (seq !== feedSeq) return;
        if (res.data.upcoming === null) {
          /* The portal could not get the upcoming list from the manager; the
           * live half came through. So the live feeds are drawn, beside the
           * last upcoming list there was (less any of it now on air, by name,
           * which is all an upcoming entry carries), and the refresh goes on
           * at that list's own pace: a feed that starts while the upcoming
           * question keeps failing still becomes a Watch button. Taken for
           * nothing coming up, it would have stopped the refresh for good.
           * With no list yet to go on, it backs off as a failure does. */
          var live = res.data.feeds || [];
          var kept = (lastUpcoming || []).filter(function (u) {
            return !live.some(function (f) { return f.name === u.name; });
          });
          if (!opening) {
            draw({ username: res.data.username, logout_url: res.data.logout_url,
              feeds: live, upcoming: kept, upcomingUnknown: lastUpcoming === null });
          }
          if (lastUpcoming === null) {
            retryFeeds();
          } else {
            feedFailures = 0;
            pollIn(kept.length ? nextPoll(kept) : FEED_POLL_MAX_MS);
          }
          if (first) loadClips(false);
          return;
        }
        feedFailures = 0;
        lastUpcoming = res.data.upcoming || [];
        if (!opening) draw(res.data);
        scheduleFeeds(res.data.upcoming);
        if (first) loadClips(false);
      })
      .catch(function (e) {
        if (e && e.message === 'unauthenticated') return;
        failed('Could not load your feeds. Try again in a moment.');
      });

    function failed(text) {
      if (seq !== feedSeq) return;
      if (first) msg(text, true);
      else retryFeeds();
    }
  }

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) {
      clearTimeout(feedTimer);
      feedTimer = null;
    } else if (feedWanted && !feedTimer) {
      loadFeeds(false);
    }
  });

  /* A press of Watch whose navigation never happens — stopped, or answered
   * with something that is not a page — leaves this page as it was: the
   * button saying "Opening…" and every refresh held off for good. So does
   * coming Back to it from the browser's back-forward cache, which restores
   * the page exactly as it was left.
   *
   * Back from the cache, the button is given back and the list fetched
   * afresh. When the navigation has simply not arrived after a while, only
   * the button is given back: it may yet arrive, and a refresh now could
   * reload the page on a 401 and cancel it. The next scheduled refresh redraws
   * if anything has changed. */
  var NAV_GIVE_UP_MS = 45 * 1000;
  var navTimer = null;

  function reopen(refresh) {
    clearTimeout(navTimer);
    navTimer = null;
    if (opening) giveBack(opening);
    opening = false;
    if (refresh) {
      signInDeferred = false;
      shown = null;
      loadFeeds(false);
    } else {
      /* A refresh found the session ended meanwhile; with the navigation
       * given up there is nothing left to cancel. */
      takeDeferredSignIn();
    }
  }

  window.addEventListener('pageshow', function (e) { if (e.persisted) reopen(true); });
  /* The navigation went ahead: nothing to give back. */
  window.addEventListener('pagehide', function () {
    clearTimeout(navTimer);
    navTimer = null;
  });

  loadFeeds(true);
})();
