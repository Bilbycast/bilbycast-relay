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
    body.textContent = '';
    var d = document.createElement('div');
    d.className = bad ? 'msg bad' : 'msg';
    d.textContent = text;
    body.appendChild(d);
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

    if (!data.feeds || !data.feeds.length) {
      /* Distinguishing "you have none" from "none are on air" would need the
       * manager to report entitlements for feeds it has decided not to show,
       * which is the oracle the API deliberately does not provide. So this
       * says what the viewer can act on. */
      msg('Nothing is available to you right now. Feeds appear here once they '
        + 'are on air. If you are expecting one, check with whoever set it up.');
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
  }

  /* The link is followed in THIS tab, not opened in a new one. A token in a
   * URL that window.open() produced gets blocked as a popup often enough that
   * the failure would read as the feed being broken. */
  function open(feed, btn) {
    btn.disabled = true;
    btn.textContent = 'Opening…';
    fetch('/api/watch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: feed.session_id })
    }).then(function (r) {
      return r.json().then(function (d) { return { ok: r.ok, data: d }; });
    }).then(function (res) {
      if (!res.ok || !res.data.watch_url) {
        btn.disabled = false;
        btn.textContent = 'Watch';
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
    }).catch(function () {
      btn.disabled = false;
      btn.textContent = 'Watch';
      msg('Could not open that feed. Try again in a moment.', true);
    });
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
  var CLIP_POLL_MS = 5000;
  var CLIP_POLL_MAX_MS = 10 * 60 * 1000;

  function loadClips(isPoll) {
    if (!isPoll) clipPollUntil = Date.now() + CLIP_POLL_MAX_MS;
    fetch('/api/clips', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.clips) return;
        renderClips(d.clips);
        /* Nothing pending means nothing to wait for. Note this is decided on
         * the server's answer, not on what was drawn — a row removed by a
         * delete must not keep the timer alive. */
        var pending = d.clips.some(function (c) { return !c.ready && !c.failed; });
        if (clipPollTimer) { clearTimeout(clipPollTimer); clipPollTimer = null; }
        if (pending && Date.now() < clipPollUntil) {
          clipPollTimer = setTimeout(function () { loadClips(true); }, CLIP_POLL_MS);
        }
      })
      .catch(function () { /* nothing to say to the viewer */ });
  }

  function renderClips(clips) {
    var section = document.getElementById('clips');
    var list = document.getElementById('cliplist');
    if (!clips.length) {
      list.textContent = '';
      section.hidden = true;
      return;
    }
    list.textContent = '';
    clips.forEach(function (c) { list.appendChild(clipRow(c, list)); });
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
          return;
        }
        del.disabled = false;
        del.textContent = 'Delete';
        return r.json().catch(function () { return null; }).then(function (e) {
          msg(e && e.error ? e.error : 'Could not delete that clip.', true);
        });
      }).catch(function () {
        del.disabled = false;
        del.textContent = 'Delete';
        msg('Could not delete that clip.', true);
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

  fetch('/api/feeds', { headers: { 'Accept': 'application/json' } })
    .then(function (r) {
      if (r.status === 401) {
        /* The proxy in front of us handles sign-in, so the fix is to land on
         * it again rather than anything this page can do. */
        window.location.reload();
        throw new Error('unauthenticated');
      }
      return r.json().then(function (d) { return { ok: r.ok, data: d }; });
    })
    .then(function (res) {
      if (!res.ok) {
        msg(res.data && res.data.error ? res.data.error
                                       : 'Could not load your feeds.', true);
        return;
      }
      render(res.data);
      loadClips(false);
    })
    .catch(function (e) {
      if (e && e.message === 'unauthenticated') return;
      msg('Could not load your feeds. Try again in a moment.', true);
    });
})();
