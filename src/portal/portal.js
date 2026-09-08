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
      window.location.href = res.data.watch_url;
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
  function loadClips() {
    fetch('/api/clips', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || !d.clips || !d.clips.length) return;
        var section = document.getElementById('clips');
        var list = document.getElementById('cliplist');
        list.textContent = '';
        d.clips.forEach(function (c) {
          var row = document.createElement('div');
          row.className = 'row';

          var label = document.createElement('div');
          var name = document.createElement('b');
          name.textContent = c.name;
          label.appendChild(name);
          var from = document.createElement('span');
          from.className = 'from';
          from.textContent = ' — ' + c.feed;
          label.appendChild(from);
          row.appendChild(label);

          if (c.ready && c.url) {
            var a = document.createElement('a');
            a.className = 'btn';
            a.href = c.url;
            /* The filename the operator was promised, not the URL's last
             * segment: browsers percent-decode inconsistently. */
            a.setAttribute('download', c.name + '.mp4');
            a.textContent = c.bytes
              ? 'Download (' + (c.bytes / 1048576).toFixed(1) + ' MB)'
              : 'Download';
            row.appendChild(a);
          } else {
            /* Said plainly rather than hidden: somebody who has just pressed
             * Export should see that it is happening. */
            var pending = document.createElement('span');
            pending.className = 'pending';
            pending.textContent = 'Being cut…';
            row.appendChild(pending);
          }
          list.appendChild(row);
        });
        section.hidden = false;
      })
      .catch(function () { /* nothing to say to the viewer */ });
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
      loadClips();
    })
    .catch(function (e) {
      if (e && e.message === 'unauthenticated') return;
      msg('Could not load your feeds. Try again in a moment.', true);
    });
})();
