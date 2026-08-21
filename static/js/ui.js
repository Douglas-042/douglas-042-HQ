/* Shared rendering helpers. Everything that produces HTML from data lives
   here so the view modules stay about layout and flow. */

const UI = (() => {

  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));

  function ago(iso) {
    if (!iso) return 'never';
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 0) return 'just now';
    if (s < 60) return `${Math.floor(s)}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  function dur(seconds) {
    if (!seconds) return '—';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    const m = Math.floor(seconds / 60), s = Math.round(seconds % 60);
    return `${m}m ${s}s`;
  }

  function bytes(n) {
    if (!n) return '—';
    const u = ['B', 'KB', 'MB', 'GB'];
    let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
  }

  const sevClass = (s) => `sev sev-${esc(s || 'INFO')}`;

  // Small inline platform marks, so a host's OS reads at a glance in the fleet
  // and the deploy chips. Kept as SVG rather than an emoji: the Windows/Linux
  // emoji render inconsistently across systems, and half the fleet showing a
  // tofu box is worse than no icon.
  function osIcon(platform) {
    const p = (platform || '').toLowerCase();
    if (p.startsWith('lin')) {
      // Tux silhouette, simplified to a single path so it scales cleanly small.
      return '<svg class="os-ico" viewBox="0 0 24 24" aria-label="Linux" '
        + 'role="img"><path fill="currentColor" d="M12 2c-2 0-3.2 1.6-3.2 3.6 0 '
        + '1 .2 1.7.2 2.4 0 .7-.6 1.3-1.2 2.1C6.6 13 5.4 14.6 5.4 16.4c0 .8.4 '
        + '1.3 1 1.6-.2.4-.5.9-.5 1.4 0 1.2 1.3 1.6 3 1.9 1 .2 1.7.7 3.1.7s2.1-.5 '
        + '3.1-.7c1.7-.3 3-.7 3-1.9 0-.5-.3-1-.5-1.4.6-.3 1-.8 1-1.6 0-1.8-1.2-3.4-2.4-'
        + '4.3-.6-.8-1.2-1.4-1.2-2.1 0-.7.2-1.4.2-2.4C15.2 3.6 14 2 12 2Zm-1.5 '
        + '4.1c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9Zm3 0c.4 0 .7.4.7.9s-.3.9-.7.9-.7-'
        + '.4-.7-.9.3-.9.7-.9ZM12 9.3c.9 0 1.9.5 1.9.9 0 .3-.9.8-1.9.8s-1.9-.5-1.9-.8c0-.4 1-.9 '
        + '1.9-.9Z"/></svg>';
    }
    // Four-pane Windows flag.
    return '<svg class="os-ico" viewBox="0 0 24 24" aria-label="Windows" '
      + 'role="img"><path fill="currentColor" d="M3 5.4 10.5 4.3v7.2H3V5.4Zm0 '
      + '13.2 7.5 1.1v-7.1H3v6ZM11.4 4.2 21 2.8v8.7h-9.6V4.2Zm0 8.2H21v8.7l-9.6-'
      + '1.4v-7.3Z"/></svg>';
  }

  function toast(title, detail = '', kind = '') {
    const wrap = document.getElementById('toasts');
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    el.innerHTML = `<b>${esc(title)}</b>${detail ? `<span>${esc(detail)}</span>` : ''}`;
    wrap.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .3s, transform .3s';
      el.style.opacity = '0'; el.style.transform = 'translateX(20px)';
      setTimeout(() => el.remove(), 300);
    }, kind === 'err' ? 6000 : 3800);
  }

  /**
   * @param dismissible  false for dialogs the person must complete — a forced
   *   password change is not a suggestion, so it gets no escape hatch.
   */
  function modal(title, bodyHtml, footerHtml = '', { dismissible = true } = {}) {
    close(true);
    const o = document.createElement('div');
    o.className = 'overlay'; o.id = 'overlay';
    if (!dismissible) o.dataset.locked = '1';
    o.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true">
        <div class="modal-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2 class="lean">${esc(title)}</h2>
          <div class="spacer" style="flex:1"></div>
          ${dismissible ? '<button class="btn btn-sm btn-ghost" onclick="UI.close()">Close</button>' : ''}
        </div>
        <div class="modal-b">${bodyHtml}</div>
        ${footerHtml ? `<div class="modal-f">${footerHtml}</div>` : ''}
      </div>`;
    if (dismissible) {
      o.addEventListener('click', e => { if (e.target === o) close(); });
    }
    document.body.appendChild(o);
    const first = o.querySelector('input, select, textarea');
    if (first) first.focus();
    return o;
  }

  function drawer(title, bodyHtml) {
    close();
    const o = document.createElement('div');
    o.className = 'overlay'; o.id = 'overlay';
    o.style.justifyContent = 'flex-end'; o.style.padding = '0';
    o.innerHTML = `
      <div class="drawer" role="dialog" aria-modal="true">
        <div class="modal-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2 class="lean">${esc(title)}</h2>
          <div style="flex:1"></div>
          <button class="btn btn-sm btn-ghost" onclick="UI.close()">Close</button>
        </div>
        <div class="modal-b">${bodyHtml}</div>
      </div>`;
    o.addEventListener('click', e => { if (e.target === o) close(); });
    document.body.appendChild(o);
    return o;
  }

  // Whether a modal or drawer is currently up. Live refreshes check this: a
  // view rebuilding itself underneath an open dialog throws the operator out
  // of whatever they were reading or typing.
  function isOpen() {
    return !!document.getElementById('overlay');
  }

  function close(force = false) {
    const o = document.getElementById('overlay');
    if (!o) return;
    if (o.dataset.locked === '1' && !force) return;
    o.remove();
  }

  function stat(value, label, { accent, sub, glow } = {}) {
    return `<div class="stat ${glow ? 'glow' : ''}" ${accent ? `style="--accent:${accent}"` : ''}>
      <div class="n">${esc(value)}</div>
      <div class="l">${esc(label)}</div>
      ${sub ? `<div class="s">${esc(sub)}</div>` : ''}
    </div>`;
  }

  function empty(title, hint = '') {
    return `<div class="empty"><div class="big">${esc(title)}</div>
      ${hint ? `<div>${esc(hint)}</div>` : ''}</div>`;
  }

  function table(headers, rowsHtml, { id = '', maxHeight } = {}) {
    return `<div class="tw"><div class="ts" ${maxHeight ? `style="max-height:${maxHeight}"` : ''}>
      <table ${id ? `id="${id}"` : ''}>
        <thead><tr>${headers.map((h, i) =>
          `<th onclick="UI.sort(this,${i})">${esc(h)}</th>`).join('')}</tr></thead>
        <tbody>${rowsHtml}</tbody>
      </table></div></div>`;
  }

  const sortState = {};
  function sort(th, col) {
    const table = th.closest('table');
    const tb = table.tBodies[0];
    if (!tb || tb.rows.length < 2) return;
    const key = (table.id || 'x') + col;
    sortState[key] = !sortState[key];
    const dir = sortState[key] ? 1 : -1;
    const rows = [...tb.rows];
    rows.sort((a, b) => {
      const x = (a.cells[col]?.innerText || '').trim();
      const y = (b.cells[col]?.innerText || '').trim();
      const nx = parseFloat(x), ny = parseFloat(y);
      if (!isNaN(nx) && !isNaN(ny)) return (nx - ny) * dir;
      return x.localeCompare(y) * dir;
    });
    rows.forEach(r => tb.appendChild(r));
  }

  function filterRows(input, tableId) {
    const q = input.value.toLowerCase();
    const t = document.getElementById(tableId);
    if (!t) return;
    [...t.tBodies[0].rows].forEach(r => {
      r.style.display = (!q || r.innerText.toLowerCase().includes(q)) ? '' : 'none';
    });
  }

  /* ---- The signature progress element ---------------------------------- */

  const PHASES = ['Profiling host', 'Hunting', 'Sweeping event logs',
                  'Scanning artifacts', 'Collecting evidence'];

  function ring(percent) {
    const r = 26, c = 2 * Math.PI * r;
    const off = c * (1 - Math.max(0, Math.min(100, percent)) / 100);
    return `<div class="ring">
      <svg viewBox="0 0 62 62">
        <circle class="trk" cx="31" cy="31" r="${r}"/>
        <circle class="bar" cx="31" cy="31" r="${r}"
          stroke-dasharray="${c.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/>
      </svg>
      <div class="pct">${Math.round(percent)}</div>
    </div>`;
  }

  function phaseIndex(name) {
    const i = PHASES.indexOf(name);
    return i < 0 ? 0 : i;
  }

  /**
   * A running hunt, rendered as status rather than console output.
   * Operators want "where is it and how long" — not a scrolling log.
   */
  // One module line in the live feed. Kept terse: this scrolls past while an
  // operator watches, so what matters is the module name and whether it found
  // anything — not a full sentence they have to read at speed.
  function activityLine(e) {
    const bad = (e.status || 'OK').toUpperCase();
    const cls = bad === 'ERROR' ? 'err' : (bad === 'SKIP' ? 'skip' : (e.findings ? 'hit' : ''));
    const ms = e.ms ? (e.ms >= 1000 ? `${(e.ms / 1000).toFixed(1)}s` : `${e.ms}ms`) : '';
    return `<div class="actline ${cls}">
      <span class="am">${esc(e.module || '')}</span>
      <span class="ar">${e.rows ? `${e.rows} rows` : ''}</span>
      <span class="af">${e.findings ? `${e.findings} finding${e.findings === 1 ? '' : 's'}`
        : (bad === 'SKIP' ? 'skipped' : (bad === 'ERROR' ? 'error' : ''))}</span>
      <span class="at">${esc(ms)}</span>
    </div>`;
  }

  // How long this hunt has been going, and roughly how long it takes. The
  // estimate is deliberately a range rather than a countdown: a sweep's length
  // depends on how much the host has to read, and a progress bar that claims
  // "2 minutes remaining" for six minutes is worse than one that says nothing.
  function elapsedLabel(job) {
    const start = job.started_at || job.dispatched_at || job.created_at;
    if (!start) return 'starting';
    const s = Math.max(0, (Date.now() - new Date(start).getTime()) / 1000);
    const mm = Math.floor(s / 60), ss = Math.floor(s % 60);
    const shown = mm ? `${mm}m ${String(ss).padStart(2, '0')}s` : `${ss}s`;
    if (job.status === 'queued') return `${shown} · waiting for the host to check in`;
    // A quick sweep is a couple of minutes; a full one with Sigma and YARA is
    // longer, and saying so up front stops people cancelling a healthy hunt.
    const expect = job.quick ? '~2 min' : '3–8 min';
    return `${shown} elapsed · usually ${expect}`;
  }

  // A finding as it arrives, shown in the same feed as the module events so
  // the operator reads one stream rather than watching two.
  function findingLine(f) {
    const sev = (f.severity || 'INFO').toUpperCase();
    const cls = sev === 'CRITICAL' ? 'crit' : (sev === 'HIGH' ? 'hit' : 'find');
    return `<div class="actline ${cls}">
      <span class="am">${esc(f.title || f.rule_id || 'finding')}</span>
      <span class="ar">${esc((f.evidence || '').slice(0, 40))}</span>
      <span class="af">${esc(sev)}</span>
      <span class="at mono">${esc(f.rule_id || '')}</span>
    </div>`;
  }

  function huntCard(job) {
    const live = ['queued', 'dispatched', 'running', 'uploading'].includes(job.status);
    const pct = job.progress || 0;
    const idx = phaseIndex(job.phase);

    let phaseName = job.phase || 'Queued';
    if (job.status === 'queued') phaseName = 'Waiting for host';
    if (job.status === 'uploading') phaseName = 'Uploading results';
    if (job.status === 'completed') phaseName = 'Complete';
    if (job.status === 'failed') phaseName = 'Failed';
    if (job.status === 'cancelled') phaseName = 'Cancelled';

    const steps = PHASES.map((_, i) => {
      if (!live) return '<b></b>';
      if (i < idx) return '<b class="done"></b>';
      if (i === idx) return '<b class="now"></b>';
      return '<b></b>';
    }).join('');

    const detail = job.status === 'failed'
      ? (job.error || 'The hunt did not finish.')
      : (job.phase_detail || (job.modules_total
          ? `Module ${job.modules_done} of ${job.modules_total}`
          : 'Preparing'));

    return `<div class="hunt ${live ? 'live' : ''}" data-job="${esc(job.id)}">
      <div class="hunt-top">
        <div>
          <div class="hunt-host lean">${esc(job.hostname || '—')}</div>
          <div class="hunt-meta">${esc(job.days)}-day window${job.quick ? ' · quick' : ''}${job.collect_raw ? ' · raw evidence' : ''}</div>
        </div>
        ${live ? ring(pct) : `<div style="margin-left:auto">${
          job.status === 'completed'
            ? `<span class="${sevClass(job.risk_level || 'CLEAN')}">${esc(job.risk_level || 'CLEAN')}</span>`
            : `<span class="tag" style="color:${job.status === 'failed' ? 'var(--crit)' : 'var(--slate)'};
                 border-color:${job.status === 'failed' ? 'var(--crit)' : 'var(--edge)'}">${esc(job.status)}</span>`
        }</div>`}
      </div>

      <div class="phase">
        <div class="phase-txt">
          <div class="phase-name">${esc(phaseName)}</div>
          <div class="phase-detail">${esc(detail)}</div>
        </div>
      </div>

      <div class="pbar"><i style="width:${
        live ? pct : (job.status === 'completed' ? 100 : Math.max(pct, 2))
      }%;${job.status === 'failed' ? 'background:var(--crit);box-shadow:0 0 12px rgba(255,45,85,.6)' : ''}"></i></div>
      <div class="hunt-steps">${steps}</div>
      <div class="hunt-legend">
        <span>Profile</span><span>Hunt</span><span>Events</span><span>Artifacts</span><span>Report</span>
      </div>

      ${live ? `
        <div class="actwrap">
          <div class="acthead">
            <span>What it is looking at</span>
            <span class="spacer"></span>
            <span class="mono" data-elapsed="${esc(job.started_at || job.created_at || '')}">${
              elapsedLabel(job)}</span>
          </div>
          <div class="actfeed" data-feed="${esc(job.id)}">
            ${(job.activity || []).slice(-40).map(activityLine).join('')
              || '<div class="actline dim"><span class="am">waiting for the host to start…</span></div>'}
          </div>
        </div>` : ''}

      ${!live ? `<div style="display:flex;gap:8px;margin-top:15px;flex-wrap:wrap">
        ${job.status === 'completed' ? `
          <a class="btn btn-sm" href="${API.reportUrl(job.id)}" target="_blank" rel="noopener">Open report</a>
          <a class="btn btn-sm" href="${API.downloadUrl(job.id)}">Download HTML</a>
          ${job.has_bundle ? `<a class="btn btn-sm btn-ghost" href="${API.bundleUrl(job.id)}">Evidence ${bytes(job.bundle_size)}</a>` : ''}
        ` : ''}
        <span class="muted mono" style="margin-left:auto;align-self:center">${dur(job.duration_seconds)}</span>
      </div>` : `<div style="display:flex;margin-top:15px">
        <button class="btn btn-sm btn-ghost btn-danger" style="margin-left:auto"
          onclick="Views.cancelHunt('${esc(job.id)}')">Cancel</button>
      </div>`}
    </div>`;
  }

  /** Update a live card in place — avoids re-rendering the whole grid on
   *  every websocket tick, which would kill the CSS transitions. */
  function patchHunt(msg) {
    const card = document.querySelector(`.hunt[data-job="${msg.job_id}"]`);
    if (!card) return false;
    const pct = msg.progress || 0;

    const bar = card.querySelector('.pbar i');
    if (bar) bar.style.width = `${pct}%`;

    const num = card.querySelector('.ring .pct');
    if (num) num.textContent = Math.round(pct);

    const arc = card.querySelector('.ring .bar');
    if (arc) {
      const c = 2 * Math.PI * 26;
      arc.setAttribute('stroke-dashoffset', (c * (1 - pct / 100)).toFixed(1));
    }

    const name = card.querySelector('.phase-name');
    if (name && msg.phase) name.textContent = msg.phase;

    const det = card.querySelector('.phase-detail');
    if (det) {
      det.textContent = msg.detail || (msg.modules_total
        ? `Module ${msg.modules_done} of ${msg.modules_total}` : 'Working');
    }

    const idx = phaseIndex(msg.phase);
    card.querySelectorAll('.hunt-steps b').forEach((b, i) => {
      b.className = i < idx ? 'done' : i === idx ? 'now' : '';
    });

    // Append whatever finished since the last tick. The websocket carries only
    // the new events, not the whole log, so appending is both correct and the
    // reason a long hunt does not resend two hundred rows every few seconds.
    const feed = card.querySelector('.actfeed');
    if (feed && msg.events && msg.events.length) {
      const dim = feed.querySelector('.actline.dim');
      if (dim) dim.remove();
      // Was the operator watching the newest line before this arrived? If they
      // had scrolled up to read something, do not yank the view away from it.
      const pinned = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 24;
      feed.insertAdjacentHTML('beforeend', msg.events.map(activityLine).join(''));
      while (feed.children.length > 60) feed.removeChild(feed.firstChild);
      if (pinned) feed.scrollTop = feed.scrollHeight;
    }
    return true;
  }

  // Findings arrive on their own websocket message, so they reach the feed
  // through their own entry point rather than riding a progress tick.
  function pushFindings(jobId, findings) {
    const feed = document.querySelector(`.actfeed[data-feed="${CSS.escape(jobId)}"]`);
    if (!feed || !findings || !findings.length) return false;
    const dim = feed.querySelector('.actline.dim');
    if (dim) dim.remove();
    const pinned = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 24;
    feed.insertAdjacentHTML('beforeend', findings.map(findingLine).join(''));
    while (feed.children.length > 60) feed.removeChild(feed.firstChild);
    if (pinned) feed.scrollTop = feed.scrollHeight;
    return true;
  }

  // Elapsed labels are the one thing on a hunt card that changes with no
  // message arriving, so they are ticked locally rather than waiting for the
  // next progress post — a card that freezes at "12s elapsed" for a minute
  // reads as a hung hunt.
  setInterval(() => {
    document.querySelectorAll('[data-elapsed]').forEach(el => {
      const card = el.closest('.hunt');
      if (!card) return;
      const start = el.getAttribute('data-elapsed');
      if (!start) return;
      const quick = /· quick/.test(card.querySelector('.hunt-meta')?.textContent || '');
      el.textContent = elapsedLabel({ started_at: start, status: 'running', quick });
    });
  }, 1000);

  function bar(label, value, max, color, { html = false } = {}) {
    const pct = max > 0 ? (value / max) * 100 : 0;
    const plain = String(label).replace(/<[^>]+>/g, '');
    return `<div class="bar-row" title="${esc(plain)}">
      <div class="lab">${html ? label : esc(label)}</div>
      <div class="trk"><i style="width:${pct}%;background:${color}"></i></div>
      <div class="val">${esc(value)}</div>
    </div>`;
  }

  return { esc, ago, dur, bytes, sevClass, osIcon, toast, modal, drawer, close, isOpen, stat, pushFindings,
           empty, table, sort, filterRows, ring, huntCard, patchHunt, bar, PHASES };
})();
