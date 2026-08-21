/* Console shell: sign-in, routing, live wiring, and the launch dialog. */

const App = (() => {

  const VIEWS = {
    dashboard: { fn: () => Views.dashboard(), title: 'Overview',      sub: 'Fleet posture at a glance' },
    cases:     { fn: () => Views.cases(),     title: 'Cases',         sub: 'Engagements, their hosts and indicators' },
    fleet:     { fn: () => Views.fleet(),     title: 'Fleet',         sub: 'Every enrolled host and its last result' },
    hunts:     { fn: () => Views.hunts(),     title: 'Hunts',         sub: 'Running and completed collections' },
    findings:  { fn: () => Views.findings(),  title: 'Findings',      sub: 'Triage results across the fleet' },
    triage:    { fn: () => Views.triage(),    title: 'Triage',        sub: 'What still needs a decision' },
    stack:     { fn: () => Views.stack(),     title: 'Frequency',     sub: 'What is rare in your environment' },
    graph:     { fn: () => Views.graph(),     title: 'Graph',         sub: 'External connections and process load' },
    matrix:    { fn: () => Views.matrix(),    title: 'ATT&CK',        sub: 'Techniques observed, by tactic' },
    diff:      { fn: () => Views.diff(),      title: 'Changes',       sub: 'What moved between two scans of a host' },
    timeline:  { fn: () => Views.timeline(),  title: 'Timeline',      sub: 'Events in time order, newest first' },
    deploy:    { fn: () => Views.deploy(),    title: 'Deploy agents', sub: 'Bring hosts into the fleet',
                 role: 'admin' },
    users:     { fn: () => Views.users(),     title: 'Users',         sub: 'Console accounts and activity',
                 role: 'admin' },
    schedules: { fn: () => Views.schedules(), title: 'Schedules',     sub: 'Sweeps that run on their own' },
    feeds:     { fn: () => Views.feeds(),     title: 'IOC feeds',     sub: 'Indicator sources merged into every hunt' },
    intel:     { fn: () => Views.intel(),     title: 'Threat intel',
                 sub: 'Reputation keys and scored addresses' },
    logs:      { fn: () => Views.logs(),      title: 'Logs & events',
                 sub: 'What each module did, and whether it worked' },
    respond:   { fn: () => Views.respond(),   title: 'Response',
                 sub: 'Act on a host: look, contain, collect', role: 'responder' },
    integrations: { fn: () => Views.integrations(), title: 'Integrations',
                    sub: 'Wazuh forwarding and API tokens', role: 'admin' },
    rules:     { fn: () => Views.rules(),     title: 'DGL rules',     sub: 'Built-in detections and how often each fires' },
    myrules:   { fn: () => Views.myrules(),   title: 'My rules',      sub: 'Detections you write and test here' },
    yara:      { fn: () => Views.yara(),      title: 'YARA rules',    sub: 'File content signatures shipped to agents',
                 role: 'admin' },
    sigma:     { fn: () => Views.sigma(),     title: 'Sigma rules',   sub: 'Community detections shipped to agents',
                 role: 'admin' },
  };

  const RANK = { viewer: 0, responder: 1, admin: 2 };

  let current = 'dashboard';
  let poller = null;
  // Starts as the least privileged role so a failed profile load cannot leave
  // admin screens reachable. The cost is the opposite failure — an admin told
  // they lack access — so track whether the profile actually arrived and say
  // so, rather than leaving them at a dead end.
  let me = { user: '—', role: 'viewer' };
  let profileLoaded = false;

  const can = (needed) => RANK[me.role] >= RANK[needed];

  /* ---------------------------------------------------------------- */
  /* Routing                                                          */
  /* ---------------------------------------------------------------- */

  // The password floor was written into three separate strings and drifted
  // from what the server enforced, so the console asked for one length and
  // then rejected it. Read it from the server instead.
  let META = { min_password_length: 8 };

  function minPassword() { return META.min_password_length; }

  async function loadMeta() {
    try { META = await API.meta(); } catch (_) { /* the fallback is fine */ }
  }

  async function go(name) {
    if (!VIEWS[name]) name = 'dashboard';
    // A bookmarked admin URL in a viewer's browser should land somewhere
    // useful rather than on an error.
    if (VIEWS[name].role && !can(VIEWS[name].role)) {
      // Name the role in effect. "Needs admin access" while signed in as an
      // admin is unanswerable; "you are signed in as viewer" is not.
      UI.toast(
        'Not available',
        profileLoaded
          ? `${VIEWS[name].title} needs ${VIEWS[name].role} access. `
            + `You are signed in as ${me.user} (${me.role}).`
          : `${VIEWS[name].title} needs ${VIEWS[name].role} access, but your `
            + 'account details never loaded, so this may be wrong. Reload the page.',
        'err');
      name = 'dashboard';
    }
    current = name;

    document.querySelectorAll('.nav-item').forEach(n =>
      n.classList.toggle('on', n.dataset.view === name));
    document.getElementById('viewTitle').textContent = VIEWS[name].title;
    document.getElementById('viewSub').textContent = VIEWS[name].sub;
    if (location.hash.slice(1) !== name) location.hash = name;

    try {
      await VIEWS[name].fn();
    } catch (e) {
      if (e.message === 'Session expired') return;
      if (e.forbidden) {
        document.getElementById('view').innerHTML =
          `<div class="view"><div class="card">${UI.empty('Not available to your role', e.message)}</div></div>`;
        return;
      }
      document.getElementById('view').innerHTML =
        `<div class="view"><div class="card">${UI.empty('Could not load this view', e.message)}
          <div style="text-align:center"><button class="btn" onclick="App.refresh()">Try again</button></div>
        </div></div>`;
    }
  }

  const refresh = () => go(current);

  /* ---------------------------------------------------------------- */
  /* Launch dialog                                                    */
  /* ---------------------------------------------------------------- */

  function openLaunch(agentIds = []) {
    const scope = agentIds.length
      ? `${agentIds.length} selected host${agentIds.length > 1 ? 's' : ''}`
      : 'every reachable host';

    UI.modal('Launch hunt', `
      <p class="muted" style="margin-top:0">
        Target: <b style="color:#22D9F5">${UI.esc(scope)}</b>.
        A hunt collects volatile state, sweeps event logs, and runs the rule engine
        on the host itself — only the results travel back here.
      </p>

      <div class="field">
        <label>Lookback window</label>
        <select id="lDays">
          <option value="7">7 days — fast first pass</option>
          <option value="14" selected>14 days — standard</option>
          <option value="30">30 days — scoping</option>
          <option value="60">60 days — deep</option>
          <option value="90">90 days — maximum</option>
        </select>
        <div class="hint">Event logs may hold less than you ask for. The report says
        so explicitly when the window exceeds what the host retained.</div>
      </div>

      <div class="grid" style="grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">
        <label class="chk"><input type="checkbox" id="lQuick">
          <div><span>Quick triage</span><small>Skip file scanning. 1–2 minutes.</small></div></label>
        <label class="chk"><input type="checkbox" id="lRaw">
          <div><span>Raw evidence</span><small>Registry hives, event logs, Amcache. Large.</small></div></label>
        <label class="chk"><input type="checkbox" id="lNoResolve">
          <div><span>No DNS lookups</span><small>Stay quiet on isolated networks.</small></div></label>
        <label class="chk"><input type="checkbox" id="lAll" ${agentIds.length ? '' : 'checked'}>
          <div><span>All reachable hosts</span><small>Ignore the selection above.</small></div></label>
      </div>

      <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
        <div class="field"><label>Scan profile</label>
          <select id="lProfile">
            <option value="auto" selected>Detect from the host</option>
            <option value="webserver">Web server — IIS, Apache, nginx, Tomcat</option>
            <option value="workstation">Workstation (Windows)</option>
            <option value="server">Server (Windows)</option>
            <option value="dc">Domain controller (Windows)</option>
          </select>
          <div class="hint">Overrides the role the machine reports. Pick
          <b>Web server</b> when a host serves pages but is not recognised as one —
          that is the case that loses the webshell hunt. The Windows roles decide
          which registry and directory-service modules run; on Linux they have no
          equivalent and detection falls back to what is actually installed.</div></div>
        <div class="field"><label>Report findings at</label>
          <select id="lFloor">
            <option value="INFO" selected>Everything</option>
            <option value="LOW">Low and above</option>
            <option value="MEDIUM">Medium and above</option>
            <option value="HIGH">High and above</option>
            <option value="CRITICAL">Critical only</option>
          </select>
          <div class="hint">Everything is still collected; this only decides what
          gets listed. The report says how many were held back.</div></div>
      </div>

      <div class="field">
        <label>Rule engines</label>
        <div class="grid" style="grid-template-columns:1fr 1fr 1fr 1fr;gap:10px">
          <label class="chk locked" title="Built into the collector; always runs">
            <input type="checkbox" checked disabled>
            <div><span>DGL rules</span><small id="lDglCount">built in</small></div></label>
          <label class="chk"><input type="checkbox" id="lSigma" checked>
            <div><span>Sigma</span><small id="lSigmaCount">community event rules</small></div></label>
          <label class="chk"><input type="checkbox" id="lYara" checked>
            <div><span>YARA</span><small id="lYaraCount">file signatures</small></div></label>
          <label class="chk"><input type="checkbox" id="lCustom" checked>
            <div><span>My rules</span><small id="lCustomCount">rules you wrote</small></div></label>
        </div>
        <div class="hint">DGL rules ship with the collector and cannot be switched
        off — they are the baseline that works before any community rule is loaded.
        If one is noisy on your estate, suppress its findings from Triage rather
        than losing the whole set. The other three are the expensive part of a
        sweep; turn them off for a fast triage pass.</div>
      </div>

      <div class="field">
        <label>Indicators to match (optional)</label>
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
          <label class="btn btn-sm" style="margin:0">
            Load from file
            <input type="file" id="lIocFile" accept=".txt,.csv,.ioc,.list,text/plain,text/csv"
                   style="display:none" onchange="App.loadIocFile(this)">
          </label>
          <button class="btn btn-sm btn-ghost" onclick="App.clearIoc()">Clear</button>
          <span class="muted mono" id="lIocCount" style="font-size:11.5px"></span>
        </div>
        <textarea id="lIoc" oninput="App.countIoc()"
                  placeholder="One per line — SHA256, IP address, domain or filename
d2b1c4e5f6a7b8c9...
185.220.101.50
evil-c2.example.com"></textarea>
        <div class="hint">Anything matching raises a critical finding wherever it appears.
        A CSV works too: the column holding hashes, addresses or domains is picked out
        automatically, so a threat feed export can be dropped in as-is.</div>
      </div>

      <label class="chk"><input type="checkbox" id="lFeeds" checked>
        <div><span>Include indicators from feeds</span>
        <small id="lFeedCount">Merged on top of anything typed above.</small></div></label>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-hunt" id="lGo">Start hunting</button>`);

    // Fill in how much each engine actually carries. An operator deciding
    // whether to skip Sigma wants to know it is 2400 rules, not a checkbox.
    (async () => {
      const setNote = (id, text) => {
        const e = document.getElementById(id);
        if (e) e.textContent = text;
      };
      const [sig, yar, cus, fee] = await Promise.all([
        API.sigmaSummary().catch(() => null),
        API.yaraSummary().catch(() => null),
        API.customRules().catch(() => null),
        API.feeds().catch(() => null),
      ]);
      const dgl = await API.builtinRules().catch(() => null);
      if (dgl) setNote('lDglCount', `${dgl.total} rules · always on`);
      if (sig) setNote('lSigmaCount', sig.enabled
        ? `${sig.enabled} rules enabled` : 'none loaded yet');
      if (yar) setNote('lYaraCount', yar.enabled
        ? `${yar.enabled} rules enabled` : 'none loaded yet');
      if (cus) setNote('lCustomCount', cus.enabled !== undefined
        ? `${cus.enabled} rules enabled` : `${cus.total || 0} written`);
      if (fee) setNote('lFeedCount', fee.pooled_indicators
        ? `${fee.pooled_indicators} indicators from ${fee.enabled} feed(s)`
        : 'No feeds configured yet.');
    })();

    document.getElementById('lGo').onclick = async () => {
      const btn = document.getElementById('lGo');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Dispatching';
      try {
        const res = await API.launch({
          agent_ids: agentIds,
          all_online: document.getElementById('lAll').checked,
          days: parseInt(document.getElementById('lDays').value, 10),
          quick: document.getElementById('lQuick').checked,
          collect_raw: document.getElementById('lRaw').checked,
          no_resolve: document.getElementById('lNoResolve').checked,
          ioc_list: document.getElementById('lIoc').value.trim() || null,
          include_feeds: document.getElementById('lFeeds').checked,
          use_sigma: document.getElementById('lSigma').checked,
          use_yara: document.getElementById('lYara').checked,
          use_custom: document.getElementById('lCustom').checked,
          min_severity: document.getElementById('lFloor').value,
          profile: document.getElementById('lProfile').value,
        });
        UI.close();
        UI.toast(`Hunt queued on ${res.queued} host${res.queued === 1 ? '' : 's'}`,
                 'Hosts pick it up on their next check-in.', 'ok');
        go('hunts');
      } catch (e) {
        btn.disabled = false;
        btn.textContent = 'Start hunting';
        UI.toast('Could not launch', e.message, 'err');
      }
    };
  }

  /* ---------------------------------------------------------------- */
  /* Indicator import                                                 */
  /* ---------------------------------------------------------------- */

  // Recognise an indicator rather than trusting column position: threat feeds
  // disagree about layout but agree about what a hash looks like.
  const IOC_PATTERNS = [
    /^[a-fA-F0-9]{64}$/,                                   // SHA256
    /^[a-fA-F0-9]{40}$/,                                   // SHA1
    /^[a-fA-F0-9]{32}$/,                                   // MD5
    /^\d{1,3}(\.\d{1,3}){3}$/,                             // IPv4
    /^(?=.{4,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/,  // domain
    /^[\w.-]+\.(exe|dll|ps1|bat|scr|vbs|js|jar|sys)$/i,    // filename
  ];

  function looksLikeIoc(value) {
    const v = (value || '').trim().replace(/^["']|["']$/g, '');
    if (!v || v.length > 260) return null;
    return IOC_PATTERNS.some(re => re.test(v)) ? v : null;
  }

  function extractIocs(text) {
    const found = new Set();
    text.split(/\r?\n/).forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      // Try the whole line first, then split on the usual delimiters so a CSV
      // row yields its indicator column without the operator choosing one.
      const whole = looksLikeIoc(trimmed);
      if (whole) { found.add(whole); return; }
      trimmed.split(/[,;\t|]/).forEach(part => {
        const hit = looksLikeIoc(part);
        if (hit) found.add(hit);
      });
    });
    return [...found];
  }

  function countIoc() {
    const box = document.getElementById('lIoc');
    const label = document.getElementById('lIocCount');
    if (!box || !label) return;
    const n = box.value.split(/\r?\n/).filter(l => l.trim() && !l.startsWith('#')).length;
    label.textContent = n ? `${n} indicator${n === 1 ? '' : 's'}` : '';
  }

  function loadIocFile(input) {
    const file = input.files && input.files[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      UI.toast('File too large', 'Indicator lists are capped at 5 MB.', 'err');
      input.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const iocs = extractIocs(String(reader.result || ''));
      const box = document.getElementById('lIoc');
      if (!iocs.length) {
        UI.toast('Nothing recognised in that file',
                 'Expected hashes, addresses, domains or filenames.', 'err');
      } else {
        const existing = box.value.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        const merged = [...new Set([...existing, ...iocs])];
        box.value = merged.join('\n');
        const added = merged.length - existing.length;
        UI.toast(`Loaded ${added} indicator${added === 1 ? '' : 's'}`,
                 `${file.name} · ${iocs.length} found, duplicates merged`, 'ok');
      }
      countIoc();
      input.value = '';
    };
    reader.onerror = () => {
      UI.toast('Could not read that file', '', 'err');
      input.value = '';
    };
    reader.readAsText(file);
  }

  function clearIoc() {
    const box = document.getElementById('lIoc');
    if (box) { box.value = ''; countIoc(); }
  }

  /* ---------------------------------------------------------------- */
  /* Live updates                                                     */
  /* ---------------------------------------------------------------- */

  function wireLive() {
    // Patch the card in place so the ring keeps animating smoothly.
    Live.on('job.progress', (msg) => {
      if (!UI.patchHunt(msg) && (current === 'hunts' || current === 'dashboard')) {
        refresh();
      }
    });

    Live.on('job.completed', (msg) => {
      const j = msg.job || {};
      const kind = j.critical_count > 0 ? 'err' : 'ok';
      UI.toast(`${j.hostname} finished`,
        `${j.risk_level} · ${j.critical_count} critical, ${j.high_count} high`, kind);
      if (['hunts', 'dashboard', 'fleet', 'findings'].includes(current)) refresh();
    });

    Live.on('job.failed', (msg) => {
      UI.toast(`${msg.job?.hostname || 'A host'} could not finish`,
               msg.job?.error || '', 'err');
      if (['hunts', 'dashboard'].includes(current)) refresh();
    });

    Live.on('agent.enrolled', (msg) => {
      UI.toast('Host joined the fleet', msg.agent?.hostname || '', 'ok');
      if (['fleet', 'dashboard'].includes(current)) refresh();
    });

    Live.on('jobs.queued', () => {
      if (['hunts', 'dashboard'].includes(current)) refresh();
    });

    Live.on('sigma.update', (msg) => {
      Views.sigmaPatchProgress(msg);
      if (!msg.running && current === 'sigma') {
        if (msg.error) UI.toast('Sigma update failed', msg.error, 'err');
        else if (msg.result) {
          UI.toast('Sigma rules updated',
                   `${msg.result.added} added, ${msg.result.updated} updated`, 'ok');
        }
        refresh();
      }
    });

    // Findings arriving while a sweep is still running. The views that list
    // findings refresh so the console fills in as the host reports, rather
    // than staying empty until the bundle uploads and producing everything at
    // once. Refreshing the view rather than splicing a row in by hand keeps
    // the filters, counts and sort order the view already applies — a row
    // inserted directly would ignore whichever filter is active and appear
    // where it does not belong.
    let findingRefresh = null;
    Live.on('finding.live', (msg) => {
      const rows = msg.findings || [];
      if (!rows.length) return;

      // A CRITICAL found mid-sweep is the reason this exists: say so
      // immediately, wherever the operator happens to be.
      rows.filter(f => f.severity === 'CRITICAL').slice(0, 3).forEach(f => {
        UI.toast(`${msg.hostname}: ${f.title || f.rule_id}`,
          (f.evidence || '').slice(0, 90), 'err');
      });

      // The hunts view shows the sweep as it happens, so findings go straight
      // into the card's feed instead of forcing a whole-view rebuild.
      if (current === 'hunts') {
        UI.pushFindings(msg.job_id, rows);
        return;
      }

      if (!['findings', 'triage', 'stack', 'dashboard'].includes(current)) return;
      // Several ticks can land close together on a busy fleet; refresh once
      // when they stop rather than once per message.
      clearTimeout(findingRefresh);
      findingRefresh = setTimeout(() => { if (!UI.isOpen()) refresh(); }, 700);
    });

    Live.on('fleet.refresh', () => {
      if (['fleet', 'dashboard'].includes(current)) refresh();
    });

    Live.on('response.updated', (msg) => {
      const a = msg.action || {};
      if (a.status === 'completed' || a.status === 'failed') {
        UI.toast(`${a.hostname}: ${a.action_name}`,
          a.status === 'failed' ? (a.error || 'It reported a failure.') : 'Finished.',
          a.status === 'failed' ? 'err' : 'ok');
      }
      if (current === 'respond') refresh();
    });

    Live.on('response.queued', () => {
      if (current === 'respond') refresh();
    });

    Live.start();
  }

  function startPolling() {
    clearInterval(poller);
    // A safety net: the console stays correct even if the socket is blocked
    // by a proxy. Slow enough not to fight the live channel.
    let tick = 0;
    poller = setInterval(async () => {
      if (document.hidden) return;
      tick++;
      // Fleet and hunt counts move minute to minute and are worth every tick.
      // Cases, reputation and queued actions do not, and asking for all five
      // on a fifteen-second loop is four requests a minute spent on numbers
      // that rarely change — so those ride a slower cadence.
      const slow = tick % 4 === 1;
      try {
        const s = await API.fleetSummary();
        const badge = document.getElementById('badgeFleet');
        if (badge) {
          badge.textContent = s.at_risk;
          badge.classList.toggle('hidden', !s.at_risk);
        }
        try {
          const q = await API.triageQueue();
          const tb = document.getElementById('badgeTriage');
          if (tb) {
            const open = (q.by_status || {}).open || 0;
            tb.textContent = open > 999 ? '999+' : open;
            tb.classList.toggle('hidden', !open);
            tb.style.background = 'var(--electric)';
            tb.style.boxShadow = 'var(--glow-blue)';
          }
        } catch (_) { /* non-fatal */ }

        const hb = document.getElementById('badgeHunts');
        if (hb) {
          hb.textContent = s.active_jobs;
          hb.classList.toggle('hidden', !s.active_jobs);
          hb.style.background = s.active_jobs ? 'var(--electric)' : 'var(--crit)';
          hb.style.boxShadow = s.active_jobs ? 'var(--glow-blue)' : 'var(--glow-crit)';
        }

        // Open cases. The element shipped in the sidebar but nothing ever
        // wrote to it, so the badge could only sit hidden forever.
        try {
          const cb = document.getElementById('badgeCases');
          if (cb && slow) {
            const cs = await API.cases();
            cb.textContent = cs.open > 999 ? '999+' : cs.open;
            cb.classList.toggle('hidden', !cs.open);
            cb.style.background = 'var(--high)';
          }
        } catch (_) { /* non-fatal */ }

        // Addresses a reputation provider called bad. Worth a badge because
        // it is the one number here that appears without anybody asking —
        // enrichment runs on its own after a hunt.
        try {
          const ib = document.getElementById('badgeIntel');
          if (ib && slow && can('responder')) {
            const e = await API.enrichment();
            ib.textContent = e.flagged > 999 ? '999+' : e.flagged;
            ib.classList.toggle('hidden', !e.flagged);
            ib.style.background = 'var(--crit)';
            ib.style.boxShadow = 'var(--glow-crit)';
          }
        } catch (_) { /* non-fatal */ }

        // Response actions still waiting on a host. These are short, so a
        // number sitting here for more than a minute means a host is not
        // picking work up.
        try {
          const rb = document.getElementById('badgeResp');
          if (rb && can('responder')) {
            const ra = await API.responseActions();
            rb.textContent = ra.running;
            rb.classList.toggle('hidden', !ra.running);
            rb.style.background = 'var(--electric)';
            rb.style.boxShadow = 'var(--glow-blue)';
          }
        } catch (_) { /* non-fatal */ }
        if (s.active_jobs && ['dashboard', 'hunts'].includes(current)) {
          const live = document.getElementById('liveGrid');
          if (!live) refresh();
        }
      } catch (_) { /* handled by the auth listener */ }
    }, 15000);
  }

  /* ---------------------------------------------------------------- */
  /* Session                                                          */
  /* ---------------------------------------------------------------- */

  function applyRole() {
    // Hide what the role cannot use rather than letting people click into a 403.
    document.querySelectorAll('.nav-item[data-role]').forEach(n => {
      n.classList.toggle('hidden', !can(n.dataset.role));
    });
    const launch = document.getElementById('launchBtn');
    if (launch) launch.classList.toggle('hidden', !can('responder'));

    // A section heading with nothing under it is just clutter.
    document.querySelectorAll('#nav .nav-label').forEach(label => {
      const items = [];
      for (let n = label.nextElementSibling; n && n.classList.contains('nav-item');
           n = n.nextElementSibling) {
        items.push(n);
      }
      const anyVisible = items.some(n => !n.classList.contains('hidden'));
      label.classList.toggle('hidden', items.length > 0 && !anyVisible);
    });

    const chip = document.getElementById('roleLabel');
    if (chip) {
      chip.textContent = me.role;
      chip.className = `rolechip role-${me.role}`;
    }
  }

  async function enterConsole(profile) {
    me = profile;
    // A profile with no role means the response shape changed or the request
    // half-failed. Falling back to viewer silently is what produces "needs
    // admin access" for an actual admin, so record what really happened.
    profileLoaded = !!(profile && profile.role);
    if (!profileLoaded) {
      me = { ...(profile || {}), role: 'viewer', user: (profile && profile.user) || '—' };
      console.warn('Douglas: signed in but no role came back; treating as viewer.');
    }
    document.getElementById('login').style.display = 'none';
    document.getElementById('app').classList.add('ready');
    document.getElementById('userLabel').textContent = profile.full_name || profile.user;
    if (profile.version) {
      document.getElementById('verLabel').textContent = `v${profile.version}`;
    }
    applyRole();

    wireLive();
    startPolling();
    await go(location.hash.slice(1) || 'dashboard');

    if (profile.must_change_password) {
      openPasswordChange(true);
    }
  }

  function openPasswordChange(forced = false) {
    UI.modal(forced ? 'Choose a new password' : 'Change password', `
      ${forced ? `<p class="muted" style="margin-top:0">
        This account is still on the password someone else set. Replace it before
        you carry on.</p>` : ''}
      <div class="field"><label>Current password</label>
        <input type="password" id="cpOld" autocomplete="current-password"></div>
      <div class="field"><label>New password</label>
        <input type="password" id="cpNew" autocomplete="new-password">
        <div class="hint">At least ${App.minPassword()} characters. A few unrelated words work well
        and are easy to type.</div></div>
      <div class="field"><label>Confirm new password</label>
        <input type="password" id="cpNew2" autocomplete="new-password"></div>
      <div id="cpErr" class="hidden" style="color:var(--crit);font-size:13px"></div>`,
      `${forced ? '' : '<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>'}
       <button class="btn btn-primary" id="cpGo">Update password</button>`,
      { dismissible: !forced });

    document.getElementById('cpGo').onclick = async () => {
      const err = document.getElementById('cpErr');
      const a = document.getElementById('cpNew').value;
      const b = document.getElementById('cpNew2').value;
      err.classList.add('hidden');
      if (a !== b) {
        err.textContent = 'The two new passwords are different.';
        err.classList.remove('hidden');
        return;
      }
      try {
        await API.changeOwnPassword(document.getElementById('cpOld').value, a);
        me.must_change_password = false;
        UI.close(true);
        UI.toast('Password updated', '', 'ok');
      } catch (e) {
        err.textContent = e.message;
        err.classList.remove('hidden');
      }
    };
  }

  function showLogin() {
    Live.stop();
    clearInterval(poller);
    document.getElementById('app').classList.remove('ready');
    document.getElementById('login').style.display = 'flex';
  }

  async function boot() {
    // Fetched before the first password prompt can appear, so the hint and the
    // rule the server applies are never out of step.
    loadMeta();

    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('loginBtn');
      const err = document.getElementById('loginErr');
      err.classList.add('hidden');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Signing in';
      try {
        const res = await API.login(
          document.getElementById('loginUser').value,
          document.getElementById('loginPass').value
        );
        await enterConsole(res);
      } catch (ex) {
        err.textContent = ex.message;
        err.classList.remove('hidden');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Sign in';
      }
    });

    document.getElementById('nav').addEventListener('click', (e) => {
      const item = e.target.closest('.nav-item');
      if (item) go(item.dataset.view);
    });

    document.getElementById('refreshBtn').onclick = refresh;
    document.getElementById('launchBtn').onclick = () => {
      if (!can('responder')) {
        UI.toast('Not available', 'Launching a hunt needs responder access.', 'err');
        return;
      }
      openLaunch(current === 'fleet' ? Views.selectedAgents() : []);
    };
    document.getElementById('changePw').onclick = (e) => {
      e.preventDefault();
      openPasswordChange(false);
    };
    document.getElementById('signOut').onclick = async (e) => {
      e.preventDefault();
      await API.logout();
      showLogin();
    };

    window.addEventListener('hashchange', () => {
      const h = location.hash.slice(1);
      if (h && h !== current) go(h);
    });
    document.addEventListener('auth:expired', showLogin);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') UI.close(); });

    try {
      await enterConsole(await API.me());
    } catch (_) {
      showLogin();
    }
  }

  return { go, refresh, openLaunch, boot, minPassword, loadMeta, can,
           loadIocFile, clearIoc, countIoc, extractIocs,
           currentView: () => current };
})();

document.addEventListener('DOMContentLoaded', App.boot);
