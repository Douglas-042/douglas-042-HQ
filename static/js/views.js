/* One render function per view. Each returns nothing and writes into #view;
   App handles which one is active and when to re-run it. */

const Views = (() => {

  const el = () => document.getElementById('view');
  const SEV_COLOR = {
    CRITICAL: '#FF2D55', HIGH: '#FF7A00', MEDIUM: '#FFC531',
    LOW: '#3DA5FF', INFO: '#5D7A9E',
  };

  let findingFilter = { severity: '', search: '', status: 'needs_review' };
  let cachedFindings = [];

  function loading() {
    el().innerHTML = `<div class="view"><div class="empty">
      <div class="spinner" style="margin:0 auto 14px"></div>Loading</div></div>`;
  }

  /* ==================================================================== */
  /* Overview                                                             */
  /* ==================================================================== */

  async function dashboard() {
    loading();
    const [summary, overview, active] = await Promise.all([
      API.fleetSummary(), API.overview(), API.activeJobs(),
    ]);

    const sev = overview.severity;
    const totalFindings = Object.values(sev).reduce((a, b) => a + b, 0);

    const liveSection = active.jobs.length ? `
      <div class="card-h" style="margin-top:28px">
        <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
        <h2>Hunts in progress</h2>
        <div class="spacer"></div>
        <span class="muted mono">${active.jobs.length} running</span>
      </div>
      <div class="hunt-grid" id="liveGrid">
        ${active.jobs.map(UI.huntCard).join('')}
      </div>` : '';

    const ranking = overview.ranking.slice(0, 12);
    const rankRows = ranking.map(r => `
      <tr class="clickable" onclick="Views.openHost('${UI.esc(r.agent_id)}')">
        <td><b>${UI.esc(r.hostname)}</b></td>
        <td><span class="${UI.sevClass(r.risk_level)}">${UI.esc(r.risk_level)}</span></td>
        <td class="mono" style="font-weight:700;color:${r.risk_score >= 50 ? '#FF2D55' : r.risk_score >= 25 ? '#FF7A00' : '#7A93B8'}">${r.risk_score}</td>
        <td class="mono">${r.critical}</td>
        <td class="mono">${r.high}</td>
        <td class="mono muted">${UI.ago(r.scanned_at)}</td>
      </tr>`).join('') || `<tr><td colspan="6">${UI.empty('No completed hunts yet',
        'Launch a hunt to populate this table.')}</td></tr>`;

    const maxRule = Math.max(1, ...overview.top_rules.map(r => r.count));
    // Two panels that fill the left column and answer the questions the
    // ranking table raises: what is left to look at, and what is watching.
    let queue = null, sigmaSum = null, yaraSum = null, builtin = null;
    try { [queue, sigmaSum, yaraSum, builtin] = await Promise.all([
      API.triageQueue().catch(() => null),
      API.sigmaSummary().catch(() => null),
      API.yaraSummary().catch(() => null),
      API.builtinRules().catch(() => null),
    ]); } catch (_) { /* panels are optional */ }

    const qs = (queue && queue.by_status) || {};
    const qOpen = qs.open || 0;
    const qMax = Math.max(1, ...Object.values(qs));
    const queueHtml = queue
      ? `${[['open', 'Open', '#1B7FE8'], ['investigating', 'Investigating', '#FFC531'],
           ['true_positive', 'Confirmed', '#FF2D55'],
           ['false_positive', 'False positive', '#7A93B8'],
           ['suppressed', 'Suppressed', '#5D7A9E']]
          .map(([k, label, c]) => UI.bar(label, qs[k] || 0, qMax, c)).join('')}
         <div class="hint" style="margin-top:10px">${
           qOpen ? `${qOpen} finding${qOpen === 1 ? '' : 's'} nobody has ruled on yet.`
                 : 'Nothing waiting on a decision.'}${
           queue.unassigned ? ` ${queue.unassigned} unassigned.` : ''}</div>`
      : '<div class="muted">No findings yet.</div>';

    const cov = [
      ['DGL', builtin ? builtin.total : 0, '#22D9F5', 'rules'],
      ['Sigma', sigmaSum ? sigmaSum.enabled : 0, '#1B7FE8', 'yara'],
      ['YARA', yaraSum ? yaraSum.enabled : 0, '#2BD9A0', 'yara'],
    ];
    const covMax = Math.max(1, ...cov.map(c => c[1]));
    const coverageHtml = `
      ${cov.map(([label, n, c]) => UI.bar(label, n, covMax, c)).join('')}
      <div class="hint" style="margin-top:10px">
        ${cov.reduce((a, c) => a + c[1], 0)} detections active across all three sets.
        ${!yaraSum || !yaraSum.enabled ? 'YARA is not loaded yet.' : ''}
        ${!sigmaSum || !sigmaSum.enabled ? 'Sigma is not loaded yet.' : ''}
      </div>`;

    const rulesHtml = overview.top_rules.length
      ? overview.top_rules.slice(0, 10).map(r =>
          UI.bar(`<b>${UI.esc(r.rule_id)}</b>${UI.esc(r.title)}`, r.count, maxRule,
                 SEV_COLOR[r.severity] || '#1B7FE8', { html: true })).join('')
      : `<div class="muted">Nothing recorded yet.</div>`;

    const maxMitre = Math.max(1, ...overview.top_mitre.map(m => m.count));
    const mitreHtml = overview.top_mitre.length
      ? overview.top_mitre.slice(0, 10).map(m =>
          UI.bar(`<b>${UI.esc(m.technique)}</b>${UI.esc(m.name || '')}`,
                 m.count, maxMitre, '#22D9F5', { html: true })).join('')
      : `<div class="muted">Nothing recorded yet.</div>`;

    el().innerHTML = `<div class="view">
      <div class="grid g-stats">
        ${UI.stat(summary.total, 'Hosts enrolled', { accent: '#22D9F5', sub: `${summary.online} reachable` })}
        ${UI.stat(summary.scanning, 'Hunting now', { accent: '#1B7FE8', sub: `${summary.active_jobs} queued or running` })}
        ${UI.stat(sev.CRITICAL, 'Critical findings', { accent: '#FF2D55', glow: sev.CRITICAL > 0, sub: `across ${overview.hosts_scanned} scanned hosts` })}
        ${UI.stat(sev.HIGH, 'High findings', { accent: '#FF7A00' })}
        ${UI.stat(summary.at_risk, 'Hosts at risk', { accent: '#FFC531', sub: 'CRITICAL or HIGH posture' })}
        ${UI.stat(totalFindings, 'Total findings', { accent: '#7A93B8' })}
      </div>

      ${liveSection}

      <div class="grid g-2" style="margin-top:28px">
        <div class="card">
          <div class="card-h"><h2>Highest risk hosts</h2><div class="spacer"></div>
            <button class="btn btn-sm btn-ghost" onclick="App.go('fleet')">See all</button></div>
          ${UI.table(['Host', 'Posture', 'Score', 'Crit', 'High', 'Scanned'], rankRows,
                     { id: 'tblRank', maxHeight: '340px' })}

          <div class="card" style="margin-top:14px">
            <div class="card-h"><h2>Triage queue</h2><div class="spacer"></div>
              <button class="btn btn-sm btn-ghost" onclick="App.go('triage')">Open</button></div>
            ${queueHtml}
          </div>

          <div class="card" style="margin-top:14px">
            <div class="card-h"><h2>Detection coverage</h2></div>
            ${coverageHtml}
          </div>
        </div>

        <div>
          <div class="card" style="margin-bottom:14px">
            <div class="card-h"><h2>Most frequent detections</h2></div>
            ${rulesHtml}
          </div>
          <div class="card">
            <div class="card-h"><h2>MITRE ATT&amp;CK coverage</h2></div>
            ${mitreHtml}
          </div>
        </div>
      </div>
    </div>`;
  }

  /* ==================================================================== */
  /* Fleet                                                                */
  /* ==================================================================== */

  async function fleet() {
    loading();
    const { agents } = await API.agents();

    if (!agents.length) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'No hosts have enrolled yet',
        'Open Deploy agents and run the one-liner on a server to add the first host.'
      )}<div style="text-align:center"><button class="btn btn-primary" onclick="App.go('deploy')">Deploy agents</button></div></div></div>`;
      return;
    }

    const rows = agents.map(a => `
      <tr class="clickable" onclick="Views.openHost('${UI.esc(a.id)}')">
        <td><input type="checkbox" class="agentPick" value="${UI.esc(a.id)}"
             onclick="event.stopPropagation()" style="width:15px;height:15px;accent-color:#22D9F5"></td>
        <td><b>${UI.esc(a.hostname)}</b>
            <div class="muted mono" style="font-size:11px">${UI.esc(a.ip_address || '')}</div></td>
        <td><span class="st st-${UI.esc(a.status)}">${UI.esc(a.status)}</span></td>
        <td class="muted">${UI.esc(a.domain_role || '—')}
            <div class="mono" style="font-size:11px">${UI.esc(a.domain || '')}</div></td>
        <td class="muted mono" style="font-size:11.5px">
            <span class="os-cell os-${UI.esc((a.platform || 'windows'))}">${UI.osIcon(a.platform)}</span>
            ${UI.esc(a.os_caption || (a.platform === 'linux' ? 'Linux' : 'Windows'))}</td>
        <td><span class="${UI.sevClass(a.risk_level)}">${UI.esc(a.risk_level)}</span></td>
        <td class="mono" style="font-weight:700">${a.risk_score}</td>
        <td class="mono">${a.critical_count ? `<span style="color:#FF2D55">${a.critical_count}</span>` : '0'}
            / ${a.high_count}</td>
        <td class="muted mono" style="font-size:11.5px">${UI.ago(a.last_scan_at)}</td>
        <td class="muted mono" style="font-size:11.5px">${UI.ago(a.last_seen)}</td>
      </tr>`).join('');

    // A host missing auditd is not a broken host — it is a host where a whole
    // class of detection cannot fire. Said here because a clean result from
    // such a host reads exactly like a clean result from a fully instrumented
    // one, and only one of them means anything.
    const gapped = agents.filter(a => (a.capability_gaps || []).length);
    const blind = gapped.filter(a =>
      (a.capability_gaps || []).some(g => g.id === 'auditd' || g.id === 'auditd_rules'));
    const gapBanner = gapped.length ? `
      <div class="notice warn-notice" style="margin-bottom:18px">
        <b>${gapped.length} Linux host${gapped.length === 1 ? '' : 's'} cannot run part of the detection</b>
        ${blind.length ? `<p style="margin:6px 0 0">On ${blind.length} of them nothing
          records what executed, so a clean sweep there only means the sweep could
          not look.</p>` : ''}
        ${gapped.slice(0, 4).map(a => `
          <div style="margin-top:9px">
            <div class="mono" style="font-size:12px;color:#FFD9A0">${UI.esc(a.hostname)}</div>
            ${(a.capability_gaps || []).map(g => `
              <div style="font-size:11.5px;color:var(--slate);margin-left:10px;margin-top:3px">
                <b style="color:var(--silver)">${UI.esc(g.label)}</b> — ${UI.esc(g.costs)}
                <div class="mono" style="font-size:11px;color:var(--slate-d);margin-top:2px">${UI.esc(g.fix)}</div>
              </div>`).join('')}
          </div>`).join('')}
        ${gapped.length > 4 ? `<div class="muted" style="font-size:11px;margin-top:6px">
          … and ${gapped.length - 4} more</div>` : ''}
      </div>` : '';

    el().innerHTML = `<div class="view">
      ${gapBanner}
      <div class="filters">
        <button class="btn btn-sm" onclick="Views.pickAll(true)">Select all</button>
        <button class="btn btn-sm btn-ghost" onclick="Views.pickAll(false)">Clear</button>
        <input type="search" placeholder="Filter by hostname, address, role or OS"
               oninput="UI.filterRows(this,'tblFleet')">
        <button class="btn btn-hunt btn-sm" onclick="Views.launchSelected()">Hunt selected</button>
        <button class="btn btn-sm btn-ghost btn-danger" data-role="admin"
                onclick="Views.removeSelected()">Remove selected</button>
      </div>
      ${UI.table(['', 'Host', 'Status', 'Role', 'Operating system', 'Posture',
                  'Score', 'Crit / High', 'Last hunt', 'Check-in'], rows, { id: 'tblFleet' })}
    </div>`;
  }

  function pickAll(state) {
    document.querySelectorAll('.agentPick').forEach(c => { c.checked = state; });
  }

  async function removeSelected() {
    // Removal lived only in the host detail panel, which is no help when that
    // panel is the thing failing to open — and a decommissioned host is
    // exactly the sort of row someone wants gone from the list.
    const ids = selectedAgents();
    if (!ids.length) {
      UI.toast('Nothing selected', 'Tick at least one host first.', 'err');
      return;
    }
    if (!confirm(
      `Remove ${ids.length} host${ids.length === 1 ? '' : 's'} from the fleet?\n\n`
      + 'Their hunt history and findings go with them. A host whose agent is '
      + 'still installed will re-enrol on its next check-in — uninstall the '
      + 'agent there first if you want it gone for good.')) return;

    let removed = 0;
    const failed = [];
    for (const id of ids) {
      try { await API.removeAgent(id); removed++; }
      catch (e) { failed.push(e.message); }
    }
    UI.toast(
      removed ? `${removed} host${removed === 1 ? '' : 's'} removed` : 'Nothing removed',
      failed.length ? `${failed.length} failed: ${failed[0]}` : '',
      failed.length ? 'err' : 'ok');
    fleet();
  }

  function selectedAgents() {
    return [...document.querySelectorAll('.agentPick:checked')].map(c => c.value);
  }

  function launchSelected() {
    const ids = selectedAgents();
    if (!ids.length) {
      UI.toast('Nothing selected', 'Tick at least one host first.', 'err');
      return;
    }
    App.openLaunch(ids);
  }

  async function openHost(agentId) {
    const { agent, jobs } = await API.agent(agentId);
    const jobRows = jobs.map(j => `
      <tr>
        <td class="mono">${UI.esc((j.finished_at || j.created_at || '').replace('T', ' ').slice(0, 16))}</td>
        <td><span class="tag">${UI.esc(j.status)}</span></td>
        <td><span class="${UI.sevClass(j.risk_level || 'CLEAN')}">${UI.esc(j.risk_level || '—')}</span></td>
        <td class="mono">${j.critical_count} / ${j.high_count}</td>
        <td class="mono muted">${UI.dur(j.duration_seconds)}</td>
        <td>${j.status === 'completed'
              ? `<a href="${API.reportUrl(j.id)}" target="_blank" rel="noopener">Report</a>` : '—'}</td>
      </tr>`).join('') || `<tr><td colspan="6" class="muted">No hunts recorded.</td></tr>`;

    UI.drawer(agent.hostname, `
      <div class="grid g-stats" style="margin-bottom:22px">
        ${UI.stat(agent.risk_score, 'Risk score', { accent: '#22D9F5' })}
        ${UI.stat(agent.critical_count, 'Critical', { accent: '#FF2D55', glow: agent.critical_count > 0 })}
        ${UI.stat(agent.high_count, 'High', { accent: '#FF7A00' })}
        ${UI.stat(agent.medium_count, 'Medium', { accent: '#FFC531' })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h"><h2>Host</h2></div>
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;font-size:13px">
          <div><div class="muted" style="font-size:11px">ADDRESS</div>${UI.esc(agent.ip_address || '—')}</div>
          <div><div class="muted" style="font-size:11px">DOMAIN</div>${UI.esc(agent.domain || '—')}</div>
          <div><div class="muted" style="font-size:11px">ROLE</div>${UI.esc(agent.domain_role || '—')}</div>
          <div><div class="muted" style="font-size:11px">OS</div>${UI.esc(agent.os_caption || '—')}</div>
          <div><div class="muted" style="font-size:11px">BUILD</div>${UI.esc(agent.os_build || '—')}</div>
          <div><div class="muted" style="font-size:11px">POWERSHELL</div>${UI.esc(agent.ps_version || '—')}</div>
          <div><div class="muted" style="font-size:11px">AGENT</div>v${UI.esc(agent.agent_version || '—')}</div>
          <div><div class="muted" style="font-size:11px">CHECK-IN</div>${UI.ago(agent.last_seen)}</div>
        </div>
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h"><h2>Hunt history</h2></div>
        ${UI.table(['When', 'Status', 'Posture', 'Crit / High', 'Duration', ''], jobRows,
                   { maxHeight: '320px' })}
      </div>

      <div style="display:flex;gap:10px">
        <button class="btn btn-hunt" onclick="UI.close();App.openLaunch(['${UI.esc(agent.id)}'])">Hunt this host</button>
        <button class="btn btn-ghost btn-danger" style="margin-left:auto"
                onclick="Views.removeHost('${UI.esc(agent.id)}','${UI.esc(agent.hostname)}')">Remove from fleet</button>
      </div>`);
  }

  async function removeHost(id, hostname) {
    if (!confirm(`Remove ${hostname} from the fleet? Its hunt history will be deleted.`)) return;
    await API.removeAgent(id);
    UI.close();
    UI.toast('Host removed', hostname, 'ok');
    App.refresh();
  }

  /* ==================================================================== */
  /* Hunts                                                                */
  /* ==================================================================== */

  async function hunts() {
    loading();
    const [active, recent] = await Promise.all([API.activeJobs(), API.jobs(60)]);
    const done = recent.jobs.filter(j => !active.jobs.find(a => a.id === j.id));

    el().innerHTML = `<div class="view">
      ${active.jobs.length ? `
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>In progress</h2><div class="spacer"></div>
          <span class="muted mono">${active.jobs.length} running</span>
        </div>
        <div class="hunt-grid" id="liveGrid" style="margin-bottom:30px">
          ${active.jobs.map(UI.huntCard).join('')}
        </div>` : `
        <div class="card" style="margin-bottom:26px">${UI.empty(
          'No hunts running',
          'Pick hosts in Fleet, or launch across everything reachable.')}
          <div style="text-align:center"><button class="btn btn-hunt" onclick="App.openLaunch([])">Launch hunt</button></div>
        </div>`}

      <div class="card-h"><h2>Completed</h2></div>
      <div class="hunt-grid">
        ${done.length ? done.slice(0, 30).map(UI.huntCard).join('')
                      : `<div class="card">${UI.empty('Nothing here yet')}</div>`}
      </div>
    </div>`;
  }

  async function cancelHunt(jobId) {
    try {
      await API.cancelJob(jobId);
      UI.toast('Hunt cancelled', '', 'ok');
      App.refresh();
    } catch (e) { UI.toast('Could not cancel', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* Findings                                                             */
  /* ==================================================================== */

  async function findings() {
    loading();
    const data = await API.findings({ limit: 2000, ...findingFilter });
    cachedFindings = data.findings;
    renderFindings(data.total, data.status_counts);
  }

  function renderFindings(total, statusCounts) {
    const counts = cachedFindings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1; return acc;
    }, {});

    const rows = cachedFindings.map(f => `
      <tr class="clickable ${f.status && f.status !== 'open' && f.status !== 'investigating' ? 'closed' : ''}"
          onclick="Views.openFinding(${f.id})">
        <td onclick="event.stopPropagation()">
          <input type="checkbox" class="findPick" value="${f.id}"
                 style="width:15px;height:15px;accent-color:#22D9F5"></td>
        <td><span class="stat-chip st-${UI.esc(f.status || 'open')}">${
          UI.esc((f.status || 'open').replace('_', ' '))}</span>
          ${f.assignee ? `<div class="tname">${UI.esc(f.assignee)}</div>` : ''}</td>
        <td><span class="${UI.sevClass(f.severity)}">${UI.esc(f.severity)}</span></td>
        <td class="mono muted">${UI.esc(f.rule_id)}</td>
        <td><b>${UI.esc(f.hostname)}</b></td>
        <td><div>${UI.esc(f.title)}</div>
            ${f.why ? `<div class="why">${UI.esc(f.why)}</div>` : ''}</td>
        <td class="ev">${UI.esc((f.evidence || '').slice(0, 190))}</td>
        <td class="mono muted">${UI.esc(f.mitre || '')}
            ${f.mitre_name && f.mitre_name !== f.mitre
              ? `<div class="tname">${UI.esc(f.mitre_name)}</div>` : ''}</td>
        <td class="mono muted" style="font-size:11px">${UI.esc((f.occurred_at || '').replace('T', ' ').slice(0, 16))}</td>
      </tr>`).join('') || `<tr><td colspan="7">${UI.empty('No findings match',
        'Widen the filter or run a hunt first.')}</td></tr>`;

    const chip = (label, value, count) =>
      `<button class="fchip ${findingFilter.severity === value ? 'on' : ''}"
        onclick="Views.setSeverity('${value}')">${label}${count !== undefined ? ` ${count}` : ''}</button>`;

    const sc = statusCounts || {};
    const sChip = (label, value) =>
      `<button class="fchip ${findingFilter.status === value ? 'on' : ''}"
        onclick="Views.setFindingStatus('${value}')">${label}</button>`;

    // An indicator match is the one finding on this screen that needs no
    // interpretation: a value from a feed the operator loaded was seen in live
    // activity on the host. It is surfaced above the filters so it is never
    // something you have to go looking for.
    const iocHits = cachedFindings.filter(f => f.rule_id === 'DGL-IOC');
    const iocHosts = [...new Set(iocHits.map(f => f.hostname))];
    const iocBanner = iocHits.length ? `
      <div class="notice bad-notice" style="margin-bottom:14px">
        <b>${iocHits.length} indicator match${iocHits.length === 1 ? '' : 'es'} on
        ${iocHosts.length} host${iocHosts.length === 1 ? '' : 's'}</b>
        <p style="margin:6px 0 0">A value from your IOC feeds was seen in live
        activity — a connection, a process, a hash or a DNS lookup. This is a
        direct match, not a heuristic.</p>
        ${iocHits.slice(0, 4).map(f => `
          <div class="mono" style="font-size:11.5px;color:#FF9AAC;margin-top:6px">
            <b>${UI.esc(f.hostname)}</b> — ${UI.esc((f.evidence || '').slice(0, 110))}</div>`).join('')}
        ${iocHits.length > 4 ? `<div class="muted" style="font-size:11px;margin-top:4px">
          … and ${iocHits.length - 4} more</div>` : ''}
        <div style="margin-top:10px">
          <button class="btn btn-sm" onclick="Views.setSearch('DGL-IOC')">Show only these</button>
        </div>
      </div>` : '';

    el().innerHTML = `<div class="view">
      ${iocBanner}
      <div class="filters" style="margin-bottom:10px">
        ${sChip('Needs review', 'needs_review')}
        ${sChip('Open', 'open')}
        ${sChip('Investigating', 'investigating')}
        ${sChip('Confirmed', 'true_positive')}
        ${sChip('False positive', 'false_positive')}
        ${sChip('Suppressed', 'suppressed')}
        ${sChip('Everything', '')}
        <span class="muted mono" style="font-size:11.5px">${
          Object.entries(sc).map(([k, v]) => `${k.replace('_', ' ')} ${v}`).join(' · ')}</span>
      </div>
      <div class="filters" id="bulkBar" style="display:none;margin-bottom:10px">
        <span class="muted mono" id="bulkCount">0 selected</span>
        <button class="btn btn-sm" onclick="Views.bulkTriage('investigating')">Investigating</button>
        <button class="btn btn-sm" onclick="Views.bulkTriage('true_positive')">Confirmed</button>
        <button class="btn btn-sm" onclick="Views.bulkTriage('false_positive')">False positive</button>
        <button class="btn btn-sm btn-ghost" onclick="Views.pickFindings(false)">Clear</button>
      </div>
      <div class="filters">
        ${chip('All', '', total)}
        ${chip('Critical', 'CRITICAL', counts.CRITICAL || 0)}
        ${chip('High', 'HIGH', counts.HIGH || 0)}
        ${chip('Medium', 'MEDIUM', counts.MEDIUM || 0)}
        ${chip('Low', 'LOW', counts.LOW || 0)}
        ${chip('Info', 'INFO', counts.INFO || 0)}
        <input type="search" id="findSearch" placeholder="Search hosts, paths, addresses, MITRE IDs"
               value="${UI.esc(findingFilter.search)}"
               onkeydown="if(event.key==='Enter')Views.setSearch(this.value)">
        <button class="btn btn-sm" onclick="Views.setSearch(document.getElementById('findSearch').value)">Search</button>
        <a class="btn btn-sm btn-ghost" href="${API.fleetExport}">Export fleet</a>
      </div>
      ${UI.table(['', 'Status', 'Severity', 'Rule', 'Host', 'Finding', 'Evidence',
                  'MITRE', 'Time (UTC)'], rows, { id: 'tblFind' })}
    </div>`;
  }

  function setSeverity(sev) { findingFilter.severity = sev; findings(); }
  function setFindingStatus(v) { findingFilter.status = v; findings(); }

  function pickFindings(state) {
    document.querySelectorAll('.findPick').forEach(c => { c.checked = state; });
    updateBulkBar();
  }

  function selectedFindings() {
    return [...document.querySelectorAll('.findPick:checked')].map(c => Number(c.value));
  }

  function updateBulkBar() {
    const n = selectedFindings().length;
    const bar = document.getElementById('bulkBar');
    const label = document.getElementById('bulkCount');
    if (bar) bar.style.display = n ? 'flex' : 'none';
    if (label) label.textContent = `${n} selected`;
  }

  async function bulkTriage(status) {
    const ids = selectedFindings();
    if (!ids.length) return;
    try {
      const res = await API.bulkStatus({ finding_ids: ids, status });
      UI.toast(`${res.changed} findings marked ${status.replace('_', ' ')}`, '', 'ok');
      findings();
    } catch (e) { UI.toast('Could not apply that', e.message, 'err'); }
  }
  function setSearch(q) { findingFilter.search = q; findings(); }

  async function openFinding(id) {
    let f = cachedFindings.find(x => x.id === id);
    if (!f) return;
    // Pull the server copy so we get the analyst guidance and the list of
    // other hosts showing the same rule.
    try { f = await API.finding(id); } catch (_) { /* fall back to the cached row */ }

    const g = f.guidance || {};
    const guidance = (g.looks_for || g.next_step) ? `
      <div class="guide">
        ${g.looks_for ? `<div class="gitem"><b>What this rule checked</b>
          <p>${UI.esc(g.looks_for)}</p></div>` : ''}
        ${g.benign ? `<div class="gitem"><b>How it fires legitimately</b>
          <p>${UI.esc(g.benign)}</p></div>` : ''}
        ${g.next_step ? `<div class="gitem next"><b>Next step</b>
          <p>${UI.esc(g.next_step)}</p></div>` : ''}
      </div>`
      : (g.family ? `<div class="hint" style="margin-bottom:16px">${UI.esc(g.family)}</div>` : '');

    const tech = (f.technique && f.technique.id) ? `
      <div class="field"><label>Technique</label>
        <div class="guide" style="margin-bottom:0">
          <div class="gitem" style="border-bottom:0">
            <b style="color:var(--cyan)">${UI.esc(f.technique.id)} — ${UI.esc(f.technique.name)}</b>
            <p>${UI.esc(f.technique.description || 'No description available.')}</p>
            ${f.technique.tactics && f.technique.tactics.length ? `
              <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
                ${f.technique.tactics.map(t => `<span class="tag">${UI.esc(t)}</span>`).join('')}
              </div>` : ''}
          </div>
        </div>
      </div>` : '';

    const spread = (f.also_seen_on && f.also_seen_on.length) ? `
      <div class="field"><label>Same rule on other hosts</label>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          ${f.also_seen_on.map(h => `<span class="tag">${UI.esc(h)}</span>`).join('')}
        </div>
        <div class="hint">${f.also_seen_on.length >= 5
          ? 'Seen widely — more likely to be how this estate is built than an intrusion.'
          : 'Seen on few hosts. Rare is where you spend your time.'}</div>
      </div>` : `
      <div class="field"><label>Same rule on other hosts</label>
        <div class="muted">Only this host.</div>
        <div class="hint">Unique to one machine. Worth an hour of your time.</div>
      </div>`;

    UI.modal(f.title, `
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:18px;flex-wrap:wrap">
        <span class="${UI.sevClass(f.severity)}">${UI.esc(f.severity)}</span>
        <span class="tag mono">${UI.esc(f.rule_id)}</span>
        ${f.mitre ? `<span class="tag mono">${UI.esc(f.mitre)}${
          f.mitre_name ? ' · ' + UI.esc(f.mitre_name) : ''}</span>` : ''}
        <span class="tag">${UI.esc(f.hostname)}</span>
      </div>
      ${f.why ? `<div class="field"><label>Why this matters</label>
        <div style="color:#C6D8F2">${UI.esc(f.why)}</div></div>` : ''}
      ${guidance}
      ${tech}
      <div class="field"><label>Evidence</label>
        <div class="code">${UI.esc(f.evidence)}</div></div>
      ${spread}
      <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
        <div class="field" style="margin:0"><label>Source artifact</label>
          <div class="mono">${UI.esc(f.artifact || '—')}</div></div>
        <div class="field" style="margin:0"><label>Event time (UTC)</label>
          <div class="mono">${UI.esc(f.occurred_at || '—')}</div></div>
      </div>
      <div class="field" style="margin-top:16px"><label>Analyst note</label>
        <textarea id="findNote" placeholder="What did you conclude?">${UI.esc(f.note || '')}</textarea></div>

      <div class="field"><label>Decision</label>
        <select id="findStatus">
          <option value="open" ${f.status === 'open' ? 'selected' : ''}>Open — not looked at yet</option>
          <option value="investigating" ${f.status === 'investigating' ? 'selected' : ''}>Investigating</option>
          <option value="true_positive" ${f.status === 'true_positive' ? 'selected' : ''}>Confirmed — this is real</option>
          <option value="false_positive" ${f.status === 'false_positive' ? 'selected' : ''}>False positive — this one only</option>
        </select>
        <div class="hint">Confirmed findings keep counting toward the score.
        False positives drop out of it.</div></div>`,
      `<button class="btn btn-ghost btn-danger" style="margin-right:auto"
         onclick="Views.suppressFrom(${f.id})">Stop showing this…</button>
       <button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" onclick="Views.saveFinding(${f.id})">Save</button>`);
  }

  async function saveFinding(id) {
    const note = document.getElementById('findNote').value;
    const status = document.getElementById('findStatus').value;
    try {
      await API.setFindingStatus(id, { status, note });
      UI.close();
      UI.toast('Saved', `Marked ${status.replace('_', ' ')}`, 'ok');
      findings();
    } catch (e) { UI.toast('Could not save', e.message, 'err'); }
  }

  /* ---- Suppression ---------------------------------------------------- */

  async function suppressFrom(findingId) {
    const f = cachedFindings.find(x => x.id === findingId);
    if (!f) return;
    UI.close();

    UI.modal('Stop showing this finding', `
      <p class="muted" style="margin-top:0">
        A suppression is a standing decision. It hides this finding now and on
        every future scan, until someone withdraws it.
      </p>
      <div class="field"><label>Rule</label>
        <div class="code">${UI.esc(f.rule_id)} — ${UI.esc(f.title)}</div></div>

      <div class="field"><label>How wide should this go?</label>
        <select id="supScope" onchange="Views.previewSuppression(${findingId})">
          <option value="evidence">Only findings matching this evidence</option>
          <option value="host">This rule on ${UI.esc(f.hostname)} only</option>
          <option value="both">This evidence, on this host only</option>
          <option value="all">This rule everywhere in the fleet</option>
        </select></div>

      <div class="field"><label>Evidence to match</label>
        <input type="text" id="supEvidence" value="${UI.esc((f.evidence || '').slice(0, 80))}"
               oninput="Views.previewSuppression(${findingId})">
        <div class="hint">A substring. Keep it specific enough that it will not
        match a real detection later.</div></div>

      <div id="supPreview" style="margin-bottom:16px"></div>

      <div class="field"><label>Why</label>
        <textarea id="supReason" placeholder="e.g. Legacy vendor application, the unquoted path is by design and cannot be changed."></textarea>
        <div class="hint">Required. In six months this is the only record of why
        the finding stopped being shown.</div></div>
      <div id="supErr" class="hidden" style="color:var(--crit);font-size:13px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="supGo">Create suppression</button>`);

    previewSuppression(findingId);
    document.getElementById('supGo').onclick = async () => {
      const f2 = cachedFindings.find(x => x.id === findingId);
      const scope = document.getElementById('supScope').value;
      const err = document.getElementById('supErr');
      err.classList.add('hidden');
      try {
        const res = await API.createSuppression({
          rule_id: f2.rule_id,
          evidence_contains: ['evidence', 'both'].includes(scope)
            ? document.getElementById('supEvidence').value.trim() : '',
          hostname: ['host', 'both'].includes(scope) ? f2.hostname : '',
          reason: document.getElementById('supReason').value.trim(),
        });
        UI.close();
        UI.toast('Suppression created',
                 `${res.hidden} finding${res.hidden === 1 ? '' : 's'} hidden`, 'ok');
        findings();
      } catch (e) {
        err.textContent = e.message;
        err.classList.remove('hidden');
      }
    };
  }

  let previewTimer = null;
  function previewSuppression(findingId) {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(async () => {
      const f = cachedFindings.find(x => x.id === findingId);
      const box = document.getElementById('supPreview');
      if (!f || !box) return;
      const scope = document.getElementById('supScope').value;
      try {
        const p = await API.previewSuppression({
          rule_id: f.rule_id,
          evidence_contains: ['evidence', 'both'].includes(scope)
            ? document.getElementById('supEvidence').value.trim() : '',
          hostname: ['host', 'both'].includes(scope) ? f.hostname : '',
        });
        box.innerHTML = `
          <div class="notice ${p.warning ? 'warn-notice' : ''}"
               style="${p.warning ? '' : 'background:var(--deep);border:1px solid var(--edge);border-left:3px solid var(--cyan)'}">
            <b>This would hide ${p.total} finding${p.total === 1 ? '' : 's'}
               across ${p.host_count} host${p.host_count === 1 ? '' : 's'}</b>
            ${p.warning ? `<p>${UI.esc(p.warning)}</p>` : ''}
            ${p.samples.length ? `<div class="mono" style="font-size:11px;color:var(--slate);margin-top:6px">
              ${p.samples.map(x => `${UI.esc(x.hostname)}: ${UI.esc(x.evidence.slice(0, 90))}`).join('<br>')}
            </div>` : ''}
          </div>`;
      } catch (_) { box.innerHTML = ''; }
    }, 350);
  }

  /* ==================================================================== */
  /* Triage                                                              */
  /* ==================================================================== */

  async function triage() {
    loading();
    const [q, sup] = await Promise.all([API.triageQueue(), API.suppressions()]);

    const totals = q.by_status || {};
    const openCount = totals.open || 0;

    if (!Object.keys(totals).length) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'Nothing to triage yet', 'Complete a hunt and its findings land here.')}</div></div>`;
      return;
    }

    const sev = q.open_by_severity || {};
    const noisy = q.noisiest_rules.map(r => `
      <tr>
        <td class="mono" style="font-weight:700">${r.count}</td>
        <td class="mono muted">${r.hosts} host${r.hosts === 1 ? '' : 's'}</td>
        <td><span class="${UI.sevClass(r.severity)}">${UI.esc(r.severity)}</span></td>
        <td class="mono muted">${UI.esc(r.rule_id)}</td>
        <td>${UI.esc(r.title)}</td>
        <td><button class="btn btn-sm btn-ghost"
              onclick="Views.reviewRule('${UI.esc(r.rule_id)}')">Review these</button></td>
      </tr>`).join('') || `<tr><td colspan="6" class="muted">Nothing open.</td></tr>`;

    const supRows = sup.suppressions.map(x => `
      <tr class="${x.active ? '' : 'closed'}">
        <td><label class="chk" style="padding:2px 6px;border:0;background:none">
          <input type="checkbox" ${x.active ? 'checked' : ''}
                 onchange="Views.toggleSuppression('${UI.esc(x.id)}', this.checked)"></label></td>
        <td class="mono muted">${UI.esc(x.rule_id)}</td>
        <td><span class="tag">${UI.esc(x.scope)}</span>
            ${x.hostname ? `<div class="tname">${UI.esc(x.hostname)}</div>` : ''}</td>
        <td class="ev">${UI.esc(x.evidence_contains || '—')}</td>
        <td>${UI.esc(x.reason)}</td>
        <td class="mono" style="font-weight:700;${x.match_count > 200 ? 'color:var(--high)' : ''}">${x.match_count}</td>
        <td class="mono muted" style="font-size:11px">${UI.esc(x.created_by || '')}<br>${UI.ago(x.created_at)}</td>
        <td><button class="btn btn-sm btn-ghost btn-danger"
              onclick="Views.deleteSuppression('${UI.esc(x.id)}')">Remove</button></td>
      </tr>`).join('') || `<tr><td colspan="8" class="muted">No suppressions yet.</td></tr>`;

    const assignees = q.by_assignee.length
      ? q.by_assignee.map(a =>
          `<span class="tag">${UI.esc(a.assignee)} · ${a.count}</span>`).join(' ')
      : '<span class="muted">Nothing assigned.</span>';

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(openCount, 'Open', { accent: '#1B7FE8', glow: openCount > 100,
          sub: `${q.unassigned} unassigned` })}
        ${UI.stat(totals.investigating || 0, 'Investigating', { accent: '#FFC531' })}
        ${UI.stat(totals.true_positive || 0, 'Confirmed', { accent: '#FF2D55' })}
        ${UI.stat((totals.false_positive || 0) + (totals.suppressed || 0), 'Ruled out',
          { accent: '#7A93B8', sub: `${totals.suppressed || 0} by suppression` })}
      </div>

      <div class="grid g-2" style="margin-bottom:20px">
        <div class="card">
          <div class="card-h">
            <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
            <h2>Open work by severity</h2>
          </div>
          ${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(k =>
            UI.bar(k, sev[k] || 0, Math.max(1, ...Object.values(sev)),
                   { CRITICAL: '#FF2D55', HIGH: '#FF7A00', MEDIUM: '#FFC531',
                     LOW: '#3DA5FF', INFO: '#5D7A9E' }[k])).join('')}
          <div style="margin-top:14px">
            <div class="muted" style="font-size:11px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:7px">Assigned to</div>
            ${assignees}
          </div>
        </div>

        <div class="card">
          <div class="card-h"><h2>How this works</h2></div>
          <p class="muted" style="margin-top:0;font-size:13.5px">
            Marking a finding <b style="color:#FF6B87">confirmed</b> keeps it in the
            risk score — it is real and the host stays red. Marking it
            <b>false positive</b> drops it from the score for that host only.
          </p>
          <p class="muted" style="font-size:13.5px">
            A <b style="color:#22D9F5">suppression</b> is different: a standing rule
            that hides the same finding on every future scan too. That is how the
            list stays short enough that somebody still reads it on the third pass.
          </p>
          <p class="muted" style="font-size:13.5px;margin-bottom:0">
            Withdraw a suppression and everything it hid comes back. Nothing is
            deleted, only set aside.
          </p>
        </div>
      </div>

      <div class="card-h">
        <h2>Noisiest rules</h2><div class="spacer"></div>
        <span class="muted mono">tuning these clears the queue fastest</span>
      </div>
      ${UI.table(['Open', 'Spread', 'Severity', 'Rule', 'Detection', ''],
                 noisy, { id: 'tblNoisy', maxHeight: '360px' })}

      <div class="card-h" style="margin-top:28px">
        <h2>Suppressions</h2><div class="spacer"></div>
        <span class="muted mono">${sup.active} active · ${sup.hidden_findings} findings hidden</span>
      </div>
      ${UI.table(['On', 'Rule', 'Scope', 'Evidence', 'Reason', 'Hidden', 'Added', ''],
                 supRows, { id: 'tblSup', maxHeight: '420px' })}
    </div>`;
  }

  function reviewRule(ruleId) {
    findingFilter = { severity: '', search: ruleId, status: 'open' };
    App.go('findings');
  }

  async function toggleSuppression(id, active) {
    try {
      const res = await API.toggleSuppression(id, active);
      UI.toast(active ? 'Suppression active again' : 'Suppression switched off',
               `${res.affected} finding${res.affected === 1 ? '' : 's'} affected`, 'ok');
      triage();
    } catch (e) { UI.toast('Could not change that', e.message, 'err'); triage(); }
  }

  async function deleteSuppression(id) {
    if (!confirm('Remove this suppression? Everything it was hiding comes back.')) return;
    try {
      const res = await API.deleteSuppression(id);
      UI.toast('Suppression removed',
               `${res.reopened} finding${res.reopened === 1 ? '' : 's'} reopened`, 'ok');
      triage();
    } catch (e) { UI.toast('Could not remove it', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* Frequency (stack counting)                                           */
  /* ==================================================================== */

  async function stack() {
    loading();
    const data = await API.stack();

    if (!data.host_count) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'Frequency analysis needs completed hunts',
        'Run hunts on several hosts, then come back.')}</div></div>`;
      return;
    }

    const unique = data.items.filter(i => i.rarity === 'unique').length;
    const rows = data.items.map(i => `
      <tr>
        <td class="rarity-${UI.esc(i.rarity)}">${i.host_count}</td>
        <td class="muted mono">${i.percent}%</td>
        <td><span class="${UI.sevClass(i.severity)}">${UI.esc(i.severity)}</span></td>
        <td class="mono muted">${UI.esc(i.rule_id)}
            ${i.mitre ? `<div class="tname">${UI.esc(i.mitre)}${
              i.mitre_name ? ' · ' + UI.esc(i.mitre_name) : ''}</div>` : ''}</td>
        <td>${UI.esc(i.title)}</td>
        <td class="ev">${UI.esc(i.evidence)}</td>
        <td class="muted mono" style="font-size:11px">${UI.esc(i.hosts.join(', '))}</td>
      </tr>`).join('');

    el().innerHTML = `<div class="view">
      <div class="card" style="margin-bottom:20px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Rare is suspicious</h2>
        </div>
        <p class="muted" style="margin:0;max-width:78ch">
          Something present on every host is how your environment is built. Something
          present on one host is worth an hour of your time. Sorted rarest first across
          <b style="color:#E8F1FF">${data.host_count}</b> scanned hosts —
          <b style="color:#FF2D55">${unique}</b> items appear exactly once.
        </p>
      </div>
      <div class="filters">
        <input type="search" placeholder="Filter items" oninput="UI.filterRows(this,'tblStack')">
      </div>
      ${UI.table(['Hosts', 'Share', 'Severity', 'Rule', 'Detection', 'Evidence', 'Seen on'],
                 rows, { id: 'tblStack' })}
    </div>`;
  }

  /* ==================================================================== */
  /* Network graph                                                        */
  /* ==================================================================== */

  // Hand-rolled force layout rather than a library: this console has to run on
  // an isolated network, so no CDN, and the graph is hub-and-spoke enough that
  // a full physics engine would be more code than the thing it draws.
  function layoutGraph(hosts, endpoints, W, H) {
    const cx = W / 2, cy = H / 2;
    const nodes = [];

    // Hosts sit in a small ring at the centre and stay put — they are the
    // anchor the reader orients from.
    hosts.forEach((h, i) => {
      const a = (i / Math.max(1, hosts.length)) * Math.PI * 2 - Math.PI / 2;
      const r = hosts.length === 1 ? 0 : 78;
      nodes.push({
        id: `h:${h.hostname}`, kind: 'host', data: h, fixed: true,
        x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r,
        radius: 26,
      });
    });

    // Endpoints start on a ring sized by how many there are, ordered so the
    // suspicious ones land at the top where the eye goes first.
    const ring = Math.min(H, W) * 0.40;
    endpoints.forEach((e, i) => {
      const a = (i / Math.max(1, endpoints.length)) * Math.PI * 2 - Math.PI / 2;
      const jitter = (i % 3) * 26;
      nodes.push({
        id: `e:${e.address}`, kind: 'ep', data: e, fixed: false,
        x: cx + Math.cos(a) * (ring + jitter),
        y: cy + Math.sin(a) * (ring + jitter),
        radius: Math.min(19, 7 + Math.sqrt(e.connections || 1) * 2.2),
      });
    });

    const byId = Object.fromEntries(nodes.map(n => [n.id, n]));
    const edges = [];
    endpoints.forEach(e => {
      (e.hosts || []).forEach(h => {
        if (byId[`h:${h}`] && byId[`e:${e.address}`]) {
          edges.push({ a: byId[`h:${h}`], b: byId[`e:${e.address}`], ep: e });
        }
      });
    });

    // Relaxation: springs pull each endpoint toward its host, repulsion keeps
    // labels from stacking. Deterministic, so the picture is the same twice.
    for (let step = 0; step < 220; step++) {
      const cool = 1 - step / 220;
      edges.forEach(({ a, b }) => {
        const dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.hypot(dx, dy) || 1;
        const target = 210;
        const f = (d - target) * 0.012 * cool;
        if (!b.fixed) { b.x -= (dx / d) * f; b.y -= (dy / d) * f; }
      });
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const n1 = nodes[i], n2 = nodes[j];
          const dx = n2.x - n1.x, dy = n2.y - n1.y;
          const d = Math.hypot(dx, dy) || 1;
          const min = n1.radius + n2.radius + 46;
          if (d < min) {
            const push = ((min - d) / d) * 0.5 * cool;
            if (!n1.fixed) { n1.x -= dx * push; n1.y -= dy * push; }
            if (!n2.fixed) { n2.x += dx * push; n2.y += dy * push; }
          }
        }
      }
      nodes.forEach(n => {
        if (n.fixed) return;
        const pad = n.radius + 46;
        n.x = Math.max(pad, Math.min(W - pad, n.x));
        n.y = Math.max(pad + 8, Math.min(H - pad, n.y));
      });
    }
    return { nodes, edges };
  }

  async function graph() {
    loading();
    const g = await API.graph();

    if (!g.has_data) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'No network or process data yet',
        'Run a hunt with an agent built from the current package and this fills in.')}
        <p class="muted" style="text-align:center;font-size:12.5px">
          Hosts collected with an older agent do not send this; they will after their next hunt.
        </p></div></div>`;
      return;
    }

    const W = 1180, H = 620;
    const { nodes, edges } = layoutGraph(g.hosts, g.endpoints, W, H);

    const edgeSvg = edges.map(({ a, b, ep }) => {
      const cls = ep.ioc_match ? 'ioc'
        : (ep.label === 'malicious' || ep.suspicious ? 'sus'
        : (ep.label === 'suspicious' || ep.unsigned ? 'uns' : ''));
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - 24;
      return `<path class="gedge ${cls}" d="M${a.x} ${a.y} Q${mx} ${my} ${b.x} ${b.y}"
               stroke-width="${Math.min(3.5, 0.8 + Math.sqrt(ep.connections || 1) * 0.4)}"/>`;
    }).join('');

    const nodeSvg = nodes.map(n => {
      if (n.kind === 'host') {
        const h = n.data;
        return `<g class="gnode" data-id="${UI.esc(n.id)}"
                  onclick="Views.graphFocus('${UI.esc(n.id)}')">
          <circle class="gn-host" cx="${n.x}" cy="${n.y}" r="${n.radius}"/>
          <text class="glabel host" x="${n.x}" y="${n.y + n.radius + 17}">${UI.esc(h.hostname)}</text>
          <text class="glabel sub" x="${n.x}" y="${n.y + n.radius + 30}">${UI.esc(h.risk_level)} · ${h.risk_score}</text>
        </g>`;
      }
      const e = n.data;
      // Colour now means "how bad", not "which directory the process was in".
      // An indicator-list match is the strongest statement available and wins
      // outright; then reputation; then the old signature-based hints.
      const cls = e.ioc_match ? 'ioc'
        : (e.label === 'malicious' ? 'sus'
        : (e.label === 'suspicious' ? 'uns'
        : (e.known_good ? 'good'
        : (e.suspicious ? 'sus' : (e.unsigned ? 'uns' : '')))));
      const label = e.rdns ? e.rdns.slice(0, 26) : e.address;
      const mark = e.ioc_match ? 'IOC'
        : (e.score >= 25 ? String(e.score) : '');
      return `<g class="gnode" data-id="${UI.esc(n.id)}"
                onmouseenter="Views.graphTip(event,'${UI.esc(e.address)}')"
                onmouseleave="Views.graphTip(null)"
                onclick="Views.graphFocus('${UI.esc(n.id)}')">
        <circle class="gn-ep ${cls}" cx="${n.x}" cy="${n.y}" r="${n.radius}"/>
        ${mark ? `<text class="gscore ${cls}" x="${n.x}" y="${n.y + 3.5}">${UI.esc(mark)}</text>` : ''}
        <text class="glabel" x="${n.x}" y="${n.y + n.radius + 14}">${UI.esc(label)}</text>
      </g>`;
    }).join('');

    graphEndpoints = Object.fromEntries(g.endpoints.map(e => [e.address, e]));

    const bar = (p, val, max, colour, unit) => `
      <div class="pbar-row ${p.suspicious ? 'sus' : ''}">
        <div class="nm" title="${UI.esc(p.path || p.name)}">${UI.esc(p.name)}
          <small>${UI.esc(p.hostname)} · pid ${UI.esc(String(p.pid))}</small></div>
        <div class="tr"><i style="width:${Math.max(2, (val / max) * 100)}%;background:${colour}"></i></div>
        <div class="vv">${val >= 1000 ? Math.round(val) : val.toFixed(1)}${unit}</div>
      </div>`;

    const num = v => { const n = parseFloat(v); return isNaN(n) ? 0 : n; };
    const maxMem = Math.max(1, ...g.top_memory.map(p => num(p.memoryMB)));
    const maxCpu = Math.max(1, ...g.top_cpu.map(p => num(p.cpu)));

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(g.hosts.length, 'Hosts', { accent: '#1B7FE8' })}
        ${UI.stat(g.endpoint_total, 'External endpoints', { accent: '#22D9F5' })}
        ${UI.stat(g.ioc_matches || 0, 'On an indicator list',
          { accent: '#FF2D55', glow: (g.ioc_matches || 0) > 0, sub: 'confirmed match' })}
        ${UI.stat(g.flagged || 0, 'Bad reputation',
          { accent: '#FF7A00', sub: (g.unrated ? `${g.unrated} not looked up` : 'all scored') })}
      </div>

      <div class="card-h">
        <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
        <h2>Where this estate is talking to</h2>
        <div class="spacer"></div>
        ${(g.unrated || 0) > 0
          ? `<button class="btn btn-sm" onclick="Views.runIntel()">Score ${g.unrated} unrated</button>`
          : ''}
        <span class="muted mono" style="font-size:11.5px">hover an endpoint · click to isolate</span>
      </div>
      <div class="graph-wrap" style="margin-bottom:22px">
        <svg viewBox="0 0 ${W} ${H}" id="netGraph">
          <g id="gEdges">${edgeSvg}</g>
          <g id="gNodes">${nodeSvg}</g>
        </svg>
        <div class="gtip" id="gTip"></div>
        <div class="glegend">
          <span><i style="background:var(--electric);border-color:#7FC4FF"></i>Host</span>
          <span><i style="background:rgba(255,45,85,.45);border-color:#FF2D55"></i>On an indicator list — confirmed</span>
          <span><i style="background:rgba(255,45,85,.22);border-color:var(--crit)"></i>Bad reputation or suspicious process</span>
          <span><i style="background:rgba(255,122,0,.22);border-color:var(--high)"></i>Some concern</span>
          <span><i style="background:rgba(43,217,160,.18);border-color:#2BD9A0"></i>Known-good service</span>
          <span><i style="background:var(--raised);border-color:var(--slate)"></i>Ordinary or not looked up</span>
          <span class="dim">Sorted worst first. Numbers on a node are the reputation score.</span>
        </div>
      </div>

      <div class="grid g-2">
        <div class="card">
          <div class="card-h"><h2>Memory</h2><div class="spacer"></div>
            <span class="muted mono">working set</span></div>
          ${g.top_memory.map(p => bar(p, num(p.memoryMB), maxMem, '#1B7FE8', ' MB')).join('')
            || '<div class="muted">No process data.</div>'}
        </div>
        <div class="card">
          <div class="card-h"><h2>CPU</h2><div class="spacer"></div>
            <span class="muted mono">seconds consumed</span></div>
          ${g.top_cpu.map(p => bar(p, num(p.cpu), maxCpu, '#22D9F5', 's')).join('')
            || '<div class="muted">No process data.</div>'}
          <p class="muted" style="font-size:12px;margin:14px 0 0">
            CPU is cumulative since the process started, so long-lived services
            naturally sit high. What matters is a short-lived process near the top.
          </p>
        </div>
      </div>
    </div>`;
  }

  let graphEndpoints = {};
  let graphFocused = null;

  function graphTip(evt, address) {
    const tip = document.getElementById('gTip');
    if (!tip) return;
    if (!evt) { tip.classList.remove('on'); return; }
    const e = graphEndpoints[address];
    if (!e) return;

    tip.innerHTML = `
      <div class="t">${UI.esc(e.address)}</div>
      ${e.rdns ? `<div class="r">${UI.esc(e.rdns)}</div>` : ''}
      ${e.ioc_match ? `<div class="tip-verdict ioc">
        <b>On an indicator list</b>
        <span>A feed you loaded names this address. This is a confirmed match, not a score.</span>
      </div>` : ''}
      ${Object.keys(e.verdicts || {}).length ? `<div class="tip-verdict">
        <b style="color:${(LABEL_STYLE[e.label] || LABEL_STYLE.unknown).c}">
          ${e.score ? `${e.score}/100 · ` : ''}${UI.esc((LABEL_STYLE[e.label] || LABEL_STYLE.unknown).t)}</b>
        ${Object.entries(e.verdicts).map(([name, v]) => `
          <span><b class="mono">${UI.esc(name)}</b> ${UI.esc(v.summary || '')}</span>`).join('')}
      </div>` : (e.rated ? '' : `<div class="tip-verdict dim">
        <b>Not looked up</b><span>No reputation provider has been asked about this address yet.</span>
      </div>`)}
      <dl>
        <dt>Connections</dt><dd>${e.connections}</dd>
        <dt>Ports</dt><dd>${UI.esc(e.ports.join(', ')) || '—'}</dd>
        <dt>Processes</dt><dd>${UI.esc(e.processes.join(', ')) || '—'}</dd>
        <dt>Hosts</dt><dd>${UI.esc(e.hosts.join(', '))}</dd>
        ${e.suspicious ? '<dt style="color:var(--crit)">Warning</dt><dd style="color:#FF6B87">Reached by a process in a temporary directory</dd>' : ''}
        ${!e.suspicious && e.unsigned ? '<dt style="color:var(--high)">Note</dt><dd>Reached by an unsigned process</dd>' : ''}
      </dl>`;

    const wrap = document.querySelector('.graph-wrap');
    const r = wrap.getBoundingClientRect();
    let x = evt.clientX - r.left + 16;
    let y = evt.clientY - r.top + 14;
    if (x > r.width - 360) x = evt.clientX - r.left - 350;
    if (y > r.height - 190) y = evt.clientY - r.top - 175;
    tip.style.left = `${Math.max(6, x)}px`;
    tip.style.top = `${Math.max(6, y)}px`;
    tip.classList.add('on');
  }

  // Clicking isolates a node and the things it touches. On a busy estate the
  // full picture is the wrong tool for answering "what talks to this".
  function graphFocus(id) {
    const svg = document.getElementById('netGraph');
    if (!svg) return;
    graphFocused = (graphFocused === id) ? null : id;

    if (!graphFocused) {
      svg.querySelectorAll('.gnode').forEach(n => n.classList.remove('dim'));
      svg.querySelectorAll('.gedge').forEach(e => { e.style.opacity = ''; });
      return;
    }

    const address = id.startsWith('e:') ? id.slice(2) : null;
    const hostname = id.startsWith('h:') ? id.slice(2) : null;
    const keep = new Set([id]);

    Object.values(graphEndpoints).forEach(e => {
      if (hostname && (e.hosts || []).includes(hostname)) keep.add(`e:${e.address}`);
      if (address && e.address === address) {
        (e.hosts || []).forEach(h => keep.add(`h:${h}`));
      }
    });

    svg.querySelectorAll('.gnode').forEach(n => {
      n.classList.toggle('dim', !keep.has(n.dataset.id));
    });
    svg.querySelectorAll('.gedge').forEach(e => { e.style.opacity = '.1'; });
  }

  /* ==================================================================== */
  /* ATT&CK matrix                                                        */
  /* ==================================================================== */

  async function matrix() {
    loading();
    const m = await API.matrix();

    if (!m.technique_count) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'No techniques observed yet',
        'Complete a hunt and any techniques it maps to will appear here.')}</div></div>`;
      return;
    }

    const cell = (t) => `
      <div class="mcell s-${UI.esc(t.severity)}"
           onclick="Views.techniqueDetail('${UI.esc(t.id)}')"
           title="${UI.esc(t.id)} — ${UI.esc(t.name)}${
             t.description ? '\n\n' + UI.esc(t.description) : ''}">
        <div class="id">${UI.esc(t.id)}</div>
        <div class="nm">${UI.esc(t.name)}</div>
        <div class="mt">${t.count} finding${t.count === 1 ? '' : 's'}${
          t.hosts > 1 ? ` · ${t.hosts} hosts` : ''}</div>
      </div>`;

    const cols = m.columns.map(c => `
      <div class="mcol ${c.techniques.length ? '' : 'empty-col'}">
        <div class="mcol-h">
          <div class="t">${UI.esc(c.tactic)}</div>
          <div class="n">${c.techniques.length} technique${c.techniques.length === 1 ? '' : 's'}</div>
        </div>
        <div class="mcol-b">
          ${c.techniques.length ? c.techniques.map(cell).join('')
                                : '<div class="mcol-empty">nothing observed</div>'}
        </div>
      </div>`).join('');

    const unmapped = m.unmapped.length ? `
      <div class="card" style="margin-top:18px">
        <div class="card-h"><h2>Unmapped techniques</h2></div>
        <p class="muted" style="margin-top:0">
          Detected but not placed in a tactic column. Shown here rather than
          dropped, so nothing observed goes unreported.</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          ${m.unmapped.map(t =>
            `<span class="tag mono">${UI.esc(t.id)} · ${t.count}</span>`).join('')}
        </div>
      </div>` : '';

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(m.technique_count, 'Techniques observed', { accent: '#22D9F5' })}
        ${UI.stat(`${m.tactics_hit}/${m.tactic_count}`, 'Tactics touched', { accent: '#1B7FE8' })}
        ${UI.stat(m.finding_count, 'Mapped findings', { accent: '#7A93B8' })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Where the attacker got to</h2>
        </div>
        <p class="muted" style="margin:0;max-width:82ch">
          Columns follow the ATT&amp;CK kill chain, left to right. A technique that
          serves several tactics appears in each of its columns, the same way the
          real matrix works. One lit column is usually noise; a path running left
          to right is an intrusion.
        </p>
      </div>

      <div class="matrix">${cols}</div>

      <div class="mlegend">
        <span><i style="background:var(--crit)"></i>Critical</span>
        <span><i style="background:var(--high)"></i>High</span>
        <span><i style="background:var(--med)"></i>Medium</span>
        <span><i style="background:var(--low)"></i>Low</span>
        <span><i style="background:var(--info)"></i>Info</span>
        <span class="dim">Cell colour is the most severe finding for that technique. Click a cell for its findings.</span>
      </div>

      ${unmapped}
    </div>`;
  }

  async function techniqueDetail(techniqueId) {
    const data = await API.findings({ limit: 400 });
    const rows = data.findings.filter(f => f.mitre === techniqueId);
    if (!rows.length) {
      UI.toast('No findings', `Nothing recorded for ${techniqueId}.`, 'err');
      return;
    }
    const body = rows.map(f => `
      <div style="border-left:3px solid var(--edge);padding:10px 14px;margin-bottom:10px;
                  background:var(--deep);border-radius:0 6px 6px 0">
        <div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:6px">
          <span class="${UI.sevClass(f.severity)}">${UI.esc(f.severity)}</span>
          <span class="tag mono">${UI.esc(f.rule_id)}</span>
          <span class="tag">${UI.esc(f.hostname)}</span>
        </div>
        <div style="font-weight:600;margin-bottom:4px">${UI.esc(f.title)}</div>
        <div class="ev">${UI.esc(f.evidence)}</div>
      </div>`).join('');

    const label = rows[0].mitre_name && rows[0].mitre_name !== techniqueId
      ? `${techniqueId} — ${rows[0].mitre_name}` : techniqueId;
    let detail = null;
    try { detail = (await API.finding(rows[0].id)).technique; } catch (_) {}

    UI.drawer(label, `
      ${detail && detail.description ? `
        <div class="guide" style="margin-bottom:14px"><div class="gitem" style="border-bottom:0">
          <b style="color:var(--cyan)">What this technique is</b>
          <p>${UI.esc(detail.description)}</p>
          ${detail.tactics && detail.tactics.length ? `
            <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
              ${detail.tactics.map(t => `<span class="tag">${UI.esc(t)}</span>`).join('')}
            </div>` : ''}
        </div></div>` : ''}
      <p class="muted" style="margin-top:0">
        ${rows.length} finding${rows.length === 1 ? '' : 's'} across
        ${new Set(rows.map(r => r.hostname)).size} host(s).
      </p>
      ${body}`);
  }

  /* ==================================================================== */
  /* Timeline                                                             */
  /* ==================================================================== */

  async function timeline() {
    loading();
    const { events } = await API.timeline({ limit: 3000 });

    if (!events.length) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'No timeline events yet', 'Complete a hunt to build the timeline.')}</div></div>`;
      return;
    }

    // Hourly density — the spike is where to start reading.
    const buckets = {};
    events.forEach(e => {
      const k = (e.time_utc || '').slice(0, 13);
      if (k) buckets[k] = (buckets[k] || 0) + 1;
    });
    const keys = Object.keys(buckets).sort();
    const peak = Math.max(1, ...Object.values(buckets));
    const w = Math.max(2, Math.min(16, Math.floor(1100 / Math.max(1, keys.length))));
    const bars = keys.map((k, i) => {
      const h = Math.max(2, Math.round(buckets[k] / peak * 118));
      return `<rect x="${i * w}" y="${128 - h}" width="${Math.max(1, w - 1)}" height="${h}"
        fill="url(#tlGrad)"><title>${UI.esc(k)}:00 — ${buckets[k]} events</title></rect>`;
    }).join('');
    const busiest = keys.reduce((a, b) => (buckets[a] > buckets[b] ? a : b), keys[0]);

    const rows = events.slice(0, 1500).map(e => `
      <tr>
        <td class="mono nowrap">${UI.esc((e.time_utc || '').replace('T', ' ').slice(0, 19))}</td>
        <td><span class="${UI.sevClass(e.severity)}">${UI.esc(e.severity)}</span></td>
        <td><b>${UI.esc(e.hostname)}</b></td>
        <td class="mono muted">${UI.esc(e.source)}</td>
        <td>${UI.esc(e.description)}</td>
        <td class="ev">${UI.esc((e.detail || '').slice(0, 160))}</td>
      </tr>`).join('');

    el().innerHTML = `<div class="view">
      <div class="card" style="margin-bottom:18px">
        <div class="card-h"><h2>Event density by hour (UTC)</h2><div class="spacer"></div>
          <span class="muted mono">peak ${UI.esc(busiest)}:00 · ${buckets[busiest]} events</span></div>
        <svg viewBox="0 0 1100 130" preserveAspectRatio="none"
             style="width:100%;height:130px;background:#071022;border:1px solid #16294A;border-radius:8px">
          <defs><linearGradient id="tlGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="#22D9F5"/><stop offset="100%" stop-color="#1B7FE8"/>
          </linearGradient></defs>${bars}
        </svg>
      </div>
      <div class="filters">
        <input type="search" placeholder="Filter events" oninput="UI.filterRows(this,'tblTl')">
        <span class="muted mono">${events.length} events</span>
      </div>
      ${UI.table(['Time (UTC)', 'Severity', 'Host', 'Source', 'Event', 'Detail'],
                 rows, { id: 'tblTl' })}
    </div>`;
  }

  /* ==================================================================== */
  /* Users                                                                */
  /* ==================================================================== */

  const ROLE_HELP = {
    admin: 'Manages accounts, removes hosts, issues enrollment tokens.',
    responder: 'Launches hunts, annotates findings, downloads raw evidence.',
    viewer: 'Reads dashboards, findings and reports. Changes nothing.',
  };

  async function users() {
    loading();
    const [{ users: list }, { events }] = await Promise.all([
      API.users(), API.activity(120),
    ]);

    const rows = list.map(u => {
      const state = !u.active ? 'off' : u.locked ? 'lock' : 'on';
      const stateLabel = !u.active ? 'Disabled' : u.locked ? 'Locked out' : 'Active';
      return `
      <tr>
        <td><b>${UI.esc(u.username)}</b>
            ${u.full_name ? `<div class="muted" style="font-size:11.5px">${UI.esc(u.full_name)}</div>` : ''}</td>
        <td class="muted mono" style="font-size:11.5px">${UI.esc(u.email)}</td>
        <td><span class="rolechip role-${UI.esc(u.role)}">${UI.esc(u.role)}</span></td>
        <td><span class="udot ${state}"></span><span class="muted" style="font-size:12px">${stateLabel}</span>
            ${u.must_change_password ? '<div class="muted" style="font-size:11px">must change password</div>' : ''}</td>
        <td class="muted mono" style="font-size:11.5px">${UI.ago(u.last_login)}</td>
        <td class="muted mono" style="font-size:11.5px">${UI.esc(u.created_by || '—')}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-sm btn-ghost" onclick="Views.editUser('${UI.esc(u.id)}')">Edit</button>
        </td>
      </tr>`;
    }).join('');

    const actRows = events.map(e => `
      <tr>
        <td class="mono muted" style="font-size:11.5px">${UI.esc((e.at || '').replace('T', ' ').slice(0, 16))}</td>
        <td><span class="tag">${UI.esc(e.kind)}</span></td>
        <td>${UI.esc(e.subject || '')}</td>
        <td class="muted" style="font-size:12px">${UI.esc(e.detail || '')}</td>
      </tr>`).join('') || `<tr><td colspan="4" class="muted">Nothing recorded yet.</td></tr>`;

    Views._users = list;

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(list.length, 'Accounts', { accent: '#22D9F5' })}
        ${UI.stat(list.filter(u => u.role === 'admin').length, 'Admins', { accent: '#FF2D55' })}
        ${UI.stat(list.filter(u => u.role === 'responder').length, 'Responders', { accent: '#1B7FE8' })}
        ${UI.stat(list.filter(u => !u.active || u.locked).length, 'Disabled or locked', { accent: '#FF7A00' })}
      </div>

      <div class="filters">
        <input type="search" placeholder="Filter by name, username or email"
               oninput="UI.filterRows(this,'tblUsers')">
        <button class="btn btn-primary btn-sm" onclick="Views.newUser()">Add person</button>
      </div>
      ${UI.table(['Account', 'Email', 'Role', 'Status', 'Last sign-in', 'Added by', ''],
                 rows, { id: 'tblUsers' })}

      <div class="card" style="margin-top:24px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>What roles mean</h2>
        </div>
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px">
          ${['admin', 'responder', 'viewer'].map(r => `
            <div>
              <span class="rolechip role-${r}">${r}</span>
              <p class="muted" style="margin:8px 0 0;font-size:13px">${ROLE_HELP[r]}</p>
            </div>`).join('')}
        </div>
        <p class="muted" style="font-size:12.5px;margin:16px 0 0;max-width:80ch">
          Launching a hunt reaches out and touches a live production host, which is
          why it sits behind its own tier rather than being bundled with read access.
          Raw evidence archives contain registry hives with credential material, so
          they are responder-only too.
        </p>
      </div>

      <div class="card-h" style="margin-top:28px"><h2>Activity</h2>
        <div class="spacer"></div>
        <span class="muted mono">last ${events.length} events</span></div>
      ${UI.table(['When (UTC)', 'Event', 'Subject', 'Detail'], actRows,
                 { id: 'tblAudit', maxHeight: '380px' })}
    </div>`;
  }

  function newUser() {
    UI.modal('Add user', `
      <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
        <div class="field"><label>Username</label>
          <input type="text" id="nuUser" placeholder="a.yilmaz" autocomplete="off">
          <div class="hint">Lowercase letters, digits, dot, dash or underscore.</div></div>
        <div class="field"><label>Full name</label>
          <input type="text" id="nuName" placeholder="Ahmet Yilmaz" autocomplete="off"></div>
      </div>
      <div class="field"><label>Email <span class="muted" style="font-weight:400">(optional)</span></label>
        <input type="text" id="nuMail" placeholder="a.yilmaz@douglas042.local" autocomplete="off">
        <div class="hint">Only used to identify the person in the activity log. Leave blank
        if your estate does not use email.</div></div>
      <div class="field"><label>Role</label>
        <select id="nuRole">
          <option value="viewer" selected>Viewer — reads dashboards and reports</option>
          <option value="responder">Responder — also launches hunts and handles evidence</option>
          <option value="admin">Admin — also manages accounts and hosts</option>
        </select></div>
      <div class="field"><label>Temporary password</label>
        <input type="text" id="nuPass" placeholder="At least ${App.minPassword()} characters" autocomplete="off">
        <div class="hint">Share it over a channel the person already trusts. They will be
        asked to replace it at first sign-in.</div></div>
      <label class="chk"><input type="checkbox" id="nuForce" checked>
        <div><span>Require a password change at first sign-in</span></div></label>
      <div id="nuErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="nuGo">Create account</button>`);

    document.getElementById('nuPass').value = suggestPassword();
    document.getElementById('nuGo').onclick = async () => {
      const err = document.getElementById('nuErr');
      err.classList.add('hidden');
      try {
        await API.createUser({
          username: document.getElementById('nuUser').value.trim(),
          full_name: document.getElementById('nuName').value.trim(),
          email: document.getElementById('nuMail').value.trim(),
          role: document.getElementById('nuRole').value,
          password: document.getElementById('nuPass').value,
          must_change_password: document.getElementById('nuForce').checked,
        });
        UI.close();
        UI.toast('Account created', 'Send them the temporary password.', 'ok');
        users();
      } catch (e) {
        err.textContent = e.message;
        err.classList.remove('hidden');
      }
    };
  }

  function suggestPassword() {
    // Four words beat a scrambled string nobody can retype over the phone.
    const words = ['harbor', 'cinder', 'lantern', 'quartz', 'meadow', 'falcon', 'timber',
                   'zenith', 'garnet', 'willow', 'cobalt', 'ember', 'marlin', 'thistle'];
    const pick = () => words[Math.floor(Math.random() * words.length)];
    return `${pick()}-${pick()}-${pick()}-${Math.floor(Math.random() * 90 + 10)}`;
  }

  function editUser(id) {
    const u = (Views._users || []).find(x => x.id === id);
    if (!u) return;

    UI.modal(u.username, `
      <div style="display:flex;gap:10px;align-items:center;margin-bottom:20px;flex-wrap:wrap">
        <span class="rolechip role-${UI.esc(u.role)}">${UI.esc(u.role)}</span>
        <span class="tag">${u.active ? (u.locked ? 'locked out' : 'active') : 'disabled'}</span>
        <span class="muted mono" style="font-size:11.5px">last sign-in ${UI.ago(u.last_login)}</span>
      </div>

      <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
        <div class="field"><label>Full name</label>
          <input type="text" id="euName" value="${UI.esc(u.full_name)}"></div>
        <div class="field"><label>Email</label>
          <input type="text" id="euMail" value="${UI.esc(u.email)}"></div>
      </div>

      <div class="field"><label>Role</label>
        <select id="euRole">
          <option value="viewer" ${u.role === 'viewer' ? 'selected' : ''}>Viewer</option>
          <option value="responder" ${u.role === 'responder' ? 'selected' : ''}>Responder</option>
          <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
        </select>
        <div class="hint">${ROLE_HELP[u.role]}</div></div>

      <label class="chk"><input type="checkbox" id="euActive" ${u.active ? 'checked' : ''}>
        <div><span>Account is enabled</span>
        <small>Disabling signs them out immediately and clears any lockout on re-enable.</small></div></label>

      <div class="field" style="margin-top:18px"><label>Set a new password</label>
        <input type="text" id="euPass" placeholder="Leave blank to keep the current one">
        <div class="hint">Use this when someone is locked out or has forgotten theirs.</div></div>

      <div id="euErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`,
      `<button class="btn btn-ghost btn-danger" onclick="Views.removeUser('${UI.esc(u.id)}','${UI.esc(u.username)}')"
         style="margin-right:auto">Delete</button>
       <button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="euGo">Save changes</button>`);

    document.getElementById('euGo').onclick = async () => {
      const err = document.getElementById('euErr');
      err.classList.add('hidden');
      try {
        await API.updateUser(u.id, {
          full_name: document.getElementById('euName').value.trim(),
          email: document.getElementById('euMail').value.trim(),
          role: document.getElementById('euRole').value,
          active: document.getElementById('euActive').checked,
        });
        const pw = document.getElementById('euPass').value;
        if (pw) await API.resetPassword(u.id, pw, true);
        UI.close();
        UI.toast('Changes saved', pw ? 'Password reset too.' : '', 'ok');
        users();
      } catch (e) {
        err.textContent = e.message;
        err.classList.remove('hidden');
      }
    };
  }

  async function removeUser(id, username) {
    if (!confirm(`Delete the account ${username}? This cannot be undone.`)) return;
    try {
      await API.deleteUser(id);
      UI.close();
      UI.toast('Account deleted', username, 'ok');
      users();
    } catch (e) {
      UI.toast('Could not delete', e.message, 'err');
    }
  }

  /* ==================================================================== */
  /* My rules (custom detections)                                         */
  /* ==================================================================== */

  let ruleSchema = null;
  let draftConditions = [];

  async function myrules() {
    loading();
    const [d, sch] = await Promise.all([API.customRules(), API.ruleSchema()]);
    ruleSchema = sch;

    const rows = d.rules.map(r => `
      <tr class="${r.enabled ? '' : 'closed'}">
        <td><input type="checkbox" class="rulePick" value="${UI.esc(r.id)}"
             style="width:15px;height:15px;accent-color:#22D9F5"></td>
        <td><label class="chk" style="padding:2px 6px;border:0;background:none">
          <input type="checkbox" ${r.enabled ? 'checked' : ''}
                 onchange="Views.toggleMyRule('${UI.esc(r.id)}', this.checked)"></label></td>
        <td class="mono muted">${UI.esc(r.rule_id)}</td>
        <td><span class="${UI.sevClass(r.severity)}">${UI.esc(r.severity)}</span></td>
        <td><div style="font-weight:600">${UI.esc(r.title)}</div>
            <div class="why">${UI.esc(r.description)}</div></td>
        <td class="mono muted">${UI.esc(r.mitre)}</td>
        <td class="mono" style="font-weight:${r.fired ? '700' : '400'}">${r.fired || '—'}</td>
        <td style="display:flex;gap:6px">
          <button class="btn btn-sm btn-ghost" onclick="Views.editMyRule('${UI.esc(r.id)}')">Edit</button>
          <button class="btn btn-sm btn-ghost btn-danger"
                  onclick="Views.deleteMyRule('${UI.esc(r.id)}')">Remove</button>
        </td>
      </tr>`).join('');

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(d.total, 'Rules written here', { accent: '#22D9F5' })}
        ${UI.stat(d.enabled, 'Enabled', { accent: '#2BD9A0' })}
        ${UI.stat(sch.artifacts.length, 'Artifacts they can read', { accent: '#1B7FE8' })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Detections you write</h2><div class="spacer"></div>
          <button class="btn btn-sm" onclick="Views.importRules()">Import</button>
          ${d.total ? `<button class="btn btn-sm btn-ghost" onclick="Views.exportRules()">Export</button>` : ''}
          <button class="btn btn-sm" onclick="Views.writeRuleText()">Write as text</button>
          <button class="btn btn-primary btn-sm" onclick="Views.newMyRule()">New rule</button>
        </div>
        <p class="muted" style="margin:0;max-width:86ch">
          Sigma reads event logs and YARA reads file content. Neither can express
          <i>a service whose binary is unsigned and sits outside Program Files</i>,
          because that question is asked of an artifact table. These rules read
          those tables — services, tasks, autoruns, connections, accounts, memory.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0">
          Every rule can be tried against a sample row before it is saved, and the
          tester says which condition failed and what value it actually saw. Write a
          set in an editor or a spreadsheet and <b>Import</b> the lot — JSON, YAML or
          CSV — or <b>Export</b> what is here to move it to another console.
        </p>
        <div style="margin-top:14px;display:flex;gap:9px;flex-wrap:wrap">
          <button class="btn btn-sm btn-ghost" onclick="Views.ruleHelp()">
            How these rules work &amp; how to write one</button>
          <button class="btn btn-sm btn-ghost" onclick="Views.importHelp()">
            File format for bulk import</button>
        </div>
      </div>

      ${d.total
        ? `<div class="filters">
            <button class="btn btn-sm" onclick="Views.pickAllRules(true)">Select all</button>
            <button class="btn btn-sm btn-ghost" onclick="Views.pickAllRules(false)">Clear</button>
            <button class="btn btn-sm" onclick="Views.bulkRuleToggle(true)">Enable selected</button>
            <button class="btn btn-sm btn-ghost" onclick="Views.bulkRuleToggle(false)">Disable selected</button>
            <button class="btn btn-sm btn-ghost btn-danger" onclick="Views.bulkRuleDelete()">Remove selected</button>
          </div>
          ${UI.table(['', 'On', 'Rule', 'Severity', 'Detection', 'MITRE', 'Fired', ''],
                     rows, { id: 'tblMyRules' })}`
        : `<div class="card">${UI.empty('No rules yet',
            'Write one, import a file, or load the worked examples to see the shape.')}
            <div style="display:flex;gap:9px;justify-content:center;flex-wrap:wrap;margin-top:6px">
              <button class="btn btn-primary" onclick="Views.newMyRule()">Use the form</button>
              <button class="btn" onclick="Views.writeRuleText()">Write as text</button>
              <button class="btn" onclick="Views.importRules()">Import a file</button>
              <button class="btn btn-ghost" onclick="Views.loadStarterPack()">Load 6 examples</button>
            </div></div>`}
    </div>`;
  }

  function conditionRow(c, i) {
    const art = ruleSchema.artifacts.find(a => a.name === currentArtifact()) || { fields: [] };
    return `
      <div class="filters" style="margin-bottom:8px" data-cond="${i}">
        <select class="cf" style="min-width:180px">
          ${art.fields.map(f =>
            `<option value="${f}" ${c.field === f ? 'selected' : ''}>${f}</option>`).join('')}
        </select>
        <select class="co" style="min-width:170px" onchange="Views.condOpChanged(${i})">
          ${ruleSchema.operators.map(o =>
            `<option value="${o.op}" ${c.op === o.op ? 'selected' : ''}>${o.label}</option>`).join('')}
        </select>
        <input type="text" class="cv" placeholder="value" value="${UI.esc(c.value || '')}"
               style="flex:1;min-width:150px">
        <button class="btn btn-sm btn-ghost btn-danger" onclick="Views.removeCond(${i})">×</button>
      </div>`;
  }

  function currentArtifact() {
    const el2 = document.getElementById('crArtifact');
    return el2 ? el2.value : (ruleSchema.artifacts[0] || {}).name;
  }

  function readConditions() {
    return [...document.querySelectorAll('[data-cond]')].map(row => ({
      field: row.querySelector('.cf').value,
      op: row.querySelector('.co').value,
      value: row.querySelector('.cv').value,
    }));
  }

  function renderConditions() {
    const box = document.getElementById('crConds');
    if (box) box.innerHTML = draftConditions.map(conditionRow).join('');
    draftConditions.forEach((_, i) => condOpChanged(i));
  }

  function condOpChanged(i) {
    const row = document.querySelector(`[data-cond="${i}"]`);
    if (!row) return;
    const op = row.querySelector('.co').value;
    const spec = ruleSchema.operators.find(o => o.op === op);
    const input = row.querySelector('.cv');
    if (spec && !spec.needs_value) {
      input.value = '';
      input.disabled = true;
      input.placeholder = 'no value needed';
    } else {
      input.disabled = false;
      input.placeholder = 'value';
    }
  }

  function addCond() {
    draftConditions = readConditions();
    const art = ruleSchema.artifacts.find(a => a.name === currentArtifact());
    draftConditions.push({ field: (art.fields || [''])[0], op: 'contains', value: '' });
    renderConditions();
  }

  function removeCond(i) {
    draftConditions = readConditions().filter((_, x) => x !== i);
    if (!draftConditions.length) addCond(); else renderConditions();
  }

  function artifactChanged() {
    draftConditions = [];
    addCond();
  }

  function ruleForm(r) {
    r = r || { rule_id: '', title: '', severity: 'MEDIUM', mitre: '', why: '',
               artifact: ruleSchema.artifacts[0].name, match: 'all', conditions: [] };
    draftConditions = (r.conditions && r.conditions.length)
      ? r.conditions.map(c => ({ ...c }))
      : [{ field: '', op: 'contains', value: '' }];

    return `
      <div class="grid" style="grid-template-columns:1fr 2fr;gap:14px">
        <div class="field"><label>Rule id</label>
          <input type="text" id="crId" value="${UI.esc(r.rule_id)}" placeholder="ACME-001">
          <div class="hint">Your own prefix. DGL, SIGMA and YARA are reserved.</div></div>
        <div class="field"><label>Title</label>
          <input type="text" id="crTitle" value="${UI.esc(r.title)}"
                 placeholder="Unsigned service outside Program Files">
          <div class="hint">Becomes the finding's headline.</div></div>
      </div>

      <div class="grid" style="grid-template-columns:1fr 1fr 1fr;gap:14px">
        <div class="field"><label>Severity</label>
          <select id="crSev">${ruleSchema.severities.map(sv =>
            `<option value="${sv}" ${r.severity === sv ? 'selected' : ''}>${sv}</option>`).join('')}
          </select></div>
        <div class="field"><label>MITRE (optional)</label>
          <input type="text" id="crMitre" value="${UI.esc(r.mitre)}" placeholder="T1543.003"></div>
        <div class="field"><label>Match</label>
          <select id="crMatch">
            <option value="all" ${r.match === 'all' ? 'selected' : ''}>All conditions</option>
            <option value="any" ${r.match === 'any' ? 'selected' : ''}>Any condition</option>
          </select></div>
      </div>

      <div class="field"><label>Look in</label>
        <select id="crArtifact" onchange="Views.artifactChanged()">
          ${ruleSchema.artifacts.map(a =>
            `<option value="${a.name}" ${r.artifact === a.name ? 'selected' : ''}>
              ${a.label} (${a.name})</option>`).join('')}
        </select></div>

      <div class="field"><label>Conditions</label>
        <div id="crConds"></div>
        <button class="btn btn-sm btn-ghost" onclick="Views.addCond()">Add condition</button></div>

      <div class="field"><label>Why this matters (optional)</label>
        <textarea id="crWhy" placeholder="Shown under the finding to whoever reads it.">${UI.esc(r.why)}</textarea></div>

      <div class="card" style="background:var(--deep);margin-top:6px">
        <div class="card-h"><h2>Try it</h2><div class="spacer"></div>
          <button class="btn btn-sm" onclick="Views.testMyRule()">Test against a sample row</button></div>
        <div id="crSample"></div>
        <div id="crResult" style="margin-top:12px"></div>
      </div>
      <div id="crErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`;
  }

  function readRule() {
    return {
      rule_id: document.getElementById('crId').value.trim(),
      title: document.getElementById('crTitle').value.trim(),
      severity: document.getElementById('crSev').value,
      mitre: document.getElementById('crMitre').value.trim(),
      why: document.getElementById('crWhy').value.trim(),
      artifact: document.getElementById('crArtifact').value,
      match: document.getElementById('crMatch').value,
      conditions: readConditions(),
    };
  }

  async function testMyRule() {
    const rule = readRule();
    const box = document.getElementById('crSample');
    const out = document.getElementById('crResult');

    // Build the sample form from the fields this rule actually reads, so the
    // operator is not asked to fill in twenty columns to test three.
    const used = [...new Set(rule.conditions.map(c => c.field))].filter(Boolean);
    if (!box.dataset.built || box.dataset.fields !== used.join(',')) {
      box.dataset.built = '1';
      box.dataset.fields = used.join(',');
      box.innerHTML = used.map(f => `
        <div class="filters" style="margin-bottom:6px">
          <span class="mono muted" style="min-width:170px;font-size:12px">${UI.esc(f)}</span>
          <input type="text" class="sv" data-field="${UI.esc(f)}"
                 placeholder="value this row would have" style="flex:1">
        </div>`).join('');
      out.innerHTML = '<div class="hint">Fill the values a real row would have, then test again.</div>';
      return;
    }

    const sample = {};
    document.querySelectorAll('#crSample .sv').forEach(i => {
      sample[i.dataset.field] = i.value;
    });

    try {
      const res = await API.testCustomRule(rule, sample);
      out.innerHTML = `
        <div class="notice ${res.matched ? '' : 'warn-notice'}"
             style="${res.matched
               ? 'background:rgba(43,217,160,.10);border-left:3px solid #2BD9A0' : ''}">
          <b style="color:${res.matched ? '#2BD9A0' : 'var(--med)'}">
            ${res.matched ? 'Match' : 'No match'}</b>
          <p>${UI.esc(res.explanation)}</p>
        </div>
        <div class="scroll" style="max-height:200px;margin-top:10px"><table><thead><tr>
          <th></th><th>Field</th><th>Test</th><th>Row had</th></tr></thead><tbody>
          ${res.conditions.map(c => `<tr>
            <td style="color:${c.matched ? '#2BD9A0' : 'var(--crit)'};font-weight:700">
              ${c.matched ? '✓' : '✕'}</td>
            <td class="mono">${UI.esc(c.field)}</td>
            <td class="muted">${UI.esc(c.op)} ${UI.esc(c.value)}</td>
            <td class="mono ev">${UI.esc(c.actual) || '<span class="muted">(empty)</span>'}</td>
          </tr>`).join('')}</tbody></table></div>`;
    } catch (e) {
      out.innerHTML = `<div style="color:var(--crit);font-size:13px">${UI.esc(e.message)}</div>`;
    }
  }

  function ruleHelp() {
    UI.drawer('Writing a detection rule', `
      <h3 class="hsec">Where a rule lives</h3>
      <p class="muted" style="margin-top:0">
        Nothing is compiled into the collector. Rules live in this console and the
        agent fetches the enabled set <b>at the start of every hunt</b>, alongside
        the Sigma and YARA bundles. That means:
      </p>
      <ul class="hlist">
        <li><b>Adding</b> a rule takes effect on the next hunt. No redeployment,
            no touching hosts.</li>
        <li><b>Switching one off</b> stops it being sent. Findings it already
            produced stay where they are — history is not rewritten.</li>
        <li><b>Deleting</b> one does the same, permanently. If you only want to
            stop seeing it, switch it off or suppress its findings instead.</li>
        <li>A host that cannot reach the console keeps its previous bundle and
            hunts with that, rather than failing.</li>
      </ul>

      <h3 class="hsec">How a rule is shaped</h3>
      <p class="muted" style="margin-top:0">
        A rule points at one <b>artifact</b> — a table the collector produces, such
        as <span class="mono">05_services</span> or
        <span class="mono">03_processes</span> — and lists <b>conditions</b> over
        that table's columns. Every row is tested; a row that satisfies the
        conditions becomes a finding.
      </p>
      <div class="code" style="white-space:pre;overflow-x:auto;line-height:1.7">${[
        'Artifact:  05_services',
        'Match:     all conditions',
        '',
        '  Signed        equals     False',
        '  BinaryPath    contains   \\ProgramData\\',
        '  IsMicrosoft   equals     False',
        '',
        '  -> "unsigned non-Microsoft service running from ProgramData"',
      ].join('\n')}</div>

      <h3 class="hsec">Operators</h3>
      <div style="border:1px solid var(--edge);border-radius:6px;overflow:hidden">
        <table style="width:100%"><thead><tr><th>Operator</th><th>Matches when</th></tr></thead><tbody>
          <tr><td class="mono">equals</td><td>The value is exactly this. Use for
            True/False columns and enumerations.</td></tr>
          <tr><td class="mono">not_equals</td><td>Anything except this.</td></tr>
          <tr><td class="mono">contains</td><td>The text appears somewhere in the
            value. The workhorse for paths and command lines.</td></tr>
          <tr><td class="mono">not_contains</td><td>The text does not appear.
            Useful for carving out a known-good directory.</td></tr>
          <tr><td class="mono">starts_with</td><td>The value begins with this.</td></tr>
          <tr><td class="mono">ends_with</td><td>The value ends with this — file
            extensions, binary names.</td></tr>
          <tr><td class="mono">regex</td><td>A .NET regular expression. Reach for it
            last: it is the easiest way to write a rule that quietly matches
            nothing.</td></tr>
          <tr><td class="mono">is_empty</td><td>The column has no value. Finds
            missing signatures and unresolved paths.</td></tr>
          <tr><td class="mono">not_empty</td><td>The column has any value.</td></tr>
          <tr><td class="mono">gt</td><td>Numerically greater than.</td></tr>
          <tr><td class="mono">lt</td><td>Numerically less than.</td></tr>
        </tbody></table>
      </div>
      <p class="muted" style="font-size:12.5px">
        Matching is case-insensitive throughout, so
        <span class="mono">\programdata\</span> and
        <span class="mono">\ProgramData\</span> behave the same.
      </p>

      <h3 class="hsec">Writing one that holds up</h3>
      <ul class="hlist">
        <li><b>Test before saving.</b> The tester loads a real row from the last
            collection and shows which condition failed and what the actual value
            was. A rule never run against real data usually matches nothing or
            everything.</li>
        <li><b>Start narrow.</b> One condition that fires 400 times is worse than
            three that fire twice — a finding nobody can get through is the same as
            no finding.</li>
        <li><b>Say what is normal.</b> The <i>why</i> field is what an analyst reads
            at 3am. "Unsigned binary" explains nothing; "legitimate services run
            from System32 or Program Files" tells them how to rule it out.</li>
        <li><b>Pick the severity honestly.</b> Critical should mean stop and look
            now. If everything is critical, nothing is.</li>
        <li><b>Add the MITRE technique</b> if you know it — the rule then appears in
            the ATT&CK matrix alongside everything else.</li>
      </ul>

      <h3 class="hsec">When it fires too much</h3>
      <p class="muted" style="margin-top:0;margin-bottom:0">
        A rule is capped at 25 findings per host per hunt; past that an INFO finding
        reports the real number so the count is never silently wrong. If a rule
        describes how your estate is built rather than an intrusion, either tighten
        it here or suppress its findings from the Triage tab — suppression keeps the
        rule running while hiding the cases you have already ruled on.
      </p>`);
  }

  function newMyRule() {
    UI.modal('New rule', ruleForm(null),
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="crGo">Create</button>`);
    renderConditions();
    document.getElementById('crGo').onclick = async () => {
      const err = document.getElementById('crErr');
      err.classList.add('hidden');
      try {
        await API.createCustomRule(readRule());
        UI.close(); UI.toast('Rule created', '', 'ok'); myrules();
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  async function editMyRule(id) {
    const d = await API.customRules();
    const r = d.rules.find(x => x.id === id);
    if (!r) return;
    UI.modal(`Edit ${r.rule_id}`, ruleForm(r),
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="crGo">Save</button>`);
    renderConditions();
    document.getElementById('crGo').onclick = async () => {
      const err = document.getElementById('crErr');
      err.classList.add('hidden');
      try {
        await API.updateCustomRule(id, readRule());
        UI.close(); UI.toast('Rule updated', '', 'ok'); myrules();
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  async function toggleMyRule(id, enabled) {
    try { await API.toggleCustomRule(id, enabled); }
    catch (e) { UI.toast('Could not change that', e.message, 'err'); myrules(); }
  }

  /* ---- Writing a rule as text ----------------------------------------- */

  // The form is faster for a first rule and slower for the twentieth. Somebody
  // who knows the shape wants to type it, paste one a colleague sent, or edit
  // an exported rule and put it back — and the form makes all three awkward.
  //
  // Checking happens as you type, and reports the line rather than the rule:
  // mid-sentence you need to know which word the parser choked on.
  let ruleTextTimer = null;
  let ruleTextValid = null;

  function writeRuleText(seed) {
    ruleTextValid = null;
    const start = seed || RULE_TEMPLATE;

    UI.modal('Write a rule', `
      <p class="muted" style="margin-top:0">
        One rule, as text. Checked as you type — the box below says what it
        will match, or which line is wrong.
      </p>

      <div class="rt-wrap">
        <div class="rt-gutter" id="rtGutter"></div>
        <textarea id="rtText" spellcheck="false" wrap="off"
          oninput="Views.ruleTextChanged()" onscroll="Views.ruleTextScroll()"
          onkeydown="Views.ruleTextKey(event)">${UI.esc(start)}</textarea>
      </div>

      <div id="rtResult" class="rt-result"></div>

      <details class="rt-help">
        <summary>What can go in a rule</summary>
        <div class="hint" style="margin-top:8px">
          <b>id</b> your own prefix and a number — ACME-001. DGL, SIGMA and YARA
          are reserved.<br>
          <b>artifact</b> which collected table to read.
          <b>when</b> one condition per line: <span class="mono">FIELD OPERATOR VALUE</span>.
          <b>match</b> all (default) or any.<br>
          <b>severity</b> CRITICAL, HIGH, MEDIUM, LOW, INFO.
          <b>mitre</b>, <b>why</b> optional.
          <button class="btn btn-sm btn-ghost" style="margin-top:8px"
                  onclick="Views.importHelp()">Full field and operator list</button>
        </div>
      </details>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn" onclick="Views.ruleTextReset()">Reset to template</button>
       <button class="btn btn-primary" id="rtSave" disabled
               onclick="Views.saveRuleText()">Save rule</button>`);

    ruleTextGutter();
    ruleTextChanged();
  }

  function ruleTextGutter() {
    const box = document.getElementById('rtText');
    const gutter = document.getElementById('rtGutter');
    if (!box || !gutter) return;
    const n = box.value.split('\n').length;
    gutter.innerHTML = Array.from({ length: n }, (_, i) =>
      `<span id="rtLn${i + 1}">${i + 1}</span>`).join('');
  }

  function ruleTextScroll() {
    const box = document.getElementById('rtText');
    const gutter = document.getElementById('rtGutter');
    if (box && gutter) gutter.scrollTop = box.scrollTop;
  }

  function ruleTextKey(e) {
    // Tab indents rather than leaving the editor, because a condition block is
    // indented and losing focus mid-rule is maddening.
    if (e.key !== 'Tab') return;
    e.preventDefault();
    const box = e.target;
    const at = box.selectionStart;
    box.value = box.value.slice(0, at) + '  ' + box.value.slice(box.selectionEnd);
    box.selectionStart = box.selectionEnd = at + 2;
    ruleTextChanged();
  }

  function ruleTextChanged() {
    ruleTextGutter();
    clearTimeout(ruleTextTimer);
    // Debounced: checking on every keystroke would report an error for every
    // half-typed word, which trains people to ignore the box.
    ruleTextTimer = setTimeout(runRuleTextCheck, 450);
  }

  async function runRuleTextCheck() {
    const box = document.getElementById('rtText');
    const out = document.getElementById('rtResult');
    const save = document.getElementById('rtSave');
    if (!box || !out) return;

    document.querySelectorAll('.rt-gutter span.bad').forEach(s => s.classList.remove('bad'));

    let r;
    try { r = await API.checkRuleText(box.value); }
    catch (e) {
      out.className = 'rt-result bad';
      out.innerHTML = `<b>Could not check it</b><span>${UI.esc(e.message)}</span>`;
      return;
    }

    if (r.ok) {
      ruleTextValid = r.rule;
      if (save) save.disabled = false;
      out.className = 'rt-result good';
      out.innerHTML = `
        <b>Valid — ${UI.esc(r.rule.rule_id)}</b>
        <span>Reads <b>${UI.esc(r.artifact_label)}</b> and matches when
        ${UI.esc(r.summary)}</span>
        ${r.exists ? `<span style="color:var(--high)">A rule with this id already
          exists — saving replaces it.</span>` : ''}`;
      return;
    }

    ruleTextValid = null;
    if (save) save.disabled = true;
    const err = (r.errors || [])[0] || { line: 1, message: 'Not valid.' };
    const mark = document.getElementById(`rtLn${err.line}`);
    if (mark) mark.classList.add('bad');
    out.className = 'rt-result bad';
    out.innerHTML = `
      <b>Line ${err.line}</b>
      <span>${UI.esc(err.message)}</span>`;
  }

  function ruleTextReset() {
    const box = document.getElementById('rtText');
    if (box) { box.value = RULE_TEMPLATE; ruleTextChanged(); }
  }

  async function saveRuleText() {
    if (!ruleTextValid) return;
    try {
      const existing = (await API.customRules()).rules
        .find(r => r.rule_id === ruleTextValid.rule_id);
      if (existing) await API.updateCustomRule(existing.id, ruleTextValid);
      else await API.createCustomRule(ruleTextValid);
      UI.close();
      UI.toast(existing ? 'Rule replaced' : 'Rule saved',
               `${ruleTextValid.rule_id} ships to every agent on their next hunt.`, 'ok');
      myrules();
    } catch (e) { UI.toast('Could not save it', e.message, 'err'); }
  }

  // Kept in the console rather than fetched, so the editor opens with
  // something in it even when the server is slow.
  const RULE_TEMPLATE = `id: ACME-001
title: Unsigned service binary outside Program Files
severity: HIGH
mitre: T1543.003
artifact: 05_services
match: all
when:
  Signed is_false
  PathName not_contains "Program Files"
  PathName not_contains "System32"
why: >
  Legitimate services are signed and installed under Program Files or
  System32. Neither being true is how most service persistence looks.
`;

  async function deleteMyRule(id) {
    if (!confirm('Remove this rule? Findings it already produced stay.')) return;
    try { await API.deleteCustomRule(id); UI.toast('Rule removed', '', 'ok'); myrules(); }
    catch (e) { UI.toast('Could not remove it', e.message, 'err'); }
  }

  /* ---- bulk operations on the rules already here ---------------------- */

  function pickedRules() {
    return [...document.querySelectorAll('.rulePick:checked')].map(c => c.value);
  }

  function pickAllRules(state) {
    document.querySelectorAll('.rulePick').forEach(c => { c.checked = state; });
  }

  async function bulkRuleToggle(enabled) {
    const ids = pickedRules();
    if (!ids.length) { UI.toast('Nothing selected', 'Tick at least one rule.', 'err'); return; }
    let done = 0; const failed = [];
    for (const id of ids) {
      try { await API.toggleCustomRule(id, enabled); done++; }
      catch (e) { failed.push(e.message); }
    }
    UI.toast(`${done} rule${done === 1 ? '' : 's'} ${enabled ? 'enabled' : 'disabled'}`,
             failed.length ? `${failed.length} failed: ${failed[0]}` : '',
             failed.length ? 'err' : 'ok');
    myrules();
  }

  async function bulkRuleDelete() {
    const ids = pickedRules();
    if (!ids.length) { UI.toast('Nothing selected', 'Tick at least one rule.', 'err'); return; }
    if (!confirm(`Remove ${ids.length} rule${ids.length === 1 ? '' : 's'}?\n\n`
      + 'Findings they already produced stay where they are.')) return;
    let done = 0; const failed = [];
    for (const id of ids) {
      try { await API.deleteCustomRule(id); done++; }
      catch (e) { failed.push(e.message); }
    }
    UI.toast(`${done} removed`, failed.length ? `${failed.length} failed` : '',
             failed.length ? 'err' : 'ok');
    myrules();
  }

  /* ---- import and export ---------------------------------------------- */

  function exportRules() {
    UI.modal('Export rules', `
      <p class="muted" style="margin-top:0">
        Every rule written here, in a form this console reads back unchanged.
        Useful for moving a tuned set to another deployment, or keeping it in
        version control alongside everything else.
      </p>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:16px">
        <a class="btn btn-primary" href="${API.ruleExportUrl('json')}" download>JSON</a>
        <a class="btn" href="${API.ruleExportUrl('yaml')}" download>YAML</a>
        <a class="btn" href="${API.ruleExportUrl('csv')}" download>CSV</a>
      </div>
      <div class="hint" style="margin-top:14px">
        JSON round-trips exactly. YAML is the one to edit by hand. CSV opens in a
        spreadsheet, with the conditions in a single column.
      </div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Close</button>`);
  }

  let importPlan = null;

  function importRules() {
    importPlan = null;
    UI.modal('Import rules', `
      <p class="muted" style="margin-top:0">
        A file of rules in <b>JSON</b>, <b>YAML</b> or <b>CSV</b>. The format is
        detected from the file. Nothing is written until you have seen what it
        would do.
      </p>

      <div class="field"><label>Choose a file</label>
        <input type="file" id="impFile" accept=".json,.yaml,.yml,.csv,.tsv,.txt"
               onchange="Views.importFilePicked(this)"></div>

      <div class="field"><label>…or paste it here</label>
        <textarea id="impText" spellcheck="false"
          style="min-height:150px;font-family:ui-monospace,monospace;font-size:12px"
          placeholder="- rule_id: ACME-001&#10;  title: Unsigned service outside Program Files&#10;  severity: HIGH&#10;  artifact: 05_services&#10;  conditions: Signed is_false; PathName not_contains &quot;Program Files&quot;"
          oninput="Views.importTextChanged()"></textarea></div>

      <div class="field"><label>If a rule id already exists</label>
        <select id="impConflict" onchange="Views.importTextChanged()">
          <option value="skip">Leave the existing one alone</option>
          <option value="replace">Overwrite it with the imported one</option>
          <option value="rename">Import alongside it as ID.2</option>
        </select></div>

      <div id="impResult" style="margin-top:14px"></div>
      <div id="impErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn" onclick="Views.importHelp()">Format help</button>
       <button class="btn" id="impPreview" onclick="Views.previewImport()">Check the file</button>
       <button class="btn btn-primary" id="impGo" onclick="Views.commitImport()" disabled>Import</button>`);
  }

  function importFilePicked(input) {
    const file = input.files && input.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      document.getElementById('impText').value = reader.result;
      importFileName = file.name;
      previewImport();
    };
    reader.onerror = () => UI.toast('Could not read that file', '', 'err');
    reader.readAsText(file);
  }

  let importFileName = '';

  function importTextChanged() {
    // The file changed, so the plan the operator saw no longer describes it.
    importPlan = null;
    const go = document.getElementById('impGo');
    if (go) go.disabled = true;
  }

  function importPayload() {
    return {
      text: document.getElementById('impText').value,
      filename: importFileName,
      on_conflict: document.getElementById('impConflict').value,
    };
  }

  async function previewImport() {
    const out = document.getElementById('impResult');
    const err = document.getElementById('impErr');
    err.classList.add('hidden');
    out.innerHTML = '<div class="hint"><span class="spinner"></span> Reading the file…</div>';
    try {
      const r = await API.previewRuleImport(importPayload());
      importPlan = r;
      renderImportPlan(r, false);
      document.getElementById('impGo').disabled = (r.add + r.replace) === 0;
    } catch (e) {
      out.innerHTML = '';
      importPlan = null;
      document.getElementById('impGo').disabled = true;
      err.textContent = e.message;
      err.classList.remove('hidden');
    }
  }

  function renderImportPlan(r, done) {
    const badge = {
      add: '#2BD9A0', replace: '#FFC531', skipped: '#7A93B8', rejected: '#FF2D55',
    };
    const label = { add: done ? 'imported' : 'will add', replace: done ? 'replaced' : 'will replace',
                    skipped: 'skipped', rejected: 'rejected' };

    const rows = r.items.map(i => `
      <tr>
        <td><span style="color:${badge[i.action]};font-weight:600;font-size:11.5px">
          ${UI.esc(label[i.action])}</span></td>
        <td class="mono">${UI.esc(i.rule_id)}</td>
        <td><div style="font-weight:600">${UI.esc(i.title || '')}</div>
            ${i.summary ? `<div class="why">${UI.esc(i.summary.slice(0, 100))}</div>` : ''}
            ${i.reason ? `<div class="why" style="color:${badge[i.action]}">${UI.esc(i.reason)}</div>` : ''}</td>
      </tr>`).join('');

    document.getElementById('impResult').innerHTML = `
      <div class="notice" style="background:var(--deep);border:1px solid var(--edge);
           border-left:3px solid ${r.rejected ? 'var(--high)' : 'var(--cyan)'}">
        <b>${UI.esc(r.format ? r.format.toUpperCase() + ' · ' : '')}${r.total} rule${r.total === 1 ? '' : 's'} read</b>
        <div class="mono" style="font-size:11.5px;color:var(--slate);margin-top:6px">
          ${done ? `${r.added} added` : `${r.add} to add`} ·
          ${done ? `${r.replaced} replaced` : `${r.replace} to replace`} ·
          ${r.skipped} skipped · ${r.rejected} rejected
        </div>
        ${r.rejected ? `<p style="margin:8px 0 0;font-size:12.5px">A rejected rule does
          not stop the rest — the reason is next to each one below.</p>` : ''}
      </div>
      <div class="scroll" style="max-height:260px;margin-top:10px"><table><tbody>
        ${rows}</tbody></table></div>`;
  }

  async function commitImport() {
    const err = document.getElementById('impErr');
    const go = document.getElementById('impGo');
    err.classList.add('hidden');
    go.disabled = true;
    try {
      const r = await API.importRules(importPayload());
      renderImportPlan(r, true);
      UI.toast(`${r.added} rule${r.added === 1 ? '' : 's'} imported`,
        r.replaced ? `${r.replaced} replaced` : (r.rejected ? `${r.rejected} rejected` : ''),
        'ok');
      // The list behind the dialog is now stale.
      myrules();
    } catch (e) {
      err.textContent = e.message;
      err.classList.remove('hidden');
      go.disabled = false;
    }
  }

  async function loadStarterPack() {
    try {
      const r = await API.importStarterPack();
      UI.toast(`${r.added} example${r.added === 1 ? '' : 's'} loaded`,
               'Imported switched off — open one to see how it is built.', 'ok');
      myrules();
    } catch (e) { UI.toast('Could not load the examples', e.message, 'err'); }
  }

  async function importHelp() {
    let h;
    try { h = await API.ruleImportHelp(); }
    catch (e) { UI.toast('Could not load the format help', e.message, 'err'); return; }

    UI.drawer('Rule file format', `
      <h3 class="hsec">What a file may be</h3>
      <div class="guide">
        ${h.formats.map(f => `<div class="gitem"><b>${UI.esc(f.name)}</b>
          <p>${UI.esc(f.note)}</p></div>`).join('')}
      </div>

      <h3 class="hsec">Fields</h3>
      <div class="scroll" style="max-height:280px"><table><thead><tr>
        <th>Field</th><th></th><th>Notes</th></tr></thead><tbody>
        ${h.fields.map(f => `<tr>
          <td class="mono">${UI.esc(f.name)}</td>
          <td>${f.required ? '<span class="tag" style="color:var(--high);border-color:rgba(255,122,0,.4)">required</span>' : '<span class="muted">optional</span>'}</td>
          <td class="muted" style="font-size:12.5px">${UI.esc(f.note)}</td></tr>`).join('')}
      </tbody></table></div>

      <h3 class="hsec">Writing conditions</h3>
      <p class="muted" style="margin-top:0">
        Either a list of <span class="mono">{field, op, value}</span> objects, or one
        compact line — the same thing, and the compact form is what fits in a
        spreadsheet cell:
      </p>
      <div class="code">${UI.esc(h.compact_syntax)}</div>

      <h3 class="hsec">Operators</h3>
      <div style="display:flex;gap:7px;flex-wrap:wrap">
        ${h.operators.map(o => `<span class="tag mono" title="${UI.esc(o.label)}">${UI.esc(o.op)}${
          o.needs_value ? '' : ' ·'}</span>`).join('')}
      </div>
      <div class="hint" style="margin-top:8px">Those marked · take no value:
        they test the column on its own.</div>

      <h3 class="hsec">Artifacts a rule can read</h3>
      <div class="scroll" style="max-height:300px"><table><thead><tr>
        <th>Artifact</th><th>Columns</th></tr></thead><tbody>
        ${h.artifacts.map(a => `<tr>
          <td><div style="font-weight:600">${UI.esc(a.label)}</div>
              <div class="mono why">${UI.esc(a.name)}</div></td>
          <td class="mono muted" style="font-size:11px">${UI.esc(a.fields.join(', '))}</td>
        </tr>`).join('')}
      </tbody></table></div>

      <h3 class="hsec">A worked example — YAML</h3>
      <div class="code" style="white-space:pre-wrap">${UI.esc(h.examples.yaml)}</div>

      <h3 class="hsec">The same rule as CSV</h3>
      <div class="code" style="white-space:pre-wrap">${UI.esc(h.examples.csv)}</div>

      <h3 class="hsec">Notes</h3>
      <ul class="hlist">
        <li>Up to <b>${h.max_rules}</b> rules in one file.</li>
        <li>A rule that fails validation is <b>named and skipped</b>; the rest still
            import. One typo does not cost you the file.</li>
        <li><b>DGL, SIGMA and YARA</b> are reserved prefixes — use your own, so a
            rule you wrote is never mistaken for a built-in one.</li>
        <li>Imported rules ship to every agent on their next hunt. Nothing is
            redeployed.</li>
      </ul>`);
  }

  /* ==================================================================== */
  /* Cases                                                                */
  /* ==================================================================== */

  let openCase = null;

  async function cases() {
    loading();
    const d = await API.cases();

    if (openCase) {
      const c = await API.caseDetail(openCase).catch(() => null);
      if (c) { renderCase(c); return; }
      openCase = null;
    }

    const rows = d.cases.map(c => `
      <tr class="clickable ${c.status === 'closed' ? 'closed' : ''}"
          onclick="Views.showCase('${UI.esc(c.id)}')">
        <td class="mono">${UI.esc(c.reference)}</td>
        <td><div style="font-weight:600">${UI.esc(c.name)}</div>
            ${c.summary ? `<div class="why">${UI.esc(c.summary.slice(0, 110))}</div>` : ''}</td>
        <td><span class="stat-chip st-${c.status === 'open' ? 'open'
          : (c.status === 'contained' ? 'investigating' : 'false_positive')}">${UI.esc(c.status)}</span></td>
        <td><span class="${UI.sevClass(c.severity)}">${UI.esc(c.severity)}</span></td>
        <td class="mono">${c.host_count}</td>
        <td class="mono">${c.ioc_count}</td>
        <td class="mono muted">${UI.esc(c.lead)}</td>
        <td class="mono muted">${UI.ago(c.opened_at)}</td>
      </tr>`).join('');

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(d.total, 'Cases', { accent: '#22D9F5' })}
        ${UI.stat(d.open, 'Open', { accent: '#FF7A00', glow: d.open > 0 })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>One incident, not forty scans</h2><div class="spacer"></div>
          <button class="btn btn-primary btn-sm" onclick="Views.newCase()">Open a case</button>
        </div>
        <p class="muted" style="margin:0;max-width:86ch">
          A case holds the hosts in scope and one indicator list for the whole
          engagement, so a host joining later is swept with the same indicators as
          the rest. Findings, the ATT&amp;CK picture and the running log are
          gathered in one place rather than spread across separate hunts.
        </p>
      </div>

      ${d.total
        ? UI.table(['Reference', 'Case', 'Status', 'Severity', 'Hosts', 'IOCs', 'Lead', 'Opened'],
                   rows, { id: 'tblCases' })
        : `<div class="card">${UI.empty('No cases yet',
            'Open one when an engagement starts.')}</div>`}
    </div>`;
  }

  function renderCase(c) {
    const counts = c.finding_counts || {};
    const cols = (c.matrix.columns || []).filter(x => x.techniques.length);

    el().innerHTML = `<div class="view">
      <div class="filters" style="margin-bottom:16px">
        <button class="btn btn-sm btn-ghost" onclick="Views.closeCase()">← All cases</button>
        <div class="spacer"></div>
        <button class="btn btn-sm" onclick="Views.caseHunt('${UI.esc(c.id)}')">Sweep every host</button>
        <button class="btn btn-sm" onclick="Views.editCase('${UI.esc(c.id)}')">Edit</button>
        <select onchange="Views.setCaseStatus('${UI.esc(c.id)}', this.value)">
          ${['open', 'contained', 'closed'].map(s =>
            `<option value="${s}" ${c.status === s ? 'selected' : ''}>${s}</option>`).join('')}
        </select>
      </div>

      <div class="card" style="margin-bottom:18px;border-left:3px solid var(--electric)">
        <div class="card-h">
          <h2>${UI.esc(c.reference)} — ${UI.esc(c.name)}</h2><div class="spacer"></div>
          <span class="${UI.sevClass(c.severity)}">${UI.esc(c.severity)}</span>
        </div>
        ${c.summary ? `<p style="color:var(--silver);margin:0 0 14px">${UI.esc(c.summary)}</p>` : ''}
        <div style="display:flex;gap:26px;flex-wrap:wrap;font-size:12.5px;color:var(--slate)">
          <span>Lead: <b style="color:var(--silver)">${UI.esc(c.lead)}</b></span>
          <span>Opened: <b style="color:var(--silver)">${UI.ago(c.opened_at)}</b></span>
          ${c.closed_at ? `<span>Closed: <b style="color:var(--silver)">${UI.ago(c.closed_at)}</b></span>` : ''}
          <span>${c.host_count} hosts · ${c.ioc_count} indicators</span>
        </div>
      </div>

      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(counts.CRITICAL || 0, 'Critical', { accent: '#FF2D55' })}
        ${UI.stat(counts.HIGH || 0, 'High', { accent: '#FF7A00' })}
        ${UI.stat(c.open_findings, 'Still open', { accent: '#1B7FE8',
          sub: c.open_findings ? 'must be ruled on before closing' : 'all ruled on' })}
        ${UI.stat(c.matrix.technique_count, 'Techniques', { accent: '#22D9F5',
          sub: `${c.matrix.tactics_hit} tactics` })}
      </div>

      <div class="grid g-2" style="margin-bottom:18px">
        <div class="card">
          <div class="card-h"><h2>Hosts in scope</h2></div>
          ${c.hosts.length ? c.hosts.map(h => `
            <div class="pbar-row">
              <div class="nm">${UI.esc(h.hostname)}
                <small>${h.critical_count} crit · ${h.high_count} high</small></div>
              <div class="tr"><i style="width:${Math.min(100, (h.risk_score / Math.max(1,
                Math.max(...c.hosts.map(x => x.risk_score)))) * 100)}%;background:${
                { CRITICAL: '#FF2D55', HIGH: '#FF7A00', MEDIUM: '#FFC531' }[h.risk_level] || '#1B7FE8'}"></i></div>
              <div class="vv">${h.risk_score}</div>
            </div>`).join('') : '<div class="muted">No hosts attached.</div>'}
        </div>
        <div class="card">
          <div class="card-h"><h2>Indicators</h2></div>
          ${(c.iocs || []).length
            ? `<div style="display:flex;gap:6px;flex-wrap:wrap">
                ${c.iocs.map(i => `<span class="tag mono">${UI.esc(i)}</span>`).join('')}</div>
               <div class="hint" style="margin-top:10px">
                 These go with every sweep launched from this case.</div>`
            : '<div class="muted">No indicators yet. Add them from Edit.</div>'}
        </div>
      </div>

      ${cols.length ? `
        <div class="card-h"><h2>Where the attacker got to</h2></div>
        <div class="matrix" style="margin-bottom:20px">
          ${cols.map(col => `
            <div class="mcol"><div class="mcol-h">
              <div class="t">${UI.esc(col.tactic)}</div>
              <div class="n">${col.techniques.length} technique${col.techniques.length === 1 ? '' : 's'}</div>
            </div><div class="mcol-b">
              ${col.techniques.map(t => `
                <div class="mcell s-${UI.esc(t.severity)}" title="${UI.esc(t.description || '')}">
                  <div class="id">${UI.esc(t.id)}</div>
                  <div class="nm">${UI.esc(t.name)}</div>
                  <div class="mt">${t.count}</div></div>`).join('')}
            </div></div>`).join('')}
        </div>` : ''}

      <div class="grid g-2">
        <div class="card">
          <div class="card-h"><h2>Findings</h2><div class="spacer"></div>
            <span class="muted mono">${c.finding_total} total</span></div>
          <div class="scroll" style="max-height:420px">
            ${c.top_findings.map(f => `
              <div style="border-left:3px solid var(--edge);padding:9px 13px;margin-bottom:8px;
                          background:var(--deep);border-radius:0 5px 5px 0">
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px">
                  <span class="${UI.sevClass(f.severity)}">${UI.esc(f.severity)}</span>
                  <span class="tag mono">${UI.esc(f.rule_id)}</span>
                  <span class="tag">${UI.esc(f.hostname)}</span>
                  <span class="stat-chip st-${UI.esc(f.status)}">${UI.esc(f.status.replace('_', ' '))}</span>
                </div>
                <div style="font-weight:600;font-size:13px">${UI.esc(f.title)}</div>
                <div class="ev">${UI.esc(f.evidence)}</div>
              </div>`).join('') || '<div class="muted">No findings yet.</div>'}
          </div>
        </div>
        <div class="card">
          <div class="card-h"><h2>Case log</h2></div>
          <div class="field">
            <textarea id="caseNote" placeholder="What did you do, and when?"></textarea>
            <button class="btn btn-sm btn-primary" style="margin-top:8px"
                    onclick="Views.addCaseNote('${UI.esc(c.id)}')">Add entry</button>
          </div>
          <div class="scroll" style="max-height:300px">
            ${(c.notes || []).map(n => `
              <div style="border-left:2px solid var(--edge);padding:8px 12px;margin-bottom:8px">
                <div class="mono muted" style="font-size:11px">
                  ${UI.esc(n.author)} · ${UI.ago(n.created_at)}</div>
                <div style="font-size:13px;margin-top:3px">${UI.esc(n.body)}</div>
              </div>`).join('') || '<div class="muted">Nothing logged yet.</div>'}
          </div>
        </div>
      </div>
    </div>`;
  }

  function showCase(id) { openCase = id; cases(); }
  function closeCase() { openCase = null; cases(); }

  function caseForm(c) {
    c = c || { reference: '', name: '', severity: 'HIGH', summary: '', lead: '',
               agent_ids: [], iocs: [] };
    return `
      <div class="grid" style="grid-template-columns:1fr 2fr;gap:14px">
        <div class="field"><label>Reference</label>
          <input type="text" id="caRef" value="${UI.esc(c.reference)}" placeholder="IR-2026-014"></div>
        <div class="field"><label>Name</label>
          <input type="text" id="caName" value="${UI.esc(c.name)}"
                 placeholder="Acme intrusion"></div>
      </div>
      <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
        <div class="field"><label>Severity</label>
          <select id="caSev">${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s =>
            `<option value="${s}" ${c.severity === s ? 'selected' : ''}>${s}</option>`).join('')}
          </select></div>
        <div class="field"><label>Lead</label>
          <input type="text" id="caLead" value="${UI.esc(c.lead)}" placeholder="Who owns this"></div>
      </div>
      <div class="field"><label>Summary</label>
        <textarea id="caSummary" placeholder="What happened, in a sentence.">${UI.esc(c.summary)}</textarea></div>
      <div class="field"><label>Hosts in scope</label>
        <div id="caHosts" class="scroll" style="max-height:180px;padding:8px;
             border:1px solid var(--edge);border-radius:6px">Loading…</div></div>
      <div class="field"><label>Indicators</label>
        <textarea id="caIocs" placeholder="One per line">${UI.esc((c.iocs || []).join('\n'))}</textarea>
        <div class="hint">Sent with every sweep launched from this case.</div></div>
      <div id="caErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`;
  }

  async function fillCaseHosts(selected) {
    const box = document.getElementById('caHosts');
    if (!box) return;
    try {
      const f = await API.agents();
      box.innerHTML = f.agents.map(a => `
        <label class="chk" style="padding:4px 6px;border:0;background:none">
          <input type="checkbox" class="ch" value="${UI.esc(a.id)}"
                 ${(selected || []).includes(a.id) ? 'checked' : ''}>
          <div><span>${UI.esc(a.hostname)}</span>
          <small>${UI.esc(a.risk_level || 'not scanned')}</small></div></label>`).join('')
        || '<div class="muted">No hosts enrolled.</div>';
    } catch (_) { box.innerHTML = '<div class="muted">Could not load hosts.</div>'; }
  }

  function readCase() {
    return {
      reference: document.getElementById('caRef').value.trim(),
      name: document.getElementById('caName').value.trim(),
      severity: document.getElementById('caSev').value,
      lead: document.getElementById('caLead').value.trim(),
      summary: document.getElementById('caSummary').value.trim(),
      agent_ids: [...document.querySelectorAll('#caHosts .ch:checked')].map(i => i.value),
      iocs: document.getElementById('caIocs').value.split('\n')
              .map(x => x.trim()).filter(Boolean),
    };
  }

  function newCase() {
    UI.modal('Open a case', caseForm(null),
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="caGo">Open</button>`);
    fillCaseHosts([]);
    document.getElementById('caGo').onclick = async () => {
      const err = document.getElementById('caErr');
      err.classList.add('hidden');
      try {
        const c = await API.createCase(readCase());
        UI.close(); UI.toast('Case opened', '', 'ok'); showCase(c.id);
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  async function editCase(id) {
    const c = await API.caseDetail(id);
    UI.modal(`Edit ${c.reference}`, caseForm(c),
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="caGo">Save</button>`);
    fillCaseHosts(c.agent_ids);
    document.getElementById('caGo').onclick = async () => {
      const err = document.getElementById('caErr');
      err.classList.add('hidden');
      try {
        await API.updateCase(id, readCase());
        UI.close(); UI.toast('Case updated', '', 'ok'); cases();
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  async function setCaseStatus(id, s) {
    try {
      await API.caseStatus(id, s);
      UI.toast(`Case marked ${s}`, '', 'ok');
      cases();
    } catch (e) { UI.toast('Could not change the status', e.message, 'err'); cases(); }
  }

  async function addCaseNote(id) {
    const box = document.getElementById('caseNote');
    const body = box.value.trim();
    if (!body) return;
    try { await API.caseNote(id, body); box.value = ''; cases(); }
    catch (e) { UI.toast('Could not add that', e.message, 'err'); }
  }

  async function caseHunt(id) {
    try {
      const r = await API.caseHunt(id);
      UI.toast(r.launched ? `${r.launched} hunts queued` : 'Nothing queued',
               r.launched ? `Carrying ${r.iocs} indicator(s)` : 'Every host is already busy.',
               r.launched ? 'ok' : 'err');
    } catch (e) { UI.toast('Could not sweep', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* Changes (scan diff)                                                  */
  /* ==================================================================== */

  let diffHost = null;

  async function diff() {
    loading();
    const hosts = await API.diffHosts();
    const usable = hosts.hosts.filter(h => h.comparable);

    if (!usable.length) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'Nothing to compare yet',
        'A comparison needs two completed scans of the same host.')}
        <p class="muted" style="text-align:center;font-size:12.5px">
          ${hosts.hosts.length
            ? `${hosts.hosts.length} host(s) have been scanned once. Run a second
               hunt, or set up a schedule so it happens on its own.`
            : 'No hosts have been scanned yet.'}
        </p>
        <div style="text-align:center">
          <button class="btn btn-primary" onclick="App.go('schedules')">Set up a schedule</button>
        </div></div></div>`;
      return;
    }

    if (!diffHost || !usable.some(h => h.agent_id === diffHost)) {
      diffHost = usable[0].agent_id;
    }
    const d = await API.diff(diffHost);

    const verdictColour = {
      worse: 'var(--crit)', better: '#2BD9A0',
      unchanged: 'var(--slate)', mixed: 'var(--med)',
    }[d.verdict] || 'var(--slate)';

    const group = (rows, label, colour, empty) => `
      <div class="card">
        <div class="card-h"><h2>${label}</h2><div class="spacer"></div>
          <span class="mono" style="color:${colour};font-weight:700">${rows.length}</span></div>
        ${rows.length ? `<div class="scroll" style="max-height:420px">
          ${rows.map(f => `
            <div style="border-left:3px solid ${colour};padding:9px 13px;margin-bottom:8px;
                        background:var(--deep);border-radius:0 5px 5px 0">
              <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:4px">
                <span class="${UI.sevClass(f.severity)}">${UI.esc(f.severity)}</span>
                <span class="tag mono">${UI.esc(f.rule_id)}</span>
              </div>
              <div style="font-weight:600;font-size:13px">${UI.esc(f.title)}</div>
              <div class="ev" style="margin-top:3px">${UI.esc(f.evidence)}</div>
            </div>`).join('')}
        </div>` : `<div class="muted" style="padding:8px 0">${empty}</div>`}
      </div>`;

    const hostOptions = usable.map(h =>
      `<option value="${UI.esc(h.agent_id)}" ${h.agent_id === diffHost ? 'selected' : ''}>
        ${UI.esc(h.hostname)} — ${h.scans} scans</option>`).join('');

    el().innerHTML = `<div class="view">
      <div class="filters" style="margin-bottom:18px">
        <select onchange="Views.setDiffHost(this.value)" style="min-width:280px">${hostOptions}</select>
        <span class="muted mono">${usable.length} host(s) can be compared</span>
      </div>

      <div class="card" style="margin-bottom:20px;border-left:3px solid ${verdictColour}">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>${UI.esc(d.hostname)}</h2>
          <div class="spacer"></div>
          <span class="stat-chip" style="background:${verdictColour};color:#fff">
            ${UI.esc(d.verdict)}</span>
        </div>
        <p style="font-size:15px;color:var(--silver);margin:0 0 14px">${UI.esc(d.headline)}</p>
        <div style="display:flex;gap:26px;flex-wrap:wrap;font-size:12.5px;color:var(--slate)">
          <span>Earlier scan: <b style="color:var(--silver)">${UI.ago(d.before.finished_at)}</b>
            · score ${d.before.risk_score}</span>
          <span>Latest scan: <b style="color:var(--silver)">${UI.ago(d.after.finished_at)}</b>
            · score ${d.after.risk_score}</span>
          <span>Change:
            <b style="color:${d.score_delta > 0 ? 'var(--crit)' : (d.score_delta < 0 ? '#2BD9A0' : 'var(--slate)')}">
              ${d.score_delta > 0 ? '+' : ''}${d.score_delta}</b></span>
        </div>
        <p class="muted" style="font-size:12.5px;margin:14px 0 0;max-width:86ch">
          Findings are matched by what they identify, not by their exact text —
          timestamps, process ids and counters move between scans, so a finding
          whose evidence reads differently is still recognised as the same one.
        </p>
      </div>

      <div class="grid g-2" style="margin-bottom:18px">
        ${group(d.appeared, 'Appeared since the last scan', 'var(--crit)',
                'Nothing new.')}
        ${group(d.resolved, 'No longer present', '#2BD9A0',
                'Nothing was cleared.')}
      </div>

      ${group(d.persisting, 'Unchanged', 'var(--slate)',
              'Nothing carried over.')}
    </div>`;
  }

  function setDiffHost(id) { diffHost = id; diff(); }

  /* ==================================================================== */
  /* Schedules                                                            */
  /* ==================================================================== */

  const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday',
                    'Friday', 'Saturday', 'Sunday'];

  async function schedules() {
    loading();
    const [d, fleet] = await Promise.all([API.schedules(), API.agents().catch(() => null)]);

    const rows = d.schedules.map(s => `
      <tr class="${s.enabled ? '' : 'closed'}">
        <td><label class="chk" style="padding:2px 6px;border:0;background:none">
          <input type="checkbox" ${s.enabled ? 'checked' : ''}
                 onchange="Views.toggleSchedule('${UI.esc(s.id)}', this.checked)"></label></td>
        <td><div style="font-weight:600">${UI.esc(s.name)}</div>
            <div class="why">${UI.esc(s.summary)} · ${UI.esc(s.scope)} · last ${s.days} days
            ${s.quick ? ' · quick' : ''}${s.collect_raw ? ' · raw evidence' : ''}</div></td>
        <td class="mono muted" style="font-size:11.5px">
          ${s.next_run_at && s.enabled ? UI.ago(s.next_run_at).replace(' ago', ' from now') : '—'}</td>
        <td class="mono muted" style="font-size:11.5px">
          ${s.last_run_at ? `${UI.ago(s.last_run_at)}<div>${s.last_run_count} hunts</div>` : 'never'}
          ${s.last_error ? `<div style="color:var(--crit)">${UI.esc(s.last_error.slice(0, 60))}</div>` : ''}</td>
        <td style="display:flex;gap:6px">
          <button class="btn btn-sm btn-ghost" onclick="Views.runSchedule('${UI.esc(s.id)}')">Run now</button>
          <button class="btn btn-sm btn-ghost" onclick="Views.editSchedule('${UI.esc(s.id)}')">Edit</button>
          <button class="btn btn-sm btn-ghost btn-danger" onclick="Views.deleteSchedule('${UI.esc(s.id)}')">Remove</button>
        </td>
      </tr>`).join('');

    const hostCount = fleet ? fleet.agents.length : 0;

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(d.total, 'Schedules', { accent: '#22D9F5' })}
        ${UI.stat(d.enabled, 'Active', { accent: '#2BD9A0' })}
        ${UI.stat(hostCount, 'Hosts they can reach', { accent: '#1B7FE8' })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Why schedule anything</h2>
          <div class="spacer"></div>
          <button class="btn btn-primary btn-sm" onclick="Views.newSchedule()">New schedule</button>
        </div>
        <p class="muted" style="margin:0;max-width:86ch">
          A single scan tells you what a host looks like. Two scans tell you what
          changed, which is the question worth asking when nothing has been
          reported — new persistence, a service that appeared, a cleanup that did
          not hold. Set a sweep running and read the <b>Changes</b> tab afterwards.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0">
          Hunts queue for offline hosts too and run when they come back. A host
          still working through the last sweep is skipped rather than stacked.
        </p>
      </div>

      ${d.total
        ? UI.table(['On', 'Schedule', 'Next run', 'Last run', ''], rows, { id: 'tblSched' })
        : `<div class="card">${UI.empty('No schedules yet',
            'Create one and the fleet sweeps itself.')}</div>`}
    </div>`;
  }

  function scheduleForm(s) {
    const isEdit = !!s;
    s = s || { name: '', frequency: 'weekly', hour_utc: 2, weekday: 6,
               days: 14, quick: false, collect_raw: false, agent_ids: [] };
    return `
      <div class="field"><label>Name</label>
        <input type="text" id="scName" value="${UI.esc(s.name)}"
               placeholder="Weekly fleet sweep" autocomplete="off"></div>

      <div class="grid" style="grid-template-columns:1fr 1fr 1fr;gap:14px">
        <div class="field"><label>How often</label>
          <select id="scFreq" onchange="Views.scheduleFreqChanged()">
            <option value="weekly" ${s.frequency === 'weekly' ? 'selected' : ''}>Weekly</option>
            <option value="daily" ${s.frequency === 'daily' ? 'selected' : ''}>Daily</option>
          </select></div>
        <div class="field" id="scDayWrap"><label>Day</label>
          <select id="scDay">${WEEKDAYS.map((d, i) =>
            `<option value="${i}" ${s.weekday === i ? 'selected' : ''}>${d}</option>`).join('')}
          </select></div>
        <div class="field"><label>Hour (UTC)</label>
          <select id="scHour">${Array.from({ length: 24 }, (_, h) =>
            `<option value="${h}" ${s.hour_utc === h ? 'selected' : ''}>${
              String(h).padStart(2, '0')}:00</option>`).join('')}
          </select></div>
      </div>

      <div class="field"><label>Look back</label>
        <select id="scDays">${[7, 14, 30, 60, 90].map(n =>
          `<option value="${n}" ${s.days === n ? 'selected' : ''}>${n} days</option>`).join('')}
        </select>
        <div class="hint">How far back each hunt reads event logs and file changes.</div></div>

      <label class="chk"><input type="checkbox" id="scQuick" ${s.quick ? 'checked' : ''}>
        <div><span>Quick mode</span>
        <small>Skips the file system phase. Faster, but misses recently written files.</small></div></label>
      <label class="chk"><input type="checkbox" id="scRaw" ${s.collect_raw ? 'checked' : ''}>
        <div><span>Collect raw evidence</span>
        <small>Registry hives, event logs, Prefetch. Produces gigabytes; leave off
        for routine sweeps.</small></div></label>

      <div class="hint" style="margin-top:12px">Runs against every enrolled host.</div>
      <div id="scErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`;
  }

  function scheduleFreqChanged() {
    const wrap = document.getElementById('scDayWrap');
    const freq = document.getElementById('scFreq').value;
    if (wrap) wrap.style.visibility = freq === 'daily' ? 'hidden' : 'visible';
  }

  function readScheduleForm() {
    return {
      name: document.getElementById('scName').value.trim(),
      frequency: document.getElementById('scFreq').value,
      weekday: Number(document.getElementById('scDay').value),
      hour_utc: Number(document.getElementById('scHour').value),
      days: Number(document.getElementById('scDays').value),
      quick: document.getElementById('scQuick').checked,
      collect_raw: document.getElementById('scRaw').checked,
      agent_ids: [],
    };
  }

  function newSchedule() {
    UI.modal('New schedule', scheduleForm(null),
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="scGo">Create</button>`);
    scheduleFreqChanged();
    document.getElementById('scGo').onclick = async () => {
      const err = document.getElementById('scErr');
      err.classList.add('hidden');
      try {
        await API.createSchedule(readScheduleForm());
        UI.close();
        UI.toast('Schedule created', '', 'ok');
        schedules();
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  async function editSchedule(id) {
    const d = await API.schedules();
    const s = d.schedules.find(x => x.id === id);
    if (!s) return;
    UI.modal('Edit schedule', scheduleForm(s),
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="scGo">Save</button>`);
    scheduleFreqChanged();
    document.getElementById('scGo').onclick = async () => {
      const err = document.getElementById('scErr');
      err.classList.add('hidden');
      try {
        await API.updateSchedule(id, readScheduleForm());
        UI.close();
        UI.toast('Schedule updated', '', 'ok');
        schedules();
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  async function toggleSchedule(id, enabled) {
    try { await API.toggleSchedule(id, enabled); schedules(); }
    catch (e) { UI.toast('Could not change that', e.message, 'err'); schedules(); }
  }

  async function runSchedule(id) {
    try {
      const r = await API.runSchedule(id);
      UI.toast(r.launched ? `${r.launched} hunts queued` : 'Nothing to queue',
               r.launched ? '' : 'Every host is already busy or none are enrolled.',
               r.launched ? 'ok' : 'err');
      schedules();
    } catch (e) { UI.toast('Could not run it', e.message, 'err'); }
  }

  async function deleteSchedule(id) {
    if (!confirm('Remove this schedule? Hunts already queued are unaffected.')) return;
    try {
      await API.deleteSchedule(id);
      UI.toast('Schedule removed', '', 'ok');
      schedules();
    } catch (e) { UI.toast('Could not remove it', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* IOC feeds                                                            */
  /* ==================================================================== */

  async function feeds() {
    loading();
    const [d, presets] = await Promise.all([API.feeds(), API.feedPresets()]);

    const rows = d.feeds.map(f => `
      <tr class="${f.enabled ? '' : 'closed'}">
        <td><label class="chk" style="padding:2px 6px;border:0;background:none">
          <input type="checkbox" ${f.enabled ? 'checked' : ''}
                 onchange="Views.toggleFeed('${UI.esc(f.id)}', this.checked)"></label></td>
        <td><div style="font-weight:600">${UI.esc(f.name)}</div>
            <div class="why mono">${UI.esc(f.url.slice(0, 66))}</div></td>
        <td><span class="tag">${UI.esc(f.kind)}</span>
            ${f.mode === 'watch'
              ? '<span class="tag" style="color:#FFC531;border-color:rgba(255,197,49,.4)">watch</span>'
              : '<span class="tag" style="color:var(--cyan);border-color:rgba(34,217,245,.4)">indicators</span>'}
            ${f.has_key ? '<span class="tag">key set</span>' : ''}</td>
        <td class="mono" style="font-weight:700">${f.mode === 'watch'
              ? (f.watch_hits && f.watch_hits.length
                  ? `<span style="color:var(--crit)">${f.watch_hits.length} hit</span>`
                  : '<span class="muted">watching</span>')
              : (f.indicator_count || '—')}
            ${f.mode !== 'watch' && Object.keys(f.breakdown || {}).length
              ? `<div class="tname">${Object.entries(f.breakdown)
                  .map(([k, v]) => `${k} ${v}`).join(' · ')}</div>` : ''}</td>
        <td class="mono muted" style="font-size:11.5px">
          ${f.last_fetch_at ? UI.ago(f.last_fetch_at) : 'never'}
          ${f.last_error ? `<div style="color:var(--crit)">${UI.esc(f.last_error.slice(0, 54))}</div>` : ''}</td>
        <td style="display:flex;gap:6px">
          <button class="btn btn-sm btn-ghost" onclick="Views.refreshFeed('${UI.esc(f.id)}')">Refresh</button>
          <button class="btn btn-sm btn-ghost" onclick="Views.editFeed('${UI.esc(f.id)}')">Edit</button>
          <button class="btn btn-sm btn-ghost btn-danger" onclick="Views.deleteFeed('${UI.esc(f.id)}')">Remove</button>
        </td>
      </tr>`).join('');

    // Watch hits are the one thing on this screen that wants shouting about:
    // your own name showing up on a leak-site feed. Surface it above everything.
    const watchHitFeeds = d.feeds.filter(f => f.mode === 'watch' && (f.watch_hits || []).length);
    const watchBanner = watchHitFeeds.length ? `
      <div class="notice bad-notice" style="margin-bottom:18px">
        <b>Your watch terms appeared on ${watchHitFeeds.length} feed${watchHitFeeds.length === 1 ? '' : 's'}</b>
        ${watchHitFeeds.map(f => `
          <div style="margin-top:8px">
            <div class="mono" style="font-size:12px;color:#FF9AAC">${UI.esc(f.name)}</div>
            ${(f.watch_hits || []).slice(0, 5).map(h =>
              `<div class="mono" style="font-size:11.5px;color:var(--slate);margin-left:8px">
                <b style="color:#FFB3C0">${UI.esc(h.term)}</b> — ${UI.esc((h.context || '').slice(0, 90))}</div>`).join('')}
            ${(f.watch_hits || []).length > 5 ? `<div class="muted" style="font-size:11px;margin-left:8px">… and ${f.watch_hits.length - 5} more</div>` : ''}
          </div>`).join('')}
        <p style="margin:10px 0 0;font-size:12.5px">Verify against the source before acting — a
        list can be stale, and another company may share your name.</p>
      </div>` : '';

    el().innerHTML = `<div class="view">
      ${watchBanner}
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(d.total, 'Feeds', { accent: '#22D9F5' })}
        ${UI.stat(d.pooled_indicators, 'Indicators in the pool', { accent: '#1B7FE8',
          sub: 'sent to every hunt' })}
        ${UI.stat(d.watch_feeds || 0, 'Watch feeds', { accent: '#FFC531',
          sub: (d.watch_hits ? `${d.watch_hits} hit${d.watch_hits === 1 ? '' : 's'}` : 'your name, not your hosts') })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Where indicators come from</h2>
          <div class="spacer"></div>
          <button class="btn btn-primary btn-sm" onclick="Views.newFeed()">Add a feed</button>
        </div>
        <p class="muted" style="margin:0;max-width:86ch">
          Pasting a list before every hunt is a habit nobody keeps. An <b>indicator</b>
          feed is fetched once and reused: every enabled one is merged into the hunt
          and matched on each host, so a C2 address you know about is caught the
          moment a host talks to it — no rule to write.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0">
          A <b style="color:#FFC531">watch</b> feed is the opposite: victim and
          leak-site lists, scanned here for <i>your</i> names. Its values are never
          sent to a host, so browsing a listed company's site is never mistaken for
          an intrusion. Indicators are cached — a slow feed never delays a sweep —
          and private addresses and obvious noise (127.0.0.1, 8.8.8.8) are dropped
          on the way in.
        </p>
      </div>

      ${d.total
        ? UI.table(['On', 'Feed', 'Mode', 'Indicators', 'Last fetch', ''], rows,
                   { id: 'tblFeeds' })
        : `<div class="card">${UI.empty('No feeds configured',
            'Add one, or keep pasting indicators by hand when you launch a hunt.')}
            <div style="display:flex;gap:9px;flex-wrap:wrap;justify-content:center;margin-top:6px">
              ${presets.presets.map((p, i) =>
                `<button class="btn btn-sm" onclick="Views.newFeed(${i})">${UI.esc(p.name)}</button>`).join('')}
            </div></div>`}
    </div>`;
  }

  let feedPresets = [];

  async function newFeed(presetIndex) {
    if (!feedPresets.length) {
      try { feedPresets = (await API.feedPresets()).presets; } catch (_) {}
    }
    const p = (presetIndex !== undefined) ? feedPresets[presetIndex] : null;
    feedForm(null, p);
  }

  async function editFeed(id) {
    const d = await API.feeds();
    const f = d.feeds.find(x => x.id === id);
    if (f) feedForm(f, null);
  }

  function feedForm(f, preset) {
    const isEdit = !!f;
    const v = f || {
      name: preset ? preset.name : '', kind: preset ? preset.kind : 'http',
      mode: preset ? (preset.mode || 'indicators') : 'indicators',
      url: preset ? preset.url : '', header_name: '', tags: '', days: 30,
      verify_tls: true, enabled: true, auto_include: true, has_key: false,
      watch_terms: '',
    };

    UI.modal(isEdit ? 'Edit feed' : 'Add an indicator feed', `
      ${preset ? `<div class="hint" style="margin-bottom:14px">${UI.esc(preset.note)}</div>` : ''}
      <div class="grid" style="grid-template-columns:2fr 1fr;gap:14px">
        <div class="field"><label>Name</label>
          <input type="text" id="fdName" value="${UI.esc(v.name)}"
                 placeholder="Feodo Tracker C2" autocomplete="off"></div>
        <div class="field"><label>Type</label>
          <select id="fdKind" onchange="Views.feedKindChanged()">
            <option value="http" ${v.kind === 'http' ? 'selected' : ''}>HTTP / API</option>
            <option value="misp" ${v.kind === 'misp' ? 'selected' : ''}>MISP</option>
          </select></div>
      </div>

      <div class="field"><label>What this feed is for</label>
        <div class="modepick">
          <label class="modeopt ${v.mode !== 'watch' ? 'on' : ''}" id="modeInd">
            <input type="radio" name="fdMode" value="indicators" ${v.mode !== 'watch' ? 'checked' : ''}
                   onchange="Views.feedModeChanged()">
            <div><b>Indicators</b><small>Known-bad values — C2 IPs, hashes, URLs.
              Sent to every host and matched against live activity. A match is a
              CRITICAL finding.</small></div>
          </label>
          <label class="modeopt ${v.mode === 'watch' ? 'on' : ''}" id="modeWatch">
            <input type="radio" name="fdMode" value="watch" ${v.mode === 'watch' ? 'checked' : ''}
                   onchange="Views.feedModeChanged()">
            <div><b>Watch</b><small>Victim / leak-site lists. Never sent to a host —
              the console tells you if <i>your</i> names appear on it.</small></div>
          </label>
        </div></div>

      <div class="field"><label>URL</label>
        <input type="text" id="fdUrl" value="${UI.esc(v.url)}"
               placeholder="https://feodotracker.abuse.ch/downloads/ipblocklist.txt" autocomplete="off">
        <div class="hint" id="fdUrlHint">JSON or plain text. Anything indicator-shaped
        in the response is picked up — no per-provider mapping needed.</div></div>

      <div class="field"><label>API key ${v.has_key ? '<span class="muted">(one is stored)</span>' : '<span class="muted">(optional)</span>'}</label>
        <input type="text" id="fdKey" placeholder="${v.has_key ? 'Leave blank to keep the current key' : 'Only if the feed needs one'}"
               autocomplete="off"></div>

      <div id="fdHttpOnly" class="field"><label>Header name <span class="muted">(optional)</span></label>
        <input type="text" id="fdHeader" value="${UI.esc(v.header_name)}"
               placeholder="e.g. Auth-Key for ThreatFox — blank for Authorization: Bearer" autocomplete="off"></div>

      <div id="fdMispOnly" style="display:none">
        <div class="grid" style="grid-template-columns:2fr 1fr;gap:14px">
          <div class="field"><label>Tags <span class="muted">(optional)</span></label>
            <input type="text" id="fdTags" value="${UI.esc(v.tags)}"
                   placeholder="tlp:amber, ransomware" autocomplete="off"></div>
          <div class="field"><label>Look back</label>
            <select id="fdDays">${[7, 30, 90, 365].map(n =>
              `<option value="${n}" ${v.days === n ? 'selected' : ''}>${n} days</option>`).join('')}
            </select></div>
        </div>
        <div class="hint">Only attributes MISP marks <span class="mono">to_ids</span> are
        pulled, and its own warninglist is applied — so known-good values are dropped
        by MISP before they reach here.</div>
      </div>

      <div id="fdWatchOnly" style="display:none">
        <div class="field"><label>Watch terms</label>
          <textarea id="fdWatchTerms" placeholder="acme.com, acme-corp, ACME Ltd"
                    style="min-height:60px">${UI.esc(v.watch_terms)}</textarea>
          <div class="hint">Your own domains and brand names, comma or newline separated.
          You are alerted if any appear in this feed. These are matched here in the
          console — they are never sent to a host.</div></div>
      </div>

      <label class="chk"><input type="checkbox" id="fdTls" ${v.verify_tls ? 'checked' : ''}>
        <div><span>Verify the TLS certificate</span>
        <small>Turn off only for an internal MISP with a self-signed certificate.</small></div></label>
      <label class="chk" id="fdAutoRow"><input type="checkbox" id="fdAuto" ${v.auto_include ? 'checked' : ''}>
        <div><span>Attach to every hunt</span>
        <small>Off keeps the feed stored but out of the pool.</small></div></label>

      <div id="fdResult" style="margin-top:14px"></div>
      <div id="fdErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn" id="fdTest">Test</button>
       <button class="btn btn-primary" id="fdGo">${isEdit ? 'Save' : 'Add feed'}</button>`);

    feedKindChanged();
    feedModeChanged();

    const read = () => ({
      name: document.getElementById('fdName').value.trim(),
      kind: document.getElementById('fdKind').value,
      mode: (document.querySelector('input[name="fdMode"]:checked') || {}).value || 'indicators',
      url: document.getElementById('fdUrl').value.trim(),
      api_key: document.getElementById('fdKey').value.trim() || (isEdit ? null : ''),
      header_name: document.getElementById('fdHeader').value.trim(),
      tags: (document.getElementById('fdTags') || {}).value || '',
      days: Number((document.getElementById('fdDays') || {}).value || 30),
      verify_tls: document.getElementById('fdTls').checked,
      auto_include: document.getElementById('fdAuto').checked,
      watch_terms: (document.getElementById('fdWatchTerms') || {}).value || '',
      enabled: true,
    });

    document.getElementById('fdTest').onclick = async () => {
      const out = document.getElementById('fdResult');
      const err = document.getElementById('fdErr');
      err.classList.add('hidden');
      out.innerHTML = '<div class="hint"><span class="spinner"></span> Fetching…</div>';
      try {
        const r = await API.testFeed(read());
        if (r.mode === 'watch') {
          out.innerHTML = `
            <div class="notice" style="background:var(--deep);border:1px solid var(--edge);
                 border-left:3px solid ${r.hits && r.hits.length ? 'var(--crit)' : 'var(--cyan)'}">
              <b>${r.hits && r.hits.length
                ? `${r.hits.length} watch match${r.hits.length === 1 ? '' : 'es'} — your terms appear in this feed`
                : `Feed reachable · ${r.count} line${r.count === 1 ? '' : 's'} scanned · no matches for your terms`}</b>
              ${r.hits && r.hits.length ? `<div class="mono" style="font-size:11px;color:#FF9AAC;margin-top:8px">
                ${r.hits.slice(0, 6).map(h => `<b>${UI.esc(h.term)}</b> — ${UI.esc(h.context.slice(0, 80))}`).join('<br>')}
              </div>` : ''}
              <div class="hint" style="margin-top:8px">${UI.esc(r.pool_note || '')}</div>
            </div>`;
        } else {
          out.innerHTML = `
            <div class="notice" style="background:var(--deep);border:1px solid var(--edge);
                 border-left:3px solid var(--cyan)">
              <b>${r.count} indicator${r.count === 1 ? '' : 's'} found</b>
              <div class="mono" style="font-size:11px;color:var(--slate);margin-top:6px">
                ${Object.entries(r.breakdown || {}).map(([k, v]) => `${k}: ${v}`).join(' · ')}
              </div>
              <div class="mono" style="font-size:11px;color:var(--slate-d);margin-top:6px">
                ${(r.sample || []).slice(0, 6).map(x => UI.esc(x)).join('<br>')}
              </div>
            </div>`;
        }
      } catch (e) {
        out.innerHTML = '';
        err.textContent = e.message;
        err.classList.remove('hidden');
      }
    };

    document.getElementById('fdGo').onclick = async () => {
      const err = document.getElementById('fdErr');
      err.classList.add('hidden');
      try {
        if (isEdit) await API.updateFeed(f.id, read());
        else await API.createFeed(read());
        UI.close();
        const watch = (document.querySelector('input[name="fdMode"]:checked') || {}).value === 'watch';
        UI.toast(isEdit ? 'Feed saved' : 'Feed added',
                 isEdit ? '' : (watch ? 'Refresh it to scan for your terms.' : 'Refresh it to pull indicators.'), 'ok');
        feeds();
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  function feedKindChanged() {
    const kind = document.getElementById('fdKind').value;
    const mode = (document.querySelector('input[name="fdMode"]:checked') || {}).value || 'indicators';
    const http = document.getElementById('fdHttpOnly');
    const misp = document.getElementById('fdMispOnly');
    const hint = document.getElementById('fdUrlHint');
    const url = document.getElementById('fdUrl');
    const name = document.getElementById('fdName');
    // MISP-only block never shows in watch mode; header/http block only for http.
    if (http) http.style.display = (kind === 'misp' || mode === 'watch') ? 'none' : '';
    if (misp) misp.style.display = (kind === 'misp' && mode !== 'watch') ? '' : 'none';
    // The placeholder bug: these were hardcoded to a tweetfeed URL, so picking
    // MISP still showed an HTTP example. Drive them from the current type.
    if (url && !url.value) {
      url.placeholder = kind === 'misp'
        ? 'https://misp.your-org.local'
        : 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt';
    }
    if (name && !name.value) {
      name.placeholder = kind === 'misp' ? 'Corporate MISP' : 'Feodo Tracker C2';
    }
    if (hint) {
      hint.textContent = kind === 'misp'
        ? 'The base URL of your MISP, without a path. The API key comes from your MISP profile page.'
        : 'JSON or plain text. Anything indicator-shaped in the response is picked up.';
    }
  }

  function feedModeChanged() {
    const mode = (document.querySelector('input[name="fdMode"]:checked') || {}).value || 'indicators';
    const watch = document.getElementById('fdWatchOnly');
    const autoRow = document.getElementById('fdAutoRow');
    const mi = document.getElementById('modeInd');
    const mw = document.getElementById('modeWatch');
    if (watch) watch.style.display = mode === 'watch' ? '' : 'none';
    // "Attach to every hunt" is meaningless for a watch feed — it never joins
    // the pool. Hide it so the two ideas do not read as related.
    if (autoRow) autoRow.style.display = mode === 'watch' ? 'none' : '';
    if (mi) mi.classList.toggle('on', mode !== 'watch');
    if (mw) mw.classList.toggle('on', mode === 'watch');
    feedKindChanged();  // re-evaluate which sub-blocks show
  }

  async function refreshFeed(id) {
    UI.toast('Fetching…', '', 'ok');
    try {
      const r = await API.refreshFeed(id);
      UI.toast(`${r.feed.indicator_count} indicators`,
               `${r.added} new, ${r.removed} gone`, 'ok');
      feeds();
    } catch (e) { UI.toast('Could not refresh that feed', e.message, 'err'); feeds(); }
  }

  async function toggleFeed(id, enabled) {
    try { await API.toggleFeed(id, enabled); feeds(); }
    catch (e) { UI.toast('Could not change that', e.message, 'err'); feeds(); }
  }

  async function deleteFeed(id) {
    if (!confirm('Remove this feed? Its indicators leave the pool.')) return;
    try { await API.deleteFeed(id); UI.toast('Feed removed', '', 'ok'); feeds(); }
    catch (e) { UI.toast('Could not remove it', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* Threat intel — reputation keys and scored addresses                  */
  /* ==================================================================== */

  const LABEL_STYLE = {
    malicious:  { c: '#FF2D55', t: 'malicious' },
    suspicious: { c: '#FF7A00', t: 'suspicious' },
    noise:      { c: '#FFC531', t: 'scanner noise' },
    benign:     { c: '#2BD9A0', t: 'benign' },
    unknown:    { c: '#7A93B8', t: 'unknown' },
    unrated:    { c: '#4A6285', t: 'not looked up' },
  };

  function repBadge(label, score) {
    const s = LABEL_STYLE[label] || LABEL_STYLE.unknown;
    return `<span class="repbadge" style="color:${s.c};border-color:${s.c}44;background:${s.c}14">
      ${score ? `<b>${score}</b>` : ''}${UI.esc(s.t)}</span>`;
  }

  async function intel() {
    loading();
    const [d, rep] = await Promise.all([
      API.enrichment(), API.reputation().catch(() => ({ addresses: [] })),
    ]);

    const cards = d.providers.map(p => `
      <div class="card intel-card ${p.enabled ? 'on' : ''}">
        <div class="card-h">
          <h2>${UI.esc(p.name)}</h2>
          <div class="spacer"></div>
          ${p.free
            ? '<span class="tag" style="color:#2BD9A0;border-color:rgba(43,217,160,.4)">free tier</span>'
            : '<span class="tag" style="color:#FFC531;border-color:rgba(255,197,49,.4)">paid</span>'}
          ${p.enabled ? '<span class="tag" style="color:#22D9F5;border-color:rgba(34,217,245,.4)">on</span>' : ''}
        </div>
        <p class="muted" style="margin:0 0 4px;font-size:13px"><b style="color:var(--silver)">Asks:</b>
          ${UI.esc(p.asks)}</p>
        <p class="muted" style="margin:0;font-size:12.5px">${UI.esc(p.note)}</p>

        <div style="display:flex;gap:9px;flex-wrap:wrap;margin-top:13px;align-items:center">
          <input type="password" id="ek_${UI.esc(p.provider)}" autocomplete="off"
                 style="flex:1;min-width:190px"
                 placeholder="${p.has_key ? 'A key is stored — type to replace it'
                                          : (p.provider === 'threatfox' ? 'Optional Auth-Key' : 'Paste API key')}">
          <button class="btn btn-sm" onclick="Views.testIntelKey('${UI.esc(p.provider)}')">Test</button>
          <button class="btn btn-sm btn-primary" onclick="Views.saveIntelKey('${UI.esc(p.provider)}', true)">
            ${p.enabled ? 'Save' : 'Save &amp; enable'}</button>
          ${p.enabled
            ? `<button class="btn btn-sm btn-ghost" onclick="Views.saveIntelKey('${UI.esc(p.provider)}', false)">Turn off</button>`
            : ''}
          ${p.has_key
            ? `<button class="btn btn-sm btn-ghost btn-danger" onclick="Views.clearIntelKey('${UI.esc(p.provider)}')">Remove key</button>`
            : ''}
        </div>

        <div class="intel-foot">
          ${p.daily_limit
            ? `<span class="mono">${p.calls_today}/${p.daily_limit} today</span>`
            : `<span class="mono">${p.calls_today} lookup${p.calls_today === 1 ? '' : 's'} today</span>`}
          ${p.ok_count || p.fail_count
            ? `<span class="mono muted">${p.ok_count} ok · ${p.fail_count} failed</span>` : ''}
          ${p.signup ? `<a href="${UI.esc(p.signup)}" target="_blank" rel="noopener">Get a key</a>` : ''}
        </div>
        ${p.last_error
          ? `<div class="notice warn-notice" style="margin-top:10px"><b>${UI.esc(p.last_error)}</b>
             <p>Recorded against this provider, not against any address — a rejected
             key says nothing about whether an address is malicious.</p></div>` : ''}
        <div id="ekr_${UI.esc(p.provider)}"></div>
      </div>`).join('');

    const rows = (rep.addresses || []).map(a => `
      <tr>
        <td class="mono" style="font-weight:600">${UI.esc(a.address)}</td>
        <td>${repBadge(a.label, a.score)}
            ${a.known_good ? '<div class="tname" style="color:#2BD9A0">known-good service</div>' : ''}</td>
        <td>${Object.entries(a.verdicts || {}).map(([name, v]) => `
              <div style="font-size:12px;margin-bottom:3px">
                <b class="mono" style="color:var(--slate)">${UI.esc(name)}</b>
                <span style="color:${(LABEL_STYLE[v.label] || LABEL_STYLE.unknown).c}">${UI.esc(v.summary || '')}</span>
              </div>`).join('') || '<span class="muted">—</span>'}</td>
        <td class="mono muted" style="font-size:11.5px">${a.fetched_at ? UI.ago(a.fetched_at) : '—'}
            ${a.stale ? '<div class="tname">stale</div>' : ''}</td>
      </tr>`).join('');

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(d.enabled, 'Providers on', { accent: '#22D9F5',
          sub: `${d.providers.length} available` })}
        ${UI.stat(d.cached, 'Addresses scored', { accent: '#1B7FE8' })}
        ${UI.stat(d.flagged, 'Flagged bad', { accent: '#FF2D55', glow: d.flagged > 0 })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>What this is for</h2>
          <div class="spacer"></div>
          <button class="btn btn-hunt btn-sm" onclick="Views.runIntel()"
            ${d.enabled ? '' : 'disabled'}>Score addresses now</button>
        </div>
        <p class="muted" style="margin:0;max-width:88ch">
          An indicator feed applies what you already knew — a C2 on the list is
          caught the moment a host talks to it. This does the opposite job: it takes
          the external addresses a hunt <i>already found</i> and asks who they are.
          Without it, sixty addresses on the graph all look equally worth
          investigating, and triage starts with whichever one is busiest — which is
          nearly always a DNS server.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0;max-width:88ch">
          Each provider's verdict is kept whole rather than blended into one number:
          they measure different things, and an average is a figure none of them
          would stand behind. The badge shows the worst verdict, with the provider
          that gave it. Results are cached for ${d.cache_hours} hours and each run
          looks up at most ${d.max_per_run} addresses, so a free tier lasts.
        </p>
      </div>

      <div class="grid g-2" style="margin-bottom:20px">${cards}</div>

      <div class="card-h"><h2>Scored addresses</h2><div class="spacer"></div>
        <span class="muted mono" style="font-size:11.5px">worst first — this is the triage order</span></div>
      ${rows
        ? UI.table(['Address', 'Verdict', 'What each provider said', 'Checked'], rows,
                   { id: 'tblRep' })
        : `<div class="card">${UI.empty('Nothing scored yet',
            d.enabled
              ? 'Run a hunt, or press "Score addresses now" to look up what the fleet has already seen.'
              : 'Add a key above first — the AbuseIPDB free tier is the one to start with.')}</div>`}
    </div>`;
  }

  function intelKey(provider) {
    const box = document.getElementById(`ek_${provider}`);
    return box ? box.value.trim() : '';
  }

  async function saveIntelKey(provider, enabled) {
    try {
      const key = intelKey(provider);
      await API.saveEnrichKey(provider, {
        // Sending null rather than "" leaves a stored key untouched, so
        // toggling a provider off and on does not wipe its credential.
        api_key: key || null,
        enabled,
      });
      UI.toast(enabled ? 'Provider on' : 'Provider off', '', 'ok');
      intel();
    } catch (e) { UI.toast('Could not save that', e.message, 'err'); }
  }

  async function testIntelKey(provider) {
    const out = document.getElementById(`ekr_${provider}`);
    out.innerHTML = '<div class="hint" style="margin-top:10px"><span class="spinner"></span> Asking the provider…</div>';
    try {
      const r = await API.testEnrichKey(provider, intelKey(provider) || null);
      out.innerHTML = `<div class="notice" style="margin-top:10px;background:var(--deep);
        border:1px solid var(--edge);border-left:3px solid #2BD9A0">
        <b style="color:#2BD9A0">Key works</b>
        <p>Test address <span class="mono">${UI.esc(r.probe)}</span> —
        ${UI.esc(r.verdict.summary || '')}</p></div>`;
    } catch (e) {
      out.innerHTML = `<div class="notice bad-notice" style="margin-top:10px">
        <b>${UI.esc(e.message)}</b></div>`;
    }
  }

  async function clearIntelKey(provider) {
    if (!confirm('Remove this key? The provider is switched off with it.')) return;
    try { await API.clearEnrichKey(provider); UI.toast('Key removed', '', 'ok'); intel(); }
    catch (e) { UI.toast('Could not remove it', e.message, 'err'); }
  }

  async function runIntel() {
    UI.toast('Looking up addresses…', 'This runs in the background.', 'ok');
    try {
      const r = await API.runEnrichment({});
      UI.toast(`${r.looked_up} address${r.looked_up === 1 ? '' : 'es'} scored`,
        r.remaining ? `${r.remaining} left for the next run — the per-run cap protects your quota.` : '',
        'ok');
      intel();
    } catch (e) { UI.toast('Could not score addresses', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* Integrations and API tokens                                          */
  /* ==================================================================== */

  async function integrations() {
    loading();
    const [d, t] = await Promise.all([API.integrations(), API.tokens().catch(() => null)]);

    const rows = d.integrations.map(i => `
      <tr class="${i.enabled ? '' : 'closed'}">
        <td><div style="font-weight:600">${UI.esc(i.name)}</div>
            <div class="why mono">${UI.esc(i.transport === 'syslog'
              ? `${i.host}:${i.port}` : i.url.slice(0, 60))}</div></td>
        <td><span class="tag">${UI.esc(i.transport)}</span>
            ${i.transport !== 'email'
              ? `<span class="tag mono">${UI.esc(i.format)}</span>` : ''}</td>
        <td><span class="${UI.sevClass(i.min_severity)}">${UI.esc(i.min_severity)}+</span></td>
        <td class="mono">${i.sent_count}
            ${i.failed_count ? `<div style="color:var(--crit)">${i.failed_count} failed</div>` : ''}</td>
        <td class="mono muted" style="font-size:11.5px">
          ${i.last_success_at ? UI.ago(i.last_success_at) : 'never'}
          ${i.last_error ? `<div style="color:var(--crit)">${UI.esc(i.last_error.slice(0, 50))}</div>` : ''}</td>
        <td><button class="btn btn-sm btn-ghost btn-danger"
              onclick="Views.deleteIntegration('${UI.esc(i.id)}')">Remove</button></td>
      </tr>`).join('');

    const tokenRows = t ? t.tokens.map(k => `
      <tr class="${k.enabled ? '' : 'closed'}">
        <td><label class="chk" style="padding:2px 6px;border:0;background:none">
          <input type="checkbox" ${k.enabled ? 'checked' : ''}
                 onchange="Views.toggleToken('${UI.esc(k.id)}', this.checked)"></label></td>
        <td><div style="font-weight:600">${UI.esc(k.name)}</div>
            <div class="why mono">${UI.esc(k.prefix)}…</div></td>
        <td><span class="rolechip">${UI.esc(k.role)}</span></td>
        <td class="mono muted">${k.use_count}</td>
        <td class="mono muted" style="font-size:11.5px">
          ${k.last_used_at ? UI.ago(k.last_used_at) : 'never'}</td>
        <td><button class="btn btn-sm btn-ghost btn-danger"
              onclick="Views.deleteToken('${UI.esc(k.id)}')">Revoke</button></td>
      </tr>`).join('') : '';

    el().innerHTML = `<div class="view">
      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Sending findings out</h2>
          <div class="spacer"></div>
          <button class="btn btn-primary btn-sm" onclick="Views.newIntegration()">Add destination</button>
        </div>
        <p class="muted" style="margin:0;max-width:88ch">
          A hunting console nobody opens is a hunting console nobody reads.
          Findings can be pushed into Wazuh, Splunk, QRadar or an inbox — whatever
          people already watch. What travels is the <b>finding</b>: a decision this
          tool made, with its evidence and MITRE technique. Not raw event log; the
          SIEM already has that.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0">
          Delivery happens off-thread and never blocks a hunt. If the destination is
          down the finding is still recorded here and the failure shows on its row.
          A cap of 500 findings per hunt applies, so one noisy sweep cannot flood a
          SIEM the way it once flooded this console.
        </p>
      </div>

      ${d.total
        ? UI.table(['Destination', 'Type', 'Floor', 'Sent', 'Last success', ''], rows,
                   { id: 'tblInteg' })
        : `<div class="card">${UI.empty('No destinations configured',
            'Findings stay in this console until you add one.')}</div>`}

      <div class="card-h" style="margin-top:28px">
        <h2>API tokens</h2><div class="spacer"></div>
        <button class="btn btn-sm" onclick="Views.newToken()">New token</button>
      </div>
      <p class="muted" style="margin:0 0 14px;max-width:86ch;font-size:13px">
        For scripts, schedulers and anything else that needs to read Douglas
        without a browser. Only a fingerprint is stored, so a copy of the database
        does not hand over working keys. Tokens cannot hold admin — account
        management should need a person.
      </p>
      ${t && t.total
        ? UI.table(['On', 'Token', 'Role', 'Uses', 'Last used', ''], tokenRows,
                   { id: 'tblTokens' })
        : `<div class="card">${UI.empty('No tokens issued', '')}</div>`}
    </div>`;
  }

  async function newIntegration() {
    let fmt = { formats: [], transports: [], fields: {}, groups: [] };
    try { fmt = await API.integrationFormats(); } catch (_) {}
    intFormats = fmt;

    UI.modal('Send findings somewhere', `
      <div class="grid" style="grid-template-columns:2fr 1fr;gap:14px">
        <div class="field"><label>Name</label>
          <input type="text" id="inName" placeholder="Wazuh manager" autocomplete="off"></div>
        <div class="field"><label>Transport</label>
          <select id="inTransport" onchange="Views.integrationTransportChanged()">
            ${fmt.transports.map(t =>
              `<option value="${UI.esc(t.id)}">${UI.esc(t.name)}</option>`).join('')}
          </select></div>
      </div>

      <div class="field" id="inFormatWrap"><label>Where it goes</label>
        <select id="inFormat" onchange="Views.integrationFormatChanged()">
          ${(fmt.groups || [{ id: '', name: '' }]).map(g => {
            const inGroup = fmt.formats.filter(f => (f.group || '') === g.id);
            if (!inGroup.length) return '';
            return `<optgroup label="${UI.esc(g.name)}">${inGroup.map(f =>
              `<option value="${UI.esc(f.id)}">${UI.esc(f.name)}</option>`).join('')}</optgroup>`;
          }).join('')}
        </select>
        <div class="hint" id="inFormatNote"></div></div>

      <div id="inHttp">
        <div class="field"><label>URL</label>
          <input type="text" id="inUrl" placeholder="https://wazuh.example.local:55000/events"
                 autocomplete="off">
          <div class="hint">Any endpoint that accepts a JSON POST. Wazuh's integrator
          or a logstash-style collector both work.</div></div>
        <div class="field"><label>API key <span class="muted">(optional)</span></label>
          <input type="text" id="inKey" placeholder="Sent as Authorization: Bearer"
                 autocomplete="off">
          <div class="hint" id="inKeyNote">For Splunk this is the HEC token.</div></div>
        <div id="inSplunk" style="display:none">
          <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
            <div class="field"><label>Index <span class="muted">(optional)</span></label>
              <input type="text" id="inIndex" placeholder="main" autocomplete="off"></div>
            <div class="field"><label>Sourcetype <span class="muted">(optional)</span></label>
              <input type="text" id="inSourcetype" placeholder="douglas:finding"
                     autocomplete="off"></div>
          </div>
        </div>
      </div>

      <div id="inEmail" style="display:none">
        <div class="grid" style="grid-template-columns:2fr 1fr;gap:14px">
          <div class="field"><label>SMTP server</label>
            <input type="text" id="inMailHost" placeholder="smtp.example.local"
                   autocomplete="off"></div>
          <div class="field"><label>Port</label>
            <input type="text" id="inMailPort" value="587" autocomplete="off"></div>
        </div>
        <div class="field"><label>Recipients</label>
          <input type="text" id="inTo" placeholder="soc@example.com, ir@example.com"
                 autocomplete="off"></div>
        <div class="grid" style="grid-template-columns:1fr 1fr;gap:14px">
          <div class="field"><label>From</label>
            <input type="text" id="inFrom" placeholder="douglas042@example.com"
                   autocomplete="off"></div>
          <div class="field"><label>Username <span class="muted">(optional)</span></label>
            <input type="text" id="inMailUser" placeholder="Leave blank for no auth"
                   autocomplete="off"></div>
        </div>
        <label class="chk"><input type="checkbox" id="inStartTls" checked>
          <div><span>STARTTLS</span><small>Usual for port 587.</small></div></label>
        <label class="chk"><input type="checkbox" id="inSsl">
          <div><span>Implicit SSL</span><small>Usual for port 465.</small></div></label>
        <div class="hint">The mail is a readable summary, not JSON — it leads with the
        worst finding and the host, and exists to make someone open the console.</div>
      </div>

      <div id="inSyslog" style="display:none">
        <div class="grid" style="grid-template-columns:2fr 1fr;gap:14px">
          <div class="field"><label>Host</label>
            <input type="text" id="inHost" placeholder="wazuh.example.local" autocomplete="off"></div>
          <div class="field"><label>Port</label>
            <input type="text" id="inPort" value="514" autocomplete="off"></div>
        </div>
        <div class="hint">One JSON object per datagram, prefixed
        <span class="mono">douglas042:</span> so a Wazuh decoder can pick it out.
        Long evidence is trimmed to survive the datagram.</div>
      </div>

      <div class="field"><label>Only send</label>
        <select id="inFloor">
          <option value="CRITICAL">Critical only</option>
          <option value="HIGH">High and above</option>
          <option value="MEDIUM" selected>Medium and above</option>
          <option value="LOW">Low and above</option>
          <option value="INFO">Everything</option>
        </select>
        <div class="hint">A cap of 500 findings per hunt applies regardless, so one
        noisy sweep cannot flood the SIEM.</div></div>

      <label class="chk"><input type="checkbox" id="inTls" checked>
        <div><span>Verify the TLS certificate</span></div></label>
      <div id="inErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>
      <div id="inOk" class="hidden" style="color:#2BD9A0;font-size:13px;margin-top:12px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn" id="inTest">Send a test event</button>
       <button class="btn btn-primary" id="inGo">Add</button>`);

    integrationTransportChanged();

    const val = (id, d = '') => {
      const e = document.getElementById(id);
      return e ? e.value.trim() : d;
    };
    const read = () => {
      const transport = document.getElementById('inTransport').value;
      return {
        name: val('inName') || 'Destination',
        kind: transport === 'email' ? 'email' : 'siem',
        transport,
        format: val('inFormat', 'json'),
        url: val('inUrl'),
        host: transport === 'email' ? val('inMailHost') : val('inHost'),
        port: Number(transport === 'email'
          ? (val('inMailPort') || 587) : (val('inPort') || 514)),
        api_key: val('inKey'),
        index_name: val('inIndex'),
        sourcetype: val('inSourcetype'),
        recipients: val('inTo'),
        mail_from: val('inFrom'),
        mail_user: val('inMailUser'),
        use_tls: (document.getElementById('inStartTls') || {}).checked !== false,
        use_ssl: !!(document.getElementById('inSsl') || {}).checked,
        verify_tls: document.getElementById('inTls').checked,
        min_severity: document.getElementById('inFloor').value,
        enabled: true,
      };
    };
    Views._integrationNotes = Object.fromEntries(fmt.formats.map(f => [f.id, f.note]));

    document.getElementById('inTest').onclick = async () => {
      const err = document.getElementById('inErr');
      const ok = document.getElementById('inOk');
      err.classList.add('hidden'); ok.classList.add('hidden');
      try {
        const r = await API.testIntegration(read());
        ok.textContent = r.message;
        ok.classList.remove('hidden');
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };

    document.getElementById('inGo').onclick = async () => {
      const err = document.getElementById('inErr');
      err.classList.add('hidden');
      try {
        await API.createIntegration(read());
        UI.close();
        UI.toast('Destination added', 'Findings will be forwarded after each hunt.', 'ok');
        integrations();
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  function integrationTransportChanged() {
    const t = document.getElementById('inTransport').value;
    const show = (id, on) => {
      const e = document.getElementById(id);
      if (e) e.style.display = on ? '' : 'none';
    };
    show('inHttp', t === 'http');
    show('inSyslog', t === 'syslog');
    show('inEmail', t === 'email');
    // Email has its own layout; a wire format would mean nothing there.
    show('inFormatWrap', t !== 'email');
    integrationFormatChanged();
  }

  // The catalogue the form was built from. Field labels come from the server
  // so they cannot drift from what the sender actually reads — Sentinel's
  // workspace ID and PagerDuty's routing key both live in general-purpose
  // columns, and a form that mislabels them produces an integration that fails
  // with a confusing error.
  let intFormats = { formats: [], transports: [], fields: {}, groups: [] };

  function integrationFormatChanged() {
    const sel = document.getElementById('inFormat');
    if (!sel) return;
    const chosen = sel.value;
    const spec = (intFormats.formats || []).find(f => f.id === chosen) || {};
    const fields = (intFormats.fields || {})[chosen] || {};

    const note = document.getElementById('inFormatNote');
    if (note) note.textContent = spec.note || '';

    // A destination that carries its own settings gets its own two boxes,
    // labelled for that product rather than for Splunk.
    const extra = document.getElementById('inSplunk');
    const wantsExtra = fields.index_name || fields.sourcetype;
    if (extra) extra.style.display = (chosen === 'splunk' || wantsExtra) ? '' : 'none';

    const label = (id, text) => {
      const box = document.getElementById(id);
      if (!box) return;
      const field = box.closest('.field');
      const lab = field && field.querySelector('label');
      if (lab) lab.textContent = text;
      if (field) field.style.display = text ? '' : 'none';
    };
    label('inIndex', fields.index_name || (chosen === 'splunk' ? 'Index' : ''));
    label('inSourcetype', fields.sourcetype || (chosen === 'splunk' ? 'Sourcetype' : ''));

    // A webhook URL is the credential, so asking for a key as well is a way to
    // have somebody paste a token that is never sent.
    const keyField = document.getElementById('inKey');
    if (keyField) {
      const wrap = keyField.closest('.field');
      const needsKey = fields.api_key !== null;
      if (wrap) wrap.style.display = needsKey ? '' : 'none';
      const lab = wrap && wrap.querySelector('label');
      if (lab && fields.api_key) lab.textContent = fields.api_key;
      else if (lab) lab.innerHTML = 'API key <span class="muted">(optional)</span>';
    }
    const keyNote = document.getElementById('inKeyNote');
    if (keyNote) {
      keyNote.textContent = chosen === 'splunk'
        ? 'The HEC token, sent as Authorization: Splunk <token>.'
        : chosen === 'sentinel'
        ? 'The workspace primary or secondary key. The request is signed with it, not bearer-authenticated.'
        : chosen === 'elastic'
        ? 'Sent as Authorization: ApiKey <key>.'
        : 'Sent as Authorization: Bearer <key>.';
    }

    const urlField = document.getElementById('inUrl');
    if (urlField && fields.url !== undefined) {
      const wrap = urlField.closest('.field');
      if (wrap) wrap.style.display = fields.url === null ? 'none' : '';
      const lab = wrap && wrap.querySelector('label');
      if (lab && fields.url) lab.textContent = fields.url;
      urlField.placeholder = {
        slack: 'https://hooks.slack.com/services/T000/B000/xxxx',
        teams: 'https://prod-00.westeurope.logic.azure.com:443/workflows/...',
        pagerduty: 'https://events.pagerduty.com/v2/enqueue',
        thehive: 'https://thehive.example.local',
        elastic: 'https://elastic.example.local:9200/_bulk',
        splunk: 'https://splunk.example.local:8088/services/collector/event',
      }[chosen] || 'https://wazuh.example.local:55000/events';
    }

    // Chat and paging destinations flood if the floor is low. Nudge it once,
    // rather than leaving somebody to discover it through their colleagues.
    const sev = document.getElementById('inFloor');
    if (sev && spec.group === 'notify' && ['INFO', 'LOW', 'MEDIUM'].includes(sev.value)) {
      sev.value = 'HIGH';
    }
  }

  async function deleteIntegration(id) {
    if (!confirm('Remove this destination? Findings stop being forwarded.')) return;
    try { await API.deleteIntegration(id); integrations(); }
    catch (e) { UI.toast('Could not remove it', e.message, 'err'); }
  }

  function newToken() {
    UI.modal('New API token', `
      <div class="field"><label>Name</label>
        <input type="text" id="tkName" placeholder="Wazuh reader" autocomplete="off">
        <div class="hint">What this token is for. It appears in the activity log.</div></div>
      <div class="field"><label>Role</label>
        <select id="tkRole">
          <option value="viewer" selected>Viewer — reads findings and reports</option>
          <option value="responder">Responder — also launches hunts</option>
        </select></div>
      <div class="field"><label>Expires</label>
        <select id="tkExp">
          <option value="0">Never</option>
          <option value="30">In 30 days</option>
          <option value="90">In 90 days</option>
          <option value="365">In a year</option>
        </select></div>
      <div id="tkOut" style="margin-top:16px"></div>
      <div id="tkErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="tkGo">Create</button>`);

    document.getElementById('tkGo').onclick = async () => {
      const err = document.getElementById('tkErr');
      err.classList.add('hidden');
      try {
        const r = await API.createToken({
          name: document.getElementById('tkName').value.trim(),
          role: document.getElementById('tkRole').value,
          expires_days: Number(document.getElementById('tkExp').value),
        });
        document.getElementById('tkOut').innerHTML = `
          <div class="notice warn-notice">
            <b>Copy this now. It is not shown again.</b>
            <div class="code" style="margin-top:8px;word-break:break-all">${UI.esc(r.token)}</div>
            <p style="margin-top:8px">Send it as
            <span class="mono">Authorization: Bearer &lt;token&gt;</span>.</p>
          </div>`;
        const btn = document.getElementById('tkGo');
        btn.textContent = 'Done';
        btn.onclick = () => { UI.close(); integrations(); };
      } catch (e) { err.textContent = e.message; err.classList.remove('hidden'); }
    };
  }

  async function toggleToken(id, enabled) {
    try { await API.toggleToken(id, enabled); }
    catch (e) { UI.toast('Could not change that', e.message, 'err'); integrations(); }
  }

  async function deleteToken(id) {
    if (!confirm('Revoke this token? Anything using it stops working immediately.')) return;
    try { await API.deleteToken(id); UI.toast('Token revoked', '', 'ok'); integrations(); }
    catch (e) { UI.toast('Could not revoke it', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* Built-in detections                                                  */
  /* ==================================================================== */

  let ruleFilter = 'all';
  // Which category the table is narrowed to, and the last payload the rules
  // view loaded — kept so opening a rule's detail does not refetch the whole
  // catalogue just to read one row.
  let ruleCategory = '';
  let cachedRules = {};

  async function rules() {
    loading();
    const d = await API.builtinRules();
    cachedRules = d;

    const shown = d.rules.filter(r => {
      if (ruleCategory && r.category !== ruleCategory) return false;
      if (ruleFilter === 'fired') return r.fired > 0;
      if (ruleFilter === 'quiet') return r.fired === 0;
      if (ruleFilter === 'suppressed') return r.suppressed;
      if (ruleFilter === 'off') return !r.enabled;
      return true;
    });

    const rows = shown.map(r => `
      <tr class="clickable ${r.enabled ? '' : 'closed'}"
          onclick="Views.ruleDetail('${UI.esc(r.rule_id)}')">
        <td onclick="event.stopPropagation()">
          <label class="chk" style="padding:2px 6px;border:0;background:none">
            <input type="checkbox" ${r.enabled ? 'checked' : ''}
                   onchange="Views.toggleRule('${UI.esc(r.rule_id)}', this.checked)"></label></td>
        <td class="mono muted">${UI.esc(r.rule_id)}</td>
        <td>${r.severity
          ? `<span class="${UI.sevClass(r.severity)}">${UI.esc(r.severity)}</span>`
          : '<span class="muted" title="Severity is decided when the rule fires; some rules vary it by what they find">varies</span>'}</td>
        <td><div style="font-weight:600">${UI.esc(r.title || r.rule_id)}</div>
            ${r.looks_for ? `<div class="why">${UI.esc(r.looks_for.slice(0, 130))}</div>` : ''}</td>
        <td><span class="tag">${UI.esc(r.category_name)}</span></td>
        <td class="mono muted">${UI.esc(r.mitre)}
            ${r.mitre_name ? `<div class="tname">${UI.esc(r.mitre_name)}</div>` : ''}</td>
        <td class="mono" style="font-weight:${r.fired ? '700' : '400'};${
          r.fired > 100 ? 'color:var(--high)' : ''}">${r.fired || '—'}</td>
        <td>${!r.enabled ? '<span class="stat-chip st-suppressed">off</span>' : ''}
            ${r.suppressed ? '<span class="stat-chip st-suppressed">suppressed</span>' : ''}</td>
      </tr>`).join('');

    const chip = (label, key, n) =>
      `<button class="fchip ${ruleFilter === key ? 'on' : ''}"
        onclick="Views.setRuleFilter('${key}')">${label}${n !== undefined ? ` ${n}` : ''}</button>`;

    // Category strip: counts, and a switch for the whole family. Turning off
    // sixteen rules one at a time is the kind of chore people skip, and then
    // the noise stays.
    const catCards = d.categories.map(c => `
      <div class="catcard ${ruleCategory === c.id ? 'on' : ''} ${c.enabled === 0 ? 'off' : ''}"
           onclick="Views.setRuleCategory('${UI.esc(c.id)}')">
        <div class="catname">${UI.esc(c.name)}</div>
        <div class="catsum">${UI.esc(c.summary)}</div>
        <div class="catnums">
          <span class="mono"><b>${c.enabled}</b>/${c.total} on</span>
          ${c.findings ? `<span class="mono" style="color:var(--high)">${c.findings} finding${c.findings === 1 ? '' : 's'}</span>` : ''}
        </div>
        <div class="catacts" onclick="event.stopPropagation()">
          <button class="btn btn-sm btn-ghost"
            onclick="Views.toggleCategory('${UI.esc(c.id)}', true)"
            ${c.enabled === c.total ? 'disabled' : ''}>Enable all</button>
          <button class="btn btn-sm btn-ghost btn-danger"
            onclick="Views.toggleCategory('${UI.esc(c.id)}', false)"
            ${c.enabled === 0 ? 'disabled' : ''}>Disable all</button>
        </div>
      </div>`).join('');

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(d.total, 'DGL rules', { accent: '#22D9F5',
          sub: `${d.categories.length} categories` })}
        ${UI.stat(d.total - d.disabled, 'Switched on', { accent: '#2BD9A0',
          sub: d.disabled ? `${d.disabled} off` : 'all of them' })}
        ${UI.stat(d.fired, 'Have fired here', { accent: '#1B7FE8' })}
        ${UI.stat(d.suppressed, 'Suppressed', { accent: '#7A93B8' })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>DGL rules — the built-in detections</h2>
        </div>
        <p class="muted" style="margin:0;max-width:86ch">
          These ship with the collector and run on every hunt — the baseline that
          works before any community rule is loaded. Sigma and YARA add to this set,
          they do not replace it. Click any rule to read what it checks.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0;max-width:86ch">
          <b>Fired</b> counts findings produced <i>in this console</i>. A dash is
          usually the healthy answer: DGL-014 only fires when a log looks cleared,
          DGL-044 only when a web server spawns a shell. The list is what the tool
          checks, not what is wrong.
        </p>
        <p class="muted" style="font-size:12.5px;margin:8px 0 0;max-width:86ch">
          <b style="color:var(--silver)">Switching a rule off is not the same as
          suppressing it.</b> Off means the collector never runs the check, so
          nothing is produced and there is nothing to review. A suppression records
          the finding and marks it as a decision somebody made, with a reason
          attached. Use off for a whole family of noise you have accepted; use
          suppression for a specific pattern on a specific host.
        </p>
      </div>

      <div class="card-h"><h2>Categories</h2><div class="spacer"></div>
        ${ruleCategory
          ? `<button class="btn btn-sm btn-ghost" onclick="Views.setRuleCategory('')">Show every category</button>`
          : '<span class="muted mono" style="font-size:11.5px">click one to filter · enable or disable a whole family</span>'}
      </div>
      <div class="catgrid">${catCards}</div>

      <div class="filters" style="margin-top:18px">
        ${chip('All', 'all', d.total)}
        ${chip('Fired here', 'fired', d.fired)}
        ${chip('Never fired', 'quiet', d.total - d.fired)}
        ${chip('Switched off', 'off', d.disabled)}
        ${chip('Suppressed', 'suppressed', d.suppressed)}
        <span class="muted mono">${shown.length} shown${
          ruleCategory ? ` · ${UI.esc((d.categories.find(c => c.id === ruleCategory) || {}).name || '')}` : ''}</span>
      </div>
      ${UI.table(['On', 'Rule', 'Severity', 'Detection', 'Category', 'MITRE', 'Fired', ''],
                 rows, { id: 'tblRules' })}
    </div>`;
  }

  function setRuleFilter(v) { ruleFilter = v; rules(); }
  function setRuleCategory(v) { ruleCategory = (ruleCategory === v) ? '' : v; rules(); }

  async function toggleRule(ruleId, enabled) {
    try {
      await API.toggleBuiltinRules({ rule_ids: [ruleId], enabled });
      UI.toast(enabled ? `${ruleId} on` : `${ruleId} off`,
        enabled ? 'It runs again on the next hunt.'
                : 'The collector will skip it from the next hunt.', 'ok');
      rules();
    } catch (e) { UI.toast('Could not change that', e.message, 'err'); rules(); }
  }

  async function toggleCategory(category, enabled) {
    const cat = (cachedRules.categories || []).find(c => c.id === category) || {};
    if (!enabled && !confirm(
      `Switch off all ${cat.total || ''} rules in "${cat.name || category}"?\n\n`
      + 'The collector stops running these checks entirely — nothing is collected '
      + 'and nothing is recorded for them. Findings they already produced stay.')) return;
    try {
      const r = await API.toggleBuiltinRules({ category, enabled });
      UI.toast(`${cat.name || category}: ${r.changed} rule${r.changed === 1 ? '' : 's'} ${enabled ? 'on' : 'off'}`,
        enabled ? '' : 'These run on no host from the next hunt.', 'ok');
      rules();
    } catch (e) { UI.toast('Could not change those', e.message, 'err'); rules(); }
  }

  async function ruleDetail(ruleId) {
    const d = cachedRules.rules ? cachedRules : await API.builtinRules();
    const r = d.rules.find(x => x.rule_id === ruleId);
    if (!r) return;

    const cat = (d.categories || []).find(c => c.id === r.category) || {};

    UI.modal(`${r.rule_id} — ${r.title || 'Not seen yet'}`, `
      <div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:16px">
        ${r.severity ? `<span class="${UI.sevClass(r.severity)}">${UI.esc(r.severity)}</span>` : ''}
        <span class="tag">${UI.esc(r.category_name)}</span>
        ${r.mitre ? `<span class="tag mono">${UI.esc(r.mitre)}${
          r.mitre_name ? ' · ' + UI.esc(r.mitre_name) : ''}</span>` : ''}
        <span class="tag">${r.fired} finding${r.fired === 1 ? '' : 's'}</span>
        ${r.hosts ? `<span class="tag">${r.hosts} host${r.hosts === 1 ? '' : 's'}</span>` : ''}
        ${r.enabled
          ? '<span class="tag" style="color:#2BD9A0;border-color:rgba(43,217,160,.4)">running</span>'
          : '<span class="tag" style="color:#FF7A00;border-color:rgba(255,122,0,.4)">switched off</span>'}
      </div>

      ${(r.looks_for || r.next_step) ? `
        <div class="guide">
          ${r.looks_for ? `<div class="gitem"><b>What this rule checks</b><p>${UI.esc(r.looks_for)}</p></div>` : ''}
          ${r.benign ? `<div class="gitem"><b>How it fires legitimately</b><p>${UI.esc(r.benign)}</p></div>` : ''}
          ${r.next_step ? `<div class="gitem next"><b>Next step</b><p>${UI.esc(r.next_step)}</p></div>` : ''}
        </div>`
        : `<div class="hint">No analyst guidance is recorded for this rule yet. Its
           title is what it reports when it fires: <b>${UI.esc(r.title || r.rule_id)}</b>.</div>`}

      <div class="card" style="background:var(--deep);margin-top:16px">
        <div class="card-h"><h2>${UI.esc(cat.name || r.category_name)}</h2></div>
        <p class="muted" style="margin:0;font-size:13px">${UI.esc(cat.detail || cat.summary || '')}</p>
        ${cat.total ? `<div class="hint" style="margin-top:10px">
          ${cat.enabled} of ${cat.total} rules in this category are running.</div>` : ''}
      </div>

      <div class="hint" style="margin-top:14px">
        ${r.enabled
          ? 'Switching this off stops the collector running the check at all — no finding is produced and there is nothing to review. To keep the detection but hide a known-noisy case, suppress it from one of its findings instead.'
          : 'This check is not running. Switch it back on and it resumes on the next hunt; nothing needs redeploying.'}
      </div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Close</button>
       ${r.fired ? `<button class="btn" onclick="UI.close();Views.reviewRule('${UI.esc(r.rule_id)}')">See its findings</button>` : ''}
       <button class="btn ${r.enabled ? 'btn-ghost btn-danger' : 'btn-primary'}"
         onclick="UI.close();Views.toggleRule('${UI.esc(r.rule_id)}', ${!r.enabled})">
         ${r.enabled ? 'Switch off' : 'Switch on'}</button>`);
  }

  /* ==================================================================== */
  /* YARA rules                                                           */
  /* ==================================================================== */

  let yaraFilter = { severity: '', search: '' };

  async function yara() {
    loading();
    const [sum, list] = await Promise.all([
      API.yaraSummary(), API.yaraRules({ limit: 1000, ...yaraFilter }),
    ]);

    const sourceCard = `
      <div class="card" id="yaraUpdCard" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Rule source</h2><div class="spacer"></div>
          <span class="muted mono" style="font-size:11.5px">${
            sum.last_update ? 'Last updated ' + UI.ago(sum.last_update) : 'Never updated'}</span>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start">
          <input type="text" id="yaraSource" value="${UI.esc(sum.source_url)}"
                 style="flex:1;min-width:300px" ${sum.running ? 'disabled' : ''}>
          <button class="btn btn-hunt" onclick="Views.yaraUpdateNow()" ${sum.running ? 'disabled' : ''}>
            ${sum.running ? '<span class="spinner"></span> Updating' : 'Update now'}</button>
          <button class="btn" onclick="Views.yaraUpload()">Upload rules</button>
        </div>
        ${sum.running ? `
          <div class="pbar" style="margin-top:12px"><i id="yaraBar" style="width:${sum.percent}%"></i></div>
          <div class="phase" style="margin-top:8px"><div class="phase-txt">
            <div class="phase-name" id="yaraPhase">${UI.esc(sum.phase)}</div>
            <div class="phase-detail" id="yaraDetail">${UI.esc(sum.detail)}</div></div></div>` : ''}
        ${(!sum.running && sum.error) ? `
          <div class="notice warn-notice"><b>The last update did not finish</b>
            <p>${UI.esc(sum.error)}</p></div>` : ''}
        ${(!sum.running && sum.result) ? `
          <div class="hint" style="margin-top:10px">
            ${sum.result.added} added, ${sum.result.updated} updated,
            ${sum.result.rejected} not supported · took ${sum.result.seconds}s</div>` : ''}
      </div>`;

    if (!sum.total) {
      el().innerHTML = `<div class="view">
        <div class="card">${UI.empty('No YARA rules loaded',
          'Fetch them from a repository, or upload a .yar file or archive.')}</div>
        ${sourceCard}
        ${yaraHelp()}
      </div>`;
      return;
    }

    const rows = list.rules.map(r => `
      <tr>
        <td><span class="${UI.sevClass(r.severity)}">${UI.esc(r.severity)}</span></td>
        <td><div style="font-weight:600">${UI.esc(r.name)}</div>
            ${r.description ? `<div class="why">${UI.esc(r.description.slice(0, 130))}</div>` : ''}</td>
        <td class="mono muted">${r.string_count}</td>
        <td class="mono muted" style="font-size:11px">${UI.esc(r.condition_text.slice(0, 46))}</td>
        <td class="mono muted" style="font-size:11px">${UI.esc((r.source || '').split('/').pop())}</td>
      </tr>`).join('');

    const chip = (label, value) =>
      `<button class="fchip ${yaraFilter.severity === value ? 'on' : ''}"
        onclick="Views.yaraSetFilter('${value}')">${label}</button>`;

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(sum.total, 'Rules loaded', { accent: '#22D9F5' })}
        ${UI.stat(sum.enabled, 'Enabled', { accent: '#2BD9A0' })}
        ${UI.stat(sum.by_severity.CRITICAL || 0, 'Critical', { accent: '#FF2D55' })}
        ${UI.stat(sum.by_severity.HIGH || 0, 'High', { accent: '#FF7A00' })}
      </div>
      ${sourceCard}
      ${yaraHelp()}
      <div class="filters" style="margin-top:18px">
        ${chip('All', '')} ${chip('Critical', 'CRITICAL')} ${chip('High', 'HIGH')}
        ${chip('Medium', 'MEDIUM')}
        <input type="search" id="yaraSearch" placeholder="Search rule names and descriptions"
               value="${UI.esc(yaraFilter.search)}"
               onkeydown="if(event.key==='Enter')Views.yaraSetSearch(this.value)">
        <span class="muted mono">${list.rules.length} of ${list.total}</span>
        <button class="btn btn-sm btn-ghost btn-danger" onclick="Views.yaraClear()">Remove all</button>
      </div>
      ${UI.table(['Severity', 'Rule', 'Strings', 'Condition', 'File'], rows, { id: 'tblYara' })}
    </div>`;
  }

  function yaraHelp() {
    return `<div class="card">
      <div class="card-h"><h2>What YARA support here can and cannot do</h2></div>
      <p class="muted" style="margin-top:0;max-width:88ch">
        There is no YARA engine in PowerShell. Shipping <span class="mono">yara64.exe</span>
        to every host would mean putting an extra binary on a machine you are trying to
        examine quietly, so instead the console compiles the part of the language that does
        <b>file content matching</b> — text and hex strings, wildcards, regular expressions,
        <span class="mono">nocase</span>, <span class="mono">wide</span>,
        <span class="mono">fullword</span>, size bounds and boolean conditions.
      </p>
      <p class="muted" style="font-size:13px;max-width:88ch">
        Rules that need the <span class="mono">pe</span>, <span class="mono">math</span> or
        <span class="mono">hash</span> modules, integer reads or byte offsets are
        <b>refused with a reason</b> rather than half-evaluated. Most public YARA rules do PE
        structure analysis, so expect a large share of any repository to be rejected — that
        is the honest number, not a failure.
      </p>
      <p class="muted" style="font-size:13px;margin-bottom:0">
        Scanning targets the files the collector already flagged: recently written
        executables, web root files, archives and attacker tooling. It is not a
        whole-volume scan.
      </p>
    </div>`;
  }

  function yaraSetFilter(v) { yaraFilter.severity = v; yara(); }
  function yaraSetSearch(v) { yaraFilter.search = v; yara(); }

  async function yaraUpdateNow() {
    const input = document.getElementById('yaraSource');
    try {
      await API.yaraUpdate(input ? input.value.trim() : null, false);
      UI.toast('Update started', 'Downloading and compiling.', 'ok');
      yaraWatch();
      yara();
    } catch (e) { UI.toast('Could not start the update', e.message, 'err'); }
  }

  let yaraPoll = null;
  function yaraWatch() {
    clearInterval(yaraPoll);
    yaraPoll = setInterval(async () => {
      try {
        const s = await API.yaraSummary();
        const bar = document.getElementById('yaraBar');
        if (bar) bar.style.width = `${s.percent || 0}%`;
        const ph = document.getElementById('yaraPhase');
        if (ph) ph.textContent = s.phase || '';
        const de = document.getElementById('yaraDetail');
        if (de) de.textContent = s.detail || '';
        if (!s.running) {
          clearInterval(yaraPoll); yaraPoll = null;
          if (App.currentView() === 'yara') yara();
        }
      } catch (_) { clearInterval(yaraPoll); yaraPoll = null; }
    }, 2000);
  }

  async function yaraClear() {
    if (!confirm('Remove every YARA rule?')) return;
    try {
      const r = await API.yaraClear();
      UI.toast(`Removed ${r.deleted} rules`, '', 'ok');
      yara();
    } catch (e) { UI.toast('Could not remove them', e.message, 'err'); }
  }

  function yaraUpload() {
    UI.modal('Upload YARA rules', `
      <p class="muted" style="margin-top:0">
        A <span class="mono">.yar</span> file, or a <span class="mono">.zip</span> of a
        rule repository. Rules are compiled and validated here before storage.
      </p>
      <div class="field"><label>Rule file</label>
        <input type="file" id="yFile" accept=".yar,.yara,.zip" style="padding:9px 12px"></div>
      <label class="chk"><input type="checkbox" id="yReplace">
        <div><span>Replace the current set</span></div></label>
      <div id="yResult" style="margin-top:16px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="yGo">Upload</button>`);

    document.getElementById('yGo').onclick = async () => {
      const f = document.getElementById('yFile').files[0];
      if (!f) { UI.toast('Pick a file first', '', 'err'); return; }
      const btn = document.getElementById('yGo');
      const out = document.getElementById('yResult');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Compiling';
      try {
        const res = await API.yaraUpload(f, document.getElementById('yReplace').checked);
        const reasons = (res.rejection_reasons || []).map(r =>
          `<tr><td class="mono">${r.count}</td><td>${UI.esc(r.reason)}</td></tr>`).join('');
        out.innerHTML = `
          <div class="grid g-stats" style="margin-bottom:14px">
            ${UI.stat(res.added, 'Added', { accent: '#2BD9A0' })}
            ${UI.stat(res.updated, 'Updated', { accent: '#1B7FE8' })}
            ${UI.stat(res.rejected, 'Rejected', { accent: res.rejected ? '#FF7A00' : '#5D7A9E' })}
          </div>
          ${reasons ? `<div class="hint" style="margin-bottom:8px">Why rules were rejected.</div>
            <div class="scroll" style="max-height:200px"><table><thead><tr><th>Count</th>
            <th>Reason</th></tr></thead><tbody>${reasons}</tbody></table></div>` : ''}`;
        btn.textContent = 'Done';
        btn.onclick = () => { UI.close(); yara(); };
        btn.disabled = false;
      } catch (e) {
        out.innerHTML = `<div style="color:var(--crit);font-size:13px">${UI.esc(e.message)}</div>`;
        btn.disabled = false; btn.textContent = 'Upload';
      }
    };
  }

  /* ==================================================================== */
  /* Sigma rules                                                          */
  /* ==================================================================== */

  let sigmaFilter = { channel: '', level: '', search: '' };

  async function sigma() {
    loading();
    const [sum, list, upd] = await Promise.all([
      API.sigmaSummary(),
      API.sigmaRules({ limit: 1200, ...sigmaFilter }),
      API.sigmaUpdateStatus(),
    ]);

    if (!sum.total) {
      el().innerHTML = `<div class="view">
        <div class="card">${UI.empty('No Sigma rules loaded',
          'Fetch them from the repository, or upload an archive if this console has no internet access.')}
          <div style="text-align:center;display:flex;gap:10px;justify-content:center;flex-wrap:wrap">
            <button class="btn btn-hunt" onclick="Views.sigmaUpdateNow()">Update from repository</button>
            <button class="btn" onclick="Views.sigmaUpload()">Upload an archive</button>
          </div>
        </div>
        ${sigmaUpdateCard(upd)}
        ${sigmaHelp()}
      </div>`;
      return;
    }

    const channels = Object.entries(sum.by_channel).sort((a, b) => b[1] - a[1]);
    const chanRows = channels.map(([ch, n]) => `
      <div class="bar-row">
        <div class="lab" title="${UI.esc(ch)}">${UI.esc(ch.replace('Microsoft-Windows-', ''))}</div>
        <div class="trk"><i style="width:${(n / channels[0][1]) * 100}%;background:var(--electric)"></i></div>
        <div class="val">${n}</div>
      </div>`).join('');

    const rows = list.rules.map(r => `
      <tr>
        <td><label class="chk" style="padding:2px 6px;border:0;background:none">
          <input type="checkbox" ${r.enabled ? 'checked' : ''}
                 onchange="Views.sigmaToggle('${UI.esc(r.id)}', this.checked)"></label></td>
        <td><span class="${UI.sevClass(r.severity)}">${UI.esc(r.level)}</span></td>
        <td><div style="font-weight:600">${UI.esc(r.title)}</div>
            ${r.description ? `<div class="why">${UI.esc(r.description.slice(0, 130))}</div>` : ''}</td>
        <td class="mono muted" style="font-size:11px">${UI.esc(r.channel.replace('Microsoft-Windows-', ''))}
            ${r.event_ids.length ? `<div>${r.event_ids.join(', ')}</div>` : ''}</td>
        <td class="mono muted">${UI.esc(r.mitre)}
            ${r.mitre_name && r.mitre_name !== r.mitre
              ? `<div class="tname">${UI.esc(r.mitre_name)}</div>` : ''}</td>
        <td class="mono muted" style="font-size:11px">${UI.esc((r.source || '').split('/').pop())}</td>
      </tr>`).join('');

    const chip = (label, key, value) =>
      `<button class="fchip ${sigmaFilter[key] === value ? 'on' : ''}"
        onclick="Views.sigmaSetFilter('${key}','${value}')">${label}</button>`;

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(sum.total, 'Rules loaded', { accent: '#22D9F5' })}
        ${UI.stat(sum.enabled, 'Enabled', { accent: '#2BD9A0',
          sub: sum.enabled < sum.total ? `${sum.total - sum.enabled} switched off` : 'all active' })}
        ${UI.stat(sum.by_level.critical || 0, 'Critical', { accent: '#FF2D55' })}
        ${UI.stat(sum.by_level.high || 0, 'High', { accent: '#FF7A00' })}
      </div>

      <div class="grid g-2" style="margin-bottom:18px">
        <div class="card">
          <div class="card-h">
            <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
            <h2>Rules by log channel</h2>
          </div>
          ${chanRows}
          <p class="muted" style="font-size:12.5px;margin:14px 0 0">
            Rules only fire on channels this tool collects. Sysmon rules need Sysmon
            installed on the host; without it they load but never match.
          </p>
        </div>
        <div class="card">
          <div class="card-h"><h2>Manage the set</h2></div>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
            <button class="btn btn-hunt btn-sm" id="sigUpdBtn"
                    onclick="Views.sigmaUpdateNow()">Update from repository</button>
            <button class="btn btn-primary btn-sm" onclick="Views.sigmaUpload()">Upload rules</button>
            <button class="btn btn-sm" onclick="Views.sigmaBulk('level','critical',true)">Enable all critical</button>
            <button class="btn btn-sm" onclick="Views.sigmaBulk('level','low',false)">Disable all low</button>
            <button class="btn btn-sm btn-ghost btn-danger" onclick="Views.sigmaClear()">Remove all</button>
          </div>
          <p class="muted" style="font-size:12.5px;margin:0">
            Rules are compiled when you upload them, so anything unsupported is
            rejected while you are looking at it rather than failing silently on
            a host later. Agents fetch the enabled set at the start of every hunt.
          </p>
        </div>
      </div>

      ${sigmaUpdateCard(upd)}

      <div class="filters">
        ${chip('All levels', 'level', '')}
        ${chip('Critical', 'level', 'critical')}
        ${chip('High', 'level', 'high')}
        ${chip('Medium', 'level', 'medium')}
        ${chip('Low', 'level', 'low')}
        <input type="search" id="sigSearch" placeholder="Search titles, descriptions, MITRE IDs"
               value="${UI.esc(sigmaFilter.search)}"
               onkeydown="if(event.key==='Enter')Views.sigmaSetFilter('search', this.value)">
        <span class="muted mono">${list.rules.length} of ${list.total}</span>
      </div>
      ${UI.table(['On', 'Level', 'Rule', 'Channel', 'MITRE', 'File'], rows, { id: 'tblSigma' })}
    </div>`;
  }

  function sigmaUpdateCard(upd) {
    const when = upd.last_update
      ? `Last updated ${UI.ago(upd.last_update)}`
      : 'Never updated from a repository';

    const running = upd.running ? `
      <div class="pbar" style="margin-top:12px"><i id="sigBar" style="width:${upd.percent}%"></i></div>
      <div class="phase" style="margin-top:8px">
        <div class="phase-txt">
          <div class="phase-name" id="sigPhase">${UI.esc(upd.phase)}</div>
          <div class="phase-detail" id="sigDetail">${UI.esc(upd.detail)}</div>
        </div>
      </div>` : '';

    const failed = (!upd.running && upd.error) ? `
      <div class="notice warn-notice">
        <b>The last update did not finish</b>
        <p>${UI.esc(upd.error)}</p>
        <button class="btn btn-sm" onclick="Views.sigmaUpload()">Upload an archive instead</button>
      </div>` : '';

    const done = (!upd.running && upd.result) ? `
      <div class="hint" style="margin-top:10px">
        ${upd.result.added} added, ${upd.result.updated} updated,
        ${upd.result.rejected} not supported${
          upd.result.kept_disabled ? `, ${upd.result.kept_disabled} kept switched off` : ''}
        · took ${upd.result.seconds}s
      </div>` : '';

    return `<div class="card" id="sigUpdCard" style="margin-bottom:18px">
      <div class="card-h">
        <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
        <h2>Rule source</h2>
        <div class="spacer"></div>
        <span class="muted mono" style="font-size:11.5px">${UI.esc(when)}</span>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start">
        <input type="text" id="sigSource" value="${UI.esc(upd.source_url)}"
               style="flex:1;min-width:300px" ${upd.running ? 'disabled' : ''}>
        <button class="btn btn-hunt" onclick="Views.sigmaUpdateNow()"
                ${upd.running ? 'disabled' : ''}>
          ${upd.running ? '<span class="spinner"></span> Updating' : 'Update now'}</button>
      </div>
      <div class="hint" style="margin-top:8px">
        The console only fetches when you ask it to. On an isolated network this
        will fail — that is expected, and Upload rules is the way in.
      </div>
      ${running}${failed}${done}
    </div>`;
  }

  async function sigmaUpdateNow() {
    const input = document.getElementById('sigSource');
    const url = input ? input.value.trim() : null;
    try {
      await API.sigmaUpdate(url || null, false);
      UI.toast('Update started', 'Downloading and compiling; this takes about a minute.', 'ok');
      sigmaWatchUpdate();
      sigma();
    } catch (e) {
      UI.toast('Could not start the update', e.message, 'err');
    }
  }

  // Progress arrives over the websocket; this is the fallback for consoles
  // behind a proxy that blocks upgrades.
  let sigmaPoll = null;
  function sigmaWatchUpdate() {
    clearInterval(sigmaPoll);
    sigmaPoll = setInterval(async () => {
      try {
        const s = await API.sigmaUpdateStatus();
        Views.sigmaPatchProgress(s);
        if (!s.running) {
          clearInterval(sigmaPoll);
          sigmaPoll = null;
          if (App.currentView() === 'sigma') sigma();
        }
      } catch (_) { clearInterval(sigmaPoll); sigmaPoll = null; }
    }, 2000);
  }

  function sigmaPatchProgress(s) {
    const bar = document.getElementById('sigBar');
    if (bar) bar.style.width = `${s.percent || 0}%`;
    const ph = document.getElementById('sigPhase');
    if (ph) ph.textContent = s.phase || '';
    const de = document.getElementById('sigDetail');
    if (de) de.textContent = s.detail || '';
  }

  function sigmaHelp() {
    return `<div class="card" style="margin-top:18px">
      <div class="card-h"><h2>Where to get rules</h2></div>
      <p class="muted" style="margin-top:0">
        The SigmaHQ repository is the community standard and is MIT licensed.
        Update now fetches it directly. If this console has no route out — the usual
        case on an incident-response network — download the archive on a machine that
        does and use Upload rules instead.
      </p>
      <div class="code">https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip</div>
      <p class="muted" style="font-size:12.5px;margin:12px 0 0">
        Upload the zip as-is. Around 95% of the Windows rules compile; the rest use
        aggregations or log sources this tool does not collect, and are listed with
        the reason rather than dropped quietly.
      </p>
    </div>`;
  }

  function sigmaSetFilter(key, value) {
    sigmaFilter[key] = value;
    sigma();
  }

  async function sigmaToggle(id, enabled) {
    try { await API.sigmaToggle(id, enabled); }
    catch (e) { UI.toast('Could not change that rule', e.message, 'err'); sigma(); }
  }

  async function sigmaBulk(key, value, enabled) {
    const payload = { enabled };
    payload[key] = value;
    try {
      const res = await API.sigmaBulkToggle(payload);
      UI.toast(`${enabled ? 'Enabled' : 'Disabled'} ${res.changed} rules`, '', 'ok');
      sigma();
    } catch (e) { UI.toast('Could not apply that', e.message, 'err'); }
  }

  async function sigmaClear() {
    if (!confirm('Remove every Sigma rule? You can upload them again afterwards.')) return;
    try {
      const res = await API.sigmaClear();
      UI.toast(`Removed ${res.deleted} rules`, '', 'ok');
      sigma();
    } catch (e) { UI.toast('Could not remove them', e.message, 'err'); }
  }

  function sigmaUpload() {
    UI.modal('Upload Sigma rules', `
      <p class="muted" style="margin-top:0">
        A single <span class="mono">.yml</span> file, or a <span class="mono">.zip</span>
        holding a whole repository. Rules are compiled here and validated before
        they are stored.
      </p>
      <div class="field">
        <label>Rule file</label>
        <input type="file" id="sigFile" accept=".yml,.yaml,.zip"
               style="padding:9px 12px">
      </div>
      <label class="chk"><input type="checkbox" id="sigReplace">
        <div><span>Replace the current set</span>
        <small>Otherwise new rules are added and existing ones updated in place.</small></div></label>
      <div id="sigResult" style="margin-top:16px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn btn-primary" id="sigGo">Upload</button>`);

    document.getElementById('sigGo').onclick = async () => {
      const input = document.getElementById('sigFile');
      const file = input.files && input.files[0];
      if (!file) { UI.toast('Pick a file first', '', 'err'); return; }

      const btn = document.getElementById('sigGo');
      const out = document.getElementById('sigResult');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> Compiling';
      out.innerHTML = '';
      try {
        const res = await API.sigmaUpload(file, document.getElementById('sigReplace').checked);
        const reasons = (res.rejection_reasons || []).map(r =>
          `<tr><td class="mono">${r.count}</td><td>${UI.esc(r.reason)}</td></tr>`).join('');
        out.innerHTML = `
          <div class="grid g-stats" style="margin-bottom:14px">
            ${UI.stat(res.added, 'Added', { accent: '#2BD9A0' })}
            ${UI.stat(res.updated, 'Updated', { accent: '#1B7FE8' })}
            ${UI.stat(res.rejected, 'Rejected', { accent: res.rejected ? '#FF7A00' : '#5D7A9E' })}
          </div>
          ${reasons ? `<div class="hint" style="margin-bottom:8px">
            Why rules were rejected. Nothing is dropped silently.</div>
            <div class="scroll" style="max-height:220px"><table><thead><tr>
            <th>Count</th><th>Reason</th></tr></thead><tbody>${reasons}</tbody></table></div>` : ''}`;
        btn.textContent = 'Done';
        btn.onclick = () => { UI.close(); sigma(); };
        btn.disabled = false;
      } catch (e) {
        out.innerHTML = `<div style="color:var(--crit);font-size:13px">${UI.esc(e.message)}</div>`;
        btn.disabled = false;
        btn.textContent = 'Upload';
      }
    };
  }

  /* ==================================================================== */
  /* Response — incident response actions against a host                  */
  /* ==================================================================== */

  let respAgent = '';
  let respOpen = null;

  async function respond() {
    loading();
    const [cat, list, fleet] = await Promise.all([
      API.responseCatalogue(), API.responseActions(respAgent), API.agents(),
    ]);
    respCatalogue = cat.actions;

    const online = fleet.agents.filter(a => a.status !== 'offline');

    if (!fleet.agents.length) {
      el().innerHTML = `<div class="view"><div class="card">${UI.empty(
        'No hosts enrolled',
        'Response actions run on a host. Deploy an agent first.')}
        <div style="text-align:center"><button class="btn btn-primary"
          onclick="App.go('deploy')">Deploy agents</button></div></div></div>`;
      return;
    }

    const group = (id, label, note) => {
      const acts = respCatalogue.filter(a => a.group === id);
      return `
        <div class="card">
          <div class="card-h"><h2>${UI.esc(label)}</h2></div>
          <p class="muted" style="margin:0 0 12px;font-size:12.5px">${note}</p>
          <div class="iractions">
            ${acts.map(a => `
              <button class="iract ${a.mutating ? 'mut' : ''}"
                      onclick="Views.runResponse('${UI.esc(a.id)}')"
                      ${respAgent ? '' : 'disabled'}>
                <span class="irname">${UI.esc(a.name)}
                  ${a.mutating ? '<i class="irwarn">changes the host</i>' : ''}</span>
                <span class="irsum">${UI.esc(a.summary)}</span>
              </button>`).join('')}
          </div>
        </div>`;
    };

    const rows = list.actions.map(a => `
      <tr class="clickable" onclick="Views.showResponse('${UI.esc(a.id)}')">
        <td><span class="stat-chip st-${a.status === 'completed' ? 'open'
          : (a.status === 'failed' ? 'false_positive' : 'investigating')}">${UI.esc(a.status)}</span></td>
        <td><b>${UI.esc(a.hostname || '')}</b></td>
        <td><div style="font-weight:600">${UI.esc(a.action_name)}
              ${a.mutating ? '<span class="tag" style="color:var(--high);border-color:rgba(255,122,0,.4)">changed the host</span>' : ''}</div>
            ${a.target ? `<div class="why mono">${UI.esc(a.target)}</div>` : ''}</td>
        <td class="muted" style="font-size:12.5px">${UI.esc((a.reason || '').slice(0, 70))}</td>
        <td class="mono muted" style="font-size:11.5px">${UI.esc(a.created_by || '')}</td>
        <td class="mono muted" style="font-size:11.5px">${UI.ago(a.created_at)}</td>
      </tr>`).join('');

    el().innerHTML = `<div class="view">
      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Act on a host</h2>
          <div class="spacer"></div>
          <select id="respHost" onchange="Views.setRespAgent(this.value)"
                  style="min-width:230px">
            <option value="">Pick a host…</option>
            ${fleet.agents.map(a => `
              <option value="${UI.esc(a.id)}" ${respAgent === a.id ? 'selected' : ''}
                ${a.status === 'offline' ? 'disabled' : ''}>
                ${UI.esc(a.hostname)} — ${UI.esc(a.status)}${
                  a.status === 'offline' ? ' (will not pick anything up)' : ''}</option>`).join('')}
          </select>
        </div>
        <p class="muted" style="margin:0;max-width:88ch">
          A hunt tells you something is wrong. This is the part where you do
          something about it — look at what is running now, stop it, or cut the
          host off — without an RDP session and a scrollback nobody keeps.
          ${online.length} of ${fleet.agents.length} hosts are reachable.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0;max-width:88ch">
          Every action returns a transcript rather than a status code, and the
          transcript is kept whether it worked or not — a failed containment
          attempt is exactly the thing you need to read. Actions that change the
          host are marked, and each one asks for a reason before it runs.
        </p>
        ${respAgent ? '' : `<div class="hint" style="margin-top:12px">
          Pick a host above to enable the actions.</div>`}
      </div>

      <div class="grid g-2" style="margin-bottom:18px">
        ${group('look', 'Look first',
          'Read-only. Nothing on the host changes, so these are the ones to run '
          + 'while you are still working out what happened.')}
        ${group('act', 'Act on what you found',
          'These change the host. Each asks for a reason, and refuses targets '
          + 'that would break the machine rather than contain the intrusion.')}
      </div>

      <div style="margin-bottom:18px">
        ${group('contain', 'Contain the host',
          'Isolation blocks everything except this console, on purpose — a host '
          + 'cut off from its own agent cannot be released remotely and somebody '
          + 'would have to walk to it.')}
      </div>

      <div class="card-h"><h2>What has been run</h2><div class="spacer"></div>
        ${respAgent ? `<button class="btn btn-sm btn-ghost" onclick="Views.setRespAgent('')">Show every host</button>` : ''}
      </div>
      ${list.total
        ? UI.table(['Status', 'Host', 'Action', 'Reason', 'Who', 'When'], rows,
                   { id: 'tblResp' })
        : `<div class="card">${UI.empty('Nothing has been run yet',
            'Pick a host and start with one of the read-only actions.')}</div>`}
    </div>`;
  }

  let respCatalogue = [];

  function setRespAgent(id) { respAgent = id; respond(); }

  // prefill lets a row in a transcript hand its own pid or address straight to
  // the dialog, so acting on what you just read is one click rather than a
  // copy, a menu and a retype.
  function runResponse(actionId, prefill) {
    const spec = respCatalogue.find(a => a.id === actionId);
    if (!spec || !respAgent) return;

    const targetLabel = {
      pid: 'Process id', path: 'Full path', user: 'Account name', service: 'Service name',
    }[spec.target];
    const targetHint = {
      pid: 'The number from a finding or from the process list.',
      path: 'The full path as it appears on the host.',
      user: 'A local account. Built-in accounts are refused.',
      service: 'The service name, not its display name.',
    }[spec.target];

    UI.modal(spec.name, `
      <p class="muted" style="margin-top:0">${UI.esc(spec.detail)}</p>

      ${spec.mutating ? `<div class="notice warn-notice">
        <b>This changes the host</b>
        <p>It runs against a live machine and cannot be undone from here.
        ${spec.id === 'isolate' ? 'Existing connections are dropped; the console stays reachable so you can release it.' : ''}</p>
      </div>` : ''}

      ${spec.target ? `<div class="field"><label>${UI.esc(targetLabel)}</label>
        <input type="text" id="respTarget" autocomplete="off"
               value="${UI.esc(prefill || '')}"
               placeholder="${UI.esc(spec.target === 'pid' ? '4812' : '')}">
        <div class="hint">${UI.esc(targetHint)}</div></div>` : ''}

      ${spec.mutating ? `<div class="field"><label>Why</label>
        <textarea id="respReason" style="min-height:64px"
          placeholder="DGL-042 flagged this as a masquerading svchost; containing while we confirm."></textarea>
        <div class="hint">Required. Six months from now the transcript is all
        anyone will have to explain why this host changed.</div></div>` : ''}

      <div id="respErr" class="hidden" style="color:var(--crit);font-size:13px;margin-top:12px"></div>`,
      `<button class="btn btn-ghost" onclick="UI.close()">Cancel</button>
       <button class="btn ${spec.mutating ? 'btn-danger' : 'btn-primary'}" id="respGo">
         ${spec.mutating ? 'Run it' : 'Run'}</button>`);

    document.getElementById('respGo').onclick = async () => {
      const err = document.getElementById('respErr');
      err.classList.add('hidden');
      const btn = document.getElementById('respGo');
      btn.disabled = true;
      try {
        const r = await API.queueResponse({
          agent_id: respAgent,
          action: actionId,
          target: (document.getElementById('respTarget') || {}).value || '',
          reason: (document.getElementById('respReason') || {}).value || '',
        });
        UI.close();
        UI.toast('Sent to the host', 'It runs on the next check-in.', 'ok');
        showResponse(r.id);
      } catch (e) {
        btn.disabled = false;
        err.textContent = e.message;
        err.classList.remove('hidden');
      }
    };
  }

  async function lookupAddress(ip) {
    UI.toast('Looking it up…', ip, 'ok');
    try {
      const r = await API.runEnrichment({ addresses: [ip] });
      if (!r.looked_up) {
        UI.toast('Nothing to add', 'No reputation provider is switched on.', 'err');
        return;
      }
      const rep = await API.reputation();
      const hit = (rep.addresses || []).find(a => a.address === ip);
      if (!hit) { UI.toast('No verdict returned', ip, 'err'); return; }
      UI.modal(`${ip}`, `
        <div style="margin-bottom:14px">${repBadge(hit.label, hit.score)}</div>
        ${Object.entries(hit.verdicts || {}).map(([name, v]) => `
          <div class="gitem"><b>${UI.esc(name)}</b><p>${UI.esc(v.summary || '')}</p></div>`).join('')
          || '<div class="hint">No provider had anything on it.</div>'}`,
        `<button class="btn btn-ghost" onclick="UI.close()">Close</button>`);
    } catch (e) { UI.toast('Lookup failed', e.message, 'err'); }
  }

  async function showResponse(id) {
    respOpen = id;
    const a = await API.responseAction(id);
    renderResponse(a);

    // Poll while it is still running: an action is short, and the operator is
    // watching for the transcript rather than a notification.
    if (a.status === 'queued' || a.status === 'running') {
      setTimeout(async () => {
        if (respOpen !== id) return;
        try {
          const again = await API.responseAction(id);
          if (respOpen === id) {
            if (again.status === 'queued' || again.status === 'running') showResponse(id);
            else { renderResponse(again); respond(); }
          }
        } catch (_) { /* the drawer may have been closed */ }
      }, 2500);
    }
  }

  /* ---- transcript rendering ------------------------------------------- *
   * The host sends plain text, and plain text in a black box is how every
   * tool has shown this since 1985 — readable if you already know what you
   * are looking at, and a wall otherwise. The agents write in a consistent
   * shape (== sections ==, KEY : value, aligned columns), so the console can
   * lift that back into tables and cards without the agent having to send a
   * second machine-readable copy it would then have to keep in step.
   *
   * Everything degrades: an unrecognised block is shown as it arrived, and
   * the raw text is always one click away.
   * -------------------------------------------------------------------- */

  function renderTranscript(text) {
    if (!text || !text.trim()) return '<div class="hint">No output.</div>';

    // Split on "== Section ==" headers, keeping anything before the first one.
    const parts = [];
    let current = { title: '', lines: [] };
    for (const raw of text.split('\n')) {
      const head = raw.match(/^\s*={2,}\s*(.+?)\s*={2,}\s*$/);
      if (head) {
        if (current.lines.length || current.title) parts.push(current);
        current = { title: head[1], lines: [] };
      } else {
        current.lines.push(raw);
      }
    }
    if (current.lines.length || current.title) parts.push(current);

    return parts.map(sectionHtml).filter(Boolean).join('');
  }

  function sectionHtml(sec) {
    const lines = sec.lines.filter(l => l.trim().length);
    if (!lines.length && !sec.title) return '';

    const body = tableHtml(lines) || kvHtml(lines) || plainHtml(lines);
    return `<div class="tsec">
      ${sec.title ? `<div class="tsec-h">${UI.esc(sec.title)}</div>` : ''}
      ${body}
    </div>`;
  }

  // Verdict lines the agents emit deliberately: RESULT, WARNING, Refusing.
  // These are the sentence the operator actually wants, so they are pulled out
  // of the flow rather than left as one more line of grey text.
  function verdictHtml(line) {
    const t = line.trim();
    let m = t.match(/^RESULT\s*:\s*(.+)$/i);
    if (m) {
      const bad = /could not|still running|failed|warning/i.test(m[1]);
      return `<div class="tverdict ${bad ? 'bad' : 'good'}">
        <b>${bad ? 'Result' : 'Done'}</b><span>${UI.esc(m[1])}</span></div>`;
    }
    if (/^WARNING\b/i.test(t)) {
      return `<div class="tverdict warn"><b>Warning</b>
        <span>${UI.esc(t.replace(/^WARNING\s*[—:-]?\s*/i, ''))}</span></div>`;
    }
    if (/^Refusing\b/i.test(t)) {
      return `<div class="tverdict bad"><b>Refused</b><span>${UI.esc(t)}</span></div>`;
    }
    if (/^\s*OK\b/.test(t) && t.length < 160) {
      return `<div class="tverdict good"><b>OK</b>
        <span>${UI.esc(t.replace(/^\s*OK\s*[—:-]?\s*/, ''))}</span></div>`;
    }
    return '';
  }

  // A block whose first line looks like a column header and whose rows line up
  // under it. Process and connection listings are exactly this.
  function tableHtml(lines) {
    if (lines.length < 3) return '';
    const header = lines[0];
    if (!/^[A-Z][A-Z0-9 _\/:().-]*$/.test(header.trim())) return '';
    const cols = header.trim().split(/\s{2,}/).filter(Boolean);
    if (cols.length < 3) return '';

    // Anything that is not a row of this table still has to be shown. An
    // earlier version filtered these out to keep the table clean and dropped
    // them entirely, so a "RESULT : stopped" printed after a process listing
    // vanished — losing output is worse than showing it plainly.
    const rows = [];
    const leftover = [];
    for (const l of lines.slice(1)) {
      if (verdictHtml(l)) { leftover.push(l); continue; }
      const cells = l.trim().split(/\s{2,}/);
      if (cells.length >= 2) rows.push(cells);
      else leftover.push(l);
    }
    if (rows.length < 2) return '';

    // A row that names a process or an address is one the operator is about to
    // act on. Offering the next step where they are already looking is most of
    // the difference between reading a result and doing something about it.
    const rowActions = (cells) => {
      const bits = [];
      const pid = (cells[0] || '').trim();
      if (/^\d{1,7}$/.test(pid) && Number(pid) > 1 && /PID/i.test(cols[0] || '')) {
        bits.push(`<button class="btn btn-sm btn-ghost btn-danger" title="Kill this process"
          onclick="event.stopPropagation();Views.runResponse('kill_process','${UI.esc(pid)}')">Kill</button>`);
      }
      const ip = cells.join(' ').match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
      // Private and loopback space has no reputation to look up, and sending
      // it to a third party would leak internal addressing for nothing.
      if (ip && !/^(0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|255\.)/.test(ip[1])) {
        bits.push(`<button class="btn btn-sm btn-ghost" title="Ask the reputation providers"
          onclick="event.stopPropagation();Views.lookupAddress('${UI.esc(ip[1])}')">Reputation</button>`);
      }
      return bits.join(' ');
    };
    const anyActions = rows.slice(0, 200).some(r => rowActions(r));

    return `<div class="scroll" style="max-height:340px">
      <table class="ttable"><thead><tr>
        ${cols.map(c => `<th>${UI.esc(c)}</th>`).join('')}
        ${anyActions ? '<th></th>' : ''}
      </tr></thead><tbody>
        ${rows.slice(0, 200).map(r => `<tr>${
          cols.map((_, i) => `<td>${UI.esc(r[i] || '')}</td>`).join('')
        }${anyActions ? `<td class="tact">${rowActions(r)}</td>` : ''}</tr>`).join('')}
      </tbody></table>
      ${rows.length > 200 ? `<div class="hint">Showing the first 200 of ${rows.length} rows.</div>` : ''}
    </div>${leftover.length ? plainHtml(leftover) : ''}`;
  }

  // "Key     : value" blocks — file details, process summaries.
  function kvHtml(lines) {
    const pairs = [];
    const rest = [];
    for (const l of lines) {
      // A verdict is shaped like a pair ("RESULT : stopped") but is the
      // sentence the operator came for, so it must not be filed away as one
      // more field in a table of attributes.
      if (verdictHtml(l)) { rest.push(l); continue; }
      const m = l.match(/^\s{0,4}([A-Za-z][A-Za-z0-9 _()-]{1,20}?)\s*:\s(.*)$/);
      if (m && m[2].trim()) pairs.push([m[1].trim(), m[2].trim()]);
      else rest.push(l);
    }
    if (pairs.length < 2) return '';

    return `<dl class="tkv">
      ${pairs.map(([k, v]) => `<dt>${UI.esc(k)}</dt><dd class="${
        /^[a-f0-9]{32,64}$/i.test(v) ? 'mono hash' : ''
      }">${UI.esc(v)}</dd>`).join('')}
    </dl>${rest.length ? plainHtml(rest) : ''}`;
  }

  function plainHtml(lines) {
    const out = [];
    const buf = [];
    const flush = () => {
      if (buf.length) {
        out.push(`<pre class="tpre">${UI.esc(buf.join('\n'))}</pre>`);
        buf.length = 0;
      }
    };
    for (const l of lines) {
      const v = verdictHtml(l);
      if (v) { flush(); out.push(v); } else { buf.push(l); }
    }
    flush();
    return out.join('');
  }

  let transcriptRaw = false;
  function toggleTranscript() {
    transcriptRaw = !transcriptRaw;
    const pretty = document.getElementById('tPretty');
    const raw = document.getElementById('tRaw');
    const btn = document.getElementById('tToggle');
    if (!pretty || !raw) return;
    pretty.style.display = transcriptRaw ? 'none' : '';
    raw.style.display = transcriptRaw ? '' : 'none';
    if (btn) btn.textContent = transcriptRaw ? 'Formatted' : 'Raw text';
  }

  function copyTranscript() {
    const raw = document.getElementById('tRaw');
    if (!raw) return;
    navigator.clipboard.writeText(raw.textContent || '')
      .then(() => UI.toast('Copied', 'The transcript is on your clipboard.', 'ok'))
      .catch(() => UI.toast('Could not copy', 'Select the raw text instead.', 'err'));
  }

  function renderResponse(a) {
    const waiting = a.status === 'queued' || a.status === 'running';
    transcriptRaw = false;
    UI.drawer(`${a.action_name} — ${a.hostname || ''}`, `
      <div style="display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin-bottom:16px">
        <span class="stat-chip st-${a.status === 'completed' ? 'open'
          : (a.status === 'failed' ? 'false_positive' : 'investigating')}">${UI.esc(a.status)}</span>
        ${a.target ? `<span class="tag mono">${UI.esc(a.target)}</span>` : ''}
        ${a.mutating ? '<span class="tag" style="color:var(--high);border-color:rgba(255,122,0,.4)">changed the host</span>' : ''}
        <span class="tag">${UI.esc(a.created_by || '')}</span>
        ${a.duration_seconds ? `<span class="tag mono">${UI.dur(a.duration_seconds)}</span>` : ''}
      </div>

      ${a.reason ? `<div class="card" style="background:var(--deep);margin-bottom:14px">
        <div class="card-h"><h2>Reason given</h2></div>
        <p class="muted" style="margin:0">${UI.esc(a.reason)}</p></div>` : ''}

      ${waiting ? `<div class="notice" style="background:var(--deep);border:1px solid var(--edge);
        border-left:3px solid var(--cyan)">
        <b><span class="spinner"></span> ${a.status === 'queued'
          ? 'Waiting for the host to pick it up' : 'Running on the host'}</b>
        <p>Hosts check for actions every few seconds, so this normally starts
        almost immediately and finishes in under a minute.</p></div>` : ''}

      ${a.error ? `<div class="notice bad-notice"><b>It reported a failure</b>
        <p>${UI.esc(a.error)}</p>
        <p style="margin-top:6px;font-size:12.5px">The transcript below is kept
        either way — a failed containment attempt is the one you most need to read.</p>
        </div>` : ''}

      <div class="card-h" style="margin-top:14px">
        <h2>What the host said</h2>
        <div class="spacer"></div>
        ${a.output ? `
          <button class="btn btn-sm btn-ghost" id="tToggle"
                  onclick="Views.toggleTranscript()">Raw text</button>
          <button class="btn btn-sm btn-ghost" onclick="Views.copyTranscript()">Copy</button>` : ''}
      </div>

      <div id="tPretty">${a.output ? renderTranscript(a.output)
        : `<div class="hint">${waiting ? 'Nothing yet — the host has not reported.' : 'No output.'}</div>`}</div>
      <pre class="transcript" id="tRaw" style="display:none">${UI.esc(a.output || '')}</pre>

      <div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap">
        ${waiting ? `<button class="btn btn-sm btn-ghost btn-danger"
          onclick="Views.cancelResponse('${UI.esc(a.id)}')">Cancel it</button>` : ''}
        ${!waiting ? `<button class="btn btn-sm"
          onclick="UI.close();Views.setRespAgent('${UI.esc(a.agent_id)}')">Run another on this host</button>` : ''}
      </div>`);
  }

  async function cancelResponse(id) {
    try {
      await API.cancelResponse(id);
      UI.toast('Cancelled', 'If the host had already started it, it will still finish.', 'ok');
      respOpen = null; UI.close(); respond();
    } catch (e) { UI.toast('Could not cancel it', e.message, 'err'); }
  }

  /* ==================================================================== */
  /* Logs — what each module did, and what the console did                */
  /* ==================================================================== */

  let logFilter = 'all';
  let logTab = 'modules';

  async function logs() {
    loading();
    const d = await API.huntLogs({ only: logFilter });
    // The audit trail is admin-only, so a responder gets the module half and
    // no error where the other half would be.
    let audit = null;
    if (App.can && App.can('admin')) {
      audit = await API.auditLog().catch(() => null);
    }

    const chip = (label, key, n) =>
      `<button class="fchip ${logFilter === key ? 'on' : ''}"
        onclick="Views.setLogFilter('${key}')">${label}${n !== undefined ? ` ${n}` : ''}</button>`;

    const statusPill = (s) => {
      const colour = { ERROR: 'var(--crit)', WARN: 'var(--high)',
                       SKIP: 'var(--slate-d)', OK: '#2BD9A0' }[s] || 'var(--slate)';
      return `<span class="logpill" style="color:${colour};border-color:${colour}55">${UI.esc(s)}</span>`;
    };

    const rows = d.rows.map(r => `
      <tr class="${r.status === 'ERROR' ? 'logbad' : ''}">
        <td>${statusPill(r.status)}${r.live ? '<div class="tname">running</div>' : ''}</td>
        <td><b>${UI.esc(r.module)}</b>
            ${r.detail ? `<div class="why">${UI.esc(r.detail.slice(0, 120))}</div>` : ''}</td>
        <td class="mono">${UI.esc(r.hostname || '')}</td>
        <td class="mono muted">${r.rows ? r.rows.toLocaleString() : '—'}</td>
        <td class="mono" style="${r.findings ? 'color:var(--high);font-weight:700' : ''}">${r.findings || '—'}</td>
        <td class="mono muted">${r.ms ? (r.ms >= 1000 ? (r.ms / 1000).toFixed(1) + 's' : r.ms + 'ms') : '—'}</td>
        <td class="mono muted" style="font-size:11.5px">${r.at ? UI.ago(r.at) : ''}</td>
      </tr>`).join('');

    const summary = d.summary.map(m => `
      <tr class="${m.error ? 'logbad' : ''}">
        <td><b>${UI.esc(m.module)}</b></td>
        <td class="mono" style="${m.error ? 'color:var(--crit);font-weight:700' : 'color:var(--slate-d)'}">${m.error || '—'}</td>
        <td class="mono muted">${m.ok}</td>
        <td class="mono" style="${m.findings ? 'color:var(--high)' : ''}">${m.findings || '—'}</td>
        <td class="mono muted">${m.hosts}</td>
      </tr>`).join('');

    const auditRows = audit ? (audit.events || []).map(e => `
      <tr>
        <td class="mono muted" style="font-size:11.5px">${UI.esc(e.at ? UI.ago(e.at) : '')}</td>
        <td><span class="tag">${UI.esc(e.kind)}</span></td>
        <td>${UI.esc(e.subject || '')}</td>
        <td class="muted" style="font-size:12.5px">${UI.esc(e.detail || '')}</td>
      </tr>`).join('') : '';

    el().innerHTML = `<div class="view">
      <div class="grid g-stats" style="margin-bottom:20px">
        ${UI.stat(d.hunts, 'Hunts covered', { accent: '#22D9F5' })}
        ${UI.stat(d.modules, 'Modules seen', { accent: '#1B7FE8' })}
        ${UI.stat(d.errors, 'Errors', { accent: '#FF2D55', glow: d.errors > 0,
          sub: d.errors ? 'a module that failed looked at nothing' : 'every module ran' })}
      </div>

      <div class="card" style="margin-bottom:18px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Did the sweep actually look?</h2>
        </div>
        <p class="muted" style="margin:0;max-width:88ch">
          Every other screen answers what is wrong. This one answers the question
          underneath it. A module that errored looked at nothing, and a host it
          errored on will report clean for exactly the things that module checks —
          which reads the same as a host that is genuinely clean.
        </p>
        <p class="muted" style="font-size:12.5px;margin:12px 0 0">
          <b>Errors</b> are the reason to open this. <b>0 findings with OK</b> is
          the healthy answer for most modules on most hosts.
        </p>
      </div>

      <div class="filters">
        <button class="fchip ${logTab === 'modules' ? 'on' : ''}"
          onclick="Views.setLogTab('modules')">Module results</button>
        <button class="fchip ${logTab === 'summary' ? 'on' : ''}"
          onclick="Views.setLogTab('summary')">By module</button>
        ${audit ? `<button class="fchip ${logTab === 'audit' ? 'on' : ''}"
          onclick="Views.setLogTab('audit')">Console activity</button>` : ''}
        <span class="spacer" style="flex:1"></span>
        ${logTab === 'modules' ? `
          ${chip('All', 'all', d.total)}
          ${chip('Errors only', 'errors', d.errors)}
          ${chip('Produced findings', 'findings')}` : ''}
      </div>

      ${logTab === 'modules'
        ? (d.total
          ? UI.table(['Status', 'Module', 'Host', 'Rows', 'Findings', 'Took', 'When'],
                     rows, { id: 'tblLogs' })
          : `<div class="card">${UI.empty('Nothing logged yet',
              'Run a hunt — every module reports what it read and whether it worked.')}</div>`)
        : ''}

      ${logTab === 'summary'
        ? UI.table(['Module', 'Errors', 'Ran ok', 'Findings', 'Hosts'], summary,
                   { id: 'tblLogSum' })
        : ''}

      ${logTab === 'audit' && audit
        ? UI.table(['When', 'Event', 'Subject', 'Detail'], auditRows, { id: 'tblAudit' })
        : ''}
    </div>`;
  }

  function setLogFilter(v) { logFilter = v; logs(); }
  function setLogTab(v) { logTab = v; logs(); }

  /* ==================================================================== */
  /* Deploy                                                               */
  /* ==================================================================== */

  function setDeployPlatform(p) {
    // Every block switches, not just the one-liner. Showing a WinRM fan-out and
    // a Group Policy path under a Linux command is worse than showing nothing:
    // it reads as instructions and none of it applies.
    const linux = p === 'linux';
    document.querySelectorAll('[data-plat="windows"]').forEach(
      el => { el.style.display = linux ? 'none' : ''; });
    document.querySelectorAll('[data-plat="linux"]').forEach(
      el => { el.style.display = linux ? '' : 'none'; });

    const cw = document.getElementById('chipWin');
    const cl = document.getElementById('chipLin');
    if (cw) cw.classList.toggle('on', !linux);
    if (cl) cl.classList.toggle('on', linux);
  }

  async function deploy() {
    loading();
    const info = await API.deployInfo();

    const sourceNote = {
      manual: 'Set here in the console.',
      environment: 'Set by DOUGLAS_PUBLIC_URL in the environment.',
      auto: 'Detected from the address you are using right now.',
    }[info.source] || '';

    // The commands below get pasted onto production servers. If the address
    // baked into them is unreachable, every one of those hosts fails the same
    // way — so say so before that happens, not after.
    const mismatchBanner = info.mismatch ? `
      <div class="notice warn-notice">
        <b>Agents will be sent to ${UI.esc(info.server_url)}</b>
        <p>You reached this console on <b>${UI.esc(info.detected_url)}</b>. If the
        first address doesn't resolve from your servers, the deploy commands below
        will fail on every host.</p>
        <button class="btn btn-sm btn-primary"
          onclick="Views.useDetectedAddress('${UI.esc(info.detected_url)}')">
          Use ${UI.esc(info.detected_url)} instead</button>
      </div>` : '';

    el().innerHTML = `<div class="view">
      <div class="card" style="margin-bottom:16px">
        <div class="card-h">
          <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
          <h2>Console address</h2>
          <div class="spacer"></div>
          <span class="tag">${UI.esc(info.source)}</span>
        </div>
        <p class="muted" style="margin-top:0">
          Where agents call back. ${UI.esc(sourceNote)} It must resolve from the
          servers you deploy to — not just from your own machine.
        </p>
        ${mismatchBanner}
        ${info.tls_warning ? `
          <div class="notice bad-notice">
            <b>This address will not connect</b>
            <p>${UI.esc(info.tls_warning)}</p>
            <button class="btn btn-sm btn-primary"
              onclick="Views.useDetectedAddress('${UI.esc((info.server_url || '').replace(/^https:/, 'http:'))}')">
              Switch to http</button>
          </div>` : ''}
        <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start;margin-top:14px">
          <input type="text" id="addrInput" value="${UI.esc(info.server_url)}"
                 placeholder="192.168.68.109:8000" style="flex:1;min-width:260px">
          <button class="btn btn-primary" onclick="Views.saveAddress()">Save address</button>
          ${info.source === 'manual'
            ? '<button class="btn btn-ghost" onclick="Views.autoAddress()">Auto-detect</button>'
            : ''}
        </div>
        <div class="hint" style="margin-top:8px">
          A bare host and port is fine — <span class="mono">192.168.68.109:8000</span>
          becomes <span class="mono">http://192.168.68.109:8000</span>. Use https only
          if you have TLS in front of the console.
        </div>
      </div>

      <div class="grid g-2">
        <div class="card">
          <div class="card-h">
            <div class="speedlines" aria-hidden="true"><i></i><i></i><i></i></div>
            <h2>Add a host</h2>
            <div class="spacer"></div>
            <div class="filters" style="margin:0;padding:0;border:0">
              <button class="fchip on" id="chipWin"
                onclick="Views.setDeployPlatform('windows')">${UI.osIcon('windows')} Windows</button>
              <button class="fchip" id="chipLin"
                onclick="Views.setDeployPlatform('linux')">${UI.osIcon('linux')} Linux</button>
            </div>
          </div>

          <div id="deployWindows" data-plat="windows">
            <p class="muted" style="margin-top:0">
              One command, run in an elevated PowerShell prompt on the host you want to
              hunt. Nothing else — the same line works on every Windows host.
            </p>
            <div class="code" id="oneliner">${UI.esc(info.oneliner)}</div>
            <button class="btn btn-primary" style="margin-top:12px"
                    onclick="Views.copy('oneliner')">Copy command</button>

            <div class="deploy-steps">
              <div class="dstep"><span class="dnum">1</span>
                <div><b>Downloads the agent</b> from this console — a single
                PowerShell script, no installer.</div></div>
              <div class="dstep"><span class="dnum">2</span>
                <div><b>Enrols the machine</b> with the token baked into the command,
                so it shows up in Fleet within a few seconds.</div></div>
              <div class="dstep"><span class="dnum">3</span>
                <div><b>Registers a scheduled task</b> running as SYSTEM, so the host
                stays reachable and re-checks in after a reboot.</div></div>
              <div class="dstep"><span class="dnum">4</span>
                <div><b>Prints its status</b> and stays resident — from then on it
                pulls hunts from here and streams progress back.</div></div>
            </div>
          </div>

          <div id="deployLinux" data-plat="linux" style="display:none">
            <p class="muted" style="margin-top:0">
              One command, run as root on the Linux host. The same line works on every
              Linux host, with or without systemd.
            </p>
            <div class="code" id="onelinerLinux">curl -sSL '${UI.esc(info.server_url)}/api/v1/reports/deploy/script?token=${UI.esc(info.token)}&platform=linux' | sudo bash</div>
            <button class="btn btn-primary" style="margin-top:12px"
                    onclick="Views.copy('onelinerLinux')">Copy command</button>

            <div class="deploy-steps">
              <div class="dstep"><span class="dnum">1</span>
                <div><b>Downloads the agent</b> from this console — a plain shell
                script needing only bash and curl.</div></div>
              <div class="dstep"><span class="dnum">2</span>
                <div><b>Enrols the machine</b> with the token in the command, so it
                appears in Fleet within a few seconds.</div></div>
              <div class="dstep"><span class="dnum">3</span>
                <div><b>Installs a systemd service</b> — or falls back to cron on a
                host without systemd — so it survives a reboot.</div></div>
              <div class="dstep"><span class="dnum">4</span>
                <div><b>Prints its status</b> and stays resident, pulling hunts from
                here and streaming progress back.</div></div>
            </div>

            <p class="muted" style="font-size:12.5px;margin:14px 0 0">
              The Linux collector is a different tool, not a translation: it hunts
              cron, systemd units, authorized_keys, LD_PRELOAD, setuid binaries,
              webshells and WordPress rather than registry hives. Nothing is installed
              on the host you are investigating.
            </p>
          </div>
        </div>

        <div class="card" data-plat="windows">
          <div class="card-h"><h2>Deploy across a domain</h2></div>
          <p class="muted" style="margin-top:0">
            Push to many hosts at once over WinRM. Run from a machine that can
            reach them with administrative rights.
          </p>
          <div class="code" id="fanout">$hosts = (Get-ADComputer -Filter {Enabled -eq $true}).Name

Invoke-Command -ComputerName $hosts -ThrottleLimit 20 -ScriptBlock {
    ${UI.esc(info.oneliner)}
}</div>
          <button class="btn" style="margin-top:12px" onclick="Views.copy('fanout')">Copy script</button>
        </div>

        <div class="card" data-plat="linux" style="display:none">
          <div class="card-h"><h2>Deploy across a fleet</h2></div>
          <p class="muted" style="margin-top:0">
            Over SSH, from a machine that can reach the hosts with a key and sudo.
          </p>
          <div class="code" id="fanoutLinux">for h in $(cat hosts.txt); do
  ssh -o StrictHostKeyChecking=accept-new "$h" \
    "curl -sSL '${UI.esc(info.server_url)}/api/v1/reports/deploy/script?token=${UI.esc(info.token)}&platform=linux' | sudo bash" &
done; wait</div>
          <button class="btn" style="margin-top:12px"
                  onclick="Views.copy('fanoutLinux')">Copy script</button>
          <p class="muted" style="font-size:12.5px;margin:12px 0 0">
            With Ansible: <span class="mono">ansible all -b -m shell -a
            "curl -sSL '...&amp;platform=linux' | bash"</span>
          </p>
        </div>
      </div>

      <div class="grid g-2" style="margin-top:16px">
        <div class="card" data-plat="windows">
          <div class="card-h"><h2>Group Policy startup script</h2></div>
          <p class="muted" style="margin-top:0">
            Computer Configuration → Policies → Windows Settings → Scripts → Startup.
          </p>
          <div class="code" id="gpo">${UI.esc(info.gpo)}</div>
          <button class="btn btn-sm" style="margin-top:12px" onclick="Views.copy('gpo')">Copy</button>
        </div>

        <div class="card" data-plat="linux" style="display:none">
          <div class="card-h"><h2>Build it into the image</h2></div>
          <p class="muted" style="margin-top:0">
            For hosts created from a template, so new machines enrol themselves.
            Add to cloud-init user data:
          </p>
          <div class="code" id="cloudinit">#cloud-config
runcmd:
  - curl -sSL '${UI.esc(info.server_url)}/api/v1/reports/deploy/script?token=${UI.esc(info.token)}&platform=linux' | bash</div>
          <button class="btn btn-sm" style="margin-top:12px"
                  onclick="Views.copy('cloudinit')">Copy</button>
        </div>

        <div class="card" data-plat="windows">
          <div class="card-h"><h2>Manual install</h2></div>
          <p class="muted" style="margin-top:0">
            For hosts with no outbound access to this console, or when you want to
            review the script before running it.
          </p>
          <div class="code" id="manual">${UI.esc(info.manual)}</div>
          <button class="btn btn-sm" style="margin-top:12px" onclick="Views.copy('manual')">Copy</button>
        </div>

        <div class="card" data-plat="linux" style="display:none">
          <div class="card-h"><h2>Manual install</h2></div>
          <p class="muted" style="margin-top:0">
            When you want to read the script before it runs, which on a host you
            are investigating is the right instinct.
          </p>
          <div class="code" id="manualLinux">curl -sSL '${UI.esc(info.server_url)}/api/v1/reports/deploy/agent/linux' -o douglas-agent.sh
less douglas-agent.sh
sudo bash douglas-agent.sh --server '${UI.esc(info.server_url)}' \
  --token '${UI.esc(info.token)}' --install</div>
          <button class="btn btn-sm" style="margin-top:12px"
                  onclick="Views.copy('manualLinux')">Copy</button>
        </div>
      </div>

      <div class="card" style="margin-top:16px">
        <div class="card-h"><h2>Before you deploy</h2></div>
        <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;font-size:13.5px">
          <div data-plat="windows">
            <b style="color:#22D9F5">Allowlist the collector</b>
            <p class="muted" style="margin:6px 0 0">Most EDR products flag this behaviour
            as discovery. Without an exclusion the hunt may be killed part-way through.</p>
          </div>
          <div data-plat="linux" style="display:none">
            <b style="color:#22D9F5">Take the memory image first</b>
            <p class="muted" style="margin:6px 0 0">The collector reads live state and
            touches access times. If a forensic image is planned, capture it before
            hunting — and note the collector cannot see a kernel rootkit.</p>
          </div>
          <div data-plat="windows">
            <b style="color:#22D9F5">Take the memory image first</b>
            <p class="muted" style="margin:6px 0 0">The collector runs live and touches file
            access times and Prefetch. If you need a forensic image, capture it before hunting.</p>
          </div>
          <div data-plat="windows">
            <b style="color:#22D9F5">Windows PowerShell 5.1</b>
            <p class="muted" style="margin:6px 0 0">Server 2016 and newer work out of the box.
            2012 R2 runs in a reduced mode and reports which modules it skipped.</p>
          </div>
          <div data-plat="linux" style="display:none">
            <b style="color:#22D9F5">Runs as root</b>
            <p class="muted" style="margin:6px 0 0">Most of what matters — process
            memory maps, /etc/shadow, other users' cron — is unreadable otherwise.
            The collector refuses to start rather than report a partial picture as
            a clean one.</p>
          </div>
          <div data-plat="linux" style="display:none">
            <b style="color:#22D9F5">Nothing gets installed</b>
            <p class="muted" style="margin:6px 0 0">Bash and coreutils only. No
            packages, no compilers, no agent runtime — the host you are
            investigating should not change because you looked at it.</p>
          </div>
        </div>
      </div>
    </div>`;
  }

  async function saveAddress() {
    const value = document.getElementById('addrInput').value;
    try {
      const res = await API.setDeployAddress(value);
      if (res.tls_warning) {
        UI.toast('Saved, but agents will fail', res.tls_warning, 'err');
      } else {
        UI.toast('Address saved', `Agents will be sent to ${res.server_url}`, 'ok');
      }
      deploy();
    } catch (e) {
      UI.toast('Could not save the address', e.message, 'err');
    }
  }

  async function useDetectedAddress(url) {
    try {
      const res = await API.setDeployAddress(url);
      UI.toast('Address updated', `Agents will be sent to ${res.server_url}`, 'ok');
      deploy();
    } catch (e) {
      UI.toast('Could not save the address', e.message, 'err');
    }
  }

  async function autoAddress() {
    try {
      const res = await API.clearDeployAddress();
      UI.toast('Auto-detect on', `Now using ${res.server_url}`, 'ok');
      deploy();
    } catch (e) {
      UI.toast('Could not change the address', e.message, 'err');
    }
  }

  function copy(id) {
    const text = document.getElementById(id).innerText;
    navigator.clipboard.writeText(text)
      .then(() => UI.toast('Copied', 'Paste into an elevated PowerShell prompt.', 'ok'))
      .catch(() => UI.toast('Copy failed', 'Select the text and copy manually.', 'err'));
  }

  return {
    dashboard, fleet, hunts, findings, stack, timeline, deploy, users, matrix, sigma,
    graph, graphTip, graphFocus, rules, setRuleFilter, setRuleCategory, ruleDetail,
    toggleRule, toggleCategory,
    myrules, ruleHelp, newMyRule, editMyRule, toggleMyRule, deleteMyRule, testMyRule,
    pickAllRules, bulkRuleToggle, bulkRuleDelete,
    writeRuleText, ruleTextChanged, ruleTextScroll, ruleTextKey, ruleTextReset, saveRuleText,
    importRules, importFilePicked, importTextChanged, previewImport, commitImport,
    exportRules, loadStarterPack, importHelp,
    addCond, removeCond, condOpChanged, artifactChanged,
    cases, showCase, closeCase, newCase, editCase, setCaseStatus,
    addCaseNote, caseHunt,
    setDeployPlatform,
    feeds, newFeed, editFeed, feedKindChanged, feedModeChanged, refreshFeed, toggleFeed, deleteFeed,
    intel, saveIntelKey, testIntelKey, clearIntelKey, runIntel,
    respond, setRespAgent, runResponse, showResponse, cancelResponse, lookupAddress,
    logs, setLogFilter, setLogTab,
    toggleTranscript, copyTranscript, renderTranscript,
    integrations, newIntegration, integrationTransportChanged,
    integrationFormatChanged, deleteIntegration,
    newToken, toggleToken, deleteToken,
    diff, setDiffHost, schedules, newSchedule, editSchedule, toggleSchedule,
    runSchedule, deleteSchedule, scheduleFreqChanged,
    yara, yaraSetFilter, yaraSetSearch, yaraUpdateNow, yaraWatch, yaraClear, yaraUpload,
    triage, reviewRule, toggleSuppression, deleteSuppression,
    sigmaSetFilter, sigmaToggle, sigmaBulk, sigmaClear, sigmaUpload,
    sigmaUpdateNow, sigmaWatchUpdate, sigmaPatchProgress,
    techniqueDetail,
    newUser, editUser, removeUser, _users: [],
    openHost, removeHost, removeSelected, pickAll, launchSelected, selectedAgents,
    cancelHunt, setSeverity, setSearch, openFinding, saveFinding, copy,
    setFindingStatus, pickFindings, selectedFindings, updateBulkBar, bulkTriage,
    suppressFrom, previewSuppression,
    saveAddress, useDetectedAddress, autoAddress,
  };
})();
