/* Thin fetch wrapper. Every call funnels through here so a 401 anywhere
   drops the operator back to the sign-in screen instead of silently failing. */
const API = (() => {
  async function call(path, { method = 'GET', body, raw = false, anonymous = false } = {}) {
    const opts = { method, headers: {}, credentials: 'same-origin' };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);

    // A 401 from the sign-in endpoint means "wrong credentials", not "your
    // session ended". Treating them the same hides the server's real reason —
    // wrong password, disabled account, locked out — behind a useless message.
    if (res.status === 401 && !anonymous) {
      document.dispatchEvent(new CustomEvent('auth:expired'));
      throw new Error('Session expired');
    }
    // 403 means the account is fine but the role is too low. Surfacing it as a
    // sign-out would be wrong and confusing.
    if (res.status === 403) {
      let detail = 'You don\'t have access to that.';
      try { const j = await res.json(); if (j.detail) detail = j.detail; } catch (_) {}
      const err = new Error(detail);
      err.forbidden = true;
      throw err;
    }
    if (!res.ok) {
      let detail = `Request failed (${res.status})`;
      try { const j = await res.json(); if (j.detail) detail = j.detail; } catch (_) {}
      throw new Error(detail);
    }
    return raw ? res : res.json();
  }

  return {
    login:   (username, password) => call('/api/v1/auth/login',
               { method: 'POST', body: { username, password }, anonymous: true }),
    logout:  () => call('/api/v1/auth/logout', { method: 'POST' }),
    me:      () => call('/api/v1/auth/me', { anonymous: true }),

    agents:      () => call('/api/v1/agents'),
    agent:       (id) => call(`/api/v1/agents/${id}`),
    removeAgent: (id) => call(`/api/v1/agents/${id}`, { method: 'DELETE' }),
    fleetSummary:() => call('/api/v1/agents/summary'),

    launch:     (payload) => call('/api/v1/jobs/launch', { method: 'POST', body: payload }),
    jobs:       (limit = 60) => call(`/api/v1/jobs?limit=${limit}`),
    activeJobs: () => call('/api/v1/jobs/active'),
    job:        (id) => call(`/api/v1/jobs/${id}`),
    cancelJob:  (id) => call(`/api/v1/jobs/${id}/cancel`, { method: 'POST' }),

    overview: () => call('/api/v1/findings/overview'),
    findings: (params = {}) => {
      const q = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
      );
      return call(`/api/v1/findings?${q}`);
    },
    finding: (id) => call(`/api/v1/findings/${id}`),
    setFindingStatus: (id, payload) =>
      call(`/api/v1/findings/${id}/status`, { method: 'POST', body: payload }),
    bulkStatus: (payload) =>
      call('/api/v1/findings/bulk-status', { method: 'POST', body: payload }),
    triageQueue: () => call('/api/v1/findings/triage/queue'),

    suppressions:      () => call('/api/v1/suppressions'),
    previewSuppression:(payload) =>
      call('/api/v1/suppressions/preview', { method: 'POST', body: payload }),
    createSuppression: (payload) =>
      call('/api/v1/suppressions', { method: 'POST', body: payload }),
    toggleSuppression: (id, active) =>
      call(`/api/v1/suppressions/${id}/toggle`, { method: 'POST', body: { active } }),
    deleteSuppression: (id) =>
      call(`/api/v1/suppressions/${id}`, { method: 'DELETE' }),

    ackFinding: (id, acknowledged, note) =>
      call(`/api/v1/findings/${id}/ack`, { method: 'POST', body: { acknowledged, note } }),
    timeline: (params = {}) => {
      const q = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
      );
      return call(`/api/v1/findings/timeline?${q}`);
    },
    stack: () => call('/api/v1/findings/stack'),
    graph: (params = {}) => {
      const q = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
      );
      return call(`/api/v1/findings/graph?${q}`);
    },
    matrix: (params = {}) => {
      const q = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
      );
      return call(`/api/v1/findings/matrix?${q}`);
    },

    deployInfo: () => call('/api/v1/reports/deploy/info'),

    sigmaRules:   (params = {}) => {
      const q = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null)
      );
      return call(`/api/v1/sigma?${q}`);
    },
    sigmaSummary: () => call('/api/v1/sigma/summary'),

    huntLogs: (p = {}) => call('/api/v1/jobs/logs'
      + (p.only || p.agent_id
         ? `?only=${encodeURIComponent(p.only || 'all')}`
           + (p.agent_id ? `&agent_id=${encodeURIComponent(p.agent_id)}` : '')
         : '')),
    auditLog: () => call('/api/v1/users/activity/log'),

    builtinRules: () => call('/api/v1/findings/rules'),

    // The console reads its own constants from the server so the length it
    // asks for and the length the server enforces cannot drift apart. This
    // was being called and had never been defined, so every console silently
    // fell back to its hardcoded 8.
    meta: () => call('/api/v1/meta'),

    responseCatalogue: () => call('/api/v1/response/catalogue'),
    responseActions: (agentId) =>
      call('/api/v1/response' + (agentId ? `?agent_id=${encodeURIComponent(agentId)}` : '')),
    responseAction: (id) => call(`/api/v1/response/${id}`),
    queueResponse: (p) => call('/api/v1/response', { method: 'POST', body: p }),
    cancelResponse: (id) => call(`/api/v1/response/${id}/cancel`, { method: 'POST' }),
    toggleBuiltinRules: (p) =>
      call('/api/v1/findings/rules/toggle', { method: 'POST', body: p }),

    feeds:        () => call('/api/v1/feeds'),
    feedPresets:  () => call('/api/v1/feeds/presets'),
    feedPool:     () => call('/api/v1/feeds/pool'),
    testFeed:     (p) => call('/api/v1/feeds/test', { method: 'POST', body: p }),
    createFeed:   (p) => call('/api/v1/feeds', { method: 'POST', body: p }),
    updateFeed:   (id, p) => call(`/api/v1/feeds/${id}`, { method: 'POST', body: p }),
    refreshFeed:  (id) => call(`/api/v1/feeds/${id}/refresh`, { method: 'POST' }),
    toggleFeed:   (id, enabled) =>
      call(`/api/v1/feeds/${id}/toggle`, { method: 'POST', body: { enabled } }),
    deleteFeed:   (id) => call(`/api/v1/feeds/${id}`, { method: 'DELETE' }),

    enrichment:       () => call('/api/v1/enrichment'),
    saveEnrichKey:    (provider, p) =>
      call(`/api/v1/enrichment/${provider}`, { method: 'POST', body: p }),
    clearEnrichKey:   (provider) =>
      call(`/api/v1/enrichment/${provider}`, { method: 'DELETE' }),
    testEnrichKey:    (provider, api_key) =>
      call(`/api/v1/enrichment/${provider}/test`, { method: 'POST', body: { api_key } }),
    runEnrichment:    (p = {}) =>
      call('/api/v1/enrichment/run', { method: 'POST', body: p }),
    reputation:       () => call('/api/v1/enrichment/reputation'),

    integrations:      () => call('/api/v1/integrations'),
    integrationFormats: () => call('/api/v1/integrations/formats'),
    testIntegration:   (p) => call('/api/v1/integrations/test', { method: 'POST', body: p }),
    createIntegration: (p) => call('/api/v1/integrations', { method: 'POST', body: p }),
    deleteIntegration: (id) => call(`/api/v1/integrations/${id}`, { method: 'DELETE' }),

    tokens:       () => call('/api/v1/tokens'),
    createToken:  (p) => call('/api/v1/tokens', { method: 'POST', body: p }),
    toggleToken:  (id, enabled) =>
      call(`/api/v1/tokens/${id}/toggle`, { method: 'POST', body: { enabled } }),
    deleteToken:  (id) => call(`/api/v1/tokens/${id}`, { method: 'DELETE' }),

    schedules:       () => call('/api/v1/schedules'),

    ruleSchema:      () => call('/api/v1/custom-rules/schema'),
    previewRuleImport: (p) =>
      call('/api/v1/custom-rules/import/preview', { method: 'POST', body: p }),
    importRules:     (p) => call('/api/v1/custom-rules/import', { method: 'POST', body: p }),
    ruleImportHelp:  () => call('/api/v1/custom-rules/import/help'),
    checkRuleText:   (text) =>
      call('/api/v1/custom-rules/check', { method: 'POST', body: { text, filename: 'rule.yaml' } }),
    importStarterPack: () =>
      call('/api/v1/custom-rules/import/starter-pack', { method: 'POST' }),
    ruleExportUrl:   (fmt) => `/api/v1/custom-rules/export?fmt=${encodeURIComponent(fmt)}`,
    customRules:     () => call('/api/v1/custom-rules'),
    createCustomRule:(p) => call('/api/v1/custom-rules', { method: 'POST', body: p }),
    updateCustomRule:(id, p) => call(`/api/v1/custom-rules/${id}`, { method: 'POST', body: p }),
    toggleCustomRule:(id, enabled) =>
      call(`/api/v1/custom-rules/${id}/toggle`, { method: 'POST', body: { enabled } }),
    deleteCustomRule:(id) => call(`/api/v1/custom-rules/${id}`, { method: 'DELETE' }),
    testCustomRule:  (rule, sample) =>
      call('/api/v1/custom-rules/test', { method: 'POST', body: { rule, sample } }),
    ruleSample:      (artifact) => call(`/api/v1/custom-rules/sample/${artifact}`),

    cases:        () => call('/api/v1/cases'),
    caseDetail:   (id) => call(`/api/v1/cases/${id}`),
    createCase:   (p) => call('/api/v1/cases', { method: 'POST', body: p }),
    updateCase:   (id, p) => call(`/api/v1/cases/${id}`, { method: 'POST', body: p }),
    caseStatus:   (id, s) => call(`/api/v1/cases/${id}/status`, { method: 'POST', body: { status: s } }),
    caseNote:     (id, body) => call(`/api/v1/cases/${id}/notes`, { method: 'POST', body: { body } }),
    caseHunt:     (id) => call(`/api/v1/cases/${id}/hunt`, { method: 'POST' }),
    deleteCase:   (id) => call(`/api/v1/cases/${id}`, { method: 'DELETE' }),
    createSchedule:  (p) => call('/api/v1/schedules', { method: 'POST', body: p }),
    updateSchedule:  (id, p) => call(`/api/v1/schedules/${id}`, { method: 'POST', body: p }),
    toggleSchedule:  (id, enabled) =>
      call(`/api/v1/schedules/${id}/toggle`, { method: 'POST', body: { enabled } }),
    runSchedule:     (id) => call(`/api/v1/schedules/${id}/run`, { method: 'POST' }),
    deleteSchedule:  (id) => call(`/api/v1/schedules/${id}`, { method: 'DELETE' }),

    diffHosts: () => call('/api/v1/diff/hosts'),
    diff: (agentId, params = {}) => {
      const q = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null));
      return call(`/api/v1/diff/${agentId}?${q}`);
    },

    yaraRules:   (params = {}) => {
      const q = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== '' && v !== undefined && v !== null));
      return call(`/api/v1/yara?${q}`);
    },
    yaraSummary: () => call('/api/v1/yara/summary'),
    yaraUpdate:  (url, replace) =>
      call('/api/v1/yara/update', { method: 'POST', body: { url, replace } }),
    yaraBulkToggle: (severity, enabled) =>
      call(`/api/v1/yara/bulk-toggle?severity=${encodeURIComponent(severity)}`,
           { method: 'POST', body: { enabled } }),
    yaraClear:   () => call('/api/v1/yara/all', { method: 'DELETE' }),
    yaraUpload:  async (file, replace) => {
      const form = new FormData();
      form.append('file', file);
      const res = await fetch(`/api/v1/yara/upload?replace=${replace ? 'true' : 'false'}`,
                              { method: 'POST', body: form, credentials: 'same-origin' });
      if (res.status === 401) {
        document.dispatchEvent(new CustomEvent('auth:expired'));
        throw new Error('Session expired');
      }
      if (!res.ok) {
        let detail = `Upload failed (${res.status})`;
        try { const j = await res.json(); if (j.detail) detail = j.detail; } catch (_) {}
        throw new Error(detail);
      }
      return res.json();
    },
    sigmaUpdate:  (url, replace) =>
      call('/api/v1/sigma/update', { method: 'POST', body: { url, replace } }),
    sigmaUpdateStatus: () => call('/api/v1/sigma/update/status'),
    sigmaToggle:  (id, enabled) =>
      call(`/api/v1/sigma/${id}/toggle`, { method: 'POST', body: { enabled } }),
    sigmaBulkToggle: (payload) =>
      call('/api/v1/sigma/bulk-toggle', { method: 'POST', body: payload }),
    sigmaClear:   () => call('/api/v1/sigma/all', { method: 'DELETE' }),
    sigmaUpload:  async (file, replace) => {
      const form = new FormData();
      form.append('file', file);
      const res = await fetch(`/api/v1/sigma/upload?replace=${replace ? 'true' : 'false'}`,
                              { method: 'POST', body: form, credentials: 'same-origin' });
      if (res.status === 401) {
        document.dispatchEvent(new CustomEvent('auth:expired'));
        throw new Error('Session expired');
      }
      if (!res.ok) {
        let detail = `Upload failed (${res.status})`;
        try { const j = await res.json(); if (j.detail) detail = j.detail; } catch (_) {}
        throw new Error(detail);
      }
      return res.json();
    },
    setDeployAddress:   (url) => call('/api/v1/reports/deploy/address',
                          { method: 'PUT', body: { url } }),
    clearDeployAddress: () => call('/api/v1/reports/deploy/address', { method: 'DELETE' }),

    users:        () => call('/api/v1/users'),
    createUser:   (payload) => call('/api/v1/users', { method: 'POST', body: payload }),
    updateUser:   (id, payload) => call(`/api/v1/users/${id}`, { method: 'PATCH', body: payload }),
    resetPassword:(id, password, mustChange) =>
      call(`/api/v1/users/${id}/password`, { method: 'POST',
        body: { password, must_change_password: mustChange } }),
    deleteUser:   (id) => call(`/api/v1/users/${id}`, { method: 'DELETE' }),
    changeOwnPassword: (current_password, new_password) =>
      call('/api/v1/users/me/password', { method: 'POST',
        body: { current_password, new_password } }),
    activity:     (limit = 200) => call(`/api/v1/users/activity/log?limit=${limit}`),

    reportUrl:   (jobId) => `/api/v1/reports/${jobId}/html`,
    downloadUrl: (jobId) => `/api/v1/reports/${jobId}/download`,
    csvUrl:      (jobId) => `/api/v1/reports/${jobId}/findings.csv`,
    bundleUrl:   (jobId) => `/api/v1/reports/${jobId}/bundle`,
    fleetExport: '/api/v1/reports/fleet/export',
  };
})();

/* Live channel. Reconnects with backoff; the console keeps working on polling
   alone if the socket never comes up. */
const Live = (() => {
  let ws = null, tries = 0, timer = null, pinger = null;
  const handlers = {};

  function setDot(up) {
    const el = document.getElementById('liveDot');
    if (el) el.classList.toggle('down', !up);
  }

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    try { ws = new WebSocket(`${proto}://${location.host}/api/v1/stream`); }
    catch (_) { return retry(); }

    ws.onopen = () => {
      tries = 0; setDot(true);
      clearInterval(pinger);
      pinger = setInterval(() => { try { ws.send('ping'); } catch (_) {} }, 25000);
    };
    ws.onmessage = (ev) => {
      let msg; try { msg = JSON.parse(ev.data); } catch (_) { return; }
      (handlers[msg.type] || []).forEach(fn => fn(msg));
      (handlers['*'] || []).forEach(fn => fn(msg));
    };
    ws.onclose = () => { setDot(false); clearInterval(pinger); retry(); };
    ws.onerror = () => { try { ws.close(); } catch (_) {} };
  }

  function retry() {
    clearTimeout(timer);
    tries = Math.min(tries + 1, 6);
    timer = setTimeout(connect, Math.min(1000 * 2 ** tries, 30000));
  }

  return {
    start: connect,
    on(type, fn) { (handlers[type] = handlers[type] || []).push(fn); },
    stop() { clearTimeout(timer); clearInterval(pinger); if (ws) { ws.onclose = null; ws.close(); } },
  };
})();
