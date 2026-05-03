/* ═══════════════════════════════════════════════════════════════
   ForenHive API client — proxied through nginx (/api → backend)
═══════════════════════════════════════════════════════════════ */

const API_BASE = '';

const TOKEN_KEY = 'forenhive.token';
const USER_KEY  = 'forenhive.user';

const api = {
  base: API_BASE,
  token() { return localStorage.getItem(TOKEN_KEY); },
  user()  { try { return JSON.parse(localStorage.getItem(USER_KEY)); } catch(e){ return null; } },
  setSession(token, user) {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    if (user)  localStorage.setItem(USER_KEY, JSON.stringify(user));
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },

  async _call(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    const tok = this.token();
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== 'string') {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(this.base + path, Object.assign({}, opts, { headers }));
    if (res.status === 401 && !path.startsWith('/api/auth/login') && !path.startsWith('/api/auth/me')) {
      this.clear();
      const loginUrl = location.pathname.includes('/pages/') ? 'login.html' : 'pages/login.html';
      window.location.href = loginUrl;
      throw new Error('session expired');
    }
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await res.json().catch(() => null) : await res.text();
    if (!res.ok) {
      const msg = (data && (data.detail || data.title)) || res.statusText || ('HTTP ' + res.status);
      const err = new Error(msg); err.status = res.status; err.data = data;
      throw err;
    }
    return data;
  },

  /* ─── auth ─── */
  async login(email, password) {
    const body = new URLSearchParams({ username: email, password });
    const data = await this._call('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    // Decode JWT payload (no signature verification needed client-side)
    const payload = JSON.parse(atob(data.access_token.split('.')[1]));
    const me = { id: payload.sub, email: payload.email, role: payload.role, full_name: payload.email, is_active: true, created_at: new Date().toISOString() };
    this.setSession(data.access_token, me);
    return me;
  },
  me()      { return this._call('/api/auth/me'); },
  refresh() { return this._call('/api/auth/refresh', { method: 'POST' }); },
  users()   { return this._call('/api/auth/users'); },

  /* ─── attacks ─── */
  attacks(params = {}) {
    /* backend uses page_size (real max ~120), not limit — page 2 always empty (backend bug) */
    const p = Object.assign({}, params);
    if (p.limit) { p.page_size = Math.min(Number(p.limit), 100); delete p.limit; }
    if (!p.page_size) p.page_size = 100;
    else p.page_size = Math.min(Number(p.page_size), 100);
    const qs = new URLSearchParams(p).toString();
    return this._call('/api/attacks' + (qs ? '?' + qs : ''));
  },
  attack(id)    { return this._call('/api/attacks/' + encodeURIComponent(id)); },
  statsHourly() { return this._call('/api/attacks/stats/hourly'); },
  statsLive(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/attacks/stats/live' + (qs ? '?' + qs : ''));
  },

  /* ─── sessions ─── */
  sessions(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/sessions' + (qs ? '?' + qs : ''));
  },
  session(id) { return this._call('/api/sessions/' + encodeURIComponent(id)); },

  /* ─── geo / profiling ─── */
  geoSplit()    { return this._call('/api/geo/honeypot-split'); },
  geoBreakdown(){ return this._call('/api/geo/breakdown'); },
  profile(ip)   { return this._call('/api/profiling/' + encodeURIComponent(ip)); },
  profilingList(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/profiling' + (qs ? '?' + qs : ''));
  },
  profilingStats()   { return this._call('/api/profiling/stats/summary'); },
  profilingById(id)  { return this._call('/api/profiling/by-id/' + encodeURIComponent(id)); },

  /* ─── forensics ─── */
  forensicsTimeline(params) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/forensics/timeline?' + qs);
  },
  yaraHits(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/forensics/yara' + (qs ? '?' + qs : ''));
  },
  forensicRunNow() { return this._call('/api/forensics/run', { method: 'POST' }); },

  /* ─── reports ─── */
  reports(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/reports' + (qs ? '?' + qs : ''));
  },
  generateReport(body) { return this._call('/api/reports/generate', { method: 'POST', body }); },
  reportDownloadUrl(id){ return this.base + '/api/reports/' + encodeURIComponent(id) + '/download'; },
  reportStixUrl(id)    { return this.base + '/api/reports/' + encodeURIComponent(id) + '/stix'; },

  /* ─── forensic PDF reports (Sprint 4) ─── */
  forensicSessions(limit = 50) { return this._call('/api/reports/forensic/sessions?limit=' + limit); },
  forensicReportPreviewUrl(sid) {
    return this.base + '/api/reports/forensic/' + encodeURIComponent(sid) + '/preview';
  },
  async forensicReportDownload(sid) {
    const tok = this.token();
    const res = await fetch(this.base + '/api/reports/forensic/' + encodeURIComponent(sid) + '/generate', {
      method: 'POST',
      headers: tok ? { 'Authorization': 'Bearer ' + tok } : {},
    });
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { const j = await res.json(); msg = j.detail || msg; } catch(e){}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const cd = res.headers.get('Content-Disposition') || '';
    const m = /filename="([^"]+)"/.exec(cd);
    a.download = m ? m[1] : 'ForenHive-' + sid + '.pdf';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    return { sha256: res.headers.get('X-PDF-SHA256') };
  },

  /* ─── alerts ─── */
  alertConfig()           { return this._call('/api/alerts/config'); },
  setAlertConfig(body)    { return this._call('/api/alerts/config', { method: 'PUT', body }); },
  alertHistory(params={}) { const qs = new URLSearchParams(params).toString(); return this._call('/api/alerts/history' + (qs?'?'+qs:'')); },
  alertTest(body)         { return this._call('/api/alerts/test', { method: 'POST', body }); },

  /* ─── audit / health ─── */
  audit(params={}) { const qs = new URLSearchParams(params).toString(); return this._call('/api/audit' + (qs?'?'+qs:'')); },
  health()         { return fetch(this.base + '/health').then(r => r.json()).catch(() => ({ status:'down' })); },
};

window.api = api;
