/* ═══════════════════════════════════════════════════════════════
   ForenHive API client — real backend integration (FastAPI :8000)
═══════════════════════════════════════════════════════════════ */

const API_BASE = (location.hostname === 'localhost' || location.hostname === '127.0.0.1')
  ? 'http://localhost:8000'
  : `http://${location.hostname}:8000`;

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
  clear() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); },

  async _call(path, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    const tok = this.token();
    if (tok) headers['Authorization'] = 'Bearer ' + tok;
    if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== 'string') {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(this.base + path, Object.assign({}, opts, { headers }));
    if (res.status === 401) {
      this.clear();
      const onLogin = /login\.html$/.test(location.pathname);
      if (!onLogin) location.href = (location.pathname.includes('/pages/') ? '' : 'pages/') + 'login.html';
      throw new Error('unauthorized');
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
    const res = await fetch(this.base + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => null);
      throw new Error((d && (d.detail || d.title)) || 'Identifiants invalides');
    }
    const data = await res.json();
    this.setSession(data.access_token, null);
    const me = await this.me();
    this.setSession(null, me);
    return me;
  },
  me()      { return this._call('/api/auth/me'); },
  refresh() { return this._call('/api/auth/refresh', { method: 'POST' }); },
  users()   { return this._call('/api/auth/users'); },

  /* ─── attacks ─── */
  attacks(params = {}) {
    const qs = new URLSearchParams(params).toString();
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

  /* ─── forensics ─── */
  forensicsTimeline(params) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/forensics/timeline?' + qs);
  },
  yaraHits(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/forensics/yara' + (qs ? '?' + qs : ''));
  },

  /* ─── reports ─── */
  reports(params = {}) {
    const qs = new URLSearchParams(params).toString();
    return this._call('/api/reports' + (qs ? '?' + qs : ''));
  },
  generateReport(body) { return this._call('/api/reports/generate', { method: 'POST', body }); },
  reportDownloadUrl(id){ return this.base + '/api/reports/' + encodeURIComponent(id) + '/download'; },
  reportStixUrl(id)    { return this.base + '/api/reports/' + encodeURIComponent(id) + '/stix'; },

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
