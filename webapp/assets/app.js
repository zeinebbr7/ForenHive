/* ═══════════════════════════════════════════════════════════════
   ForenHive SOC Platform — Router + Auth + Helpers
   (données réelles via api.js → FastAPI)
═══════════════════════════════════════════════════════════════ */

const ROLES = {
  admin:   { label: 'Admin',   color: 'gold',    icon: '👑' },
  analyst: { label: 'Analyst', color: 'blue',    icon: '🔎' },
  viewer:  { label: 'Viewer',  color: 'purple',  icon: '👤' },
  user:    { label: 'User',    color: 'purple',  icon: '👤' },
};

const NAV = [
  { id: 'dashboard',  label: 'Dashboard',    icon: '🏠', roles: ['admin','analyst','viewer','user'] },
  { id: 'stats',      label: 'Statistiques', icon: '📊', roles: ['admin','analyst','viewer'] },
  { id: 'timeline',   label: 'Timeline',     icon: '⏱️', roles: ['admin','analyst','viewer'] },
  { id: 'sessions',   label: 'Sessions',     icon: '🖥️', roles: ['admin','analyst','viewer'] },
  { id: 'geomap',     label: 'Carte Géo',    icon: '🌍', roles: ['admin','analyst','viewer'] },
  { id: 'profiling',  label: 'Profiling',    icon: '🧠', roles: ['admin','analyst'] },
  { id: 'reporting',  label: 'Reporting',    icon: '📋', roles: ['admin','analyst','viewer','user'] },
  { id: 'settings',   label: 'Paramètres',   icon: '⚙️', roles: ['admin','analyst','viewer','user'] },
  { id: 'health',     label: 'Health Check', icon: '💊', roles: ['admin'], section: 'Système' },
  { id: 'config',     label: 'Configuration',icon: '🔧', roles: ['admin'] },
];

/* Zeek = NDR (IDS passif), pas un honeypot */
const HONEYPOTS = ['cowrie', 'dionaea', 'galah'];
const SENSORS   = ['zeek'];
const ALL_SOURCES = [...HONEYPOTS, ...SENSORS];
const SOURCE_META = {
  cowrie:  { label: 'Cowrie',  icon: '🐚', kind: 'honeypot', color: 'var(--gold)',    desc: 'SSH/Telnet' },
  dionaea: { label: 'Dionaea', icon: '🕷️', kind: 'honeypot', color: 'var(--red2)',    desc: 'Malware capture' },
  galah:   { label: 'Galah',   icon: '🦜', kind: 'honeypot', color: 'var(--purple2)', desc: 'LLM Web' },
  zeek:    { label: 'Zeek',    icon: '🔍', kind: 'sensor',   color: 'var(--blue2)',   desc: 'NDR · IDS passif' },
};

const COUNTRIES_ISO = {
  RU:'🇷🇺', CN:'🇨🇳', US:'🇺🇸', BR:'🇧🇷', IN:'🇮🇳', DE:'🇩🇪', NL:'🇳🇱', UA:'🇺🇦',
  IR:'🇮🇷', VN:'🇻🇳', TN:'🇹🇳', KP:'🇰🇵', FR:'🇫🇷', GB:'🇬🇧', JP:'🇯🇵', KR:'🇰🇷',
  TR:'🇹🇷', PL:'🇵🇱', IT:'🇮🇹', ES:'🇪🇸', RO:'🇷🇴', CA:'🇨🇦', MX:'🇲🇽', AU:'🇦🇺',
  CH:'🇨🇭', BE:'🇧🇪', SE:'🇸🇪', FI:'🇫🇮', NO:'🇳🇴', DK:'🇩🇰', AT:'🇦🇹', IE:'🇮🇪',
  ZA:'🇿🇦', EG:'🇪🇬', NG:'🇳🇬', KE:'🇰🇪', MA:'🇲🇦', DZ:'🇩🇿', LY:'🇱🇾', SA:'🇸🇦',
  AE:'🇦🇪', IL:'🇮🇱', SG:'🇸🇬', HK:'🇭🇰', TW:'🇹🇼', ID:'🇮🇩', TH:'🇹🇭', MY:'🇲🇾',
  PH:'🇵🇭', PK:'🇵🇰', BD:'🇧🇩', AR:'🇦🇷', CL:'🇨🇱', CO:'🇨🇴', PE:'🇵🇪', VE:'🇻🇪',
};
const COUNTRY_LATLNG = {
  RU:[55,37],CN:[35,105],US:[39,-98],BR:[-14,-52],IN:[21,78],DE:[51,10],NL:[52,5],
  UA:[49,32],IR:[32,53],VN:[16,108],TN:[34,9],KP:[40,127],FR:[46,2],GB:[54,-2],
  JP:[36,138],KR:[36,128],TR:[39,35],PL:[52,19],IT:[42,12],ES:[40,-4],RO:[46,25],
  CA:[56,-106],MX:[23,-102],AU:[-25,134],CH:[47,8],BE:[50,4],SE:[62,16],FI:[64,26],
  NO:[62,10],DK:[56,10],AT:[47,14],IE:[53,-8],ZA:[-30,24],EG:[27,30],NG:[10,8],
  KE:[0,37],MA:[31,-7],DZ:[28,1],LY:[27,17],SA:[24,45],AE:[24,54],IL:[31,35],
  SG:[1.3,103],HK:[22,114],TW:[23,121],ID:[-5,118],TH:[15,101],MY:[4,102],PH:[12,122],
  PK:[30,70],BD:[24,90],AR:[-38,-63],CL:[-35,-71],CO:[4,-72],PE:[-9,-75],VE:[8,-66],
};
const flag = iso => COUNTRIES_ISO[iso] || '🏳️';
const countryLL = iso => COUNTRY_LATLNG[iso] || [0, 0];

/* ───────── AUTH ───────── */
const Auth = {
  current()   { return api.user(); },
  async login(email, password) {
    const me = await api.login(email, password);
    return me;
  },
  logout() { api.clear(); location.href = (location.pathname.includes('/pages/') ? '' : 'pages/') + 'login.html'; },
  require() {
    const u = this.current();
    if (!u) { location.href = (location.pathname.includes('/pages/') ? '' : 'pages/') + 'login.html'; return null; }
    return u;
  },
  can(page) {
    const u = this.current(); if (!u) return false;
    const nav = NAV.find(n => n.id === page); if (!nav) return false;
    return nav.roles.includes(u.role);
  },
};

/* ───────── HELPERS ───────── */
const fmt = {
  date(ts){ const d = new Date(ts); return isNaN(d) ? '—' : d.toLocaleString('fr-FR', {year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}); },
  time(ts){ const d = new Date(ts); return isNaN(d) ? '—' : d.toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit',second:'2-digit'}); },
  ago(ts){ const t = typeof ts === 'number' ? ts : +new Date(ts);
    const s = Math.max(1, Math.floor((Date.now()-t)/1000));
    if (s < 60) return s+'s';
    if (s < 3600) return Math.floor(s/60)+'m';
    if (s < 86400) return Math.floor(s/3600)+'h';
    return Math.floor(s/86400)+'j'; },
  dur(sec){ if (sec<60) return sec+'s'; if (sec<3600) return Math.floor(sec/60)+'m'+(sec%60)+'s'; return Math.floor(sec/3600)+'h'+Math.floor((sec%3600)/60)+'m'; },
  num(n){ if (n == null) return '—'; if (n >= 1e6) return (n/1e6).toFixed(1)+'M'; if (n >= 1e3) return (n/1e3).toFixed(1)+'k'; return String(n); },
  shortHash(h){ return h && h.length > 18 ? h.slice(0,10)+'…'+h.slice(-6) : (h || '—'); },
  scoreClass(s){ if (s == null) return 'lo'; return s<40 ? 'lo' : (s<70 ? 'md' : 'hi'); },
  sevToClass(s){ return {critical:'crit',high:'hi',medium:'md',low:'lo'}[String(s).toLowerCase()] || 'lo'; },
};

const $  = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

/* utilitaires extraction champs depuis attack event (structure backend) */
function evField(ev, ...candidates) {
  for (const k of candidates) {
    const parts = k.split('.');
    let v = ev;
    for (const p of parts) { if (v == null) break; v = v[p]; }
    if (v != null && v !== '') return v;
  }
  return null;
}
function evNormalize(ev) {
  const raw = ev.raw || {};
  const tags = raw.tags || [];
  const hp = ev.honeypot && ev.honeypot !== 'unknown'
    ? ev.honeypot
    : (raw['honeypot.type'] || tags.find(t => ALL_SOURCES.includes(t)) || 'unknown');
  return {
    id: ev.id,
    timestamp: ev.timestamp || raw['@timestamp'],
    honeypot: hp,
    source_ip: ev.source_ip || raw['source.ip'] || raw.src_ip || raw.remote_host,
    dest_ip: raw['destination.ip'] || raw.dst_ip,
    dest_port: ev.dest_port || raw['destination.port'] || raw.dst_port,
    source_port: ev.source_port || raw['source.port'],
    protocol: ev.protocol || raw['network.transport'] || raw.service || raw.protocol,
    severity: ev.severity || 'low',
    risk_score: ev.risk_score,
    session_id: ev.session_id || raw['session.id'] || raw.session,
    /* auth fields (Cowrie) */
    username: ev.username || raw['user.name'] || raw.username,
    password: ev.password || raw['user.password'] || raw.password,
    /* command (Cowrie shell) */
    command: ev.command || raw['process.command_line'] || raw.input || raw.command,
    /* event type */
    event_action: ev.event_type || raw['event.action'] || raw['event.id'],
    event_category: raw['event.category'],
    /* human-readable message */
    message: raw.message || (raw.event && raw.event.original),
    /* Dionaea-specific */
    dionaea_msg: raw['dionaea.msg'],
    dionaea_module: raw['dionaea.module'],
    /* HTTP (Galah) */
    http_method: ev.http_method || raw['http.request.method'],
    http_path: ev.http_path || raw.url || (raw.http && raw.http.path),
    user_agent: ev.user_agent || raw['user_agent.original'] || raw['http.request.headers.user-agent'],
    country: (ev.geo && ev.geo.country_iso) || (raw['source.geo'] && raw['source.geo'].country_iso_code) || null,
    raw,
  };
}

/* ───────── ROUTER ───────── */
const Router = {
  pages: ['dashboard','stats','timeline','sessions','geomap','profiling','reporting','settings','health','config'],
  current: null,
  async go(page, push = true) {
    if (!this.pages.includes(page)) page = 'dashboard';
    const user = Auth.current();
    if (!user) { Auth.require(); return; }
    const nav = NAV.find(n => n.id === page);
    if (!nav || !nav.roles.includes(user.role)) page = 'dashboard';
    if (push) history.replaceState({page}, '', '#'+page);
    const content = $('#content');
    content.classList.remove('visible');
    try {
      if (typeof window.__pageCleanup === 'function') { try { window.__pageCleanup(); } catch(e){} }
      window.__pageCleanup = null;
      const res = await fetch('pages/' + page + '.html?v=3', {cache: 'no-cache'});
      const html = await res.text();
      content.innerHTML = html;
      // re-exécute les <script> injectés
      content.querySelectorAll('script').forEach(old => {
        const s = document.createElement('script');
        for (const a of old.attributes) s.setAttribute(a.name, a.value);
        s.textContent = old.textContent;
        old.replaceWith(s);
      });
      content.classList.add('visible');
      this.current = page;
      $$('#sb-nav .sb-item').forEach(el => el.classList.toggle('active', el.dataset.page === page));
      $('#tb-title').textContent = (NAV.find(n => n.id === page) || {label:'ForenHive'}).label;
      window.scrollTo({top:0});
    } catch(e) {
      content.innerHTML = `<div class="alert err">Erreur de chargement · ${esc(e.message || e)}</div>`;
      console.error(e);
    }
  },
  init() {
    window.addEventListener('hashchange', () => this.go(location.hash.slice(1) || 'dashboard', false));
    const start = location.hash.slice(1) || 'dashboard';
    this.go(start, true);
  }
};

/* ───────── APP SHELL INIT ───────── */
function buildSidebar(user) {
  const mainItems = NAV.filter(n => !n.section);
  const sysItems  = NAV.filter(n => n.section === 'Système');
  const render = items => items.map(n => {
    const allowed = n.roles.includes(user.role);
    return `<a class="sb-item ${allowed?'':'disabled'}" data-page="${n.id}" href="#${n.id}">
      <span class="sb-item-ic">${n.icon}</span><span>${n.label}</span>
    </a>`;
  }).join('');
  $('#sb-nav').innerHTML = render(mainItems) + (sysItems.length ? `<div class="sb-section">Système</div>${render(sysItems)}` : '');
  $$('#sb-nav .sb-item').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      if (el.classList.contains('disabled')) return;
      Router.go(el.dataset.page);
    });
  });
}

function updateTime() {
  const el = $('#tb-time'); if (el) el.textContent = new Date().toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

async function initAppShell() {
  const user = Auth.require(); if (!user) return;
  // refresh user info from backend (role may have changed)
  try { const me = await api.me(); api.setSession(null, me); } catch(e) { /* offline? use cached */ }
  const cur = Auth.current();
  const role = ROLES[cur.role] || ROLES.viewer;
  $('#sb-role').className = `sb-role ${cur.role}`;
  $('#sb-role').innerHTML = `<span class="sb-role-dot"></span>${role.label}`;
  $('#tb-avatar').textContent = role.icon;
  $('#tb-name').textContent = cur.email.split('@')[0];
  $('#tb-role').textContent = role.label;
  buildSidebar(cur);
  $('#sb-logout').addEventListener('click', () => Auth.logout());
  const burger = $('#burger'); if (burger) burger.addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  updateTime(); setInterval(updateTime, 1000);
  Router.init();
}

/* expose pour les pages */
window.FH = {
  Auth, Router, NAV, ROLES, HONEYPOTS, SENSORS, ALL_SOURCES, SOURCE_META,
  COUNTRIES_ISO, COUNTRY_LATLNG, flag, countryLL,
  fmt, esc, $, $$, evNormalize, evField,
};
