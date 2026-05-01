/* ═══════════════════════════════════════════════════════════════
   ForenHive SOC Platform — Router + Auth + Helpers
═══════════════════════════════════════════════════════════════ */

const ROLES = {
  admin:   { label: 'Admin',   color: 'gold', icon: '' },
  analyst: { label: 'Analyst', color: 'blue', icon: '' },
};

const NAV_GROUPS = [
  { label: null, items: [
    { id: 'dashboard', label: 'Home', icon: '', roles: ['admin','analyst'] },
  ]},
  { label: 'Monitoring', items: [
    { id: 'alerts',   label: 'Alerts / Incidents', icon: '', roles: ['admin','analyst'] },
    { id: 'sessions', label: 'Sessions',           icon: '', roles: ['admin','analyst'] },
    { id: 'health',   label: 'Health Check',       icon: '', roles: ['admin'] },
  ]},
  { label: 'Forensic Analysis', items: [
    { id: 'timeline',       label: 'Timeline',              icon: '', roles: ['admin','analyst'] },
    { id: 'reconstruction', label: 'Attack Reconstruction', icon: '', roles: ['admin','analyst'] },
    { id: 'evidence',       label: 'Evidence Logs',         icon: '', roles: ['admin','analyst'] },
    { id: 'profiling',      label: 'Profiling',             icon: '', roles: ['admin','analyst'] },
  ]},
  { label: 'Threat Intelligence', items: [
    { id: 'geomap', label: 'Geo Map',    icon: '', roles: ['admin','analyst'] },
    { id: 'stats',  label: 'Statistics', icon: '', roles: ['admin','analyst'] },
  ]},
  { label: 'Reports', items: [
    { id: 'reporting', label: 'Reporting', icon: '', roles: ['admin','analyst'] },
  ]},
  { label: 'Honeypot Management', items: [
    { id: 'honeypots', label: 'Honeypots', icon: '', roles: ['admin'] },
  ]},
  { label: 'Access Control', items: [
    { id: 'access', label: 'Access Control', icon: '', roles: ['admin'] },
  ]},
];

const NAV = NAV_GROUPS.flatMap(g => g.items);

const HONEYPOTS = ['cowrie', 'dionaea', 'galah'];
const SENSORS   = ['zeek'];
const ALL_SOURCES = [...HONEYPOTS, ...SENSORS];
const SOURCE_META = {
  cowrie:  { label: 'Cowrie',  icon: '', kind: 'honeypot', color: 'var(--gold)',    desc: 'SSH/Telnet' },
  dionaea: { label: 'Dionaea', icon: '', kind: 'honeypot', color: 'var(--red2)',    desc: 'Malware capture' },
  galah:   { label: 'Galah',   icon: '', kind: 'honeypot', color: 'var(--purple2)', desc: 'LLM Web' },
  zeek:    { label: 'Zeek',    icon: '', kind: 'sensor',   color: 'var(--blue2)',   desc: 'NDR · Passive IDS' },
};

const COUNTRIES_ISO = {
  RU:'', CN:'', US:'', BR:'', IN:'', DE:'', NL:'', UA:'',
  IR:'', VN:'', TN:'', KP:'', FR:'', GB:'', JP:'', KR:'',
  TR:'', PL:'', IT:'', ES:'', RO:'', CA:'', MX:'', AU:'',
  CH:'', BE:'', SE:'', FI:'', NO:'', DK:'', AT:'', IE:'',
  ZA:'', EG:'', NG:'', KE:'', MA:'', DZ:'', LY:'', SA:'',
  AE:'', IL:'', SG:'', HK:'', TW:'', ID:'', TH:'', MY:'',
  PH:'', PK:'', BD:'', AR:'', CL:'', CO:'', PE:'', VE:'',
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
const flag = iso => COUNTRIES_ISO[iso] || '';
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
  date(ts){ const d = new Date(ts); return isNaN(d) ? '—' : d.toLocaleString('en-US', {year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}); },
  time(ts){ const d = new Date(ts); return isNaN(d) ? '—' : d.toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}); },
  ago(ts){ const t = typeof ts === 'number' ? ts : +new Date(ts);
    const s = Math.max(1, Math.floor((Date.now()-t)/1000));
    if (s < 60) return s+'s';
    if (s < 3600) return Math.floor(s/60)+'m';
    if (s < 86400) return Math.floor(s/3600)+'h';
    return Math.floor(s/86400)+'d'; },
  dur(sec){ if (sec<60) return sec+'s'; if (sec<3600) return Math.floor(sec/60)+'m'+(sec%60)+'s'; return Math.floor(sec/3600)+'h'+Math.floor((sec%3600)/60)+'m'; },
  num(n){ if (n == null) return '—'; if (n >= 1e6) return (n/1e6).toFixed(1)+'M'; if (n >= 1e3) return (n/1e3).toFixed(1)+'k'; return String(n); },
  shortHash(h){ return h && h.length > 18 ? h.slice(0,10)+'…'+h.slice(-6) : (h || '—'); },
  scoreClass(s){ if (s == null) return 'lo'; return s<40 ? 'lo' : (s<70 ? 'md' : 'hi'); },
  sevToClass(s){ return {critical:'crit',high:'hi',medium:'md',low:'lo'}[String(s).toLowerCase()] || 'lo'; },
};

const $  = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

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
    username: ev.username || raw['user.name'] || raw.username,
    password: ev.password || raw['user.password'] || raw.password,
    command: ev.command || raw['process.command_line'] || raw.input || raw.command,
    event_action: ev.event_type || raw['event.action'] || raw['event.id'],
    event_category: raw['event.category'],
    message: raw.message || (raw.event && raw.event.original),
    dionaea_msg: raw['dionaea.msg'],
    dionaea_module: raw['dionaea.module'],
    http_method: ev.http_method || raw['http.request.method'],
    http_path: ev.http_path || raw['http.request.uri'] || raw['http.request.path'] || raw.url || (raw.http && raw.http.path),
    user_agent: ev.user_agent || raw['http.request.user_agent'] || raw['user_agent.original'] || raw['http.request.headers.user-agent'],
    country: (ev.geo && ev.geo.country_iso) || (raw['source.geo'] && (raw['source.geo'].country_iso_code || (raw['source.geo'].geo && raw['source.geo'].geo.country_iso_code))) || null,
    raw,
  };
}

/* ───────── ROUTER ───────── */
const Router = {
  pages: ['dashboard','alerts','sessions','health','timeline','reconstruction','evidence','profiling','geomap','stats','reporting','honeypots','access','settings','config'],
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
      content.innerHTML = `<div class="alert err">Loading error — ${esc(e.message || e)}</div>`;
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
  const html = NAV_GROUPS.map(group => {
    const visible = group.items.filter(n => n.roles.includes(user.role));
    if (!visible.length) return '';
    const header = group.label ? `<div class="sb-section">${group.label}</div>` : '';
    const items = visible.map(n => `
      <a class="sb-item" data-page="${n.id}" href="#${n.id}">
        <span class="sb-item-ic">${n.icon}</span><span>${n.label}</span>
      </a>`).join('');
    return header + items;
  }).join('');
  $('#sb-nav').innerHTML = html;
  $$('#sb-nav .sb-item').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      if (el.classList.contains('disabled')) return;
      Router.go(el.dataset.page);
    });
  });
}

function updateTime() {
  const el = $('#tb-time'); if (el) el.textContent = new Date().toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
}

async function initAppShell() {
  const user = Auth.require(); if (!user) return;
  try { const me = await api.me(); api.setSession(null, me); } catch(e) { /* offline — use cached */ }
  const cur = Auth.current();
  const role = ROLES[cur.role] || ROLES.analyst;
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

window.FH = {
  Auth, Router, NAV, NAV_GROUPS, ROLES, HONEYPOTS, SENSORS, ALL_SOURCES, SOURCE_META,
  COUNTRIES_ISO, COUNTRY_LATLNG, flag, countryLL,
  fmt, esc, $, $$, evNormalize, evField,
};
