/* ═══════════════════════════════════════════════════════════════
   HIVE — ForenHive forensic terminal  ·  multi-session
═══════════════════════════════════════════════════════════════ */

// ── language ───────────────────────────────────────────────────────────────────
const _lang = (() => {
  const l = (document.documentElement.lang || navigator.language || 'en').toLowerCase();
  return l.startsWith('fr') ? 'fr' : 'en';
})();
const T = {
  en: {
    title:       'HIVE — forensic terminal',
    welcome:     'Hi, I\x27m HIVE — your friendly ForenHive assistant.\nAsk me anything about the ForenHive platform or cybersecurity in general.\nNew here? Type /help to see what I can do.\n',
    help:
      'Available commands:\n' +
      '  /sessions [n]   last n honeypot sessions (default 20)\n' +
      '  /iocs           indicators of compromise\n' +
      '  /profil         suspect profiles\n' +
      '  /mitre          MITRE ATT\x26CK mappings\n' +
      '  /clear          clear this terminal tab\n\n' +
      'Or ask anything in English or French.',
    cleared: 'Terminal cleared.', offline: 'HIVE offline — check connection',
    placeholder: 'Enter command or question…', you: 'you',
    groq: 'groq online', off: 'offline',
    newTab: 'new session', session: 'session',
  },
  fr: {
    title:       'HIVE — terminal forensique',
    welcome:     'Bonjour, je suis HIVE — votre assistant ForenHive convivial.\nPosez-moi vos questions sur la plateforme ForenHive ou la cybersécurité en général.\nPremière visite ? Tapez /help pour découvrir mes commandes.\n',
    help:
      'Commandes disponibles :\n' +
      '  /sessions [n]   n dernières sessions honeypot (défaut 20)\n' +
      '  /iocs           indicateurs de compromission\n' +
      '  /profil         profils suspects\n' +
      '  /mitre          mappings MITRE ATT\x26CK\n' +
      '  /clear          effacer cet onglet\n\n' +
      'Ou posez une question en français ou anglais.',
    cleared: 'Terminal effacé.', offline: 'HIVE hors ligne — vérifiez la connexion',
    placeholder: 'Entrez une commande ou question…', you: 'you',
    groq: 'groq online', off: 'offline',
    newTab: 'nouvelle session', session: 'session',
  },
};
const t = T[_lang];

// ── CSS ────────────────────────────────────────────────────────────────────────
if (!document.getElementById('hive-chat-styles')) {
  const s = document.createElement('style');
  s.id = 'hive-chat-styles';
  s.textContent = `
  /* ── FAB: floating hacker character ── */
  #hive-fab {
    position:fixed; bottom:32px; right:32px; z-index:9999;
    width:64px; height:72px;
    background:none; border:none; padding:0; margin:0;
    cursor:pointer; display:flex; flex-direction:column;
    align-items:center; justify-content:flex-end;
    user-select:none; outline:none;
    animation: hive-float 3s ease-in-out infinite;
    filter: drop-shadow(0 8px 18px rgba(140,26,43,.6));
    transition: filter .15s ease;
  }
  #hive-fab:hover {
    filter: drop-shadow(0 12px 28px rgba(140,26,43,.9)) brightness(1.12);
    animation-play-state: paused;
  }
  #hive-fab:active { transform:scale(.92); animation-play-state:paused; }

  @keyframes hive-float {
    0%,100% { transform:translateY(0px) rotate(0deg); }
    25%      { transform:translateY(-8px) rotate(-1.5deg); }
    75%      { transform:translateY(-4px) rotate(1deg); }
  }

  /* shadow that shrinks/grows as character bobs */
  #hive-fab-shadow {
    width:36px; height:7px; border-radius:50%;
    background:rgba(140,26,43,.35);
    position:absolute; bottom:-10px; left:50%; transform:translateX(-50%);
    animation: hive-shadow 3s ease-in-out infinite;
    pointer-events:none;
    filter: blur(3px);
  }
  @keyframes hive-shadow {
    0%,100% { transform:translateX(-50%) scaleX(1);   opacity:.35; }
    25%      { transform:translateX(-50%) scaleX(.6);  opacity:.18; }
    75%      { transform:translateX(-50%) scaleX(.8);  opacity:.25; }
  }

  #hive-badge {
    position:absolute; top:2px; right:2px;
    min-width:18px; height:18px; border-radius:9px;
    background:var(--accent-gold,#D4A84A); color:#1a0a0f;
    font-size:9px; font-weight:800; font-family:'Inter',sans-serif;
    display:none; align-items:center; justify-content:center;
    padding:0 3px; border:2px solid var(--bg,#0f0a0b);
    z-index:1;
  }
  #hive-badge.on { display:flex; }

  #hive-window {
    position:fixed; bottom:116px; right:28px; z-index:9998;
    width:440px; height:540px;
    display:flex; flex-direction:column;
    background:var(--bg2); border:1px solid var(--border2); border-radius:8px;
    box-shadow:var(--shadow-lg);
    overflow:hidden; font-family:'JetBrains Mono',ui-monospace,monospace;
    opacity:0; transform:translateY(16px); pointer-events:none;
    transition:opacity .18s ease, transform .18s ease;
  }
  #hive-window.open { opacity:1; transform:translateY(0); pointer-events:all; }

  /* title bar */
  #hive-titlebar {
    background:var(--bg3); border-bottom:1px solid var(--border);
    padding:8px 12px; display:flex; align-items:center; gap:8px; flex-shrink:0;
  }
  .hive-tbar-dots { display:flex; gap:5px; }
  .hive-tbar-dot  { width:11px; height:11px; border-radius:50%; cursor:pointer; transition:opacity .15s; }
  .hive-tbar-dot:hover { opacity:.7; }
  .hive-dot-r{background:#FF5F57} .hive-dot-y{background:#FEBC2E} .hive-dot-g{background:#28C840}
  #hive-titlebar-text { flex:1; font-size:11px; font-weight:600; color:var(--text3); letter-spacing:.5px; }
  #hive-titlebar-text span { color:var(--accent-gold); }
  #hive-backend-pill {
    font-size:9px; font-weight:600; letter-spacing:.5px;
    padding:2px 7px; border-radius:3px; border:1px solid currentColor;
    font-family:'JetBrains Mono',ui-monospace,monospace; transition:color .3s;
  }
  #hive-backend-pill.groq   { color:var(--teal); }
  #hive-backend-pill.unknown{ color:var(--text3); }

  /* ── session tabs ── */
  #hive-tabs {
    display:flex; align-items:stretch;
    background:var(--bg2); border-bottom:1px solid var(--border);
    overflow-x:auto; flex-shrink:0;
    scrollbar-width:none;
  }
  #hive-tabs::-webkit-scrollbar { display:none; }
  .hive-tab {
    display:flex; align-items:center; gap:5px;
    font-family:'JetBrains Mono',ui-monospace,monospace;
    font-size:10px; font-weight:600; letter-spacing:.3px;
    color:var(--text3); padding:5px 10px 4px;
    cursor:pointer; white-space:nowrap;
    border-bottom:2px solid transparent;
    border-right:1px solid var(--border);
    transition:color .12s, border-color .12s;
    user-select:none;
  }
  .hive-tab:hover:not(.active) { color:var(--text2); background:rgba(255,255,255,.02); }
  .hive-tab.active { color:var(--accent-gold); border-bottom-color:var(--gold); }
  .hive-tab-x {
    font-size:11px; line-height:1; padding:0 2px; border-radius:2px;
    color:var(--text3); transition:color .1s, background .1s;
  }
  .hive-tab-x:hover { color:var(--red2) !important; background:rgba(201,61,85,.12); }
  #hive-new-tab {
    font-family:'JetBrains Mono',ui-monospace,monospace;
    font-size:16px; font-weight:300; color:var(--text3);
    background:transparent; border:none; cursor:pointer;
    padding:4px 12px; flex-shrink:0;
    transition:color .12s;
  }
  #hive-new-tab:hover { color:var(--accent-gold); }

  /* status bar */
  #hive-statusbar {
    background:var(--bg2); border-bottom:1px solid var(--border);
    padding:4px 12px; display:flex; align-items:center; gap:14px; flex-shrink:0;
  }
  .hive-si {
    display:flex; align-items:center; gap:5px;
    font-size:9px; color:var(--text3); letter-spacing:.4px;
    font-family:'JetBrains Mono',ui-monospace,monospace;
  }
  .hive-sdot { width:5px; height:5px; border-radius:50%; background:var(--text3); transition:background .4s; }
  .hive-sdot.ok  { background:var(--teal); }
  .hive-sdot.err { background:var(--red2); }

  /* terminal body */
  #hive-terminal {
    flex:1; overflow-y:auto; padding:10px 12px 6px;
    scrollbar-width:thin; scrollbar-color:var(--border2) transparent;
    display:flex; flex-direction:column; background:var(--bg);
  }
  #hive-terminal::-webkit-scrollbar { width:4px; }
  #hive-terminal::-webkit-scrollbar-thumb { background:var(--gold); border-radius:2px; }

  .hive-line {
    display:flex; line-height:1.6; font-size:12px;
    font-family:'JetBrains Mono',ui-monospace,monospace;
    white-space:pre-wrap; word-break:break-word;
  }
  .hive-line.spacer { height:6px; }
  .hive-line-prefix { flex-shrink:0; user-select:none; margin-right:8px; }
  .hive-line.from-hive .hive-line-prefix { color:var(--gold); }
  .hive-line.from-you  .hive-line-prefix { color:var(--accent-gold); }
  .hive-line.from-err  .hive-line-prefix { color:var(--red2); }
  .hive-line.from-sys  .hive-line-prefix { color:var(--text3); }
  .hive-line-body { color:var(--text); flex:1; }
  .hive-line.from-you  .hive-line-body { color:var(--accent-gold); }
  .hive-line.from-err  .hive-line-body { color:var(--red2); }
  .hive-line.from-sys  .hive-line-body { color:var(--text3); }

  .hp-mitre {
    background:rgba(123,47,190,.15); border:1px solid rgba(159,106,224,.35);
    color:var(--purple2,#9F6AE0); border-radius:3px;
    font-size:10px; font-weight:600; padding:0 4px; margin:0 1px;
  }
  .hp-risk {
    background:var(--gold-glow); border:1px solid var(--border2);
    color:var(--red2); border-radius:3px;
    font-size:10px; font-weight:600; padding:0 4px; margin:0 1px;
  }
  .hp-ip { color:var(--blue2,#6AB0FF); }

  .hive-cursor {
    display:inline-block; width:7px; height:12px;
    background:var(--gold); margin-left:2px; vertical-align:text-bottom;
    animation:hive-blink .9s step-end infinite;
  }
  @keyframes hive-blink { 0%,100%{opacity:1} 50%{opacity:0} }

  /* chips */
  #hive-chips {
    padding:5px 10px; display:flex; gap:4px; flex-wrap:wrap;
    flex-shrink:0; background:var(--bg3); border-top:1px solid var(--border);
  }
  .hive-chip {
    font-family:'JetBrains Mono',ui-monospace,monospace;
    font-size:10px; font-weight:600; letter-spacing:.3px;
    color:var(--text3); background:var(--surface);
    border:1px solid var(--border); border-radius:3px;
    padding:3px 8px; cursor:pointer; transition:color .12s, border-color .12s;
  }
  .hive-chip:hover { color:var(--accent-gold); border-color:var(--border2); }

  /* input */
  #hive-input-row {
    display:flex; align-items:center; padding:7px 12px;
    background:var(--bg3); border-top:1px solid var(--border2); flex-shrink:0;
  }
  #hive-prompt-label {
    font-family:'JetBrains Mono',ui-monospace,monospace;
    font-size:12px; font-weight:700; color:var(--gold);
    margin-right:8px; flex-shrink:0; user-select:none; white-space:nowrap;
  }
  #hive-input {
    flex:1; background:transparent; border:none; outline:none;
    font-family:'JetBrains Mono',ui-monospace,monospace;
    font-size:12px; color:var(--text); caret-color:var(--accent-gold);
  }
  #hive-input::placeholder { color:var(--text3); opacity:.5; }
  #hive-send {
    width:28px; height:28px; border-radius:4px;
    background:var(--gold); border:none; cursor:pointer;
    display:flex; align-items:center; justify-content:center;
    flex-shrink:0; margin-left:6px; transition:background .12s;
  }
  #hive-send:hover  { background:var(--gold2,#A62240); }
  #hive-send:active { transform:scale(.92); }
  #hive-send svg { width:13px; height:13px; color:#fff; }
  `;
  document.head.appendChild(s);
}

// ── HTML ───────────────────────────────────────────────────────────────────────
const _root = document.createElement('div');
_root.id = 'hive-chat-root';
_root.innerHTML = `
  <button id="hive-fab" title="${t.title}" aria-label="Open HIVE terminal">
    <div id="hive-badge"></div>
    <svg width="54" height="58" viewBox="0 0 54 58" fill="none" xmlns="http://www.w3.org/2000/svg" style="pointer-events:none;display:block;">
      <!-- ghost body -->
      <path d="M7 24 C7 10 47 10 47 24 L47 46 L40 40 L33 46 L27 40 L21 46 L14 40 L7 46 Z" fill="#8C1A2B"/>
      <!-- eyes -->
      <circle cx="20" cy="28" r="5" fill="white"/>
      <circle cx="34" cy="28" r="5" fill="white"/>
      <circle id="ghost-pupil-l" cx="21" cy="29" r="2.5" fill="#1a0810"/>
      <circle id="ghost-pupil-r" cx="35" cy="29" r="2.5" fill="#1a0810"/>
    </svg>
    <div id="hive-fab-shadow"></div>
  </button>
  <div id="hive-window" role="dialog" aria-label="HIVE terminal">
    <div id="hive-titlebar">
      <div class="hive-tbar-dots">
        <div class="hive-tbar-dot hive-dot-r" id="hive-close-dot"></div>
        <div class="hive-tbar-dot hive-dot-y"></div>
        <div class="hive-tbar-dot hive-dot-g"></div>
      </div>
      <span id="hive-titlebar-text"><span>hive</span>@forensic:~</span>
      <span id="hive-backend-pill" class="unknown">● …</span>
    </div>
    <div id="hive-tabs">
      <button id="hive-new-tab" title="${t.newTab}">+</button>
    </div>
    <div id="hive-statusbar">
      <div class="hive-si"><div class="hive-sdot" id="hive-dot-es"></div>elasticsearch</div>
      <div class="hive-si"><div class="hive-sdot" id="hive-dot-pg"></div>postgresql</div>
      <div class="hive-si"><div class="hive-sdot" id="hive-dot-llm"></div>llm</div>
    </div>
    <div id="hive-terminal"></div>
    <div id="hive-chips">
      <button class="hive-chip" data-cmd="/sessions">/sessions</button>
      <button class="hive-chip" data-cmd="/iocs">/iocs</button>
      <button class="hive-chip" data-cmd="/profil">/profil</button>
      <button class="hive-chip" data-cmd="/mitre">/mitre</button>
      <button class="hive-chip" data-cmd="/help">/help</button>
    </div>
    <div id="hive-input-row">
      <span id="hive-prompt-label">hive@forensic:~$</span>
      <input id="hive-input" type="text"
             placeholder="${t.placeholder}" autocomplete="off" spellcheck="false">
      <button id="hive-send" title="Run">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
             stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="9 18 15 12 9 6"/>
        </svg>
      </button>
    </div>
  </div>
`;
document.body.appendChild(_root);

// ── helpers ────────────────────────────────────────────────────────────────────
const _hid = id => document.getElementById(id);

function _authHeaders() {
  const tok = localStorage.getItem('forenhive.token') || '';
  const h = { 'Content-Type': 'application/json' };
  if (tok) h['Authorization'] = 'Bearer ' + tok;
  return h;
}

function _fmt(text) {
  return text
    .replace(/\b(T\d{4}(?:\.\d{3})?)\b/g, '<span class="hp-mitre">$1</span>')
    .replace(/\b((?:risk[\s_]?score|score)\s*[:\s]+\d+|\b\d{1,3}\/100)\b/gi, '<span class="hp-risk">$1</span>')
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="hp-ip">$1</span>');
}

function _scrollBottom() {
  const el = _hid('hive-terminal');
  if (el) el.scrollTop = el.scrollHeight;
}

// ── sessions data ──────────────────────────────────────────────────────────────
let _sessions   = [];   // [{ id, name, history:[], html:'', welcomed:false }]
let _activeId   = 0;
let _nextId     = 1;
let _open       = false;
let _unread     = 0;
let _streaming  = false;

function _mkSession(name) {
  return { id: _nextId++, name, history: [], html: '', welcomed: false };
}

function _active() {
  return _sessions.find(s => s.id === _activeId);
}

// Auto-name a session from first message keywords
function _autoName(msg) {
  const m = msg.toLowerCase();
  if (/ioc|hash|yara|malware|sha/.test(m))           return 'IOCs';
  if (/mitre|ttp|technique|tactic/.test(m))           return 'MITRE';
  if (/profil|suspect|actor/.test(m))                 return 'Profiling';
  if (/session|honeypot|cowrie|dionaea|galah/.test(m))return 'Sessions';
  if (/risk|score|danger/.test(m))                    return 'Risk';
  if (/platform|dashboard|overview/.test(m))          return 'Platform';
  return msg.slice(0, 10).trim() || t.session;
}

// ── tab rendering ──────────────────────────────────────────────────────────────
function _renderTabs() {
  const bar = _hid('hive-tabs');
  // remove existing tabs (keep #hive-new-tab)
  bar.querySelectorAll('.hive-tab').forEach(el => el.remove());

  const btn = _hid('hive-new-tab');
  _sessions.forEach(sess => {
    const tab = document.createElement('div');
    tab.className = 'hive-tab' + (sess.id === _activeId ? ' active' : '');
    tab.dataset.id = sess.id;

    const lbl = document.createElement('span');
    lbl.textContent = sess.name;
    tab.appendChild(lbl);

    if (_sessions.length > 1) {
      const x = document.createElement('span');
      x.className = 'hive-tab-x';
      x.textContent = '×';
      x.title = 'Close';
      x.addEventListener('click', e => { e.stopPropagation(); _closeSession(sess.id); });
      tab.appendChild(x);
    }

    tab.addEventListener('click', () => _switchSession(sess.id));
    bar.insertBefore(tab, btn);
  });
}

// ── session ops ────────────────────────────────────────────────────────────────
function _saveActive() {
  const sess = _active();
  if (sess) sess.html = _hid('hive-terminal').innerHTML;
}

function _newSession(name) {
  _saveActive();
  const sess = _mkSession(name || `${t.session} ${_nextId - 1}`);
  _sessions.push(sess);
  _activeId = sess.id;
  _hid('hive-terminal').innerHTML = '';
  _renderTabs();
  _printWelcome(sess);
  setTimeout(() => _hid('hive-input') && _hid('hive-input').focus(), 50);
}

function _switchSession(id) {
  if (id === _activeId) return;
  _saveActive();
  _activeId = id;
  const sess = _active();
  _hid('hive-terminal').innerHTML = sess ? sess.html : '';
  _renderTabs();
  _scrollBottom();
  setTimeout(() => _hid('hive-input') && _hid('hive-input').focus(), 50);
}

function _closeSession(id) {
  if (_sessions.length <= 1) return; // always keep at least one
  const idx = _sessions.findIndex(s => s.id === id);
  _sessions.splice(idx, 1);
  if (_activeId === id) {
    const next = _sessions[Math.min(idx, _sessions.length - 1)];
    _activeId = next.id;
    _hid('hive-terminal').innerHTML = next.html;
  }
  _renderTabs();
  _scrollBottom();
}

// ── terminal print helpers ─────────────────────────────────────────────────────
function _printLine(role, text, isHTML = false) {
  const term = _hid('hive-terminal');
  const prefixMap = {
    'from-hive': 'hive ›',
    'from-you' : t.you  + ' ›',
    'from-err' : 'err  ›',
    'from-sys' : '     ·',
  };
  const lines = (text || '').split('\n');
  let bodyEl = null;
  lines.forEach((line, i) => {
    const row = document.createElement('div');
    row.className = 'hive-line ' + role;
    const pre = document.createElement('span');
    pre.className = 'hive-line-prefix';
    pre.textContent = i === 0 ? prefixMap[role] : '        ';
    const body = document.createElement('span');
    body.className = 'hive-line-body';
    if (isHTML) body.innerHTML = line; else body.textContent = line;
    row.appendChild(pre); row.appendChild(body);
    term.appendChild(row);
    if (i === 0) bodyEl = body;
  });
  _scrollBottom();
  return bodyEl;
}

function _printSpacer() {
  const el = document.createElement('div');
  el.className = 'hive-line spacer';
  _hid('hive-terminal').appendChild(el);
}

function _printWelcome(sess) {
  if (sess.welcomed) return;
  sess.welcomed = true;
  _printLine('from-sys', '─'.repeat(52));
  t.welcome.split('\n').forEach(l => _printLine('from-hive', l));
  _printLine('from-sys', '─'.repeat(52));
  _printSpacer();
}

// ── cursor helpers ─────────────────────────────────────────────────────────────
function _addCursor(parent) {
  const c = document.createElement('span');
  c.className = 'hive-cursor'; c.id = 'hive-cursor';
  parent.appendChild(c); return c;
}
function _removeCursor() { const c = _hid('hive-cursor'); if (c) c.remove(); }

// ── /sessions n — direct ES table ─────────────────────────────────────────────
async function _cmdSessions(n) {
  _printLine('from-hive', _lang === 'fr' ? `Récupération de ${n} sessions…` : `Fetching ${n} sessions…`);
  try {
    const r = await fetch(`/api/chat/sessions?n=${n}`, { headers: _authHeaders() });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const d = await r.json();
    if (d.error) { _printLine('from-err', d.error); _printSpacer(); return; }
    const W = { ts:19, hp:10, ip:16, cc:4, act:18 };
    const pad = (s, w) => String(s ?? '—').slice(0, w).padEnd(w);
    const sep = '─'.repeat(W.ts+W.hp+W.ip+W.cc+W.act+12);
    _printLine('from-hive', (_lang==='fr'?`${d.rows.length} sessions (total ES : ${d.total})`:`${d.rows.length} sessions  (total in ES: ${d.total})`));
    _printLine('from-sys', sep);
    _printLine('from-sys', `${pad(_lang==='fr'?'HORODATAGE':'TIMESTAMP',W.ts)}  ${pad('HONEYPOT',W.hp)}  ${pad(_lang==='fr'?'IP SOURCE':'SOURCE IP',W.ip)}  ${pad('CC',W.cc)}  ${pad('ACTION',W.act)}`);
    _printLine('from-sys', sep);
    if (!d.rows.length) { _printLine('from-sys', _lang==='fr'?'  (aucune donnée)':'  (no data)'); }
    else d.rows.forEach(row => _printLine('from-hive', _fmt(`${pad(row.ts,W.ts)}  ${pad(row.honeypot,W.hp)}  ${pad(row.ip,W.ip)}  ${pad(row.cc,W.cc)}  ${pad(row.action,W.act)}`), true));
    _printLine('from-sys', sep);
  } catch (err) { _printLine('from-err', String(err)); }
  _printSpacer();
}

// ── status refresh ─────────────────────────────────────────────────────────────
function _updateBadge() {
  const b = _hid('hive-badge');
  if (!b) return;
  if (_unread > 0 && !_open) { b.textContent = _unread > 9 ? '9+' : String(_unread); b.classList.add('on'); }
  else b.classList.remove('on');
}

async function _refreshStatus() {
  try {
    const r = await fetch('/health');
    if (r.ok) {
      const d = await r.json();
      _hid('hive-dot-es').className = 'hive-sdot ' + (d.elasticsearch ? 'ok' : 'err');
      _hid('hive-dot-pg').className = 'hive-sdot ' + (d.postgresql    ? 'ok' : 'err');
    }
  } catch (_) {}
  try {
    const r = await fetch('/api/chat/status', { headers: _authHeaders() });
    if (!r.ok) throw new Error();
    const d = await r.json();
    const online = d.backend === 'groq' && d.reachable !== false;
    const pill = _hid('hive-backend-pill');
    pill.className = online ? 'groq' : 'unknown';
    pill.textContent = '● ' + (online ? t.groq : t.off);
    _hid('hive-dot-llm').className = 'hive-sdot ' + (online ? 'ok' : 'err');
  } catch (_) {
    _hid('hive-backend-pill').className = 'unknown';
    _hid('hive-backend-pill').textContent = '● ' + t.off;
    _hid('hive-dot-llm').className = 'hive-sdot err';
  }
}

// ── open / close ───────────────────────────────────────────────────────────────
function _openChat() {
  if (_open) return;
  _open = true;
  _hid('hive-window').classList.add('open');
  _unread = 0; _updateBadge();
  _refreshStatus();
  if (_sessions.length === 0) {
    const sess = _mkSession(t.session + ' 1');
    _sessions.push(sess);
    _activeId = sess.id;
    _renderTabs();
    _printWelcome(sess);
  }
  setTimeout(() => _hid('hive-input') && _hid('hive-input').focus(), 180);
}

function _closeChat() {
  _saveActive();
  _open = false;
  _hid('hive-window').classList.remove('open');
}

// ── send ───────────────────────────────────────────────────────────────────────
async function _send(rawText) {
  if (_streaming) return;
  const msg = rawText.trim();
  if (!msg) return;
  _hid('hive-input').value = '';

  if (msg === '/help') {
    _printLine('from-you', msg);
    t.help.split('\n').forEach(l => _printLine('from-hive', l));
    _printSpacer(); return;
  }
  if (msg === '/clear') {
    const sess = _active();
    if (sess) { sess.history = []; sess.welcomed = false; }
    _hid('hive-terminal').innerHTML = '';
    _printLine('from-sys', t.cleared); _printSpacer(); return;
  }
  if (msg.startsWith('/sessions')) {
    const n = parseInt(msg.trim().split(/\s+/)[1], 10) || 20;
    _printLine('from-you', msg);
    await _cmdSessions(n); return;
  }

  const queryMap = {
    '/iocs':   _lang==='fr' ? 'Liste les derniers indicateurs de compromission (IOCs)' : 'List the latest indicators of compromise (IOCs)',
    '/profil': _lang==='fr' ? 'Donne les profils suspects récents' : 'Show recent suspect profiles',
    '/mitre':  _lang==='fr' ? 'Quels sont les derniers mappings MITRE ATT&CK ?' : 'What are the latest MITRE ATT&CK mappings?',
  };
  const query = queryMap[msg] || msg;

  const sess = _active();
  if (!sess) return;

  // Auto-rename tab on first real message
  if (sess.history.length === 0 && !queryMap[msg]) {
    sess.name = _autoName(msg);
    _renderTabs();
  }

  _printLine('from-you', msg);
  sess.history.push({ role: 'user', content: query });
  if (sess.history.length > 60) sess.history = sess.history.slice(-60);

  _streaming = true;
  let fullReply = '', currentBodyEl = null, extraLines = [];

  currentBodyEl = _printLine('from-hive', '');
  _addCursor(currentBodyEl);

  try {
    const res = await fetch('/api/chat', {
      method: 'POST', headers: _authHeaders(),
      body: JSON.stringify({ message: query, history: sess.history.slice(0, -1).slice(-30), lang: _lang }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');
      const blocks = buf.split('\n\n'); buf = blocks.pop();
      for (const block of blocks) {
        for (const line of block.split('\n')) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6).trim();
          if (data === '[DONE]') break;
          try {
            const p = JSON.parse(data);
            if (p.error) { _removeCursor(); currentBodyEl.innerHTML = `<span style="color:var(--red2)">${p.error}</span>`; break; }
            if (p.token) {
              fullReply += p.token;
              _removeCursor();
              _renderStream(fullReply, currentBodyEl, extraLines);
              const last = _hid('hive-terminal').querySelector('.hive-line.from-hive:last-child .hive-line-body');
              if (last) _addCursor(last);
              _scrollBottom();
            }
          } catch (_) {}
        }
      }
    }
  } catch (_err) {
    _removeCursor();
    if (currentBodyEl) currentBodyEl.textContent = t.offline;
    _hid('hive-dot-llm').className = 'hive-sdot err';
  }

  _removeCursor();
  if (fullReply) {
    sess.history.push({ role: 'assistant', content: fullReply });
    if (sess.history.length > 60) sess.history = sess.history.slice(-60);
    if (!_open) { _unread++; _updateBadge(); }
  }
  _printSpacer();
  _streaming = false;
}

function _renderStream(text, firstEl, extra) {
  const term = _hid('hive-terminal');
  const parts = _fmt(text).split('\n');
  firstEl.innerHTML = parts[0];
  for (let i = 1; i < parts.length; i++) {
    if (!extra[i-1]) {
      const row = document.createElement('div'); row.className = 'hive-line from-hive';
      const pre = document.createElement('span'); pre.className = 'hive-line-prefix'; pre.textContent = '        ';
      const body = document.createElement('span'); body.className = 'hive-line-body'; body.innerHTML = parts[i];
      row.appendChild(pre); row.appendChild(body); term.appendChild(row); extra[i-1] = body;
    } else { extra[i-1].innerHTML = parts[i]; }
  }
}

// ── event wiring ───────────────────────────────────────────────────────────────
_hid('hive-fab').addEventListener('click', e => { e.stopPropagation(); _open ? _closeChat() : _openChat(); });
_hid('hive-close-dot').addEventListener('click', _closeChat);
_hid('hive-send').addEventListener('click', () => _send(_hid('hive-input').value));
_hid('hive-input').addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); _send(e.target.value); } });
_hid('hive-new-tab').addEventListener('click', () => _newSession());
document.querySelectorAll('.hive-chip').forEach(c => c.addEventListener('click', () => _send(c.dataset.cmd)));
document.addEventListener('click', e => {
  if (_open && !_hid('hive-window').contains(e.target) && !_hid('hive-fab').contains(e.target)) _closeChat();
});

// ── ghost eyes follow mouse ─────────────────────────────────────────────────
(function(){
  var EYES = [
    {id:'ghost-pupil-l', cx:21, cy:29},
    {id:'ghost-pupil-r', cx:35, cy:29}
  ];
  var MAX_R = 2.2;
  document.addEventListener('mousemove', function(e){
    var fab = document.getElementById('hive-fab');
    if(!fab) return;
    var svg = fab.querySelector('svg');
    if(!svg) return;
    var rect = svg.getBoundingClientRect();
    var mouseX = (e.clientX - rect.left) * (54 / rect.width);
    var mouseY = (e.clientY - rect.top)  * (58 / rect.height);
    EYES.forEach(function(eye){
      var el = document.getElementById(eye.id);
      if(!el) return;
      var dx = mouseX - eye.cx, dy = mouseY - eye.cy;
      var dist = Math.sqrt(dx*dx + dy*dy);
      var s = dist > MAX_R ? MAX_R/dist : 1;
      el.setAttribute('cx', eye.cx + dx*s);
      el.setAttribute('cy', eye.cy + dy*s);
    });
  });
})();
