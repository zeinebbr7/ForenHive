import React, { useState, useEffect, useMemo, useCallback, useRef, useDeferredValue, memo } from 'react';
import api from '../api';
import { fmt, flag } from '../utils';
import { riskLevel } from '../constants';

const SOPH_MAP = {
  apt:          { text: 'APT / State', cls: 'soph-apt',   chip: 'soph-apt-chip',   chipText: 'APT' },
  high:         { text: 'Professional', cls: 'soph-high', chip: 'soph-high-chip',  chipText: 'PRO' },
  intermediate: { text: 'Intermediate', cls: 'soph-mid',  chip: 'soph-mid-chip',   chipText: 'INT' },
  low:          { text: 'Script Kiddie', cls: 'soph-low', chip: 'soph-low-chip',   chipText: 'SK' },
};

const SEV_COLOR = {
  CRITICAL: 'var(--red2)',
  HIGH:     'var(--accent-gold, var(--gold))',
  MEDIUM:   'var(--blue2)',
  LOW:      'var(--text3)',
};

const HONEYPOTS = ['ALL', 'cowrie', 'dionaea', 'galah', 'zeek'];
const SORT_OPTIONS = [
  ['risk_score', 'Risk Score ↓'],
  ['last_seen',  'Last Seen ↓'],
  ['sessions',   'Sessions ↓'],
];

// Curated MITRE ATT&CK reference for techniques commonly observed on honeypots.
// Used to enrich plain IDs returned by the backend with name / tactic / brief methods.
const MITRE_DB = {
  'T1018':     { name:'Remote System Discovery',           tactic:'Discovery',           desc:'Adversary maps internal hosts after gaining a foothold — `ip a`, `arp -a`, `cat /etc/hosts`, ping sweeps.' },
  'T1021.004': { name:'SSH',                               tactic:'Lateral Movement',    desc:'Authenticated SSH used to pivot to additional hosts; observed when stolen keys or guessed creds are reused.' },
  'T1027':     { name:'Obfuscated Files or Information',   tactic:'Defense Evasion',     desc:'Base64-encoded payloads, packed binaries, or here-doc shell snippets that hide intent from log scanners.' },
  'T1033':     { name:'System Owner / User Discovery',     tactic:'Discovery',           desc:'`id`, `whoami`, `who`, `last` — confirms the account context immediately after a successful login.' },
  'T1041':     { name:'Exfiltration Over C2 Channel',      tactic:'Exfiltration',        desc:'Captured data shipped out over the same channel used for command & control (HTTP/HTTPS, IRC, custom).' },
  'T1046':     { name:'Network Service Discovery',         tactic:'Discovery',           desc:'Internal port-scan or service-banner grab from the compromised host — `nmap`, `nc -zv`, `masscan`.' },
  'T1053.003': { name:'Cron',                              tactic:'Persistence',         desc:'Persistence via `crontab -e` / `@reboot` jobs that re-fetch and re-execute the implant on every boot.' },
  'T1057':     { name:'Process Discovery',                 tactic:'Discovery',           desc:'`ps aux`, `top` — enumerates running services to identify EDR / monitoring agents or competing miners.' },
  'T1059.004': { name:'Unix Shell',                        tactic:'Execution',           desc:'Direct shell execution via `/bin/sh` or `bash -c`; near-universal once the attacker has interactive access.' },
  'T1070.003': { name:'Clear Command History',             tactic:'Defense Evasion',     desc:'`history -c`, `unset HISTFILE`, `rm ~/.bash_history` to remove forensic evidence before disconnect.' },
  'T1071':     { name:'Application Layer Protocol',        tactic:'Command and Control', desc:'C2 traffic carried inside common protocols (HTTP, DNS, IRC) to blend with normal network noise.' },
  'T1071.001': { name:'Web Protocols (C2)',                tactic:'Command and Control', desc:'C2 callbacks over HTTP/S — `wget`/`curl` to attacker-controlled domains, often retrieving stage-2 payloads.' },
  'T1078':     { name:'Valid Accounts',                    tactic:'Defense Evasion / Initial Access', desc:'Reuse of legitimate or default credentials (root/root, admin/admin) — bypasses signature-based detection.' },
  'T1083':     { name:'File and Directory Discovery',      tactic:'Discovery',           desc:'`ls -la /`, `find / -perm -u=s` — locates sensitive files, SUID binaries, config with secrets.' },
  'T1105':     { name:'Ingress Tool Transfer',             tactic:'Command and Control', desc:'`wget` / `curl` / `tftp` of secondary payloads from a hard-coded URL — the classic Mirai-style fetch.' },
  'T1110':     { name:'Brute Force',                       tactic:'Credential Access',   desc:'High-volume guessing of usernames/passwords; primary signal on every SSH and Telnet honeypot.' },
  'T1110.001': { name:'Password Guessing',                 tactic:'Credential Access',   desc:'Dictionary attack against known accounts (root, admin) — usually with the Mirai default wordlist.' },
  'T1110.003': { name:'Password Spraying',                 tactic:'Credential Access',   desc:'A few common passwords tried across many accounts to avoid lockout — typically rate-limited tooling.' },
  'T1133':     { name:'External Remote Services',          tactic:'Initial Access',      desc:'Inbound access via exposed SSH, RDP, VPN — the very vector cowrie/Dionaea simulate.' },
  'T1136':     { name:'Create Account',                    tactic:'Persistence',         desc:'Adding a new user (`useradd`, edit `/etc/passwd`) to keep access after the original creds are rotated.' },
  'T1190':     { name:'Exploit Public-Facing Application', tactic:'Initial Access',      desc:'CVE-driven attacks against the HTTP / SMB / database service exposed by the honeypot.' },
  'T1552.001': { name:'Credentials in Files',              tactic:'Credential Access',   desc:'Searches for cleartext creds in config files (`.aws/credentials`, `.git-credentials`, deploy keys).' },
  'T1562.001': { name:'Disable / Modify Tools',            tactic:'Defense Evasion',     desc:'Killing security agents, removing `auditd`, masking systemd units — clears the way for follow-on actions.' },
  'T1003':     { name:'OS Credential Dumping',             tactic:'Credential Access',   desc:'`cat /etc/shadow`, mimikatz on Windows — extracts hashes for offline cracking.' },
};

function mitreInfo(t) {
  // `t` is either a string ID like "T1110.001" or an object {id, name, tactic}.
  const id = (t && typeof t === 'object') ? (t.id || t.name || '') : String(t);
  const known = MITRE_DB[id];
  if (known) return { id, ...known };
  // Fallback: try the parent technique (strip sub-technique suffix).
  const parent = id.includes('.') ? id.split('.')[0] : null;
  const parentInfo = parent && MITRE_DB[parent];
  if (parentInfo) return { id, name: parentInfo.name, tactic: parentInfo.tactic, desc: parentInfo.desc };
  // Use object hints if available.
  if (t && typeof t === 'object') return { id, name: t.name || '—', tactic: t.tactic || '—', desc: '' };
  return { id, name: '—', tactic: '—', desc: '' };
}

function mitreUrl(id) {
  // attack.mitre.org expects "T1110/001" not "T1110.001".
  return `https://attack.mitre.org/techniques/${String(id).replace('.', '/')}/`;
}

// Hoisted styles — referentially stable, avoids re-allocating per render.
const S = {
  filtersRow:    { marginBottom:'8px', flexWrap:'wrap', gap:'8px', display:'flex' },
  sortSelect:    { minWidth:'130px', height:'32px', padding:'0 28px 0 10px', fontSize:'11px' },
  searchInput:   { minWidth:'200px', height:'32px', padding:'0 10px', fontSize:'12px', marginLeft:'auto' },
  lookupInput:   { minWidth:'170px', height:'32px', padding:'0 10px', fontSize:'12px' },
  hpRow:         { display:'flex', gap:'6px', flexWrap:'wrap', marginBottom:'14px', alignItems:'center' },
  hpLabel:       { fontSize:'9px', fontFamily:"'JetBrains Mono',monospace", color:'var(--text3)', textTransform:'uppercase', letterSpacing:'.8px', marginRight:'2px' },
  layout:        { display:'grid', gridTemplateColumns:'340px 1fr', gap:'16px', alignItems:'start' },
  listCardH:     { padding:'12px 16px', margin:0, borderBottom:'1px solid var(--border)' },
  listCardT:     { fontSize:'13px' },
  scrollList:    { maxHeight:'calc(100vh - 360px)', minHeight:'420px', overflowY:'auto' },
  alertM:        { margin:'14px' },
  dossierWrap:   { display:'flex', flexDirection:'column', gap:'12px' },
  dossierRow:    { display:'flex', gap:'14px', alignItems:'flex-start' },
  dossierIdent:  { flex:1, minWidth:0 },
  dossierIp:     { fontFamily:"'JetBrains Mono',monospace", fontSize:'18px', fontWeight:700, color:'var(--text)', marginBottom:'4px' },
  dossierMeta:   { fontSize:'11px', color:'var(--text3)', fontFamily:"'JetBrains Mono',monospace" },
  chipRow:       { display:'flex', gap:'6px', flexWrap:'wrap', marginTop:'10px' },
  hpChipRow:     { marginTop:'10px', display:'flex', flexWrap:'wrap', gap:'5px' },
  statsGrid:     { display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(120px,1fr))', gap:'8px', marginTop:'14px' },
  statBlock:     { padding:'8px 10px', background:'var(--bg3)', border:'1px solid var(--border)', borderRadius:'6px', minWidth:0 },
  statLabel:     { fontSize:'9px', fontFamily:"'JetBrains Mono',monospace", color:'var(--text3)', textTransform:'uppercase', letterSpacing:'.7px', marginBottom:'3px' },
  statValue:     { fontFamily:"'Rajdhani',sans-serif", fontSize:'15px', fontWeight:600, color:'var(--text)' },
  narrative:     { fontSize:'13px', lineHeight:1.6, color:'var(--text2)', whiteSpace:'pre-wrap' },
  cardMetaSpaced:{ marginTop:'2px' },
  gaugeWrap:     { position:'relative', width:'90px', height:'90px' },
  gaugeInner:    { position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' },
  abuseRow:      { display:'flex', gap:'14px', alignItems:'center', flexWrap:'wrap' },
  abuseBar:      { flex:1, minWidth:'220px', height:'10px', background:'var(--bg3)', border:'1px solid var(--border)', borderRadius:'6px', overflow:'hidden', position:'relative' },
  abuseBarFill:  (col, pct) => ({ width:`${pct}%`, height:'100%', background:col, transition:'width .3s' }),
  abuseScoreBig: col => ({ fontFamily:"'Rajdhani',sans-serif", fontSize:'28px', fontWeight:800, color:col, lineHeight:1, minWidth:'58px', textAlign:'right' }),
  abuseMeta:     { fontSize:'10px', fontFamily:"'JetBrains Mono',monospace", color:'var(--text3)', letterSpacing:'.6px', textTransform:'uppercase' },
  credsTable:    { width:'100%', borderCollapse:'collapse', fontFamily:"'JetBrains Mono',monospace", fontSize:'11px' },
  credCell:      { padding:'5px 8px', borderBottom:'1px solid var(--border)', color:'var(--text2)' },
  credCellHead:  { padding:'5px 8px', borderBottom:'1px solid var(--border)', color:'var(--text3)', textTransform:'uppercase', fontSize:'9px', letterSpacing:'.7px', textAlign:'left' },
  cmdBlock:      { padding:'10px 12px', background:'var(--bg3)', border:'1px solid var(--border)', borderRadius:'6px', fontFamily:"'JetBrains Mono',monospace", fontSize:'11.5px', color:'var(--text2)', lineHeight:1.7, overflow:'auto', whiteSpace:'pre' },
  topGrid:       { display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))', gap:'12px' },
  topLabel:      { fontSize:'9px', fontFamily:"'JetBrains Mono',monospace", color:'var(--text3)', textTransform:'uppercase', letterSpacing:'.8px', marginBottom:'6px' },
  anonChip:      { padding:'2px 7px', borderRadius:'3px', border:'1px solid', fontSize:'9px', fontWeight:700, letterSpacing:'.8px', textTransform:'uppercase', fontFamily:"'Share Tech Mono',monospace" },
};

// Styles for the inline per-service OSINT cards.
const SRC = {
  head:      { display:'flex', alignItems:'baseline', justifyContent:'space-between', gap:'10px', marginBottom:'12px', paddingBottom:'8px', borderBottom:'1px solid var(--border)' },
  name:      accent => ({ fontFamily:"'Rajdhani',sans-serif", fontSize:'17px', fontWeight:700, color: accent || 'var(--text)', letterSpacing:'.3px' }),
  tag:       { fontSize:'10px', color:'var(--text3)', fontFamily:"'JetBrains Mono',monospace", textTransform:'uppercase', letterSpacing:'.6px' },
  row:       { display:'grid', gridTemplateColumns:'150px 1fr', gap:'12px', padding:'8px 0', alignItems:'baseline' },
  rowLabel:  { fontSize:'10px', fontFamily:"'JetBrains Mono',monospace", color:'var(--text3)', textTransform:'uppercase', letterSpacing:'.6px' },
  rowVal:    { fontSize:'12.5px', color:'var(--text)', fontFamily:"'JetBrains Mono',monospace", wordBreak:'break-word' },
  accentBar: accent => ({ borderLeft:`3px solid ${accent || 'var(--border)'}` }),
};

// Styles for the expanded MITRE list.
const MT = {
  item:    { padding:'12px 0', borderBottom:'1px solid var(--border)' },
  head:    { display:'flex', alignItems:'center', gap:'10px', flexWrap:'wrap', marginBottom:'6px' },
  id:      { fontFamily:"'JetBrains Mono',monospace", fontSize:'12px', fontWeight:700, color:'var(--accent-gold, var(--gold))', letterSpacing:'.3px' },
  name:    { fontFamily:"'Rajdhani',sans-serif", fontSize:'14.5px', fontWeight:600, color:'var(--text)' },
  tactic:  { fontSize:'9px', padding:'2px 7px', borderRadius:'3px', border:'1px solid var(--border2)', color:'var(--text2)', background:'var(--bg3)', fontFamily:"'Share Tech Mono',monospace", textTransform:'uppercase', letterSpacing:'.7px' },
  link:    { fontSize:'10px', fontFamily:"'JetBrains Mono',monospace", color:'var(--text3)', textDecoration:'none', marginLeft:'auto' },
  desc:    { fontSize:'12.5px', color:'var(--text2)', lineHeight:1.55, fontFamily:'Inter,system-ui,sans-serif' },
};

const ANON_FLAGS = [
  { key:'isTor',     label:'TOR EXIT',  color:'var(--red2)',     bg:'rgba(201,61,85,.08)',  border:'rgba(201,61,85,.35)' },
  { key:'isVpn',     label:'VPN',       color:'var(--accent-gold, var(--gold))', bg:'rgba(212,168,74,.08)', border:'rgba(212,168,74,.35)' },
  { key:'isProxy',   label:'PROXY',     color:'var(--accent-gold, var(--gold))', bg:'rgba(212,168,74,.08)', border:'rgba(212,168,74,.35)' },
  { key:'isHosting', label:'HOSTING',   color:'var(--blue2)',    bg:'rgba(106,176,255,.08)', border:'rgba(106,176,255,.3)' },
];

function severityFromScore(score) {
  const lvl = riskLevel(score);
  return lvl === 'INFO' ? 'LOW' : lvl;
}

function normalize(p) {
  const out = { ...p };
  if (!out.severity) out.severity = severityFromScore(Number(out.risk_score) || 0);
  return out;
}

function ipOf(p) { return p.source_ip || p.ip || ''; }

// IPv4/IPv6 — return false for private, loopback, link-local; OSINT pivots are useless for those.
function isPublicIp(ip) {
  if (!ip) return false;
  if (ip.includes(':')) {
    const lo = ip.toLowerCase();
    if (lo === '::1' || lo.startsWith('fe80') || lo.startsWith('fc') || lo.startsWith('fd')) return false;
    return true;
  }
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 169 && b === 254) return false;
  if (a === 0 || a >= 224) return false;
  return true;
}

// Each service declares an external URL builder and a `fields(p, osint)` extractor
// that returns ONLY [label, value] rows present in this profile's analysis.
// Services whose extractors return [] for the current profile are not rendered.
const OSINT_SERVICES = [
  {
    key:'iplocate', name:'IPLocate', accent:'var(--text2)',
    tagline:'geolocation, ASN & reverse-DNS (used by ForenHive backend)',
    url: ip => `https://www.iplocate.io/insights/${encodeURIComponent(ip)}`,
    fields: (p) => {
      const out = [];
      if (p.country_name || p.country) out.push(['Country',  `${p.country ? flag(p.country) + ' ' : ''}${p.country_name || p.country}`]);
      if (p.city)         out.push(['City',     p.city]);
      if (p.asn)          out.push(['ASN',      `AS${p.asn}`]);
      if (p.as_org)       out.push(['AS Org',   p.as_org]);
      if (p.isp)          out.push(['ISP',      p.isp]);
      if (p.ptr)          out.push(['Reverse DNS (PTR)', p.ptr]);
      if (p.network_cidr) out.push(['Network CIDR', p.network_cidr]);
      return out;
    },
  },
  {
    key:'shodan', name:'Shodan', accent:'var(--blue2)',
    tagline:'internet-exposed services & banners',
    url: ip => `https://www.shodan.io/host/${encodeURIComponent(ip)}`,
    fields: (p, o) => {
      const s = o.shodan || {};
      const out = [];
      if (s.ports?.length)     out.push(['Open Ports',  { chips: s.ports, cls: 'rc-chip hl' }]);
      if (s.hostnames?.length) out.push(['Hostnames',   { mono: s.hostnames }]);
      if (s.os)                out.push(['OS',          s.os]);
      if (s.tags?.length)      out.push(['Tags',        { chips: s.tags }]);
      if (s.vulns?.length)     out.push(['Known CVEs',  { chips: s.vulns, cls: 'rc-chip red' }]);
      return out;
    },
  },
  {
    key:'vt', name:'VirusTotal', accent:'var(--accent-gold, var(--gold))',
    tagline:'multi-engine malware & URL scanner',
    url: ip => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}`,
    fields: (p, o) => {
      const out = [];
      if (o.vtDetections)     out.push(['Detections', o.vtDetections]);
      if (o.vtFamily)         out.push(['Malware Family', o.vtFamily]);
      if (o.iocHashes.length) out.push(['Hashes (SHA-256)', { mono: o.iocHashes }]);
      return out;
    },
  },
];

// Normalize OSINT-relevant fields from both flat (backend) and nested (mock `enrichment.*`) shapes.
function getOsint(p) {
  const enr = p.enrichment || {};
  const abuse = enr.abuse || {};
  const anon = enr.anonymization || {};
  const shodan = enr.shodan || p.shodan || {};
  const whois = enr.whois || {};
  return {
    abuseScore:    p.abuseipdb_score ?? abuse.score ?? null,
    abuseReports:  p.abuseipdb_reports ?? abuse.total_reports ?? null,
    abuseCategories: abuse.categories || p.abuse_categories || [],
    isTor:     Boolean(p.is_tor ?? anon.is_tor),
    isVpn:     Boolean(p.is_vpn ?? anon.is_vpn),
    isProxy:   Boolean(p.is_proxy ?? anon.is_proxy),
    isHosting: Boolean(anon.is_hosting ?? p.is_hosting),
    shodan,
    whoisOrg:    whois.org    || p.network_name || null,
    whoisCidr:   whois.cidr   || p.network_cidr || null,
    topUsernames: p.top_usernames || [],
    topPasswords: p.top_passwords || [],
    topCommands:  p.top_commands  || [],
    yaraMatches:  p.yara_matches  || (p.malware?.yara_match ? [p.malware.yara_match] : []),
    iocHashes:    p.ioc_hashes    || (p.malware?.sha256 ? [p.malware.sha256] : []),
    credentialsAttempted: p.credentials_attempted || [],
    commandsExecuted:     p.commands_executed || [],
    signatureIndicators:  p.signature_indicators || [],
    behavioralTraits:     p.behavioral_traits || [],
    killChain:            p.kill_chain_phase || null,
    actorType:            p.actor_type || null,
    vtDetections: p.malware?.vt_detections || null,
    vtFamily:     p.malware?.vt_family || null,
  };
}

function abuseColor(score) {
  if (score == null) return 'var(--text3)';
  if (score >= 75) return 'var(--red2)';
  if (score >= 40) return 'var(--accent-gold, var(--gold))';
  if (score >= 15) return 'var(--blue2)';
  return 'var(--text3)';
}

const ScoreGauge = memo(function ScoreGauge({ score, sev }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const arc = circ * Math.min(score / 100, 1);
  const col = SEV_COLOR[sev] || 'var(--text3)';
  return (
    <div style={S.gaugeWrap}>
      <svg width="90" height="90" viewBox="0 0 90 90" aria-hidden="true">
        <circle cx="45" cy="45" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="7" />
        <circle cx="45" cy="45" r={r} fill="none" stroke={col} strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={`${arc.toFixed(2)} ${(circ - arc).toFixed(2)}`}
          transform="rotate(-90 45 45)" />
      </svg>
      <div style={S.gaugeInner}>
        <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:'22px',fontWeight:800,color:col,lineHeight:1}}>{score}</div>
        <div style={{fontSize:'8px',fontFamily:"'JetBrains Mono',monospace",color:col,letterSpacing:'1px',textTransform:'uppercase'}}>{sev}</div>
      </div>
    </div>
  );
});

const ProfileCard = memo(function ProfileCard({ p, active, onSelect }) {
  const sev = p.severity || 'LOW';
  const soph = SOPH_MAP[p.sophistication];
  const ts = p.last_seen || p.first_seen;
  const sc = Number(p.session_count || p.sessions_count) || 0;
  const ip = ipOf(p) || '—';
  const handleClick = () => onSelect(p.id);
  const onKey = (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(p.id); }
  };
  return (
    <div
      className={`p-card p-card-bdr-${sev}${active ? ' active' : ''}`}
      onClick={handleClick}
      onKeyDown={onKey}
      role="button"
      tabIndex={0}
      aria-pressed={active}
      aria-label={`Profile ${ip}, severity ${sev}, risk score ${Number(p.risk_score) || 0}`}
    >
      <div className="p-card-top">
        <div style={{minWidth:0}}>
          <div className="p-card-ip">{ip}</div>
          <div className="p-card-meta">
            <span className={`p-sev-tag p-sev-${sev}`}>{sev}</span>
            {soph && <span className={`p-soph-chip ${soph.chip}`} style={{borderColor:'currentColor',opacity:.85}}>{soph.chipText}</span>}
            {p.country && <span>{flag(p.country)}</span>}
            {p.city ? <span>{p.city}</span> : p.country_name ? <span>{p.country_name}</span> : null}
          </div>
        </div>
        <div className={`p-card-score p-score-${sev}`}>{Number(p.risk_score) || 0}</div>
      </div>
      <div className="p-card-meta" style={S.cardMetaSpaced}>
        {ts && <span>{fmt.ago(ts)} ago</span>}
        {sc > 0 && <span>{sc} session{sc > 1 ? 's' : ''}</span>}
        {p.actor_type && <span style={{color:'var(--text3)'}}>{String(p.actor_type).replaceAll('_', ' ')}</span>}
      </div>
    </div>
  );
});

const StatBlock = memo(function StatBlock({ label, value }) {
  return (
    <div style={S.statBlock}>
      <div style={S.statLabel}>{label}</div>
      <div style={S.statValue}>{value}</div>
    </div>
  );
});

const MitreList = memo(function MitreList({ items }) {
  if (!Array.isArray(items) || !items.length) return null;
  const rows = items.map(mitreInfo);
  return (
    <div className="card">
      <div className="card-h">
        <div className="card-t">MITRE ATT&CK Techniques</div>
        <div className="card-sub">{rows.length} observed · tactic & methods</div>
      </div>
      <div>
        {rows.map((r, i) => (
          <div
            key={r.id + '_' + i}
            style={{...MT.item, borderBottom: i === rows.length - 1 ? 'none' : MT.item.borderBottom}}
          >
            <div style={MT.head}>
              <span style={MT.id}>{r.id}</span>
              <span style={MT.name}>{r.name}</span>
              <span style={MT.tactic}>{r.tactic}</span>
              <a
                href={mitreUrl(r.id)}
                target="_blank"
                rel="noopener noreferrer"
                style={MT.link}
                title={`Open ${r.id} on attack.mitre.org`}
              >attack.mitre.org ↗</a>
            </div>
            {r.desc && <div style={MT.desc}>{r.desc}</div>}
          </div>
        ))}
      </div>
    </div>
  );
});

const ChipList = memo(function ChipList({ items, className = 'rc-chip' }) {
  return (
    <div className="rc-chips" style={{marginTop:0}}>
      {items.map((v, i) => {
        const label = (v && typeof v === 'object') ? (v.id || v.name || JSON.stringify(v)) : String(v);
        const title = (v && typeof v === 'object' && v.id && v.name) ? `${v.id} — ${v.name}` : undefined;
        return <span key={i} className={className} title={title}>{label}</span>;
      })}
    </div>
  );
});

const AnonChips = memo(function AnonChips({ osint }) {
  const flags = ANON_FLAGS.filter(f => osint[f.key]);
  if (!flags.length) return null;
  return (
    <>
      {flags.map(f => (
        <span key={f.key} style={{...S.anonChip, color:f.color, background:f.bg, borderColor:f.border}}>
          ● {f.label}
        </span>
      ))}
    </>
  );
});

const AbuseCard = memo(function AbuseCard({ osint }) {
  if (osint.abuseScore == null && !osint.abuseReports && !osint.abuseCategories.length) return null;
  const score = osint.abuseScore;
  const col = abuseColor(score);
  const pct = score == null ? 0 : Math.max(0, Math.min(100, score));
  return (
    <div className="card">
      <div className="card-h">
        <div className="card-t">AbuseIPDB Reputation</div>
        <div className="card-sub">community abuse intelligence</div>
      </div>
      <div style={S.abuseRow}>
        <div style={S.abuseScoreBig(col)}>{score == null ? '—' : `${score}`}</div>
        <div style={S.abuseBar} aria-label={`Abuse confidence ${score ?? 'unknown'} of 100`}>
          <div style={S.abuseBarFill(col, pct)} />
        </div>
        <div style={S.abuseMeta}>
          {score != null && <>confidence&nbsp;/ 100</>}
          {osint.abuseReports != null && <> · {fmt.num(osint.abuseReports)} reports</>}
        </div>
      </div>
      {osint.abuseCategories.length > 0 && (
        <div className="rc-chips" style={{marginTop:'10px'}}>
          {osint.abuseCategories.map((c, i) => <span key={i} className="rc-chip red">{String(c)}</span>)}
        </div>
      )}
    </div>
  );
});

function renderFieldValue(v) {
  if (v == null) return '—';
  if (Array.isArray(v)) return v.join(', ');
  if (typeof v === 'object') {
    if (v.chips) {
      return (
        <div className="rc-chips" style={{marginTop:0}}>
          {v.chips.map((c, i) => <span key={i} className={v.cls || 'rc-chip'}>{String(c)}</span>)}
        </div>
      );
    }
    if (v.mono) {
      return v.mono.map((m, i) => <div key={i} className="mono" style={{fontSize:'11px', marginBottom:'2px'}}>{String(m)}</div>);
    }
  }
  return String(v);
}

// One inline card per OSINT service that has data for THIS profile.
// Services that return no rows are not rendered at all.
const OsintSources = memo(function OsintSources({ p, osint, ip }) {
  const populated = OSINT_SERVICES
    .map(svc => ({ svc, rows: svc.fields(p, osint) }))
    .filter(({ rows }) => rows.length > 0);

  if (!populated.length) return null;

  return (
    <>
      {populated.map(({ svc, rows }) => (
        <div key={svc.key} className="card" style={SRC.accentBar(svc.accent)}>
          <div style={SRC.head}>
            <div>
              <div style={SRC.name(svc.accent)}>{svc.name}</div>
              <div style={SRC.tag}>{svc.tagline}</div>
            </div>
            {isPublicIp(ip) && (
              <a
                href={svc.url(ip)}
                target="_blank"
                rel="noopener noreferrer"
                style={{color:svc.accent || 'var(--text3)', fontFamily:"'JetBrains Mono',monospace", fontSize:'11px', textDecoration:'none', letterSpacing:'.4px'}}
                title={`Open ${ip} in ${svc.name}`}
              >
                {svc.name} ↗
              </a>
            )}
          </div>
          <div>
            {rows.map(([label, value], i) => (
              <div
                key={i}
                style={{
                  ...SRC.row,
                  borderBottom: i === rows.length - 1 ? 'none' : '1px solid var(--border)',
                }}
              >
                <div style={SRC.rowLabel}>{label}</div>
                <div style={SRC.rowVal}>{renderFieldValue(value)}</div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </>
  );
});

const TopValuesCard = memo(function TopValuesCard({ osint }) {
  const hasAny = osint.topUsernames.length || osint.topPasswords.length || osint.topCommands.length;
  if (!hasAny) return null;
  return (
    <div className="card">
      <div className="card-h">
        <div className="card-t">Observed Indicators</div>
        <div className="card-sub">top values across collected events</div>
      </div>
      <div style={S.topGrid}>
        {osint.topUsernames.length > 0 && (
          <div>
            <div style={S.topLabel}>Top Usernames</div>
            <div className="rc-chips" style={{marginTop:0}}>
              {osint.topUsernames.map((v, i) => <span key={i} className="rc-chip">{String(v)}</span>)}
            </div>
          </div>
        )}
        {osint.topPasswords.length > 0 && (
          <div>
            <div style={S.topLabel}>Top Passwords</div>
            <div className="rc-chips" style={{marginTop:0}}>
              {osint.topPasswords.map((v, i) => <span key={i} className="rc-chip hl">{String(v)}</span>)}
            </div>
          </div>
        )}
        {osint.topCommands.length > 0 && (
          <div>
            <div style={S.topLabel}>Top Commands</div>
            <div className="rc-chips" style={{marginTop:0}}>
              {osint.topCommands.map((v, i) => <span key={i} className="rc-chip">{String(v)}</span>)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
});

const CredentialsTable = memo(function CredentialsTable({ creds }) {
  if (!Array.isArray(creds) || !creds.length) return null;
  return (
    <div className="card">
      <div className="card-h">
        <div className="card-t">Credentials Attempted</div>
        <div className="card-sub">{creds.length} entr{creds.length === 1 ? 'y' : 'ies'} · ↑ successful</div>
      </div>
      <table style={S.credsTable}>
        <thead>
          <tr>
            <th style={S.credCellHead}>Username</th>
            <th style={S.credCellHead}>Password</th>
            <th style={{...S.credCellHead, textAlign:'right'}}>Result</th>
          </tr>
        </thead>
        <tbody>
          {creds.map((c, i) => (
            <tr key={i}>
              <td style={S.credCell}>{c.username || '—'}</td>
              <td style={S.credCell}>{c.password || '—'}</td>
              <td style={{...S.credCell, textAlign:'right', color: c.success ? 'var(--red2)' : 'var(--text3)'}}>
                {c.success ? '● SUCCESS' : '○ failed'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
});

const CommandsBlock = memo(function CommandsBlock({ cmds }) {
  if (!Array.isArray(cmds) || !cmds.length) return null;
  return (
    <div className="card">
      <div className="card-h">
        <div className="card-t">Commands Executed</div>
        <div className="card-sub">post-authentication shell activity</div>
      </div>
      <div style={S.cmdBlock}>{cmds.map((c, i) => `$ ${c}`).join('\n')}</div>
    </div>
  );
});

const IocCard = memo(function IocCard({ osint }) {
  const hasYara = osint.yaraMatches.length > 0;
  const hasIoc = osint.iocHashes.length > 0;
  if (!hasYara && !hasIoc && !osint.vtDetections) return null;
  return (
    <div className="card">
      <div className="card-h">
        <div className="card-t">Malware & IOCs</div>
        <div className="card-sub">YARA hits, hashes, VT detections</div>
      </div>
      <table className="tbl">
        <tbody>
          {hasYara && (
            <tr><th style={{width:'170px'}}>YARA Matches</th>
              <td><ChipList items={osint.yaraMatches} className="rc-chip red" /></td>
            </tr>
          )}
          {osint.vtFamily && (
            <tr><th>VT Family</th><td className="mono">{osint.vtFamily}</td></tr>
          )}
          {osint.vtDetections && (
            <tr><th>VT Detections</th>
              <td>
                <a
                  href={`https://www.virustotal.com/gui/file/${encodeURIComponent(osint.iocHashes[0] || '')}`}
                  target="_blank" rel="noopener noreferrer"
                  style={{color:'var(--accent-gold, var(--gold))', textDecoration:'none', fontFamily:"'JetBrains Mono',monospace", fontSize:'11.5px'}}
                >
                  {osint.vtDetections} ↗
                </a>
              </td>
            </tr>
          )}
          {hasIoc && (
            <tr><th>IOC Hashes</th>
              <td style={{wordBreak:'break-all'}}>
                {osint.iocHashes.map((h, i) => (
                  <div key={i} className="mono" style={{fontSize:'11px', marginBottom:'2px'}}>{h}</div>
                ))}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
});

const BehaviorCard = memo(function BehaviorCard({ osint }) {
  if (!osint.behavioralTraits.length && !osint.signatureIndicators.length && !osint.killChain && !osint.actorType) return null;
  return (
    <div className="card">
      <div className="card-h">
        <div className="card-t">Behavioral Fingerprint</div>
      </div>
      <table className="tbl">
        <tbody>
          {osint.actorType && (
            <tr><th style={{width:'170px'}}>Actor Type</th><td className="mono">{String(osint.actorType).replaceAll('_', ' ')}</td></tr>
          )}
          {osint.killChain && (
            <tr><th>Kill Chain Phase</th><td className="mono">{String(osint.killChain).replaceAll('_', ' ')}</td></tr>
          )}
          {osint.behavioralTraits.length > 0 && (
            <tr><th>Traits</th><td><ChipList items={osint.behavioralTraits.map(t => String(t).replaceAll('_', ' '))} /></td></tr>
          )}
        </tbody>
      </table>
      {osint.signatureIndicators.length > 0 && (
        <div style={{marginTop:'10px'}}>
          <div style={S.topLabel}>Signature Indicators</div>
          <ul style={{margin:0, paddingLeft:'18px', fontSize:'12px', color:'var(--text2)', lineHeight:1.7}}>
            {osint.signatureIndicators.map((s, i) => <li key={i}>{s}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
});

function Dossier({ p }) {
  const score = Number(p.risk_score) || 0;
  const sev = p.severity || severityFromScore(score);
  const sevColor = SEV_COLOR[sev];
  const ip = ipOf(p);

  const osint = useMemo(() => getOsint(p), [p]);

  const { soph, ts, geoText, stats, narrative } = useMemo(() => {
    const soph = SOPH_MAP[p.sophistication];
    const ts = p.last_seen || p.first_seen;
    const geoParts = [];
    if (p.country) geoParts.push(`${flag(p.country)} ${p.country_name || p.country}`);
    if (p.city) geoParts.push(p.city);
    if (p.asn) geoParts.push(`AS${p.asn}`);
    if (p.as_org) geoParts.push(p.as_org);

    const confidencePct = p.confidence != null ? Math.round(Number(p.confidence) * 100) : null;
    const stats = [];
    if (p.event_count)         stats.push(['Events',     fmt.num(p.event_count)]);
    if (p.session_count)       stats.push(['Sessions',   fmt.num(p.session_count)]);
    if (confidencePct != null) stats.push(['Confidence', `${confidencePct}%`]);
    if (p.first_seen)          stats.push(['First Seen', `${fmt.ago(p.first_seen)} ago`]);
    if (p.last_seen)           stats.push(['Last Seen',  `${fmt.ago(p.last_seen)} ago`]);
    if (p.isp)                 stats.push(['ISP',        p.isp]);
    if (p.ptr)                 stats.push(['Hostname',   p.ptr]);
    if (p.usage_type)          stats.push(['Usage Type', p.usage_type]);
    if (p.distinct_reporters)  stats.push(['Reporters',  `${fmt.num(p.distinct_reporters)} distinct`]);

    return {
      soph, ts,
      geoText: geoParts.join(' · '),
      stats,
      narrative: p.detective_narrative || p.mistral_analysis,
    };
  }, [p]);

  return (
    <div style={S.dossierWrap}>
      <div className="card" style={{borderTop:`3px solid ${sevColor}`, padding:'16px'}}>
        <div style={S.dossierRow}>
          <div style={S.dossierIdent}>
            <div style={S.dossierIp}>{ipOf(p) || '—'}</div>
            <div style={S.dossierMeta}>
              {ts && `Last activity ${fmt.ago(ts)} ago`}
              {geoText && ` · ${geoText}`}
            </div>
            <div style={S.chipRow}>
              <span className={`p-sev-tag p-sev-${sev}`}>{sev}</span>
              {soph && <span className={`p-soph-chip ${soph.chip}`}>{soph.text}</span>}
              <AnonChips osint={osint} />
              {p.disguise_used && <span className="rc-chip red">● DISGUISED · {String(p.disguise_type || 'anonymous').toUpperCase()}</span>}
              {p.escalation_detected && <span className="rc-chip red">! ESCALATION DETECTED</span>}
            </div>
            {Array.isArray(p.honeypots) && p.honeypots.length > 0 && (
              <div style={S.hpChipRow}>
                {p.honeypots.map((hp, i) => (
                  <span key={i} className="rc-chip" style={{textTransform:'uppercase',fontSize:'9px'}}>{hp}</span>
                ))}
              </div>
            )}
          </div>
          <ScoreGauge score={score} sev={sev} />
        </div>

        {stats.length > 0 && (
          <div style={S.statsGrid}>
            {stats.map(([l, v], i) => <StatBlock key={i} label={l} value={v} />)}
          </div>
        )}
      </div>

      <AbuseCard osint={osint} />

      <OsintSources p={p} osint={osint} ip={ip} />

      {narrative && (
        <div className="card">
          <div className="card-h">
            <div className="card-t">Behavioral Analysis</div>
            <div className="card-sub">LLM-generated narrative</div>
          </div>
          <div style={S.narrative}>{narrative}</div>
        </div>
      )}

      <BehaviorCard osint={osint} />

      <TopValuesCard osint={osint} />

      <CredentialsTable creds={osint.credentialsAttempted} />

      <CommandsBlock cmds={osint.commandsExecuted} />

      <IocCard osint={osint} />

      {(p.shodan || p.network_cidr || p.abuse_contact) && (
        <div className="card">
          <div className="card-h">
            <div className="card-t">Network & Infrastructure</div>
          </div>
          <table className="tbl">
            <tbody>
              {p.network_cidr && <tr><th style={{width:'170px'}}>Network CIDR</th><td className="mono">{p.network_cidr}</td></tr>}
              {p.network_name && <tr><th>Network Name</th><td className="mono">{p.network_name}</td></tr>}
              {p.abuse_contact && <tr><th>Abuse Contact</th><td className="mono">{p.abuse_contact}</td></tr>}
              {p.shodan?.ports?.length > 0 && (
                <tr><th>Open Ports</th><td><ChipList items={p.shodan.ports} className="rc-chip hl" /></td></tr>
              )}
              {p.shodan?.vulns?.length > 0 && (
                <tr><th>CVEs</th><td><ChipList items={p.shodan.vulns} className="rc-chip red" /></td></tr>
              )}
              {p.shodan?.tags?.length > 0 && (
                <tr><th>Tags</th><td><ChipList items={p.shodan.tags} /></td></tr>
              )}
              {p.shodan?.os && <tr><th>OS</th><td className="mono">{p.shodan.os}</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {Array.isArray(p.attack_categories) && p.attack_categories.length > 0 && (
        <div className="card">
          <div className="card-h"><div className="card-t">Attack Categories</div></div>
          <ChipList items={p.attack_categories} className="rc-chip red" />
        </div>
      )}

      <MitreList items={p.mitre_techniques} />
    </div>
  );
}

export default function Profiling() {
  const [profiles, setProfiles] = useState([]);
  const [stats, setStats] = useState(null);
  const [activeId, setActiveId] = useState(null);
  const [activeProfile, setActiveProfile] = useState(null);
  const [useMock, setUseMock] = useState(false);
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState('risk_score');
  const [hpFilter, setHpFilter] = useState('ALL');
  const [lookupIp, setLookupIp] = useState('');
  const [error, setError] = useState('');
  const [detailLoading, setDetailLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  // Deferred search keeps typing snappy while filter recomputes in the background.
  const deferredSearch = useDeferredValue(search);

  // Track the latest in-flight detail request so older responses can't overwrite newer ones.
  const detailReqRef = useRef(0);
  const mockRef = useRef(useMock);
  mockRef.current = useMock;

  const loadAll = useCallback(async () => {
    setRefreshing(true);
    setUseMock(false);
    let nextProfiles = [];
    let nextError = '';
    try {
      const s = await api.profilingStats();
      setStats(s);
    } catch {
      setStats(null);
    }
    try {
      const data = await api.profilingList({ limit: 200 });
      nextProfiles = Array.isArray(data) ? data.map(normalize) : [];
    } catch (e) {
      nextError = e.status === 404
        ? 'Profile list unavailable. Use "Profile an IP" above, or load demo data.'
        : e.message;
    }
    setProfiles(nextProfiles);
    setError(nextError);
    setRefreshing(false);
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const loadMock = useCallback(async () => {
    try {
      const mod = await import('../mockProfiles.js');
      const mockProfiles = mod.MOCK_PROFILES || mod.default || (typeof window !== 'undefined' ? window.MOCK_PROFILES : null) || [];
      const normalized = mockProfiles.map(normalize);
      setUseMock(true);
      setProfiles(normalized);
      setError('');
      const total = normalized.length;
      setStats({
        total,
        critical: normalized.filter(p => p.severity === 'CRITICAL').length,
        high:     normalized.filter(p => p.severity === 'HIGH').length,
        avg_score: total ? Math.round(normalized.reduce((s, p) => s + (Number(p.risk_score) || 0), 0) / total) : 0,
      });
      if (normalized.length) {
        setActiveId(normalized[0].id);
        setActiveProfile(normalized[0]);
      }
    } catch (e) {
      setError(`Failed to load demo profiles: ${e.message}`);
    }
  }, []);

  const loadDetail = useCallback(async (id) => {
    setActiveId(id);
    if (mockRef.current) {
      setProfiles(prev => {
        const m = prev.find(p => p.id === id);
        if (m) setActiveProfile(m);
        return prev;
      });
      return;
    }
    const reqId = ++detailReqRef.current;
    setDetailLoading(true);
    try {
      const rec = await api.profilingById(id);
      if (reqId !== detailReqRef.current) return;
      setActiveProfile(normalize(rec));
    } catch (e) {
      if (reqId !== detailReqRef.current) return;
      setProfiles(prev => {
        const listItem = prev.find(p => p.id === id);
        setActiveProfile(listItem || { error: e.message });
        return prev;
      });
    } finally {
      if (reqId === detailReqRef.current) setDetailLoading(false);
    }
  }, []);

  const handleLookup = useCallback(async () => {
    const ip = lookupIp.trim();
    if (!ip) return;
    if (mockRef.current) {
      const m = profiles.find(p => ipOf(p) === ip);
      if (m) { setActiveProfile(m); setActiveId(m.id); return; }
    }
    const reqId = ++detailReqRef.current;
    setDetailLoading(true);
    try {
      const rec = await api.profile(ip);
      if (reqId !== detailReqRef.current) return;
      setActiveProfile(normalize(rec));
      setActiveId(rec?.id ?? null);
    } catch (e) {
      if (reqId !== detailReqRef.current) return;
      setActiveProfile({ error: e.status === 404 ? `No profile found for ${ip}.` : e.message });
    } finally {
      if (reqId === detailReqRef.current) setDetailLoading(false);
    }
  }, [lookupIp, profiles]);

  const onLookupKey = useCallback((e) => { if (e.key === 'Enter') handleLookup(); }, [handleLookup]);
  const onSearchChange = useCallback((e) => setSearch(e.target.value), []);
  const onLookupChange = useCallback((e) => setLookupIp(e.target.value), []);
  const onSortChange   = useCallback((e) => setSortBy(e.target.value), []);
  const clearSearch    = useCallback(() => setSearch(''), []);

  const filtered = useMemo(() => {
    let list = profiles;
    if (hpFilter !== 'ALL') {
      list = list.filter(p => Array.isArray(p.honeypots) ? p.honeypots.includes(hpFilter) : p.honeypot === hpFilter);
    }
    if (deferredSearch) {
      const q = deferredSearch.toLowerCase();
      list = list.filter(p => ipOf(p).toLowerCase().includes(q));
    }
    // Sort a copy — avoid mutating the source array.
    const out = list === profiles ? list.slice() : list;
    if (sortBy === 'risk_score')      out.sort((a, b) => (Number(b.risk_score) || 0) - (Number(a.risk_score) || 0));
    else if (sortBy === 'last_seen')  out.sort((a, b) => new Date(b.last_seen || 0) - new Date(a.last_seen || 0));
    else if (sortBy === 'sessions')   out.sort((a, b) => (Number(b.session_count) || 0) - (Number(a.session_count) || 0));
    return out;
  }, [profiles, hpFilter, deferredSearch, sortBy]);

  // Auto-select first profile once a real-data list arrives and nothing is selected yet.
  useEffect(() => {
    if (!activeId && filtered.length > 0 && !detailLoading) {
      loadDetail(filtered[0].id);
    }
  }, [activeId, filtered, detailLoading, loadDetail]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{marginBottom:'8px'}}>Forensic Profiling</div>
          <h2 className="page-title">Attacker <span>Dossiers</span></h2>
          <div className="page-sub">FBI criminal profiling methodology applied to cyber attacker behavioral analysis · LLM-powered</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={loadAll} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Refresh'}</button>
        </div>
      </div>

      <div className="fkpi-row">
        <div className="fkpi" style={{borderColor:'#f0b42955'}}>
          <div className="fkpi-label">Total Profiles</div>
          <div className="fkpi-val" style={{color:'var(--gold)'}}>{stats?.total ?? '—'}</div>
          <div className="fkpi-sub">{stats?.total ? 'stored profiles' : 'no profiles yet'}</div>
        </div>
        <div className="fkpi" style={{borderColor:'#ff505055'}}>
          <div className="fkpi-label">Critical</div>
          <div className="fkpi-val" style={{color:'#ff5050'}}>{stats?.critical ?? '—'}</div>
          <div className="fkpi-sub">score ≥ 70</div>
        </div>
        <div className="fkpi" style={{borderColor:'#ff993355'}}>
          <div className="fkpi-label">High</div>
          <div className="fkpi-val" style={{color:'#ff9933'}}>{stats?.high ?? '—'}</div>
          <div className="fkpi-sub">40 – 69</div>
        </div>
        <div className="fkpi" style={{borderColor:'#2dd4bf55'}}>
          <div className="fkpi-label">Avg Score</div>
          <div className="fkpi-val" style={{color:'#2dd4bf'}}>{stats?.avg_score ?? '—'}</div>
          <div className="fkpi-sub">out of 100</div>
        </div>
      </div>

      <div className="filters" style={S.filtersRow}>
        <select className="form-s" value={sortBy} onChange={onSortChange} style={S.sortSelect} aria-label="Sort profiles by">
          {SORT_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <input
          className="form-i"
          placeholder="Filter by IP…"
          value={search}
          onChange={onSearchChange}
          style={S.searchInput}
          aria-label="Filter profiles by IP"
        />
        {search && (
          <button className="btn btn-gh btn-sm" onClick={clearSearch} title="Clear filter">×</button>
        )}
        <input
          className="form-i"
          placeholder="Profile an IP…"
          value={lookupIp}
          onChange={onLookupChange}
          onKeyDown={onLookupKey}
          style={S.lookupInput}
          aria-label="Look up profile for an IP"
        />
        <button className="btn btn-gold btn-sm" onClick={handleLookup}>Profile →</button>
      </div>

      <div style={S.hpRow}>
        {HONEYPOTS.map(hp => (
          <button
            key={hp}
            className={`p-hp-chip${hpFilter === hp ? ' active' : ''}`}
            onClick={() => setHpFilter(hp)}
            aria-pressed={hpFilter === hp}
          >
            {hp === 'ALL' ? 'All' : hp.charAt(0).toUpperCase() + hp.slice(1)}
          </button>
        ))}
      </div>

      <div className="p-layout" style={S.layout}>
        <div className="p-list-col">
          <div className="card" style={{padding:0}}>
            <div className="card-h" style={S.listCardH}>
              <div className="card-t" style={S.listCardT}>Suspect Registry</div>
              <div className="card-sub">{filtered.length}{filtered.length !== profiles.length ? ` of ${profiles.length}` : ''}</div>
            </div>
            <div className="scroll-y" style={S.scrollList}>
              {error ? (
                <div className="alert info" style={S.alertM}>{error}</div>
              ) : !filtered.length ? (
                <div className="alert info" style={S.alertM}>
                  {profiles.length ? 'No profiles match the current filters.' : 'No profiles yet.'}
                </div>
              ) : (
                filtered.map(p => (
                  <ProfileCard
                    key={p.id || ipOf(p)}
                    p={p}
                    active={p.id === activeId}
                    onSelect={loadDetail}
                  />
                ))
              )}
            </div>
          </div>
        </div>

        <div className="p-detail-col">
          {detailLoading ? (
            <div className="card"><div className="alert info">Loading dossier…</div></div>
          ) : activeProfile?.error ? (
            <div className="card"><div className="alert err">{activeProfile.error}</div></div>
          ) : activeProfile ? (
            <Dossier p={activeProfile} />
          ) : (
            <div className="card p-empty">
              <div className="p-empty-icon">◉</div>
              <div className="p-empty-t">Select a Suspect</div>
              <div className="p-empty-s">to open the forensic dossier</div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
