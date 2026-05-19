import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, Cell,
} from 'recharts';
import api from '../api';
import { fmt } from '../utils';

const HONEYPOTS_META = [
  { id: 'cowrie',  name: 'Cowrie',  ports: 'SSH:2222 · Telnet:2323',                   desc: 'SSH/Telnet Honeypot — captures brute force and shell commands',     container: 'forenhive-cowrie'  },
  { id: 'dionaea', name: 'Dionaea', ports: 'SMB:445 · MySQL:3306 · MongoDB:27017 · …', desc: 'Multi-protocol Honeypot — captures malware binaries (Mirai, etc.)', container: 'forenhive-dionaea' },
  { id: 'galah',   name: 'Galah',   ports: 'HTTP:8080 · HTTPS:8888',                   desc: 'LLM-driven HTTP Honeypot (Ollama Mistral 7B) — dynamic responses',  container: 'forenhive-galah'   },
];

const HP_DETAILS = {
  cowrie: {
    tagline: 'Low-interaction SSH/Telnet honeypot with a banking-DB persona.',
    about: [
      'Cowrie pretends to be a real Linux server called db-prod — a banking database machine that looks poorly secured.',
      'When an attacker brute-forces their way in via SSH or Telnet, they land inside a fake shell. Every command they type, every file they try to download, every tool they run is silently recorded.',
      'Nothing is real — the filesystem is fake, credentials work but lead nowhere — but the attacker has no way to know that.',
    ],
    profile: [
      ['Hostname', 'db-prod'],
      ['SSH banner', 'SSH-2.0-OpenSSH_8.9p1'],
      ['Auth backend', 'UserDB (etc/userdb.txt)'],
      ['Theme', 'Simulated banking database server'],
    ],
    ports: [
      ['SSH', '2222', 'Interactive shell capture'],
      ['Telnet', '2223', 'Telnet brute-force capture'],
    ],
    accounts: [
      { user: 'root',    passwords: 'root, toor, admin, password, 123456, mongo2024, banking123' },
      { user: 'mongodb', passwords: 'mongodb, mongo123, password' },
      { user: 'dbadmin', passwords: 'dbadmin, Admin@2024' },
      { user: 'ubuntu',  passwords: 'ubuntu, changeme' },
    ],
    notes: 'Logs every command, file upload, and credential attempt to cowrie.json for replay and timeline reconstruction.',
  },
  dionaea: {
    tagline: 'Multi-protocol low-interaction honeypot — collects malware binaries.',
    about: [
      'Dionaea opens a wide range of fake network services — SMB file shares, SQL databases, MongoDB, HTTP, MQTT — all on one container.',
      'It does not give attackers a real shell. Instead it speaks just enough of each protocol to lure automated malware into uploading itself, letting us capture the binary for analysis.',
      'This is where worms like Mirai get caught: they scan for open ports, find what looks like a vulnerable service, and drop their payload directly into our collection folder.',
    ],
    profile: [
      ['SMB persona',  'Windows Server 2019 · WORKGROUP'],
      ['MSSQL persona','Microsoft SQL Server 2019 (SQLSERVER2019)'],
      ['Modules',      'smb, mssql, mysql, http, ftp, tftp, sip, pcap'],
    ],
    ports: [
      ['SMB',       '445',   'EternalBlue / SMB exploits'],
      ['MSSQL',     '1433',  'SQL Server probes'],
      ['MySQL',     '3306',  'MySQL brute-force'],
      ['MongoDB',   '27017', 'Unauth Mongo scans'],
      ['HTTP',      '80',    'Web exploit probes'],
      ['HTTPS',     '443',   'TLS / cert harvesting'],
      ['RPC',       '135',   'Windows RPC'],
      ['Telnet',    '23',    'Legacy Telnet'],
      ['PPTP',      '1723',  'VPN scans'],
      ['MQTT',      '1883',  'IoT broker probes'],
      ['Memcached', '11211', 'Amp / reflection scans'],
    ],
    notes: 'Captured malware binaries are stored under /opt/dionaea/var/lib/dionaea/binaries/ for offline analysis (Mirai variants commonly seen).',
  },
  galah: {
    tagline: 'LLM-driven HTTP honeypot — Ollama generates believable responses on the fly.',
    about: [
      'Galah is a web server that does not serve a real site — it uses a local LLM (Mistral 7B via Ollama) to invent a plausible response to whatever HTTP request it receives.',
      'Scanner tools and exploit bots probe websites looking for admin panels, login pages, or known CVE paths. Galah generates realistic-looking pages for each probe instead of returning the same static 404, making it very hard to fingerprint as a honeypot.',
      'Responses are cached so repeated probes get the same answer, and every request is logged for analysis.',
    ],
    profile: [
      ['LLM provider', 'Ollama'],
      ['Model',        'Mistral 7B (configurable via OLLAMA_MODEL)'],
      ['Cache',        'cache.db (replays prior LLM answers)'],
    ],
    ports: [
      ['HTTP',  '8080', 'Plain HTTP scraping & exploit attempts'],
      ['HTTPS', '8888', 'TLS — fake admin panels, APIs'],
    ],
    notes: 'Each request is answered by a freshly generated response, so scanners cannot fingerprint on static content.',
  },
};

const HP_COLORS = { cowrie: '#8C1A2B', dionaea: '#ff5050', galah: '#b464ff' };
const TOOLTIP_STYLE = {
  backgroundColor: '#0d111e', border: '1px solid #1e2538', borderRadius: '6px',
  fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: '#e0e6f0',
};
const AXIS_TICK = { fontSize: 10, fill: '#8892a4', fontFamily: "'JetBrains Mono',monospace" };

function HpChart({ barData }) {
  if (!barData.length) return null;
  return (
    <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 10, padding: '16px 20px' }}>
      <div style={{ fontFamily: "'Rajdhani',sans-serif", fontSize: 15, fontWeight: 700, color: 'var(--text1)', marginBottom: 2 }}>
        Event Volume Comparison
      </div>
      <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: "'JetBrains Mono',monospace", marginBottom: 12 }}>
        Total captured events per honeypot sensor
      </div>
      <ResponsiveContainer width="100%" height={100}>
        <BarChart data={barData} layout="vertical" margin={{ top: 0, right: 60, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
          <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
          <YAxis type="category" dataKey="name" width={80} tick={{ ...AXIS_TICK, fill: '#e0e6f0' }} tickLine={false} axisLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} formatter={v => [v.toLocaleString('en-US') + ' events', 'Count']} />
          <Bar dataKey="events" name="Events" radius={[0, 3, 3, 0]} barSize={20}
            label={{ position: 'right', style: { fill: '#8892a4', fontSize: 11, fontFamily: "'JetBrains Mono',monospace" }, formatter: v => v.toLocaleString('en-US') }}>
            {barData.map((entry, i) => (
              <Cell key={i} fill={(HP_COLORS[entry.id] || '#888') + 'cc'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function HpDetailsPanel({ h, onClose }) {
  const d = HP_DETAILS[h.id];
  if (!d) return null;
  return (
    <>
      <div className="hp-panel-backdrop" onClick={onClose} />
      <aside className={`hp-panel hp-${h.id}`} role="dialog" aria-label={`${h.name} details`}>
        <div className="hp-panel-h">
          <div>
            <div className="hp-panel-tag">Honeypot config</div>
            <div className="hp-panel-title">{h.name}</div>
            <div className="hp-panel-sub">{h.container}</div>
          </div>
          <button className="hp-panel-x" onClick={onClose} aria-label="Close">×</button>
        </div>

        <div className="hp-panel-tagline">{d.tagline}</div>

        <div className="hp-panel-section">
          <div className="hp-panel-sectk">What it does</div>
          <div className="hp-panel-about">
            {d.about.map((p, i) => <p key={i}>{p}</p>)}
          </div>
        </div>

        <div className="hp-panel-section">
          <div className="hp-panel-sectk">Profile</div>
          {d.profile.map(([k, v]) => (
            <div key={k} className="hp-panel-kv"><b>{k}</b><span>{v}</span></div>
          ))}
        </div>

        <div className="hp-panel-section">
          <div className="hp-panel-sectk">Ports exposed</div>
          <table className="hp-panel-ports">
            <thead>
              <tr><th>Service</th><th>Port</th><th>Captures</th></tr>
            </thead>
            <tbody>
              {d.ports.map(([svc, port, note]) => (
                <tr key={svc + port}>
                  <td>{svc}</td>
                  <td className="mono">{port}</td>
                  <td>{note}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {d.accounts && (
          <div className="hp-panel-section">
            <div className="hp-panel-sectk">Simulated accounts (userdb)</div>
            {d.accounts.map(a => (
              <div key={a.user} className="hp-panel-acct">
                <div className="hp-panel-user">{a.user}</div>
                <div className="hp-panel-pw">{a.passwords}</div>
              </div>
            ))}
          </div>
        )}

        <div className="hp-panel-section">
          <div className="hp-panel-sectk">Notes</div>
          <div className="hp-panel-notes">{d.notes}</div>
        </div>
      </aside>
    </>
  );
}

function HpCard({ h, stats, containerStatus, services, onAction, onShowDetails }) {
  const [actionPending, setActionPending] = useState(null);
  const s = stats[h.id] || { count: 0, last: 0 };
  const ctState = (containerStatus[h.id] || '').toLowerCase();
  const upDown = ctState || services[h.id] || services[h.container] || (s.count > 0 ? 'up' : 'unknown');
  const isUp = ctState
    ? ctState === 'running'
    : (String(upDown).toLowerCase() === 'up' || s.count > 0);

  async function handleAction(action) {
    if (action === 'stop' && !window.confirm(`Shutdown the ${h.name} honeypot?`)) return;
    setActionPending(action);
    try {
      await onAction(h.id, action);
    } finally {
      setActionPending(null);
    }
  }

  return (
    <div className={`hp-card hp-${h.id}`}>
      <div className="hp-card-h">
        <div>
          <div className="hp-name">{h.name}</div>
          <div className="hp-sub">{h.container}</div>
        </div>
        <span className={`hp-status ${isUp ? 'up' : 'down'}`}>
          {isUp ? '● RUNNING' : '○ STOPPED'}
        </span>
      </div>
      <div className="hp-stat">
        <div>
          <div className="hp-stat-k">Events</div>
          <div className="hp-stat-v">{fmt.num(s.count)}</div>
        </div>
        <div>
          <div className="hp-stat-k">Last</div>
          <div className="hp-stat-v" style={{ fontSize: 14 }}>{s.last ? fmt.ago(s.last) : '—'}</div>
        </div>
      </div>
      <div style={{ marginTop: 14 }}>
        <div className="hp-row"><b>Ports</b><span className="mono">{h.ports}</span></div>
        <div className="hp-row">
          <b>Description</b>
          <span style={{ textAlign: 'right', color: 'var(--text3)', fontSize: 11, maxWidth: '60%' }}>{h.desc}</span>
        </div>
      </div>
      <div style={{ marginTop: 10, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        <button
          className="btn btn-gh btn-sm"
          disabled={isUp || actionPending !== null}
          onClick={() => handleAction('start')}
        >
          {actionPending === 'start' ? '⏳ Starting…' : '▶ Turn On'}
        </button>
        <button
          className="btn btn-gh btn-sm"
          disabled={!isUp || actionPending !== null}
          style={{ color: 'var(--red2)' }}
          onClick={() => handleAction('stop')}
        >
          {actionPending === 'stop' ? '⏳ Stopping…' : '■ Shutdown'}
        </button>
        {ctState && (
          <span style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: 10, color: 'var(--text3)', alignSelf: 'center' }}>
            docker: {ctState}
          </span>
        )}
      </div>
      <div style={{ marginTop: 14, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        <button className="btn btn-gh btn-sm" onClick={() => onShowDetails(h.id)}>
          config
        </button>
        <a className="btn btn-gh btn-sm" href="/evidence">View logs</a>
        <a className="btn btn-gh btn-sm" href="/sessions">Sessions</a>
      </div>
    </div>
  );
}

export default function Honeypots() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [stats, setStats] = useState({});
  const [containerStatus, setContainerStatus] = useState({});
  const [services, setServices] = useState({});
  const [barData, setBarData] = useState([]);
  const [selectedHp, setSelectedHp] = useState(null);

  useEffect(() => {
    if (!selectedHp) return;
    const onKey = (e) => { if (e.key === 'Escape') setSelectedHp(null); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedHp]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      let split = { split: [] }, health = {}, ctStatus = {};
      try { split = await api.geoSplit(); } catch (e) {}
      try { health = await api.health(); } catch (e) {}
      try { ctStatus = await api._call('/api/honeypots/status'); } catch (e) {}

      const splitMap = {};
      (split.split || []).forEach(s => { splitMap[s.honeypot] = s.count; });

      const newStats = {};
      HONEYPOTS_META.forEach(h => { newStats[h.id] = { count: splitMap[h.id] || 0, last: 0 }; });

      await Promise.all(HONEYPOTS_META.map(async h => {
        try {
          const r = await api.attacks({ page_size: 1, honeypot: h.id });
          const ev = r && r.items && r.items[0];
          if (ev) newStats[h.id].last = +new Date(ev.timestamp || 0);
        } catch (e) {}
      }));

      const svcMap = (health && health.services) || {};
      setStats(newStats);
      setContainerStatus(ctStatus || {});
      setServices(svcMap);
      setBarData(
        HONEYPOTS_META.map(hp => ({ name: hp.name, id: hp.id, events: newStats[hp.id].count }))
          .sort((a, b) => b.events - a.events)
      );
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleAction(hpId, action) {
    try {
      await api._call(`/api/honeypots/${hpId}/${action}`, { method: 'POST' });
      await new Promise(r => setTimeout(r, 800));
      await load();
    } catch (e) {
      alert(`${action} ${hpId} failed: ${e.message}`);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>Honeypot Management</div>
          <h2 className="page-title">Active <span>Honeypots</span></h2>
          <div className="page-sub">Container status · captured volume · last event.</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={load} disabled={loading}>Refresh</button>
        </div>
      </div>

      {barData.length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <HpChart barData={barData} />
        </div>
      )}

      <div className="grid-2">
        {loading && <div className="alert info">Loading…</div>}
        {error && <div className="alert err">{error}</div>}
        {!loading && !error && HONEYPOTS_META.map(h => (
          <HpCard
            key={h.id}
            h={h}
            stats={stats}
            containerStatus={containerStatus}
            services={services}
            onAction={handleAction}
            onShowDetails={setSelectedHp}
          />
        ))}
      </div>

      {selectedHp && (
        <HpDetailsPanel
          h={HONEYPOTS_META.find(x => x.id === selectedHp)}
          onClose={() => setSelectedHp(null)}
        />
      )}

      <style>{`
        .hp-card { border:1px solid var(--border); border-radius:10px; background: var(--bg2); padding: 18px; }
        .hp-card-h { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px; }
        .hp-name { font-family:'Rajdhani',sans-serif; font-size:18px; font-weight:700; letter-spacing:.5px; }
        .hp-cowrie  .hp-name { color: var(--gold); }
        .hp-dionaea .hp-name { color: var(--red2); }
        .hp-galah   .hp-name { color: var(--purple2, #9F6AE0); }
        .hp-zeek    .hp-name { color: var(--blue2); }
        .hp-sub { font-family:'Share Tech Mono',monospace; font-size:11px; color: var(--text3); margin-top:2px; }
        .hp-stat { display:flex; gap:18px; margin-top:8px; }
        .hp-stat-k { font-family:'Share Tech Mono',monospace; font-size:10px; color: var(--text3); letter-spacing:1px; text-transform:uppercase; }
        .hp-stat-v { font-family:'Rajdhani',sans-serif; font-size:22px; font-weight:700; color: var(--text); }
        .hp-status { font-family:'Share Tech Mono',monospace; font-size:10px; padding: 3px 8px; border-radius: 3px; letter-spacing:1px; }
        .hp-status.up   { background: rgba(140,26,43,.12); color: var(--gold); border:1px solid var(--border2); }
        .hp-status.down { background: rgba(198,40,40,.12); color: var(--red2); border:1px solid rgba(198,40,40,.30); }
        .hp-row { display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid var(--border); font-size:12px; }
        .hp-row:last-child { border-bottom:none; }
        .hp-row b { color: var(--text2); }
        .hp-row .mono { color: var(--gold); }

        .hp-panel-backdrop {
          position: fixed; inset: 0; background: rgba(0,0,0,0.45);
          z-index: 40; animation: hp-fade 0.18s ease;
        }
        .hp-panel {
          position: fixed; top: 0; right: 0; bottom: 0;
          width: min(420px, 92vw);
          background: var(--bg2); border-left: 1px solid var(--border);
          padding: 22px 22px 28px; overflow-y: auto; z-index: 41;
          box-shadow: -8px 0 24px rgba(0,0,0,0.4);
          animation: hp-slide 0.22s ease;
        }
        @keyframes hp-fade { from { opacity: 0 } to { opacity: 1 } }
        @keyframes hp-slide { from { transform: translateX(100%) } to { transform: translateX(0) } }
        .hp-panel.hp-cowrie  { border-left-color: var(--gold); }
        .hp-panel.hp-dionaea { border-left-color: var(--red2); }
        .hp-panel.hp-galah   { border-left-color: var(--purple2, #9F6AE0); }
        .hp-panel-h { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px; }
        .hp-panel-tag { font-family:'Share Tech Mono',monospace; font-size:10px; letter-spacing:2px; text-transform:uppercase; color: var(--text3); }
        .hp-panel-title { font-family:'Rajdhani',sans-serif; font-size:24px; font-weight:700; margin-top:2px; }
        .hp-panel.hp-cowrie  .hp-panel-title { color: var(--gold); }
        .hp-panel.hp-dionaea .hp-panel-title { color: var(--red2); }
        .hp-panel.hp-galah   .hp-panel-title { color: var(--purple2, #9F6AE0); }
        .hp-panel-sub { font-family:'Share Tech Mono',monospace; font-size:11px; color: var(--text3); margin-top:2px; }
        .hp-panel-x {
          background: transparent; border: 1px solid var(--border); color: var(--text2);
          width: 28px; height: 28px; border-radius: 4px; font-size: 18px; line-height: 1;
          cursor: pointer;
        }
        .hp-panel-x:hover { color: var(--text); border-color: var(--text3); }
        .hp-panel-tagline { font-size: 12px; color: var(--text2); margin-bottom: 18px; line-height: 1.5; }
        .hp-panel-section { margin-bottom: 18px; }
        .hp-panel-sectk { font-family:'Share Tech Mono',monospace; font-size:10px; letter-spacing:1.5px; text-transform:uppercase; color: var(--text3); margin-bottom: 8px; }
        .hp-panel-kv { display:flex; justify-content:space-between; gap:12px; padding:5px 0; font-size:12px; border-bottom:1px dashed var(--border); }
        .hp-panel-kv b { color: var(--text2); font-weight: 600; }
        .hp-panel-kv span { color: var(--text); text-align:right; }
        .hp-panel-ports { width: 100%; border-collapse: collapse; font-size: 11px; }
        .hp-panel-ports th { text-align: left; color: var(--text3); font-weight: 600; padding: 5px 6px; border-bottom: 1px solid var(--border); font-family:'Share Tech Mono',monospace; font-size:10px; text-transform:uppercase; letter-spacing:1px; }
        .hp-panel-ports td { padding: 6px; border-bottom: 1px solid var(--border); color: var(--text); }
        .hp-panel-ports td.mono { font-family:'JetBrains Mono',monospace; color: var(--gold); }
        .hp-panel-acct { padding: 6px 0; border-bottom: 1px dashed var(--border); }
        .hp-panel-user { font-family:'JetBrains Mono',monospace; font-size: 12px; color: var(--gold); font-weight: 600; }
        .hp-panel-pw { font-family:'JetBrains Mono',monospace; font-size: 11px; color: var(--text3); margin-top: 2px; word-break: break-word; }
        .hp-panel-notes { font-size: 12px; color: var(--text2); line-height: 1.55; }
        .hp-panel-about { display: flex; flex-direction: column; gap: 8px; }
        .hp-panel-about p { margin: 0; font-family: 'JetBrains Mono', monospace; font-size: 11.5px; color: var(--text2); line-height: 1.7; }
      `}</style>
    </>
  );
}
