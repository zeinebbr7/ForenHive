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

function HpCard({ h, stats, containerStatus, services, onAction }) {
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
      <div style={{ marginTop: 14 }}>
        <a className="btn btn-gh btn-sm" href="/evidence">View logs</a>
        <a className="btn btn-gh btn-sm" href="/sessions" style={{ marginLeft: 6 }}>Sessions</a>
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
          />
        ))}
      </div>

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
      `}</style>
    </>
  );
}
