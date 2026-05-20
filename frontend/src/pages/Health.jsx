import React, { useState, useEffect, useCallback } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip,
} from 'recharts';
import api from '../api';
import { fmt, evNormalize } from '../utils';

const TOOLTIP_STYLE = {
  backgroundColor: '#0d111e', border: '1px solid #1e2538', borderRadius: '6px',
  fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: '#e0e6f0',
};
const AXIS_TICK = { fontSize: 10, fill: '#8892a4', fontFamily: "'JetBrains Mono',monospace" };

const SVC_META = {
  api:           { name: 'Backend API',   icon: 'API', layer: 'c4', desc: 'FastAPI · Python 3.11' },
  elasticsearch: { name: 'Elasticsearch', icon: 'ES',  layer: 'c2', desc: 'honeypot-logs indices' },
  postgresql:    { name: 'PostgreSQL',    icon: 'PG',  layer: 'c4', desc: 'users · reports · audit' },
  ollama:        { name: 'Ollama / LLM',  icon: 'LLM', layer: 'c3', desc: 'Mistral 7B Q4_K_M' },
  cowrie:        { name: 'Cowrie',        icon: 'SSH', layer: 'c1', desc: 'SSH :2222 · Telnet :2223' },
  dionaea:       { name: 'Dionaea',       icon: 'SMB', layer: 'c1', desc: 'SMB · FTP · MySQL…' },
  galah:         { name: 'Galah',         icon: 'HTTP',layer: 'c1', desc: 'HTTP :8080/:8888' },
  zeek:          { name: 'Zeek',          icon: 'NSM', layer: 'c1', desc: 'eno12399 · passive' },
  filebeat:      { name: 'Filebeat',      icon: 'FB',  layer: 'c2', desc: 'tail honeypot logs' },
  logstash:      { name: 'Logstash',      icon: 'LS',  layer: 'c2', desc: 'ECS · GeoIP · filters' },
  nginx:         { name: 'Nginx',         icon: 'NGX', layer: 'c5', desc: 'reverse proxy · SPA' },
};

const STLABEL = { up: 'OPERATIONAL', ok: 'OPERATIONAL', down: 'OFFLINE', unknown: 'UNKNOWN', degraded: 'DEGRADED', warn: 'DEGRADED' };
const STBADGE = { up: 'teal', ok: 'teal', down: 'red', unknown: '', degraded: 'gold', warn: 'gold' };
const DOTCLS  = { up: 'up', ok: 'up', down: 'down', degraded: 'warn', warn: 'warn', unknown: '' };

function dotClass(st) { return DOTCLS[st] || ''; }

const PIPE_STEPS = [
  { id: 'c1', label: 'Honeypots',       sub: 'Cowrie · Dionaea · Galah · Zeek' },
  { id: 'c2', label: 'ETL Pipeline',    sub: 'Filebeat → Logstash → ES' },
  { id: 'c3', label: 'Forensic Engine', sub: 'YARA · Enrichment · Ollama' },
  { id: 'c4', label: 'Backend',         sub: 'FastAPI · PostgreSQL' },
  { id: 'c5', label: 'Interface',       sub: 'React SPA · Nginx' },
];

function PipelineStrip({ pipeDots }) {
  return (
    <div className="hc-pipeline mb-20">
      {PIPE_STEPS.map((step, i) => {
        const dot = pipeDots[step.id] || '';
        return (
          <React.Fragment key={step.id}>
            {i > 0 && <div className="hc-pipe-arrow">→</div>}
            <div className={`hc-pipe-step${dot ? ' pipe-' + dot : ''}`}>
              <div className="hc-pipe-label">{step.label}</div>
              <div className="hc-pipe-sub">{step.sub}</div>
              <div className={`hc-pipe-dot${dot ? ' ' + dot : ''}`} />
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );
}

function SvcCard({ name, status, detail }) {
  const st = status || 'unknown';
  const dc = dotClass(st);
  const cardCls = dc === 'up' ? 'svc-up' : dc === 'down' ? 'svc-down' : 'svc-warn';
  const meta = SVC_META[name] || { name, icon: '⬡', desc: '' };
  return (
    <div className={`hc-svc-card ${cardCls}`}>
      <div className="hc-svc-top">
        <div className="hc-svc-icon">{meta.icon}</div>
        <span className={`badge ${STBADGE[st] || 'gold'}`} style={{ fontSize: 9 }}>
          <span className={`dot ${dc}`} />{STLABEL[st] || String(st).toUpperCase()}
        </span>
      </div>
      <div className="hc-svc-name">{meta.name || name}</div>
      <div className="hc-svc-detail">{detail || meta.desc || (st === 'unknown' ? 'not exposed by /health' : '—')}</div>
    </div>
  );
}

function BarChartBlock({ data, dataKey, labelKey, height, color }) {
  if (!data.length) return <div className="alert info">No data.</div>;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 20, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
        <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
        <YAxis type="category" dataKey={labelKey} width={100} tick={{ ...AXIS_TICK, fill: '#e0e6f0' }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} formatter={v => [v + ' events', 'Count']} />
        <Bar dataKey={dataKey} name="Events" radius={[0, 3, 3, 0]} barSize={14} fill={color} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export default function Health() {
  const [pipeDots, setPipeDots] = useState({});
  const [svcEntries, setSvcEntries] = useState([]);
  const [svcLoading, setSvcLoading] = useState(true);
  const [svcError, setSvcError] = useState(null);
  const [zeekProtos, setZeekProtos] = useState([]);
  const [zeekIps, setZeekIps] = useState([]);
  const [zeekLoading, setZeekLoading] = useState(true);
  const [zeekError, setZeekError] = useState(null);
  const [auditItems, setAuditItems] = useState([]);
  const [auditLoading, setAuditLoading] = useState(true);
  const [auditError, setAuditError] = useState(null);
  const [lastCheck, setLastCheck] = useState('—');
  const [refreshing, setRefreshing] = useState(false);

  const loadZeek = useCallback(async () => {
    setZeekLoading(true);
    setZeekError(null);
    try {
      const res = await api.attacks({ honeypot: 'zeek', page_size: 200 });
      const items = (res && res.items) || [];
      const normalized = items.map(evNormalize);
      const ipCounts = {}, protoCounts = {};
      for (const n of normalized) {
        if (n.source_ip) ipCounts[n.source_ip] = (ipCounts[n.source_ip] || 0) + 1;
        const proto = (n.protocol || (n.dest_port ? 'port:' + n.dest_port : 'other')).toString();
        protoCounts[proto] = (protoCounts[proto] || 0) + 1;
      }
      const topProto = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
      const topIp = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
      setZeekProtos(topProto.map(([p, c]) => ({ proto: p, count: c })));
      setZeekIps(topIp.map(([ip, c]) => ({ ip, count: c })));
      setPipeDots(prev => ({ ...prev, c1: items.length > 0 ? 'up' : 'warn' }));
    } catch (e) {
      setZeekError(e.message);
      setPipeDots(prev => ({ ...prev, c1: 'warn' }));
    } finally {
      setZeekLoading(false);
    }
  }, []);

  const loadServices = useCallback(async () => {
    setSvcLoading(true);
    setSvcError(null);
    try {
      const h = await api.health();
      let components = h.components || h.checks || h.services || null;
      if (!components || !Object.keys(components).length) {
        components = {};
        if ('elasticsearch' in h) components.elasticsearch = h.elasticsearch ? 'up' : 'down';
        components.api = h.status === 'ok' ? 'up' : (h.status || 'unknown');
        const probe = async hp => {
          try { const r = await api.attacks({ honeypot: hp, page_size: 1 }); return (r && r.total > 0) ? 'up' : 'unknown'; }
          catch (_) { return 'unknown'; }
        };
        const [cowrie, dionaea, galah, zeek] = await Promise.all([probe('cowrie'), probe('dionaea'), probe('galah'), probe('zeek')]);
        components.cowrie = cowrie; components.dionaea = dionaea; components.galah = galah; components.zeek = zeek;
        components.postgresql = ('postgresql' in h) ? (h.postgresql ? 'up' : 'down') : 'unknown';
        components.ollama     = ('ollama'     in h) ? (h.ollama     ? 'up' : 'down') : 'unknown';
      }
      const order = ['api', 'elasticsearch', 'postgresql', 'ollama', 'cowrie', 'dionaea', 'galah', 'zeek', 'filebeat', 'logstash', 'nginx'];
      const entries = Object.entries(components).sort((a, b) => {
        const ai = order.indexOf(a[0]), bi = order.indexOf(b[0]);
        return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi);
      });
      setSvcEntries(entries);

      const stOf = name => {
        const v = components[name];
        return typeof v === 'string' ? v : (v && v.status) || 'unknown';
      };
      const c1 = ['cowrie', 'dionaea', 'galah', 'zeek'].map(stOf);
      setPipeDots(prev => ({
        ...prev,
        c1: c1.includes('up') ? 'up' : c1.includes('down') ? 'warn' : 'warn',
        c2: stOf('elasticsearch') === 'up' ? 'up' : stOf('elasticsearch') === 'down' ? 'down' : 'warn',
        c3: stOf('ollama') === 'up' ? 'up' : 'warn',
        c4: (stOf('api') === 'up' || stOf('api') === 'ok') ? 'up' : stOf('api') === 'down' ? 'down' : 'warn',
        c5: 'up',
      }));
    } catch (e) {
      setSvcError(e.message);
      setPipeDots(prev => ({ ...prev, c2: 'down', c3: 'down', c4: 'down' }));
    } finally {
      setSvcLoading(false);
    }
  }, []);

  const loadAudit = useCallback(async () => {
    setAuditLoading(true);
    setAuditError(null);
    try {
      const res = await api.audit({ limit: 10 });
      setAuditItems((res && res.items) || []);
    } catch (e) {
      setAuditError(e.message);
    } finally {
      setAuditLoading(false);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    setRefreshing(true);
    await Promise.all([loadZeek(), loadServices(), loadAudit()]);
    setLastCheck('updated ' + new Date().toLocaleTimeString('en-US', { hour12: false }));
    setRefreshing(false);
  }, [loadZeek, loadServices, loadAudit]);

  useEffect(() => { refreshAll(); }, [refreshAll]);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>Monitoring · System</div>
          <h2 className="page-title">Health <span>Check</span></h2>
          <div className="page-sub">
            ForenHive platform status · Zeek sensor on <span className="mono">eno12399</span>.
          </div>
        </div>
        <div className="page-actions">
          <span className="mono" style={{ fontSize: 11, color: 'var(--text3)' }}>{lastCheck}</span>
          <button className="btn btn-gold btn-sm" onClick={refreshAll} disabled={refreshing}>
            {refreshing ? '↺ Checking…' : '↺ Check'}
          </button>
        </div>
      </div>

      <PipelineStrip pipeDots={pipeDots} />

      <div style={{ fontSize: 9, fontFamily: "'Share Tech Mono',monospace", color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '1.4px', marginBottom: 10 }}>
        Services &amp; Containers
      </div>
      <div className="hc-svc-grid mb-20">
        {svcLoading && <div className="alert info" style={{ gridColumn: '1/-1' }}>Checking services…</div>}
        {svcError && <div className="alert err" style={{ gridColumn: '1/-1' }}>Backend unreachable: {svcError}</div>}
        {!svcLoading && !svcError && svcEntries.map(([name, st]) => {
          const status = typeof st === 'string' ? st : (st.status || 'unknown');
          const detail = (typeof st === 'object' && (st.version || st.detail || st.message)) || '';
          return <SvcCard key={name} name={name} status={status} detail={detail} />;
        })}
      </div>

      <div className="card mb-20">
        <div className="card-h">
          <div className="card-t">Audit trail</div>
          <div className="card-sub">Last 10 actions</div>
        </div>
        <div className="scroll-y" style={{ maxHeight: 260 }}>
          {auditLoading && <div className="alert info">Loading…</div>}
          {auditError && <div className="alert err">{auditError}</div>}
          {!auditLoading && !auditError && auditItems.length === 0 && (
            <div className="alert info">No entries.</div>
          )}
          {!auditLoading && !auditError && auditItems.map((a, i) => (
            <div key={i} className="log-row">
              <div className="log-t">{fmt.time(a.timestamp)}</div>
              <div className="log-s" style={{ color: 'var(--gold)' }}>{a.action}</div>
              <div className="log-ip">{a.actor_email || '—'}</div>
              <div className="log-m">{(a.method || '') + ' ' + (a.path || '')}</div>
            </div>
          ))}
        </div>
      </div>

      <style>{`
        .hc-pipeline { display:flex;align-items:center;gap:0;background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px 16px;overflow-x:auto; }
        .hc-pipe-step { flex:1;min-width:120px;text-align:center;position:relative;padding:8px 10px 10px;border-radius:6px;border:1px solid var(--border);background:var(--surface);transition:border-color .2s; }
        .hc-pipe-step.pipe-up   { border-color: rgba(0,191,165,.35); }
        .hc-pipe-step.pipe-down { border-color: rgba(201,61,85,.4); }
        .hc-pipe-step.pipe-warn { border-color: rgba(232,184,75,.35); }
        .hc-pipe-icon { font-size:20px;margin-bottom:4px; }
        .hc-pipe-label { font-family:'Rajdhani',sans-serif;font-size:12px;font-weight:700;color:var(--text1);letter-spacing:.4px; }
        .hc-pipe-sub { font-size:9px;color:var(--text3);font-family:'Share Tech Mono',monospace;margin-top:2px;letter-spacing:.3px; }
        .hc-pipe-dot { width:8px;height:8px;border-radius:50%;background:var(--text3);margin:6px auto 0;transition:background .3s; }
        .hc-pipe-dot.up   { background:var(--teal);box-shadow:0 0 6px rgba(0,191,165,.5);animation:pulse2 2s infinite; }
        .hc-pipe-dot.down { background:var(--red2);box-shadow:0 0 6px rgba(201,61,85,.5); }
        .hc-pipe-dot.warn { background:var(--yellow); }
        .hc-pipe-arrow { color:var(--text3);font-size:18px;padding:0 8px;flex-shrink:0; }
        .hc-svc-grid { display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px; }
        .hc-svc-card { background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 14px;transition:border-color .2s; }
        .hc-svc-card.svc-down { border-color:rgba(201,61,85,.35); }
        .hc-svc-card.svc-warn { border-color:rgba(232,184,75,.3); }
        .hc-svc-top { display:flex;align-items:center;justify-content:space-between;margin-bottom:8px; }
        .hc-svc-name { font-size:13px;font-weight:700;color:var(--text1); }
        .hc-svc-icon { font-size:18px; }
        .hc-svc-detail { font-size:10px;color:var(--text3);font-family:'Share Tech Mono',monospace;line-height:1.5; }
      `}</style>
    </>
  );
}
