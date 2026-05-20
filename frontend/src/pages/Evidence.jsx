import { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api';
import { fmt, esc, evNormalize } from '../utils';

// ── STIX 2.1 helpers ─────────────────────────────────────────────────────────
function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function toStixBundle(items, honeypot) {
  const now = new Date().toISOString();
  const identityId = 'identity--' + uuidv4();
  const identity = {
    type: 'identity', spec_version: '2.1', id: identityId,
    created: now, modified: now,
    name: 'ForenHive Honeypot Platform · ' + honeypot,
    identity_class: 'system',
    description: 'ForenHive deception platform exporting captured ' + honeypot + ' events.',
  };
  const objects = [identity];
  items.forEach(ev => {
    const n = evNormalize(ev);
    const raw = n.raw || ev.raw || ev;
    const t = new Date(n.timestamp || Date.now()).toISOString();
    const obsId = 'observed-data--' + uuidv4();
    const sdoObs = {
      type: 'observed-data', spec_version: '2.1', id: obsId,
      created_by_ref: identityId, created: t, modified: t,
      first_observed: t, last_observed: t, number_observed: 1,
      object_refs: [],
    };
    const obj_refs = [];
    if (n.source_ip) {
      const ipId = 'ipv4-addr--' + uuidv4();
      objects.push({ type: 'ipv4-addr', spec_version: '2.1', id: ipId, value: n.source_ip });
      obj_refs.push(ipId);
    }
    if (n.username || n.password) {
      const acctId = 'user-account--' + uuidv4();
      objects.push({ type: 'user-account', spec_version: '2.1', id: acctId, user_id: n.username || '', credential: n.password || '' });
      obj_refs.push(acctId);
    }
    if (n.command) {
      const procId = 'process--' + uuidv4();
      objects.push({ type: 'process', spec_version: '2.1', id: procId, command_line: n.command });
      obj_refs.push(procId);
    }
    if (n.http_path) {
      const netId = 'network-traffic--' + uuidv4();
      objects.push({
        type: 'network-traffic', spec_version: '2.1', id: netId,
        protocols: ['ipv4', 'tcp', 'http'],
        extensions: { 'http-request-ext': { request_method: n.http_method || 'GET', request_value: n.http_path } }
      });
      obj_refs.push(netId);
    }
    const hash = ev.sha256 || raw.sha256;
    const noteId = 'note--' + uuidv4();
    objects.push({
      type: 'note', spec_version: '2.1', id: noteId,
      created_by_ref: identityId, created: t, modified: t,
      abstract: honeypot + ' raw event' + (hash ? ' · SHA-256 ' + hash : ''),
      content: JSON.stringify(raw),
      object_refs: obj_refs.length ? obj_refs : [identityId],
      labels: ['honeypot:' + honeypot, 'action:' + (n.event_action || 'unknown'), 'severity:' + (n.severity || 'low')],
    });
    sdoObs.object_refs = obj_refs.length ? obj_refs : [noteId];
    objects.push(sdoObs);
  });
  return { type: 'bundle', id: 'bundle--' + uuidv4(), objects };
}

// ── Drawer component ──────────────────────────────────────────────────────────
function EvidenceDrawer({ ev, onClose }) {
  const [showRaw, setShowRaw] = useState(false);

  useEffect(() => {
    setShowRaw(false);
  }, [ev]);

  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  if (!ev) return null;

  const n = evNormalize(ev);
  const raw = n.raw || {};
  const hash = ev.sha256 || raw.sha256 || '';
  const hpColor = n.honeypot === 'cowrie' ? 'gold' : n.honeypot === 'dionaea' ? 'red' : n.honeypot === 'galah' ? 'purple' : 'blue';
  const geo = (raw.source && typeof raw.source === 'object' && raw.source.geo) || raw.geo || {};
  const evFields = [
    ['Timestamp', fmt.date(n.timestamp)],
    ['Action', n.event_action || n.message || '—'],
    ['Honeypot', n.honeypot],
    ['Source IP', n.source_ip],
    ['Protocol', n.protocol],
    ['Dest Port', n.dest_port],
    ['Dest IP', n.dest_ip],
    ['Session', n.session_id],
    ['Severity', n.severity],
  ].filter(([, v]) => v != null && v !== '');

  return (
    <>
      <div
        className="ev-backdrop show"
        onClick={onClose}
        style={{ position: 'fixed', inset: 0, zIndex: 99, background: 'rgba(0,0,0,.35)', opacity: 1, pointerEvents: 'auto' }}
      />
      <div
        className="ev-drawer open"
        style={{ position: 'fixed', top: 0, right: 0, height: '100vh', width: 400, maxWidth: '100vw', background: 'var(--bg2)', borderLeft: '1px solid var(--border2)', zIndex: 100, display: 'flex', flexDirection: 'column', boxShadow: '-6px 0 28px rgba(0,0,0,.45)', transform: 'translateX(0)' }}
      >
        <div className="ev-drawer-head" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10, padding: '16px 16px 12px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <div style={{ minWidth: 0 }}>
            <div className="ev-drawer-title" style={{ fontFamily: "'Rajdhani', sans-serif", fontSize: 15, fontWeight: 700, color: 'var(--gold)', letterSpacing: '.4px' }}>Log Detail</div>
            <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: 'var(--text3)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.source_ip || '—'}</div>
          </div>
          <button
            onClick={onClose}
            title="Close (Esc)"
            style={{ background: 'none', border: 'none', color: 'var(--text3)', fontSize: 16, cursor: 'pointer', padding: '2px 4px', lineHeight: 1, borderRadius: 4, flexShrink: 0 }}
          >×</button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>
          {/* Hero */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 14 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 16, fontWeight: 700, color: 'var(--text1)' }}>{n.source_ip || '—'}</div>
            <span className={`badge ${hpColor}`}>{n.honeypot || '?'}</span>
          </div>

          {(n.username || n.password) && (
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'var(--red2)', background: 'rgba(201,61,85,.07)', borderLeft: '2px solid var(--red2)', padding: '6px 10px', borderRadius: '0 4px 4px 0', margin: '6px 0' }}>
              User: {n.username || '?'} &nbsp;/&nbsp; {n.password || '?'}
            </div>
          )}
          {n.command && (
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'var(--gold)', background: 'rgba(140,26,43,.08)', borderLeft: '2px solid var(--gold)', padding: '6px 10px', borderRadius: '0 4px 4px 0', margin: '6px 0', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              $ {n.command}
            </div>
          )}
          {n.http_path && (
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'var(--gold)', background: 'rgba(140,26,43,.08)', borderLeft: '2px solid var(--gold)', padding: '6px 10px', borderRadius: '0 4px 4px 0', margin: '6px 0' }}>
              {n.http_method || 'GET'} {n.http_path}
            </div>
          )}

          {/* Event fields */}
          <div style={{ fontSize: 9, fontFamily: "'Share Tech Mono', monospace", color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: 1, margin: '14px 0 6px', paddingBottom: 4, borderBottom: '1px solid var(--border)' }}>Event</div>
          {evFields.map(([k, v]) => (
            <div key={k} style={{ display: 'grid', gridTemplateColumns: '100px 1fr', gap: '4px 10px', padding: '4px 0', fontSize: 12, borderBottom: '1px solid rgba(255,255,255,.03)' }}>
              <div style={{ color: 'var(--text3)', fontFamily: "'Share Tech Mono', monospace", fontSize: 11 }}>{k}</div>
              <div style={{ color: 'var(--text1)', wordBreak: 'break-all' }}>{String(v)}</div>
            </div>
          ))}

          {/* Geo */}
          {(geo.country_name || geo.city_name) && (
            <>
              <div style={{ fontSize: 9, fontFamily: "'Share Tech Mono', monospace", color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: 1, margin: '14px 0 6px', paddingBottom: 4, borderBottom: '1px solid var(--border)' }}>Geolocation</div>
              {[['Country', geo.country_name], ['City', geo.city_name], ['Region', geo.region_name],
                ['ASN', raw.source && typeof raw.source === 'object' && raw.source.as && raw.source.as.number]
              ].filter(([, v]) => v).map(([k, v]) => (
                <div key={k} style={{ display: 'grid', gridTemplateColumns: '100px 1fr', gap: '4px 10px', padding: '4px 0', fontSize: 12, borderBottom: '1px solid rgba(255,255,255,.03)' }}>
                  <div style={{ color: 'var(--text3)', fontFamily: "'Share Tech Mono', monospace", fontSize: 11 }}>{k}</div>
                  <div style={{ color: 'var(--text1)', wordBreak: 'break-all' }}>{String(v)}</div>
                </div>
              ))}
            </>
          )}

          {/* Integrity */}
          {hash && (
            <>
              <div style={{ fontSize: 9, fontFamily: "'Share Tech Mono', monospace", color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: 1, margin: '14px 0 6px', paddingBottom: 4, borderBottom: '1px solid var(--border)' }}>Integrity</div>
              <div style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: 'var(--accent-gold)', background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 4, padding: '5px 8px', margin: '6px 0', wordBreak: 'break-all', lineHeight: 1.5 }}>
                SHA-256 · {hash}
              </div>
            </>
          )}

          {/* Raw JSON toggle */}
          <button
            onClick={() => setShowRaw(p => !p)}
            style={{ background: 'none', border: '1px solid var(--border)', color: 'var(--text3)', fontSize: 11, fontFamily: "'Share Tech Mono', monospace", padding: '4px 10px', borderRadius: 4, cursor: 'pointer', marginTop: 12 }}
          >
            {showRaw ? 'Hide JSON ▴' : 'Show raw JSON ▾'}
          </button>
          {showRaw && (
            <pre style={{ display: 'block', background: 'var(--bg3)', border: '1px solid var(--border)', borderRadius: 4, padding: 8, marginTop: 6, fontFamily: "'Share Tech Mono', monospace", fontSize: 10, color: 'var(--text3)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 240, overflowY: 'auto' }}>
              {JSON.stringify(raw, null, 2)}
            </pre>
          )}
        </div>
      </div>
    </>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function Evidence() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [hpFilter, setHpFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeIdx, setActiveIdx] = useState(null);
  const [runStatus, setRunStatus] = useState('');
  const [running, setRunning] = useState(false);
  const [stixLoading, setStixLoading] = useState({});
  const pollRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setActiveIdx(null);
    try {
      const params = { page_size: 500 };
      let result = [];
      let totalCount = 0;
      if (hpFilter) {
        const res = await api.attacks({ ...params, honeypot: hpFilter });
        result = (res && res.items) || [];
        totalCount = (res && res.total) || result.length;
      } else {
        const results = await Promise.allSettled([
          api.attacks({ ...params, honeypot: 'cowrie' }),
          api.attacks({ ...params, honeypot: 'dionaea' }),
          api.attacks({ ...params, honeypot: 'galah' }),
        ]);
        result = results.flatMap(r => r.status === 'fulfilled' ? ((r.value && r.value.items) || []) : []);
        totalCount = results.reduce((acc, r) => acc + (r.status === 'fulfilled' ? ((r.value && r.value.total) || 0) : 0), 0);
        result.sort((a, b) =>
          +new Date(b.timestamp || (b.raw && b.raw['@timestamp']) || 0) -
          +new Date(a.timestamp || (a.raw && a.raw['@timestamp']) || 0)
        );
      }
      setItems(result);
      setTotal(totalCount || result.length);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [hpFilter]);

  useEffect(() => { load(); }, [load]);

  // Fetch run status on mount
  useEffect(() => {
    api._call('/api/forensics/status').then(s => {
      if (!s || !s.timestamp) return;
      if (s.status === 'running') {
        setRunning(true);
        setRunStatus('⏳ Analysis in progress...');
        startPolling();
      } else {
        setRunStatus(`Last run: ${new Date(s.timestamp).toLocaleString()} · ${s.status}`);
      }
    }).catch(() => {});
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  function startPolling() {
    if (pollRef.current) return;
    pollRef.current = setInterval(async () => {
      try {
        const s = await api._call('/api/forensics/status');
        if (!s) return;
        if (s.status === 'completed') {
          clearInterval(pollRef.current); pollRef.current = null;
          setRunning(false);
          setRunStatus('Done — Completed! Refreshing...');
          setTimeout(() => load(), 2000);
        } else if (['error', 'failed', 'timeout'].includes(s.status)) {
          clearInterval(pollRef.current); pollRef.current = null;
          setRunning(false);
          setRunStatus(`Failed: ${s.error || s.status}`);
        } else {
          setRunStatus(`Status: ${s.status}`);
        }
      } catch (_) {}
    }, 10000);
  }

  async function handleRunNow() {
    setRunning(true);
    setRunStatus('Queuing analysis...');
    try {
      await api._call('/api/forensics/run', { method: 'POST' });
      setRunStatus('Queued — may take 2–5 min.');
      startPolling();
    } catch (e) {
      setRunning(false);
      setRunStatus(`Error: ${e.message}`);
    }
  }

  async function exportStix(honeypot) {
    setStixLoading(p => ({ ...p, [honeypot]: true }));
    try {
      const res = await api.attacks({ honeypot, page_size: 1000 });
      const its = (res && res.items) || [];
      if (!its.length) { alert('No ' + honeypot + ' events to export.'); return; }
      const bundle = toStixBundle(its, honeypot);
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/stix+json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      a.href = url; a.download = `forenhive-${honeypot}-stix2.1-${ts}.json`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    } catch (e) {
      alert('STIX export failed: ' + e.message);
    } finally {
      setStixLoading(p => ({ ...p, [honeypot]: false }));
    }
  }

  const activeEv = activeIdx !== null ? items[activeIdx] : null;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>Forensic Analysis</div>
          <h2 className="page-title">Evidence <span>Logs</span></h2>
          <div className="page-sub">Raw honeypot logs · filter by sensor · SHA-256 verification per entry.</div>
        </div>
        <div className="page-actions" style={{ gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: 'var(--text3)' }}>{runStatus}</span>
          <button className="btn btn-primary btn-sm" onClick={handleRunNow} disabled={running}>
            {running ? '⏳ Running...' : ' Run Analysis Now'}
          </button>
          <button className="btn btn-gh btn-sm" onClick={load}>Refresh</button>
          <button className="btn btn-gh btn-sm" onClick={() => exportStix('cowrie')} disabled={!!stixLoading.cowrie} title="Export Cowrie logs as STIX 2.1 bundle">
            {stixLoading.cowrie ? '⏳ Building…' : '↓ STIX · Cowrie'}
          </button>
          <button className="btn btn-gh btn-sm" onClick={() => exportStix('dionaea')} disabled={!!stixLoading.dionaea} title="Export Dionaea logs as STIX 2.1 bundle">
            {stixLoading.dionaea ? '⏳ Building…' : '↓ STIX · Dionaea'}
          </button>
          <button className="btn btn-gh btn-sm" onClick={() => exportStix('galah')} disabled={!!stixLoading.galah} title="Export Galah logs as STIX 2.1 bundle">
            {stixLoading.galah ? '⏳ Building…' : '↓ STIX · Galah'}
          </button>
        </div>
      </div>

      <div className="fkpi-row">
        <div className="fkpi" style={{ borderColor: '#f0b42955' }}>
          <div className="fkpi-label">Total Logs</div>
          <div className="fkpi-val" style={{ color: 'var(--gold)' }}>{total.toLocaleString('en-US')}</div>
          <div className="fkpi-sub">raw entries</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#3b82f655' }}>
          <div className="fkpi-label">Active Source</div>
          <div className="fkpi-val" style={{ color: '#3b82f6' }}>{hpFilter || 'All'}</div>
          <div className="fkpi-sub">honeypot filter</div>
        </div>
      </div>

      <div className="card mb-16">
        <div className="card-h">
          <div className="card-t">Filters</div>
        </div>
        <div className="form-g" style={{ maxWidth: 480 }}>
          <label className="form-l">Source</label>
          <select className="form-s" value={hpFilter} onChange={e => setHpFilter(e.target.value)}>
            <option value="">All honeypots (Cowrie + Dionaea + Galah)</option>
            <option value="cowrie">Cowrie only</option>
            <option value="dionaea">Dionaea only</option>
            <option value="galah">Galah only</option>
          </select>
        </div>
      </div>

      <div className="card">
        <div className="card-h">
          <div className="card-t">Raw Logs</div>
          <div className="card-sub">raw honeypot logs</div>
        </div>
        {loading && <div className="alert info">Loading…</div>}
        {error && <div className="alert err">{error}</div>}
        {!loading && !error && items.length === 0 && <div className="alert info">No logs matching these filters.</div>}
        {!loading && !error && items.map((ev, i) => {
          const n = evNormalize(ev);
          const raw = n.raw || ev.raw || ev;
          const hash = ev.sha256 || (raw && raw.sha256) || '';
          const hpColor = n.honeypot === 'cowrie' ? 'gold' : n.honeypot === 'dionaea' ? 'red' : n.honeypot === 'galah' ? 'purple' : 'blue';
          const realLog = JSON.stringify(raw);
          return (
            <div
              key={ev.id || i}
              className={`evlog${activeIdx === i ? ' active' : ''}`}
              onClick={() => setActiveIdx(i)}
              style={{ borderBottom: '1px solid var(--border)', padding: '9px 8px', cursor: 'pointer', borderRadius: 4, margin: '0 -8px' }}
            >
              <div className="evlog-h" style={{ display: 'grid', gridTemplateColumns: '90px 80px 1fr auto', gap: 10, alignItems: 'center' }}>
                <div className="evlog-time" style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: 11, color: 'var(--text3)' }}>{fmt.time(n.timestamp)}</div>
                <div><span className={`badge ${hpColor}`}>{n.honeypot}</span></div>
                <div style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: 11, color: 'var(--text3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{realLog}</div>
                <div style={{ fontFamily: "'Share Tech Mono',monospace", fontSize: 10, color: 'var(--gold)' }}>
                  {hash ? '⬡ ' + fmt.shortHash(hash) : <span style={{ color: 'var(--text3)' }}>—</span>}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {activeEv && <EvidenceDrawer ev={activeEv} onClose={() => setActiveIdx(null)} />}
    </>
  );
}
