import React, { useState, useEffect, useRef, useCallback } from 'react';
import api from '../api';
import { SOURCE_META } from '../constants';
import { fmt, evNormalize } from '../utils';

const HP_COLORS  = { cowrie: '#8C1A2B', dionaea: '#ff5050', galah: '#b464ff', zeek: '#50a0ff' };
const SEV_COLORS = { critical: '#ff5050', high: '#ff9933', medium: '#f59e0b', low: '#2dd4bf' };
const SEV_COLOR  = { critical: 'red', high: 'red', medium: 'gold', low: 'teal' };
const SEV_LABEL  = { critical: ' CRIT', high: ' HIGH', medium: ' MED', low: ' LOW' };
const MAX_TICKS  = 20;
const HP_KEYS    = ['cowrie', 'dionaea', 'galah', 'zeek'];

function evActionLabel(n) {
  const a = (n.event_action || '').toLowerCase();
  if (a.includes('login.success'))                             return ' Login success';
  if (a.includes('login.fail') || a.includes('auth.fail'))    return ' Auth failed';
  if (a.includes('login.attempt') || a.includes('login'))     return ' Login attempt';
  if (a.includes('command.input') || a.includes('cmd'))       return ' Shell command';
  if (a.includes('session.connect') || a.includes('connect')) return ' Connection';
  if (a.includes('session.closed') || a.includes('closed'))   return ' Session closed';
  if (a.includes('file') || a.includes('malware'))            return ' Malicious file';
  if (n.http_method)    return ` ${n.http_method}`;
  if (n.dionaea_module) return ` ${n.dionaea_module}`;
  if (n.honeypot === 'zeek') {
    const svc = n.protocol ? n.protocol.toUpperCase() : 'TCP';
    return ` Traffic ${svc}`;
  }
  if (n.message) return n.message.slice(0, 70);
  return ' Event';
}

function EvRow({ n, isNew }) {
  const meta = SOURCE_META[n.honeypot] || { label: n.honeypot || '?', icon: '' };
  const sev  = (n.severity || 'low').toLowerCase();

  return (
    <div className={`ev-row${isNew ? ' ev-new' : ''}`}>
      <div className="ev-time">{fmt.time(n.timestamp)}</div>
      <div className="ev-src">
        <span className="ev-src-icon">{meta.icon}</span>
        <span className="ev-src-label">{meta.label}</span>
      </div>
      <div className="ev-ip">{n.source_ip || '—'}</div>
      <div className="ev-detail">
        <div className="ev-action">{evActionLabel(n)}</div>
        {(n.username || n.password) && (
          <div className="ev-cred"> {n.username || '?'} /  {n.password || '?'}</div>
        )}
        {n.command && <div className="ev-cmd">$ {n.command}</div>}
        {n.dionaea_msg && !n.command && !n.username && (
          <div className="ev-cmd">{n.dionaea_msg}</div>
        )}
        {n.http_path && (
          <div className="ev-cmd">{n.http_method || 'GET'} {n.http_path}</div>
        )}
        {(n.protocol || n.dest_port || (n.dest_ip && n.honeypot === 'zeek') || n.session_id) && (
          <div className="ev-meta">
            {[
              n.protocol ? n.protocol.toUpperCase() : null,
              n.dest_port ? `port ${n.dest_port}` : null,
              n.dest_ip && n.honeypot === 'zeek' ? `→ ${n.dest_ip}` : null,
              n.session_id ? `sess: ${String(n.session_id).slice(-8)}` : null,
            ].filter(Boolean).join(' · ')}
          </div>
        )}
      </div>
      <div className="ev-badges">
        <span className={`badge ${SEV_COLOR[sev] || 'teal'}`} style={{ fontSize: 10 }}>
          {SEV_LABEL[sev] || sev}
        </span>
      </div>
    </div>
  );
}

function ChartsPanel({ history, byHp, bySev, total, paused }) {
  const hpData = Object.entries(byHp)
    .map(([hp, count]) => ({
      name:  (SOURCE_META[hp] || { label: hp }).label,
      hp, count,
      pct:  ((count / (total || 1)) * 100).toFixed(0),
    }))
    .sort((a, b) => b.count - a.count);

  const sevData = ['critical', 'high', 'medium', 'low'].map(k => ({
    name:  k.charAt(0).toUpperCase() + k.slice(1),
    value: bySev[k] || 0,
    color: SEV_COLORS[k],
  }));
  const sevTotal = Object.values(bySev).reduce((a, b) => a + b, 0) || 1;

  const lastTick = history.length ? history[history.length - 1].total : 0;
  const peakTick = history.reduce((m, h) => Math.max(m, h.total), 0);
  const avgTick  = history.length
    ? Math.round(history.reduce((s, h) => s + h.total, 0) / history.length)
    : 0;

  return (
    <div className="tl-grid">
      {/* Live Activity area chart */}
      <div className="tl-chart-card tl-live">
        <div className="tl-chart-head">
          <div>
            <div className="tl-chart-title">Live Activity</div>
            <div className="tl-chart-sub">
              Events per 5 s · last {MAX_TICKS} ticks
            </div>
          </div>
          <div className="tl-pulse-pill" data-paused={paused ? '1' : '0'}>
            <span
              className="tl-pulse-dot"
              style={{ animationPlayState: paused ? 'paused' : 'running' }}
            />
            <span className="tl-pulse-txt">
              {paused ? 'PAUSED' : history.length ? `${lastTick} now` : 'waiting…'}
            </span>
          </div>
        </div>

        <div className="tl-kpis">
          <div className="tl-kpi">
            <div className="tl-kpi-val">{lastTick}</div>
            <div className="tl-kpi-lbl">last tick</div>
          </div>
          <div className="tl-kpi">
            <div className="tl-kpi-val">{peakTick}</div>
            <div className="tl-kpi-lbl">peak</div>
          </div>
          <div className="tl-kpi">
            <div className="tl-kpi-val">{avgTick}</div>
            <div className="tl-kpi-lbl">avg</div>
          </div>
        </div>

        <div className="tl-mini-legend">
          {HP_KEYS.map(hp => (
            <span key={hp} className="tl-mini-legend-item">
              <span className="tl-mini-dot" style={{ background: HP_COLORS[hp] }} />
              {(SOURCE_META[hp] || { label: hp }).label}
            </span>
          ))}
        </div>
      </div>

      {/* Source split donut */}
      <div className="tl-chart-card tl-split">
        <div className="tl-chart-head">
          <div>
            <div className="tl-chart-title">Source Split</div>
            <div className="tl-chart-sub">Current batch by sensor</div>
          </div>
          <div className="tl-split-total">
            <span className="tl-split-total-val">{total}</span>
            <span className="tl-split-total-lbl">events</span>
          </div>
        </div>

        {total === 0 ? (
          <div className="tl-wait">No events yet.</div>
        ) : (
          <div className="tl-split-body">
            <div className="tl-legend">
              {hpData.map((e, i) => (
                <div key={i} className="tl-legend-row">
                  <div className="tl-legend-head">
                    <span className="tl-legend-dot" style={{ background: HP_COLORS[e.hp] || '#888' }} />
                    <span className="tl-legend-label">{e.name}</span>
                    <span className="tl-legend-val">{e.pct}%</span>
                  </div>
                  <div className="tl-legend-bar">
                    <div
                      className="tl-legend-bar-fill"
                      style={{ width: `${e.pct}%`, background: HP_COLORS[e.hp] || '#888' }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

    </div>
  );
}

export default function Timeline() {
  const [srcFilter, setSrcFilter] = useState('');
  const [sevFilter, setSevFilter] = useState('');
  const [paused, setPaused]       = useState(false);
  const [feedRows, setFeedRows]   = useState([]);  // { n, isNew, key }
  const [feedError, setFeedError] = useState(null);

  /* Chart state */
  const [history, setHistory] = useState([]);
  const [chartByHp, setChartByHp]   = useState({});
  const [chartBySev, setChartBySev] = useState({ critical: 0, high: 0, medium: 0, low: 0 });
  const [chartTotal, setChartTotal] = useState(0);

  const seen      = useRef(new Set());
  const tlHistory = useRef([]);
  const timerRef  = useRef(null);
  const pausedRef = useRef(false);

  /* keep pausedRef in sync */
  useEffect(() => { pausedRef.current = paused; }, [paused]);

  const pushTick = useCallback((newByHp) => {
    const now = new Date();
    const t = now.getHours().toString().padStart(2, '0') + ':'
            + now.getMinutes().toString().padStart(2, '0') + ':'
            + now.getSeconds().toString().padStart(2, '0');
    const entry = {
      t,
      cowrie:  newByHp.cowrie  || 0,
      dionaea: newByHp.dionaea || 0,
      galah:   newByHp.galah   || 0,
      zeek:    newByHp.zeek    || 0,
      total:   Object.values(newByHp).reduce((a, b) => a + b, 0),
    };
    tlHistory.current.push(entry);
    if (tlHistory.current.length > MAX_TICKS) tlHistory.current.shift();
    setHistory([...tlHistory.current]);
  }, []);

  const renderCharts = useCallback((normalized, isPaused) => {
    const byHp  = {};
    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    normalized.forEach(n => {
      byHp[n.honeypot] = (byHp[n.honeypot] || 0) + 1;
      const s = (n.severity || 'low').toLowerCase();
      if (s in bySev) bySev[s]++;
    });
    setChartByHp(byHp);
    setChartBySev(bySev);
    setChartTotal(normalized.length);
  }, []);

  const loadFeed = useCallback(async (isRefresh) => {
    const src = srcFilter;
    const sev = sevFilter;
    try {
      const res = await api.attacks({ page_size: 100, page: 1 });
      const normalized = (res?.items || []).map(evNormalize);
      let filtered = normalized;
      if (src) filtered = filtered.filter(n => n.honeypot === src);
      if (sev) filtered = filtered.filter(n => (n.severity || 'low').toLowerCase() === sev);

      /* chart tick */
      const newByHp = { cowrie: 0, dionaea: 0, galah: 0, zeek: 0 };
      if (!isRefresh) {
        normalized.forEach(n => { if (n.honeypot in newByHp) newByHp[n.honeypot]++; });
      } else {
        const arrivals = normalized.filter(n => !seen.current.has(n.id));
        arrivals.forEach(n => { if (n.honeypot in newByHp) newByHp[n.honeypot]++; });
      }
      pushTick(newByHp);
      renderCharts(normalized, pausedRef.current);

      if (!isRefresh) {
        seen.current.clear();
        filtered.forEach(n => seen.current.add(n.id));
        setFeedError(null);
        setFeedRows(filtered.map(n => ({ n, isNew: false, key: n.id || Math.random() })));
        return;
      }

      /* refresh: prepend new rows */
      const newItems = filtered.filter(n => !seen.current.has(n.id));
      if (!newItems.length) return;
      newItems.forEach(n => seen.current.add(n.id));
      setFeedRows(prev => {
        const combined = [
          ...newItems.map(n => ({ n, isNew: true, key: n.id || Math.random() })),
          ...prev,
        ].slice(0, 200);
        return combined;
      });
    } catch (e) {
      if (!isRefresh) setFeedError(e.message);
    }
  }, [srcFilter, sevFilter, pushTick, renderCharts]);

  /* initial load */
  useEffect(() => {
    loadFeed(false);
  }, [srcFilter, sevFilter]); // re-run when filters change

  /* timer */
  useEffect(() => {
    timerRef.current = setInterval(() => {
      if (!pausedRef.current) {
        loadFeed(true);
      } else {
        /* keep pulse in chart paused state */
        setHistory(h => [...h]);
      }
    }, 5000);
    return () => clearInterval(timerRef.current);
  }, [loadFeed]);

  const handleFilterChange = useCallback((setter) => (e) => {
    seen.current.clear();
    setter(e.target.value);
  }, []);

  const togglePause = () => {
    setPaused(v => !v);
  };

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>Timeline</div>
          <h2 className="page-title">Live <span>Timeline</span></h2>
          <div className="page-sub">Live stream · auto-refresh every 5 s · charts update in real-time.</div>
        </div>
        <div className="page-actions" style={{ gap: 8 }}>
          <select
            className="form-s"
            style={{ minWidth: 130 }}
            value={srcFilter}
            onChange={handleFilterChange(setSrcFilter)}
          >
            <option value="">All sources</option>
            <option value="cowrie"> Cowrie</option>
            <option value="dionaea"> Dionaea</option>
            <option value="galah"> Galah</option>
            <option value="zeek"> Zeek</option>
          </select>
          <select
            className="form-s"
            style={{ minWidth: 120 }}
            value={sevFilter}
            onChange={handleFilterChange(setSevFilter)}
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <button
            className={`btn btn-sm ${paused ? 'btn-gold' : 'btn-gh'}`}
            onClick={togglePause}
          >
            {paused ? '▶ Resume' : ' Pause'}
          </button>
        </div>
      </div>

      {/* Charts panel */}
      <div style={{ marginBottom: 14 }}>
        <ChartsPanel
          history={history}
          byHp={chartByHp}
          bySev={chartBySev}
          total={chartTotal}
          paused={paused}
        />
      </div>

      {/* Event feed */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ maxHeight: 'calc(100vh - 380px)', overflowY: 'auto' }}>
          {feedError ? (
            <div className="alert err" style={{ margin: 16 }}>{feedError}</div>
          ) : feedRows.length === 0 ? (
            <div className="tl-empty">
              No events{srcFilter || sevFilter ? ' for this filter' : ''}.
            </div>
          ) : (
            feedRows.map(({ n, isNew, key }) => (
              <EvRow key={key} n={n} isNew={isNew} />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
