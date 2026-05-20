import React, { useState, useEffect, useCallback } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, PieChart, Pie, Cell,
} from 'recharts';
import api from '../api';
import { SOURCE_META, HONEYPOTS } from '../constants';
import { fmt, flag, evNormalize } from '../utils';

const COLORS = {
  cowrie:  '#8C1A2B',
  dionaea: '#ff5050',
  galah:   '#b464ff',
  zeek:    '#50a0ff',
};
const SEV_COLORS = {
  critical: '#ff5050',
  high:     '#ff9933',
  medium:   '#8C1A2B',
  low:      '#2dd4bf',
};
const TOOLTIP_STYLE = {
  backgroundColor: '#0d111e',
  border: '1px solid #1e2538',
  borderRadius: '6px',
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '11px',
  color: '#e0e6f0',
};
const AXIS_TICK = { fontSize: 10, fill: '#8892a4', fontFamily: "'JetBrains Mono', monospace" };

async function fetchAllData() {
  const [hourlyRes, splitRes, topIpsRes, topPortsRes, ...hpResults] = await Promise.all([
    api.statsHourly().catch(() => []),
    api.geoSplit().catch(() => ({ split: [] })),
    api.statsTopIps(10).catch(() => ({ items: [] })),
    api.statsTopPorts(10).catch(() => ({ items: [] })),
    api.attacks({ page_size: 100, page: 1, honeypot: 'cowrie'  }).catch(() => ({ items: [], total: 0 })),
    api.attacks({ page_size: 100, page: 1, honeypot: 'dionaea' }).catch(() => ({ items: [], total: 0 })),
    api.attacks({ page_size: 100, page: 1, honeypot: 'galah'   }).catch(() => ({ items: [], total: 0 })),
  ]);

  const hpTotals = {
    cowrie:  hpResults[0]?.total || 0,
    dionaea: hpResults[1]?.total || 0,
    galah:   hpResults[2]?.total || 0,
  };
  const grandTotal = Object.values(hpTotals).reduce((a, b) => a + b, 0);

  const seen = new Set();
  const allItems = [];
  for (const r of hpResults) {
    for (const item of (r?.items || [])) {
      if (!seen.has(item.id)) { seen.add(item.id); allItems.push(evNormalize(item)); }
    }
  }

  const hourlyArr = Array.isArray(hourlyRes) ? hourlyRes : [];
  const last24 = hourlyArr.slice(-24);
  const hourlyData = last24.map(entry => ({
    hour: new Date(entry.hour).getUTCHours().toString().padStart(2, '0') + ':00',
    cowrie:  (entry.by_honeypot || {}).cowrie  || 0,
    dionaea: (entry.by_honeypot || {}).dionaea || 0,
    galah:   (entry.by_honeypot || {}).galah   || 0,
  }));

  const splitRaw = (splitRes?.split || [])
    .filter(x => HONEYPOTS.includes(x.honeypot))
    .sort((a, b) => b.count - a.count);
  const hpTotal = splitRaw.reduce((s, x) => s + x.count, 0) || 1;
  const splitData = splitRaw.map(x => ({
    name:     SOURCE_META[x.honeypot]?.label || x.honeypot,
    honeypot: x.honeypot,
    count:    x.count,
    pct:      ((x.count / hpTotal) * 100).toFixed(1),
  }));

  const topIpsData = (topIpsRes?.items || []).map(x => ({
    ip:    (x.country ? flag(x.country) + ' ' : '') + x.ip,
    count: x.count,
    color: COLORS[x.honeypot] || '#8892a4',
    hp:    x.honeypot,
  }));

  const topPortsData = (topPortsRes?.items || []).map(x => ({
    port:  `${x.port}/${x.protocol || 'tcp'}`,
    count: x.count,
    color: COLORS[x.honeypot] || '#50a0ff',
  }));

  return { grandTotal, hpTotals, hourlyData, splitData, topIpsData, topPortsData, allItems };
}

export default function Stats() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [hpFilter, setHpFilter] = useState('');
  const [runStatus, setRunStatus] = useState('idle'); // idle | running | warn

  useEffect(() => {
    fetchAllData()
      .then(d => setData(d))
      .catch(e => setError(e));
  }, []);

  const handleRunAnalysis = useCallback(async () => {
    setRunStatus('running');
    try {
      const res = await api.forensicRunNow();
      if (res && res.triggered) {
        setTimeout(() => setRunStatus('idle'), 8000);
      } else {
        setRunStatus('warn');
        setTimeout(() => setRunStatus('idle'), 3000);
      }
    } catch {
      setRunStatus('warn');
      setTimeout(() => setRunStatus('idle'), 3000);
    }
  }, []);

  const runLabel = runStatus === 'running' ? '⟳ Running…'
    : runStatus === 'warn' ? 'Already running'
    : 'Run Analysis';

  const badgeClass = error ? 'badge red' : data ? 'badge blue' : 'badge blue';
  const badgeText = error ? 'Error'
    : data ? `${data.grandTotal.toLocaleString('en-US')} honeypot events`
    : 'Loading…';

  return (
    <div style={{ width: '100%' }}>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>SOC Platform</div>
          <h2 className="page-title">Dash<span>board</span></h2>
          <div className="page-sub">Live data from Elasticsearch · interactive charts powered by Recharts.</div>
        </div>
        <div className="page-actions" style={{ gap: 8 }}>
          <select
            className="form-s"
            style={{ minWidth: 130 }}
            value={hpFilter}
            onChange={e => setHpFilter(e.target.value)}
          >
            <option value="">All honeypots</option>
            <option value="cowrie"> Cowrie</option>
            <option value="dionaea"> Dionaea</option>
            <option value="galah"> Galah</option>
          </select>
          <button
            className="btn btn-gh btn-sm"
            onClick={handleRunAnalysis}
            disabled={runStatus !== 'idle'}
            title="Trigger an immediate C3 forensic analysis run"
          >
            {runLabel}
          </button>
          <span className={badgeClass} style={{ fontSize: 12 }}>{badgeText}</span>
        </div>
      </div>

      {error && (
        <div className="alert err">Failed to load statistics: {error.message}</div>
      )}
      {!error && !data && (
        <div className="alert info" style={{ margin: '20px 0' }}>Loading statistics…</div>
      )}
      {data && (
        <StatsContent data={data} hpFilter={hpFilter} />
      )}
    </div>
  );
}

function StatsContent({ data, hpFilter }) {
  const { grandTotal, hpTotals, hourlyData, splitData, topIpsData, topPortsData, allItems } = data;

  const filteredItems = hpFilter ? allItems.filter(n => n.honeypot === hpFilter) : allItems;

  const filteredHourly = hpFilter
    ? hourlyData.map(row => ({ hour: row.hour, [hpFilter]: row[hpFilter] || 0 }))
    : hourlyData;

  const filteredSplit = hpFilter
    ? splitData.filter(d => d.honeypot === hpFilter)
    : splitData;

  const filteredIps = hpFilter
    ? topIpsData.filter(d => d.hp === hpFilter)
    : topIpsData;

  const filteredBySev = { critical: 0, high: 0, medium: 0, low: 0 };
  filteredItems.forEach(n => {
    const s = (n.severity || 'low').toLowerCase();
    if (s in filteredBySev) filteredBySev[s]++;
  });

  const activeHPs = hpFilter ? [hpFilter] : HONEYPOTS;
  const displayTotal = hpFilter ? (hpTotals[hpFilter] || 0) : grandTotal;

  return (
    <div>
      {/* KPI Row */}
      <div className="st-kpi-row">
        <div className="st-kpi" style={{ borderColor: 'var(--border2)' }}>
          <div className="st-kpi-label">Total Events</div>
          <div className="st-kpi-val" style={{ color: 'var(--gold)' }}>{displayTotal.toLocaleString('en-US')}</div>
          <div className="st-kpi-sub">{hpFilter ? SOURCE_META[hpFilter]?.label || hpFilter : 'all honeypots'}</div>
        </div>
        {['cowrie', 'dionaea', 'galah'].map(hp => (
          <div
            key={hp}
            className="st-kpi"
            style={{ borderColor: (COLORS[hp] || '#888') + '44', opacity: hpFilter && hpFilter !== hp ? 0.4 : 1 }}
          >
            <div className="st-kpi-label">{SOURCE_META[hp]?.label || hp}</div>
            <div className="st-kpi-val" style={{ color: COLORS[hp] }}>{(hpTotals[hp] || 0).toLocaleString('en-US')}</div>
            <div className="st-kpi-sub">events captured</div>
          </div>
        ))}
      </div>

      {/* Charts grid row 1: Hourly + Source split */}
      <div className="st-grid-2">
        {/* Hourly Activity */}
        <div className="st-chart-card">
          <div className="st-chart-title">Hourly Activity</div>
          <div className="st-chart-sub">Last 24 hours · events per honeypot</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={filteredHourly} margin={{ top: 4, right: 8, bottom: 0, left: -10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="hour" tick={AXIS_TICK} tickLine={false} axisLine={false} />
              <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Legend iconSize={8} wrapperStyle={{ fontSize: '11px', fontFamily: "'JetBrains Mono', monospace", paddingTop: '8px' }} />
              {activeHPs.map((hp, idx) => (
                <Bar
                  key={hp}
                  dataKey={hp}
                  stackId="a"
                  fill={COLORS[hp] + 'cc'}
                  stroke={COLORS[hp]}
                  strokeWidth={1}
                  name={SOURCE_META[hp]?.label || hp}
                  radius={idx === activeHPs.length - 1 ? [2, 2, 0, 0] : [0, 0, 0, 0]}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Source Distribution */}
        <div className="st-chart-card">
          <div className="st-chart-title">Source Distribution</div>
          <div className="st-chart-sub">Events per honeypot sensor</div>
          <div className="st-split-wrap">
            <PieChart width={180} height={180}>
              <Pie
                data={filteredSplit}
                dataKey="count"
                nameKey="name"
                cx={85}
                cy={85}
                innerRadius={54}
                outerRadius={80}
                paddingAngle={2}
              >
                {filteredSplit.map((entry, i) => (
                  <Cell key={i} fill={COLORS[entry.honeypot] + 'cc'} stroke={COLORS[entry.honeypot]} strokeWidth={1} />
                ))}
              </Pie>
              <Tooltip contentStyle={TOOLTIP_STYLE} />
            </PieChart>
            <div className="st-legend" style={{ flex: 1 }}>
              {filteredSplit.map((entry, i) => (
                <div key={i} className="st-legend-row">
                  <span className="st-legend-dot" style={{ background: COLORS[entry.honeypot] }} />
                  <span className="st-legend-label">{(SOURCE_META[entry.honeypot]?.icon || '') + ' ' + entry.name}</span>
                  <span className="st-legend-val">{entry.pct}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Charts grid row 2: Top IPs + Top Ports */}
      <div className="st-grid-2">
        {/* Top Source IPs */}
        <div className="st-chart-card">
          <div className="st-chart-title">Top Source IPs</div>
          <div className="st-chart-sub">
            Top 10 attacker IPs · {hpFilter ? SOURCE_META[hpFilter]?.label || hpFilter : 'all honeypots'}
          </div>
          {filteredIps.length === 0 ? (
            <div className="alert info" style={{ marginTop: 12 }}>No source IPs in recent events.</div>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(180, filteredIps.length * 28 + 20)}>
              <BarChart data={filteredIps} layout="vertical" margin={{ top: 0, right: 20, bottom: 0, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="ip"
                  width={150}
                  tick={{ ...AXIS_TICK, fill: '#e0e6f0' }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip contentStyle={TOOLTIP_STYLE} formatter={v => [v + ' events', 'Count']} />
                <Bar dataKey="count" name="Events" radius={[0, 3, 3, 0]} barSize={16}>
                  {filteredIps.map((entry, i) => (
                    <Cell key={i} fill={entry.color + 'bb'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Top Targeted Ports */}
        <div className="st-chart-card">
          <div className="st-chart-title">Top Targeted Ports</div>
          <div className="st-chart-sub">Top 10 destination ports · all honeypots</div>
          {topPortsData.length === 0 ? (
            <div className="alert info" style={{ marginTop: 12 }}>No port data available.</div>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(180, topPortsData.length * 28 + 20)}>
              <BarChart data={topPortsData} layout="vertical" margin={{ top: 0, right: 20, bottom: 0, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis
                  type="category"
                  dataKey="port"
                  width={90}
                  tick={{ ...AXIS_TICK, fill: '#e0e6f0' }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip contentStyle={TOOLTIP_STYLE} formatter={v => [v + ' hits', 'Count']} />
                <Bar dataKey="count" name="Hits" radius={[0, 3, 3, 0]} barSize={16}>
                  {topPortsData.map((entry, i) => (
                    <Cell key={i} fill={entry.color + 'bb'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
