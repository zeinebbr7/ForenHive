import React, { useState, useEffect, useCallback } from 'react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis,
  Tooltip, PieChart, Pie, Cell,
} from 'recharts';
import api from '../api';
import { SOURCE_META, HONEYPOTS, SENSORS } from '../constants';
import { fmt, esc, evNormalize } from '../utils';
import { useModal } from '../contexts/ModalContext';

const TOOLTIP_STYLE = {
  backgroundColor: '#0d111e',
  border: '1px solid #1e2538',
  borderRadius: '6px',
  fontFamily: "'JetBrains Mono', monospace",
  fontSize: '11px',
  color: '#e0e6f0',
};
const AXIS_TICK = { fontSize: 10, fill: '#8892a4', fontFamily: "'JetBrains Mono', monospace" };
const HP_COLORS = { cowrie: '#8C1A2B', dionaea: '#ff5050', galah: '#b464ff', zeek: '#50a0ff' };

export default function Dashboard() {
  const { openDrawer, closeDrawer, openModal, closeModal } = useModal();

  const [kpis, setKpis] = useState({
    total: '—', totalDelta: 'loading…',
    hour: '—', hourDelta: '—',
    hps: '—', hpsDelta: '—',
    sens: '—', sensDelta: '—',
    srcCount: '—',
  });
  const [donutData, setDonutData] = useState([]);
  const [last12, setLast12] = useState([]);
  const [logs, setLogs] = useState([]);
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const REFRESH_INTERVAL = 30000;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [split, recent, hourly] = await Promise.all([
        api.geoSplit(),
        api.attacks({ limit: 20 }),
        api.statsHourly(),
      ]);

      const total = (recent && recent.total) || 0;
      const hourlyArr = Array.isArray(hourly) ? hourly : (hourly?.items || []);
      const lastEntry = hourlyArr[hourlyArr.length - 1];
      const splitArr = (split && split.split) || [];
      const hpActive = splitArr.filter(x => HONEYPOTS.includes(x.honeypot) && x.count > 0);
      const sensActive = splitArr.filter(x => SENSORS.includes(x.honeypot) && x.count > 0);

      setKpis({
        total: fmt.num(total),
        totalDelta: `▲ ${total.toLocaleString('en-US')} indexed events`,
        hour: lastEntry ? fmt.num(lastEntry.count) : '0',
        hourDelta: lastEntry ? `${Object.keys(lastEntry.by_honeypot || {}).length} sources` : 'no recent activity',
        hps: hpActive.length + '/' + HONEYPOTS.length,
        hpsDelta: hpActive.map(x => x.honeypot).join(' · ') || 'none',
        sens: sensActive.length + '/' + SENSORS.length,
        sensDelta: sensActive.map(x => x.honeypot).join(' · ') || 'none',
        srcCount: hpActive.length + sensActive.length,
      });

      const donut = splitArr
        .map(x => ({
          name: (SOURCE_META[x.honeypot] || { label: x.honeypot }).label,
          hp: x.honeypot,
          count: x.count,
        }))
        .filter(d => d.count > 0);
      setDonutData(donut);

      const last12h = (Array.isArray(hourly) ? hourly : []).slice(-12).map(e => ({
        h: new Date(e.hour).getUTCHours().toString().padStart(2, '0') + ':00',
        cowrie:  (e.by_honeypot || {}).cowrie  || 0,
        dionaea: (e.by_honeypot || {}).dionaea || 0,
        galah:   (e.by_honeypot || {}).galah   || 0,
      }));
      setLast12(last12h);

      const items = (recent && recent.items) || [];
      setLogs(items);
      setEvents(items);
    } catch (e) {
      setError(e.message || 'Failed to load');
    } finally {
      setLoading(false);
      setLastUpdated(new Date());
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, REFRESH_INTERVAL);
    return () => clearInterval(timer);
  }, [load]);

  const handleEventClick = useCallback(async (ev) => {
    try {
      const raw = await api.attack(ev.id);
      const n = evNormalize(raw);
      openDrawer(
        <div>
          <div className="drawer-h">
            <div>
              <div className="card-t">Event {n.id.slice(0, 12)}…</div>
              <div className="card-sub">{fmt.date(n.timestamp)}</div>
            </div>
            <button className="drawer-close" onClick={closeDrawer} />
          </div>
          <div className="drawer-b">
            <div className="flex gap-8 mb-12" style={{ flexWrap: 'wrap' }}>
              <span className="badge gold">{n.honeypot}</span>
              <span className={`badge ${fmt.sevToClass(n.severity) === 'crit' || fmt.sevToClass(n.severity) === 'hi' ? 'red' : 'gold'}`}>
                {n.severity}
              </span>
              {n.source_ip && (
                <span className="mono">{n.source_ip}{n.source_port ? ':' + n.source_port : ''}</span>
              )}
              {n.dest_port && <span className="tag">→ port {n.dest_port}</span>}
            </div>
            {n.command && (
              <>
                <div className="card-sub mb-12">Command</div>
                <pre className="pre">{n.command}</pre>
              </>
            )}
            {n.http_path && (
              <>
                <div className="card-sub mb-12">HTTP</div>
                <pre className="pre">{n.http_method || 'GET'} {n.http_path}</pre>
              </>
            )}
            <div className="card-sub mb-12" style={{ marginTop: 16 }}>Raw document</div>
            <pre className="pre" style={{ maxHeight: 320, overflow: 'auto' }}>
              {JSON.stringify(n.raw, null, 2)}
            </pre>
          </div>
        </div>
      );
    } catch (ex) {
      openModal(
        <div>
          <div className="alert err">{ex.message}</div>
          <div className="flex gap-8" style={{ justifyContent: 'flex-end', marginTop: 12 }}>
            <button className="btn btn-gold btn-sm" onClick={closeModal}>OK</button>
          </div>
        </div>
      );
    }
  }, [openDrawer, closeDrawer, openModal, closeModal]);

  return (
    <div>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>Overview</div>
          <h2 className="page-title">Dash<span>board</span></h2>
          <div className="page-sub">
            Real-time monitoring · <span>{kpis.srcCount}</span> active sources
            {lastUpdated && <> · updated {lastUpdated.toLocaleTimeString()}</>}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={load} disabled={loading}>
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="kpi-grid">
        <div className="kpi g">
          <div className="kpi-label">Total Events</div>
          <div className="kpi-val">{kpis.total}</div>
          <div className="kpi-delta up">{kpis.totalDelta}</div>
        </div>
        <div className="kpi r">
          <div className="kpi-label">Last Hour</div>
          <div className="kpi-val">{kpis.hour}</div>
          <div className="kpi-delta">{kpis.hourDelta}</div>
        </div>
        <div className="kpi b">
          <div className="kpi-label">Active Honeypots</div>
          <div className="kpi-val">{kpis.hps}</div>
          <div className="kpi-delta">{kpis.hpsDelta}</div>
        </div>
        <div className="kpi p">
          <div className="kpi-label">NDR Sensors</div>
          <div className="kpi-val">{kpis.sens}</div>
          <div className="kpi-delta">{kpis.sensDelta}</div>
        </div>
      </div>

      <div className="grid-2 mb-20">
        <div className="card">
          <div className="card-h">
            <div className="card-t">Source Distribution</div>
            <div className="card-sub">honeypots + sensors</div>
          </div>
          {loading ? (
            <div className="alert info">Loading…</div>
          ) : (
            <DashCharts donutData={donutData} last12={last12} />
          )}
        </div>

        <div className="card">
          <div className="card-h">
            <div className="card-t">Live logs</div>
            <div className="card-sub"><span className="dot warn" />Last 20 events</div>
          </div>
          <div className="scroll-y" style={{ maxHeight: 340 }}>
            {loading ? (
              <div className="alert info">Loading…</div>
            ) : logs.length === 0 ? (
              <div className="alert info">No events.</div>
            ) : (
              logs.map((raw, i) => {
                const ev = evNormalize(raw);
                const meta = SOURCE_META[ev.honeypot] || { label: ev.honeypot, icon: '' };
                return (
                  <div key={ev.id || i} className="log-row">
                    <div className="log-t">{fmt.time(ev.timestamp)}</div>
                    <div className={`log-s ${ev.honeypot}`}>{meta.label}</div>
                    <div className="log-ip">{ev.source_ip || '—'}</div>
                    <div className="log-m">
                      {(ev.command || ev.http_path || ev.protocol || '—').slice(0, 80)}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-h">
          <div className="card-t">Latest Events</div>
          <div className="card-sub">click to view details</div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Source IP</th>
                <th>Port</th>
                <th>Severity</th>
                <th>Type</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7}><div className="alert info">Loading…</div></td></tr>
              ) : error ? (
                <tr><td colSpan={7}><div className="alert err">Error: {error}</div></td></tr>
              ) : events.length === 0 ? (
                <tr><td colSpan={7}><div className="alert info">No events.</div></td></tr>
              ) : (
                events.map((raw, i) => {
                  const ev = evNormalize(raw);
                  const meta = SOURCE_META[ev.honeypot] || { label: ev.honeypot, icon: '' };
                  const sevCls = fmt.sevToClass(ev.severity);
                  return (
                    <tr key={ev.id || i} style={{ cursor: 'pointer' }} onClick={() => handleEventClick(ev)}>
                      <td className="mono" style={{ fontSize: 11 }}>{fmt.time(ev.timestamp)}</td>
                      <td>
                        <span className={`badge ${meta.kind === 'sensor' ? 'blue' : 'gold'}`}>
                          {meta.label}
                        </span>
                      </td>
                      <td className="mono">{ev.source_ip || '—'}</td>
                      <td className="mono">{ev.dest_port || '—'}</td>
                      <td><span className={`score ${sevCls}`}>{ev.severity || 'low'}</span></td>
                      <td className="mono" style={{ fontSize: 11 }}>{ev.protocol || ev.event_action || '—'}</td>
                      <td><button className="btn btn-out btn-sm">View</button></td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function DashCharts({ donutData, last12 }) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 14 }}>
        <PieChart width={140} height={140}>
          <Pie
            data={donutData}
            dataKey="count"
            nameKey="name"
            cx={65}
            cy={65}
            innerRadius={40}
            outerRadius={60}
            paddingAngle={2}
          >
            {donutData.map((e, i) => (
              <Cell
                key={i}
                fill={(HP_COLORS[e.hp] || '#888') + 'cc'}
                stroke={HP_COLORS[e.hp] || '#888'}
                strokeWidth={1}
              />
            ))}
          </Pie>
          <Tooltip contentStyle={TOOLTIP_STYLE} />
        </PieChart>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 7, flex: 1 }}>
          {donutData.map((e, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{
                width: 9, height: 9, borderRadius: '50%',
                background: HP_COLORS[e.hp] || '#888',
                flexShrink: 0, display: 'inline-block',
              }} />
              <span style={{ fontSize: 12, flex: 1 }}>
                {(SOURCE_META[e.hp] || { icon: '' }).icon} {(SOURCE_META[e.hp] || { label: e.hp }).label}
              </span>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: 'var(--text2)' }}>
                {e.count.toLocaleString('en-US')}
              </span>
            </div>
          ))}
        </div>
      </div>
      {last12.length > 0 && (
        <div>
          <div style={{
            fontSize: 10, color: 'var(--text3)', fontFamily: "'JetBrains Mono', monospace",
            marginBottom: 4, letterSpacing: '.06em', textTransform: 'uppercase',
          }}>
            Hourly Activity (last 12h)
          </div>
          <ResponsiveContainer width="100%" height={90}>
            <BarChart data={last12} margin={{ top: 0, right: 4, bottom: 0, left: -28 }}>
              <XAxis dataKey="h" tick={AXIS_TICK} tickLine={false} axisLine={false} />
              <YAxis tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="cowrie"  stackId="a" fill="#8C1A2Bcc" name="Cowrie" />
              <Bar dataKey="dionaea" stackId="a" fill="#ff5050cc" name="Dionaea" />
              <Bar dataKey="galah"   stackId="a" fill="#b464ffcc" name="Galah" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
