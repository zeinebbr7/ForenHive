import { useState, useEffect } from 'react';
import {
  PieChart, Pie, Cell, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  ResponsiveContainer,
} from 'recharts';
import api from '../api';
import { fmt, evNormalize } from '../utils';

const TOOLTIP_STYLE = {
  backgroundColor: '#0d111e',
  border: '1px solid #1e2538',
  borderRadius: '6px',
  fontFamily: "'JetBrains Mono',monospace",
  fontSize: '11px',
  color: '#e0e6f0',
};

const HP_COLORS = { cowrie: '#8C1A2B', dionaea: '#ff5050', galah: '#b464ff', zeek: '#50a0ff' };

function actionIcon(action) {
  const a = (action || '').toLowerCase();
  if (a.includes('connect'))                          return '';
  if (a.includes('login.success'))                    return '';
  if (a.includes('login.fail') || a.includes('auth.fail')) return '';
  if (a.includes('login'))                            return '';
  if (a.includes('command'))                          return '';
  if (a.includes('closed') || a.includes('disconnect')) return '';
  return '';
}

function actionLabel(n) {
  const a = (n.event_action || '').toLowerCase();
  if (a.includes('session.connect'))  return 'SSH Connect';
  if (a.includes('login.success'))    return 'Login Success';
  if (a.includes('login.fail'))       return 'Login Failed';
  if (a.includes('login'))            return 'Login Attempt';
  if (a.includes('command.input'))    return 'Command';
  if (a.includes('session.closed'))   return 'Session Closed';
  if (a.includes('client.version'))   return 'SSH Client Version';
  if (a.includes('client.kex'))       return 'Key Negotiation';
  if (a.includes('client.var'))       return 'Terminal Variable';
  if (a.includes('client.size'))      return 'Terminal Size';
  if (a.includes('session.params'))   return 'Session Params';
  if (n.message) return n.message.slice(0, 80);
  return n.event_action || 'Event';
}

async function fetchAllSessions() {
  const pages = [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
  const results = await Promise.allSettled(pages.map(p => api.attacks({ page_size: 100, page: p })));
  const seen = new Set();
  const all = [];
  for (const r of results) {
    if (r.status !== 'fulfilled') continue;
    for (const item of ((r.value && r.value.items) || [])) {
      if (!seen.has(item.id)) { seen.add(item.id); all.push(item); }
    }
  }
  return all.map(evNormalize);
}

function buildSessions(normalized) {
  const map = {};
  normalized.forEach(n => {
    if (!n.session_id) return;
    if (!map[n.session_id]) {
      map[n.session_id] = { id: n.session_id, honeypot: n.honeypot, source_ip: n.source_ip, events: [], commands: [], credentials: [], first_ts: n.timestamp, last_ts: n.timestamp };
    }
    const s = map[n.session_id];
    s.events.push(n);
    if (n.timestamp < s.first_ts) s.first_ts = n.timestamp;
    if (n.timestamp > s.last_ts)  s.last_ts  = n.timestamp;
    if (n.command)  s.commands.push(n.command);
    if (n.username) s.credentials.push({ user: n.username, pass: n.password });
  });
  return Object.values(map).sort((a, b) => (b.first_ts > a.first_ts ? 1 : -1));
}

// ── Summary charts ────────────────────────────────────────────────────────────
function SessionCharts({ sessions }) {
  const byHp = {};
  sessions.forEach(s => { byHp[s.honeypot] = (byHp[s.honeypot] || 0) + 1; });
  const hpData = Object.entries(byHp).map(([hp, n]) => ({
    name: hp.charAt(0).toUpperCase() + hp.slice(1), hp, value: n,
  }));

  const successCount = sessions.filter(s => s.events.some(e => (e.event_action || '').includes('login.success'))).length;
  const outcomeData = [
    { name: 'Login Success', value: successCount, color: '#ff5050' },
    { name: 'Blocked', value: sessions.length - successCount, color: '#2dd4bf' },
  ];

  const cmdBuckets = [
    { label: 'No cmds', count: 0, color: '#8892a4' },
    { label: '1–5 cmds', count: 0, color: '#f59e0b' },
    { label: '6–20 cmds', count: 0, color: '#ff9933' },
    { label: '20+ cmds', count: 0, color: '#ff5050' },
  ];
  sessions.forEach(s => {
    const n = s.commands.length;
    if (n === 0) cmdBuckets[0].count++;
    else if (n <= 5) cmdBuckets[1].count++;
    else if (n <= 20) cmdBuckets[2].count++;
    else cmdBuckets[3].count++;
  });

  const cardStyle = {
    background: 'var(--card-bg)', border: '1px solid var(--border)',
    borderRadius: 10, padding: '14px 18px',
  };
  const titleStyle = { fontFamily: "'Rajdhani',sans-serif", fontSize: 14, fontWeight: 700, color: 'var(--text1)', marginBottom: 2 };
  const subStyle = { fontSize: 10, color: 'var(--text3)', fontFamily: "'JetBrains Mono',monospace", marginBottom: 10 };

  function DonutCard({ title, sub, data, colorFn }) {
    return (
      <div style={cardStyle}>
        <div style={titleStyle}>{title}</div>
        <div style={subStyle}>{sub}</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <PieChart width={120} height={120}>
            <Pie data={data} dataKey="value" nameKey="name" cx={56} cy={56} innerRadius={33} outerRadius={52} paddingAngle={2}>
              {data.map((e, i) => (
                <Cell key={i} fill={colorFn(e, i) + 'cc'} stroke={colorFn(e, i)} strokeWidth={1} />
              ))}
            </Pie>
            <Tooltip contentStyle={TOOLTIP_STYLE} />
          </PieChart>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {data.map((e, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: colorFn(e, i), flexShrink: 0, display: 'inline-block' }} />
                <span style={{ fontSize: 11, flex: 1 }}>{e.name}</span>
                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--text2)' }}>{e.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 14 }}>
      <DonutCard title="By Honeypot" sub="Sessions per sensor" data={hpData} colorFn={e => HP_COLORS[e.hp] || '#888'} />
      <DonutCard title="Login Outcomes" sub="Success vs blocked" data={outcomeData} colorFn={e => e.color} />
      <div style={cardStyle}>
        <div style={titleStyle}>Command Activity</div>
        <div style={subStyle}>Shell commands per session</div>
        <ResponsiveContainer width="100%" height={100}>
          <BarChart data={cmdBuckets} margin={{ top: 0, right: 8, bottom: 0, left: -20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
            <XAxis dataKey="label" tick={{ fontSize: 9, fill: '#8892a4', fontFamily: "'JetBrains Mono',monospace" }} tickLine={false} axisLine={false} />
            <YAxis tick={{ fontSize: 10, fill: '#8892a4', fontFamily: "'JetBrains Mono',monospace" }} tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip contentStyle={TOOLTIP_STYLE} />
            <Bar dataKey="count" name="Sessions" radius={[3, 3, 0, 0]} barSize={28}>
              {cmdBuckets.map((e, i) => <Cell key={i} fill={e.color + 'bb'} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ── Session card ──────────────────────────────────────────────────────────────
function SessionCard({ s }) {
  const [open, setOpen] = useState(false);
  const [pdfState, setPdfState] = useState({ loading: false, label: ' PDF' });
  const [previewLoading, setPreviewLoading] = useState(false);

  const dur_s = Math.round((new Date(s.last_ts) - new Date(s.first_ts)) / 1000);
  const uniqCreds = [...new Map(s.credentials.map(c => [c.user + '|' + c.pass, c])).values()];
  const isSuccess = s.events.some(n => (n.event_action || '').includes('login.success'));

  async function handlePdf(e) {
    e.stopPropagation();
    setPdfState({ loading: true, label: ' Generating…' });
    try {
      const r = await api.forensicReportDownload(s.id);
      setPdfState({ loading: false, label: ' Downloaded' });
      setTimeout(() => setPdfState({ loading: false, label: ' PDF' }), 2500);
    } catch (err) {
      setPdfState({ loading: false, label: ' Error' });
      alert('PDF error: ' + err.message);
      setTimeout(() => setPdfState({ loading: false, label: ' PDF' }), 2500);
    }
  }

  async function handlePreview(e) {
    e.stopPropagation();
    setPreviewLoading(true);
    try {
      const tok = api.token();
      const res = await fetch(api.forensicReportPreviewUrl(s.id), { headers: tok ? { Authorization: 'Bearer ' + tok } : {} });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const html = await res.text();
      const w = window.open('', '_blank');
      w.document.open(); w.document.write(html); w.document.close();
    } catch (err) {
      alert('Preview unavailable: ' + err.message);
    } finally {
      setPreviewLoading(false);
    }
  }

  return (
    <div className="sess-card" style={{ background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 10, marginBottom: 14, overflow: 'hidden' }}>
      <div
        className="sess-head"
        style={{ display: 'grid', gridTemplateColumns: '150px 1fr auto auto auto', alignItems: 'center', gap: 12, padding: '14px 18px', cursor: 'pointer' }}
        onClick={() => setOpen(o => !o)}
      >
        <div>
          <div className="sess-ip" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 14, fontWeight: 700, color: 'var(--text1)' }}>{s.source_ip || '—'}</div>
          <div className="sess-id" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>{s.id}</div>
        </div>
        <div className="flex gap-8" style={{ flexWrap: 'wrap', alignItems: 'center' }}>
          {isSuccess
            ? <span className="badge red"> Login Success</span>
            : <span className="badge teal"> Blocked</span>}
          {s.commands.length > 0 && <span className="badge gold"> {s.commands.length} cmd{s.commands.length > 1 ? 's' : ''}</span>}
          {uniqCreds.length > 0 && <span className="badge purple"> {uniqCreds.length} cred{uniqCreds.length > 1 ? 's' : ''}</span>}
          <span className="badge blue">{s.events.length} events</span>
        </div>
        <div className="sess-times" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--text3)', textAlign: 'right' }}>
          <div>{fmt.date(s.first_ts)}</div>
          <div style={{ color: 'var(--text3)' }}> {fmt.dur(dur_s)}</div>
        </div>
        <div className="flex gap-8" style={{ paddingLeft: 8 }}>
          <button className="btn btn-gold btn-sm" onClick={handlePdf} disabled={pdfState.loading} title="Generate PDF report">{pdfState.label}</button>
          <button className="btn btn-gh btn-sm" onClick={handlePreview} disabled={previewLoading} title="Preview (HTML)">Preview</button>
        </div>
        <span style={{ fontSize: 18, color: 'var(--text3)', paddingLeft: 8 }}>{open ? '▼' : '▶'}</span>
      </div>

      {open && (
        <div className="sess-body open" style={{ borderTop: '1px solid var(--border)' }}>
          {uniqCreds.length > 0 && (
            <>
              <div className="sect-label" style={{ fontSize: 10, color: 'var(--text3)', fontFamily: "'JetBrains Mono',monospace", padding: '8px 18px 4px', letterSpacing: '.06em' }}>TESTED CREDENTIALS</div>
              <div className="flex gap-8" style={{ flexWrap: 'wrap', padding: '0 18px 12px' }}>
                {uniqCreds.map((c, i) => (
                  <span key={i} className="badge red" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11 }}>{c.user} / {c.pass || '?'}</span>
                ))}
              </div>
            </>
          )}
          {s.commands.length > 0 && (
            <>
              <div className="sect-label" style={{ fontSize: 10, color: 'var(--text3)', fontFamily: "'JetBrains Mono',monospace", padding: '8px 18px 4px', letterSpacing: '.06em', borderTop: '1px solid var(--border)' }}>EXECUTED COMMANDS</div>
              <div style={{ padding: '0 18px 12px' }}>
                {s.commands.map((cmd, i) => (
                  <div key={i} className="ev-line-cmd" style={{ display: 'block', marginBottom: 4, fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: 'var(--gold)', background: 'rgba(140,26,43,.08)', borderLeft: '2px solid var(--gold)', padding: '2px 8px', borderRadius: '0 4px 4px 0' }}>$ {cmd}</div>
                ))}
              </div>
            </>
          )}
          <div className="sect-label" style={{ fontSize: 10, color: 'var(--text3)', fontFamily: "'JetBrains Mono',monospace", padding: '8px 18px 4px', letterSpacing: '.06em', borderTop: '1px solid var(--border)' }}>TIMELINE</div>
          {s.events.map((n, i) => (
            <div key={i} className="ev-line" style={{ display: 'grid', gridTemplateColumns: '72px 26px 1fr', alignItems: 'start', gap: 8, padding: '6px 18px', borderBottom: '1px solid rgba(255,255,255,.03)' }}>
              <div className="ev-line-time" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--text3)', paddingTop: 2 }}>{fmt.time(n.timestamp)}</div>
              <div className="ev-line-icon" style={{ fontSize: 13 }}>{actionIcon(n.event_action)}</div>
              <div className="ev-line-body" style={{ minWidth: 0, fontSize: 12, color: 'var(--text1)' }}>
                {actionLabel(n)}
                {n.command && (
                  <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: 'var(--gold)', background: 'rgba(140,26,43,.08)', borderLeft: '2px solid var(--gold)', padding: '2px 8px', marginTop: 3, borderRadius: '0 4px 4px 0' }}>$ {n.command}</div>
                )}
                {(n.username && !n.command) && (
                  <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 11, color: 'var(--red2)', background: 'rgba(255,80,80,.07)', borderLeft: '2px solid var(--red2)', padding: '2px 8px', marginTop: 3, borderRadius: '0 4px 4px 0' }}>
                    {n.username}{n.password ? ' / ' + n.password : ''}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function Sessions() {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    fetchAllSessions()
      .then(normalized => {
        setSessions(buildSessions(normalized));
        setLoading(false);
      })
      .catch(e => {
        setError(e.message);
        setLoading(false);
      });
  }, []);

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}> Sessions</div>
          <h2 className="page-title">Attack <span>Sessions</span></h2>
          <div className="page-sub">
            Grouped by Cowrie SSH <span className="mono">session_id</span> · <span>{loading ? '—' : sessions.length}</span> sessions.
          </div>
        </div>
      </div>

      {loading && <div className="alert info"> Searching last 7 days…</div>}
      {error && <div className="alert err">{error}</div>}

      {!loading && !error && (
        <>
          {sessions.length > 0 && <SessionCharts sessions={sessions} />}
          {sessions.length === 0 ? (
            <div className="alert info">
              <b>No sessions with session_id found in the last 7 days.</b><br />
              Sessions appear when Cowrie SSH records a <span className="mono">session_id</span> in its logs.
              Zeek and Dionaea do not create named sessions.
            </div>
          ) : (
            sessions.map((s, i) => <SessionCard key={s.id || i} s={s} defaultOpen={i === 0} />)
          )}
        </>
      )}
    </>
  );
}
