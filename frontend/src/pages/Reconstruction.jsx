import React, { useState, useEffect, useMemo, useCallback, useRef, useDeferredValue, memo } from 'react';
import api from '../api';
import { fmt, flag } from '../utils';

const KC = ['Recon','Weapon','Delivery','Exploit','Install','C&C','Lateral','Actions'];

const HONEYPOTS = ['', 'cowrie', 'dionaea', 'galah', 'zeek'];
const SORT_OPTIONS = [
  ['date',  'Most recent'],
  ['risk',  'Highest risk'],
  ['stage', 'Furthest kill-chain'],
];

// Hoisted style objects — stable references, no per-render re-allocation.
const S = {
  searchRow:    { display:'flex', gap:'8px', alignItems:'center', marginBottom:'12px' },
  filterRow:    { display:'flex', justifyContent:'space-between', alignItems:'center', gap:'12px', flexWrap:'wrap', marginBottom:'8px' },
  filterGroup:  { display:'flex', gap:'6px', alignItems:'center', flexWrap:'wrap' },
  filterLabel:  { fontFamily:"'JetBrains Mono',monospace", fontSize:'10px', color:'var(--text3)', textTransform:'uppercase', letterSpacing:'1px', marginRight:'4px' },
  sortSelect:   { width:'auto', minWidth:'160px', padding:'6px 28px 6px 10px', fontSize:'11px' },
  sessionGroup: { marginTop:'14px' },
  sessionCount: { color:'var(--text3)', fontSize:'11px', textTransform:'none', letterSpacing:0 },
  panelHead:    { paddingBottom:'12px' },
  threatHead:   { margin:'18px 0 14px' },
  threatTitle:  { fontFamily:"'Rajdhani',sans-serif", fontSize:'16px', fontWeight:700, color:'var(--gold)', letterSpacing:'.5px' },
  threatSub:    { marginTop:'2px' },
  abuseScore:   col => ({ fontFamily:"'Rajdhani',sans-serif", fontSize:'38px', fontWeight:700, color:col, lineHeight:1 }),
  abuseScoreRow:{ display:'flex', alignItems:'center', gap:'12px', marginBottom:'12px' },
  abuseScoreL:  { fontFamily:"'JetBrains Mono',monospace", fontSize:'10px', color:'var(--text3)', textTransform:'uppercase' },
  abuseScoreS:  { fontSize:'11px', color:'var(--text2)', marginTop:'3px' },
  vtMetrics:    { margin:'0 0 14px' },
  yaraMetaCell: { fontSize:'11px' },
  mitreLink:    { color:'var(--gold)' },
  actionsRow:   { display:'flex', gap:'8px', flexWrap:'wrap' },
  alertM:       { margin:0, fontSize:'12px' },
  chipsTight:   { marginTop:0 },
  chipsBlock:   { marginTop:'10px' },
  chipsMitre:   { marginTop:'14px' },
  mitreSubLbl:  { marginBottom:'6px' },
  vtMetricVal:  col => ({ color: col }),
  refreshBtn:   { marginLeft:'auto' },

  // Compact summary card styles.
  sumLine:      { display:'flex', alignItems:'center', gap:'10px', flexWrap:'wrap', fontSize:'13px', color:'var(--text)', fontFamily:"'JetBrains Mono',monospace", marginBottom:'6px' },
  sumLineSub:   { display:'flex', alignItems:'center', gap:'8px', flexWrap:'wrap', fontSize:'11px', color:'var(--text3)', fontFamily:"'JetBrains Mono',monospace", marginBottom:'8px' },
  sumLabel:     { color:'var(--text3)', fontSize:'10px', textTransform:'uppercase', letterSpacing:'.5px' },
  bigVal:       col => ({ fontFamily:"'Rajdhani',sans-serif", fontSize:'34px', fontWeight:700, color:col, lineHeight:1 }),
  bigBar:       { flex:1, minWidth:'140px', height:'8px', background:'var(--bg3)', border:'1px solid var(--border)', borderRadius:'5px', overflow:'hidden' },
  bigBarFill:   (col, pct) => ({ width:`${pct}%`, height:'100%', background:col }),
  inlineRow:    { display:'flex', alignItems:'center', gap:'12px', flexWrap:'wrap' },

  // Session parameters table styles.
  paramSecLbl:  { fontSize:'10px', color:'var(--gold)', textTransform:'uppercase', letterSpacing:'1px', marginBottom:'10px', fontFamily:"'JetBrains Mono',monospace", paddingBottom:'4px', borderBottom:'1px solid var(--border)' },
  paramRow:     { display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:'12px', padding:'5px 0', borderBottom:'1px solid color-mix(in srgb, var(--border) 50%, transparent)' },
  paramKey:     { fontSize:'11px', color:'var(--text3)', whiteSpace:'nowrap', flexShrink:0 },
  paramVal:     { fontSize:'12px', color:'var(--text)', fontFamily:"'JetBrains Mono',monospace", textAlign:'right', wordBreak:'break-all' },
  paramDivider: { borderTop:'1px solid var(--border)', marginTop:'14px', paddingTop:'14px' },
};

function riskColor(rs) {
  if (rs >= 80) return 'var(--red2)';
  if (rs >= 50) return 'var(--gold)';
  if (rs >= 20) return '#a98a3a';
  return 'var(--text3)';
}

function riskLabel(rs) {
  if (rs >= 80) return 'CRITICAL';
  if (rs >= 50) return 'HIGH';
  if (rs >= 20) return 'MEDIUM';
  return 'LOW';
}

function attackPath(s) {
  const hits = Array.isArray(s.honeypots_hit) && s.honeypots_hit.length
    ? s.honeypots_hit
    : [s.honeypot_type].filter(Boolean);
  return ['Zeek', ...hits.map(h => h.charAt(0).toUpperCase() + h.slice(1))];
}

function sessionDuration(s) {
  if (!s.started_at || !s.ended_at) return '—';
  const ms = new Date(s.ended_at) - new Date(s.started_at);
  return ms > 0 ? `${(ms / 1000).toFixed(1)} s` : '—';
}

const MetricTiles = memo(function MetricTiles({ s }) {
  const tiles = useMemo(() => {
    const out = [];
    const push = (lbl, val, cls = '') => {
      if (val === null || val === undefined || val === '') return;
      if (val === 0 && !['Risk Score','Login Attempts'].includes(lbl)) return;
      out.push({ lbl, val, cls });
    };
    const rs = s.risk_score || 0;
    push('Risk Score', rs, rs >= 70 ? 'crit' : rs >= 40 ? 'warn' : '');
    push('Risk Level', s.risk_level);
    push('Confidence', s.confidence);
    push('Honeypots Hit', s.honeypot_count);
    push('Sub-sessions', s.sessions_count);
    push('Login Attempts', s.login_attempts);
    push('Successful Auth', s.success_count, (s.success_count || 0) > 0 ? 'crit' : '');
    if (s.attack_velocity) push('Velocity (ev/s)', Number(s.attack_velocity).toFixed(2));
    return out;
  }, [s]);

  if (!tiles.length) return null;
  return (
    <div className="rc-metrics">
      {tiles.map((t, i) => (
        <div key={i} className={`rc-metric ${t.cls}`}>
          <div className="lbl">{t.lbl}</div>
          <div className="val">{String(t.val)}</div>
        </div>
      ))}
    </div>
  );
});

function isEmpty(v) {
  return v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0);
}

// Legacy KVTable kept for backwards-compat — same as before, filters empties.
const KVTable = memo(function KVTable({ rows }) {
  const cells = useMemo(() => rows.filter(([_, v]) => !isEmpty(v)), [rows]);
  if (!cells.length) return <div className="card-sub">No data.</div>;
  return (
    <table className="tbl">
      <tbody>
        {cells.map(([k, v], i) => (
          <tr key={i}>
            <th style={{width:'170px'}}>{k}</th>
            <td>
              {Array.isArray(v) ? (
                <div className="rc-chips" style={S.chipsTight}>
                  {v.map((x, j) => <span key={j} className="rc-chip">{String(x)}</span>)}
                </div>
              ) : typeof v === 'boolean' ? (
                v ? <span className="rc-chip red">yes</span> : <span className="rc-chip">no</span>
              ) : (
                <span className="mono">{String(v)}</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
});

const SrcBadge = memo(function SrcBadge({ src }) {
  if (src === 'live')  return <span className="rc-src-badge live">LIVE</span>;
  if (src === 'cache') return <span className="rc-src-badge cache">CACHED</span>;
  return <span className="rc-src-badge none">NO DATA</span>;
});

const PanelHead = memo(function PanelHead({ title, sub, badge }) {
  return (
    <div className="card-h" style={S.panelHead}>
      <div>
        <div className="card-t">{title}</div>
        {sub && <div className="card-sub">{sub}</div>}
      </div>
      {badge && <div>{badge}</div>}
    </div>
  );
});

const Enrichment = memo(function Enrichment({ data, s }) {
  if (!data) return null;
  const ip = data.iplocate || {};
  const a  = data.abuseipdb || {};
  const sh = data.shodan || {};
  const w  = data.whois || {};
  const vt = data.virustotal;

  const abScore = a.abuse_score != null ? a.abuse_score : null;
  const abColor = abScore >= 50 ? 'var(--red2)' : abScore >= 20 ? 'var(--gold)' : 'var(--text2)';

  const privacyFlags = [
    ip.is_tor      && ['TOR',     'red'],
    ip.is_vpn      && ['VPN',     'red'],
    ip.is_proxy    && ['PROXY',   'red'],
    ip.is_hosting  && ['HOSTING', ''],
    ip.is_datacenter && ['DC',    ''],
    ip.is_bogon    && ['BOGON',   'red'],
  ].filter(Boolean);

  const hasIp    = !!(ip.country || ip.city || ip.asn || ip.as_org || privacyFlags.length);
  const hasAbuse = abScore != null || a.usage_type || a.isp || a.domain || a.total_reports != null;
  const hasSh    = !!(sh.ports?.length || sh.vulns?.length || sh.tags?.length || sh.hostnames?.length);
  const hasWhois = !!(w.organization || w.registrar || w.net_range || w.abuse_email);
  const hasVt    = !!vt;
  const hasFiles = data.captured_files?.length > 0;
  const hasYara  = data.yara?.length > 0;
  const hasMitre = data.mitre?.length > 0;

  const vtRatio = hasVt ? `${vt.malicious || 0}/${(vt.malicious || 0) + (vt.suspicious || 0) + (vt.harmless || 0) + (vt.undetected || 0)}` : null;
  const vtColor = hasVt && vt.malicious >= 5 ? 'var(--red2)' : hasVt && vt.malicious > 0 ? 'var(--gold)' : 'var(--text2)';

  const noData = { fontSize:'12px', color:'var(--text3)', fontStyle:'italic' };

  return (
    <>
      <div style={S.threatHead}>
        <div style={S.threatTitle}>Threat Intelligence</div>
      </div>

      {/* Row 1: IPLocate · AbuseIPDB · Shodan — always shown */}
      <div className="rc-3col mb-20">
        <div className="card">
          <PanelHead title="IPLocate" badge={<SrcBadge src={hasIp ? (ip._source || 'live') : 'none'} />} />
          {hasIp ? (
            <>
              <div style={S.sumLine}>
                {ip.country_iso && <span>{flag(ip.country_iso)}</span>}
                <span>{ip.country || '—'}{ip.city ? ` · ${ip.city}` : ''}</span>
              </div>
              {(ip.asn || ip.as_org) && (
                <div style={S.sumLineSub}>
                  {ip.asn && <span>AS{ip.asn}</span>}
                  {ip.as_org && <span>· {ip.as_org}</span>}
                </div>
              )}
              {privacyFlags.length > 0 && (
                <div className="rc-chips" style={S.chipsTight}>
                  {privacyFlags.map(([label, cls], i) => <span key={i} className={`rc-chip ${cls}`}>{label}</span>)}
                </div>
              )}
            </>
          ) : <div style={noData}>No geolocation data available</div>}
        </div>

        <div className="card">
          <PanelHead title="AbuseIPDB" badge={<SrcBadge src={hasAbuse ? (a._source || 'live') : 'none'} />} />
          {hasAbuse ? (
            <>
              {abScore != null && (
                <div style={{...S.inlineRow, marginBottom:'8px'}}>
                  <div style={S.bigVal(abColor)}>{abScore}</div>
                  <div style={S.bigBar}><div style={S.bigBarFill(abColor, Math.max(0, Math.min(100, abScore)))} /></div>
                </div>
              )}
              <div style={S.sumLineSub}>
                {a.total_reports != null && <span>{fmt.num(a.total_reports)} reports</span>}
                {a.usage_type && <span>· {a.usage_type}</span>}
                {a.isp && <span>· {a.isp}</span>}
                {a.domain && <span>· {a.domain}</span>}
              </div>
            </>
          ) : <div style={noData}>No abuse reports found</div>}
        </div>

        <div className="card">
          <PanelHead title="Shodan" badge={<SrcBadge src={hasSh ? (sh._source || 'cache') : 'none'} />} />
          {hasSh ? (
            <>
              {sh.ports?.length > 0 && (
                <div style={{marginBottom:'8px'}}>
                  <div style={S.sumLabel}>PORTS</div>
                  <div className="rc-chips" style={S.chipsTight}>
                    {sh.ports.map((p, i) => <span key={i} className="rc-chip hl">{String(p)}</span>)}
                  </div>
                </div>
              )}
              {sh.vulns?.length > 0 && (
                <div style={{marginBottom:'8px'}}>
                  <div style={S.sumLabel}>CVEs</div>
                  <div className="rc-chips" style={S.chipsTight}>
                    {sh.vulns.map((v, i) => <span key={i} className="rc-chip red">{v}</span>)}
                  </div>
                </div>
              )}
              {sh.tags?.length > 0 && (
                <div className="rc-chips" style={S.chipsTight}>
                  {sh.tags.map((t, i) => <span key={i} className="rc-chip">{t}</span>)}
                </div>
              )}
            </>
          ) : <div style={noData}>No Shodan data available</div>}
        </div>
      </div>

      {/* Row 2: WHOIS · VirusTotal — always shown */}
      <div className="rc-2col mb-20">
        <div className="card">
          <PanelHead title="WHOIS" badge={<SrcBadge src={hasWhois ? (w._source || 'cache') : 'none'} />} />
          {hasWhois ? (
            <>
              <div style={S.sumLine}>{w.organization || w.registrar || '—'}</div>
              {w.net_range  && <div style={S.sumLineSub}>{w.net_range}</div>}
              {w.abuse_email && <div style={S.sumLineSub}>abuse: <span className="mono">{w.abuse_email}</span></div>}
            </>
          ) : <div style={noData}>No WHOIS data available</div>}
        </div>

        <div className="card">
          <PanelHead title="VirusTotal" badge={<SrcBadge src={hasVt ? 'live' : hasFiles ? 'cache' : 'none'} />} />
          {hasVt ? (
            <>
              <div style={{...S.inlineRow, marginBottom:'6px'}}>
                <div style={S.bigVal(vtColor)}>{vtRatio}</div>
                <div style={S.sumLabel}>MALICIOUS / TOTAL</div>
              </div>
              <div style={S.sumLineSub}>
                {vt.family && <span className="rc-chip red">{vt.family}</span>}
                {vt.sha256 && <span className="mono">{String(vt.sha256).slice(0, 16)}…</span>}
              </div>
              {vt.permalink && (
                <a className="btn btn-gh btn-sm" style={{marginTop:'8px'}} href={vt.permalink} target="_blank" rel="noreferrer">Open on VT →</a>
              )}
            </>
          ) : hasFiles ? (
            <div style={S.sumLineSub}>
              {data.captured_files.length} file{data.captured_files.length !== 1 ? 's' : ''} captured — no VT verdict yet
            </div>
          ) : <div style={noData}>No VirusTotal verdict available</div>}
        </div>
      </div>

      {/* YARA — only when rules matched */}
      {hasYara && (
        <div className="card mb-20">
          <PanelHead title="YARA" badge={<SrcBadge src="cache" />} sub={`${data.yara.length} rule${data.yara.length !== 1 ? 's' : ''} matched`} />
          <div className="rc-chips" style={S.chipsTight}>
            {data.yara.map((y, i) => <span key={i} className="rc-chip red">{y.rule || '?'}</span>)}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK — only when techniques are mapped */}
      {hasMitre && (
        <div className="card mb-20">
          <PanelHead
            title="MITRE ATT&CK"
            sub={`${data.mitre.length} technique${data.mitre.length > 1 ? 's' : ''} mapped`}
            badge={<SrcBadge src="cache" />}
          />
          <table className="tbl">
            <thead><tr><th style={{width:'90px'}}>ID</th><th>Technique</th><th>Tactic</th></tr></thead>
            <tbody>
              {data.mitre.map((m, i) => (
                <tr key={i}>
                  <td className="mono" style={{width:'90px'}}>
                    <a href={m.url} target="_blank" rel="noreferrer" style={S.mitreLink}>{m.id}</a>
                  </td>
                  <td>{m.name}</td>
                  <td><span className="rc-chip">{m.tactic}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
});

function ParamSection({ title, rows }) {
  const cells = rows.filter(([, v]) => v != null && v !== '' && v !== false);
  if (!cells.length) return null;
  return (
    <div>
      <div style={S.paramSecLbl}>{title}</div>
      {cells.map(([k, v], i) => (
        <div key={i} style={S.paramRow}>
          <span style={S.paramKey}>{k}</span>
          <span style={S.paramVal}>{String(v)}</span>
        </div>
      ))}
    </div>
  );
}

const SessionParams = memo(function SessionParams({ s }) {
  const durStr = sessionDuration(s);
  const rs = s.risk_score || 0;
  const mitre = Array.isArray(s.mitre_techniques) ? s.mitre_techniques : [];
  const hpHit = Array.isArray(s.honeypots_hit) && s.honeypots_hit.length ? s.honeypots_hit : [];

  return (
    <div className="card mb-20">
      <div className="card-h"><div className="card-t">Session Parameters</div></div>

      <div className="rc-3col">
        <ParamSection title="Identity" rows={[
          ['Session ID',  s.session_id],
          ['Source IP',   s.source_ip],
          ['Honeypot',    s.honeypot_type],
        ]} />
        <ParamSection title="Timeline" rows={[
          ['Started',  s.started_at ? fmt.date(s.started_at) : null],
          ['Ended',    s.ended_at   ? fmt.date(s.ended_at)   : null],
          ['Duration', durStr !== '—' ? durStr : null],
        ]} />
        <ParamSection title="Activity" rows={[
          ['Login Attempts',  s.login_attempts],
          ['Successful Auth', s.success_count],
          ['Velocity (ev/s)', s.attack_velocity != null ? Number(s.attack_velocity).toFixed(2) : null],
          ['Sub-sessions',    s.sessions_count],
          ['Honeypots Hit',   s.honeypot_count],
        ]} />
      </div>

      <div style={S.paramDivider}>
        <div className="rc-2col">
          <ParamSection title="Classification" rows={[
            ['Risk Score',       rs],
            ['Risk Level',       s.risk_level || riskLabel(rs)],
            ['Confidence',       s.confidence],
            ['Kill-chain Phase', s.kill_chain_phase],
            ['Kill-chain Stage', s.kill_chain_stage],
            ['Primary Technique',s.primary_technique],
          ]} />
          <div>
            {mitre.length > 0 && (
              <>
                <div style={S.paramSecLbl}>MITRE Techniques</div>
                <div className="rc-chips" style={S.chipsTight}>
                  {mitre.map((t, i) => (
                    <span key={i} className={`rc-chip${t === s.primary_technique ? ' hl' : ''}`}>{t}</span>
                  ))}
                </div>
              </>
            )}
            {hpHit.length > 0 && (
              <div style={mitre.length ? {marginTop:'14px'} : {}}>
                <div style={S.paramSecLbl}>Honeypots Hit</div>
                <div className="rc-chips" style={S.chipsTight}>
                  {hpHit.map((h, i) => <span key={i} className="rc-chip">{h}</span>)}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
});

const SessionPanel = memo(function SessionPanel({ s, enrichment, enrichmentError }) {
  const stage = Math.max(0, Math.min(8, s.kill_chain_stage || 0));
  const pct = (stage / 8) * 100;
  const path = useMemo(() => attackPath(s), [s]);
  const rs = s.risk_score || 0;

  return (
    <>
      <div className="card mb-20">
        <div className="rc-hero">
          <div className="rc-hero-l">
            <div className="card-t">{s.kill_chain_phase || 'Kill chain in progress'}</div>
            <div className="card-sub">Step {stage} / 8 · {(s.honeypot_type || 'unknown').toUpperCase()} · {s.source_ip || '?'}</div>
          </div>
          <div className="rc-hero-r">
            <div className="rc-risk-big" style={{color: riskColor(rs)}}>{rs}</div>
            <div className="rc-risk-lbl">Risk · {s.risk_level || riskLabel(rs)}</div>
          </div>
        </div>

        <div className="kc-prog"><div className="kc-prog-bar" style={{width:`${pct}%`}} /></div>
        <div className="kc-grid">
          {KC.map((lab, i) => {
            const cls = i < stage - 1 ? 'done' : (i === stage - 1 ? 'active' : '');
            return (
              <div key={i} className={`kc-cell ${cls}`}>
                <div className="kc-num">0{i + 1}</div>
                <div className="kc-lab">{lab}</div>
              </div>
            );
          })}
        </div>

        <div className="card-sub" style={{marginTop:'14px'}}>ATTACK PATH</div>
        <div className="flow">
          <span className="flow-node src">{s.source_ip || '?'}</span>
          {path.map((p, i) => (
            <React.Fragment key={i}>
              <span className="flow-arrow">→</span>
              <span className={`flow-node${i === path.length - 1 ? ' tgt' : ''}`}>{p}</span>
            </React.Fragment>
          ))}
        </div>

      </div>

      <SessionParams s={s} />

      {enrichmentError ? (
        <div className="card mb-20">
          <div className="alert warn" style={S.alertM}>Threat intelligence unavailable: {enrichmentError}</div>
        </div>
      ) : !enrichment ? (
        <div className="card mb-20"><div className="card-sub">Loading threat intelligence…</div></div>
      ) : (
        <Enrichment data={enrichment} s={s} />
      )}

      <div className="card">
        <div className="card-h"><div className="card-t">Actions</div></div>
        <div style={S.actionsRow}>
          <a className="btn btn-gold btn-sm" href="/timeline">View detailed timeline →</a>
          <a className="btn btn-gh btn-sm" href={api.forensicReportPreviewUrl(s.session_id)} target="_blank" rel="noreferrer">HTML report preview</a>
          <a className="btn btn-gh btn-sm" href={`/profiling?ip=${encodeURIComponent(s.source_ip || '')}`}>Profile this IP</a>
        </div>
      </div>
    </>
  );
});

async function loadSessions() {
  let list = [];
  let missing = false;
  try {
    list = await api.forensicSessions(50);
  } catch (e) {
    if (e.status === 404) missing = true;
    else throw e;
  }
  if (missing || !list.length) {
    try {
      const ss = await api.sessions({ page_size: 50 });
      const items = (ss && ss.items) || [];
      if (items.length) {
        list = items.map(s => ({
          session_id: s.session_id || s.id,
          source_ip: s.source_ip,
          honeypot_type: s.honeypot_type || s.honeypot,
          risk_score: s.risk_score,
          kill_chain_phase: s.kill_chain_phase,
          kill_chain_stage: s.kill_chain_stage,
          primary_technique: s.primary_technique,
          started_at: s.started_at || s.first_event_at || s.created_at,
        }));
        missing = false;
      }
    } catch { /* keep missing flag */ }
  }
  return { list, missing };
}

export default function Reconstruction() {
  const [sessions, setSessions] = useState([]);
  const [error, setError] = useState('');
  const [endpointMissing, setEndpointMissing] = useState(false);
  const [hpFilter, setHpFilter] = useState('');
  const [sortMode, setSortMode] = useState('date');
  const [query, setQuery] = useState('');
  const [selectedSid, setSelectedSid] = useState('');
  const [enrichment, setEnrichment] = useState(null);
  const [enrichmentError, setEnrichmentError] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const deferredQuery = useDeferredValue(query);

  // Bumped when an enrichment request fires; older responses are dropped.
  const enrichReqRef = useRef(0);

  const refresh = useCallback(async () => {
    setRefreshing(true);
    try {
      const { list, missing } = await loadSessions();
      setSessions(list);
      setEndpointMissing(missing);
      setError('');
    } catch (e) {
      setError(e.message);
    } finally {
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const filtered = useMemo(() => {
    let list = sessions;
    if (hpFilter) list = list.filter(s => (s.honeypot_type || '').toLowerCase() === hpFilter);
    const q = deferredQuery.trim().toLowerCase();
    if (q) {
      list = list.filter(s => {
        const hay = [
          s.session_id, s.source_ip, s.honeypot_type, s.primary_technique,
          s.kill_chain_phase, s.risk_level,
          ...(Array.isArray(s.mitre_techniques) ? s.mitre_techniques : []),
          ...(Array.isArray(s.honeypots_hit) ? s.honeypots_hit : []),
        ].filter(Boolean).join(' ').toLowerCase();
        return hay.includes(q);
      });
    }
    const out = list === sessions ? list.slice() : list;
    if (sortMode === 'risk')       out.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
    else if (sortMode === 'stage') out.sort((a, b) => (b.kill_chain_stage || 0) - (a.kill_chain_stage || 0));
    else                            out.sort((a, b) => new Date(b.started_at || 0) - new Date(a.started_at || 0));
    return out;
  }, [sessions, hpFilter, sortMode, deferredQuery]);

  const selected = useMemo(() => sessions.find(s => s.session_id === selectedSid), [sessions, selectedSid]);

  // Auto-select the first session once data arrives.
  useEffect(() => {
    if (!selectedSid && filtered.length > 0) {
      setSelectedSid(filtered[0].session_id);
    }
  }, [filtered, selectedSid]);

  // Fetch enrichment when the selected session id changes — depend on the primitive,
  // not the object, so a new `sessions` array reference doesn't trigger a refetch.
  useEffect(() => {
    if (!selectedSid) { setEnrichment(null); setEnrichmentError(''); return; }
    const reqId = ++enrichReqRef.current;
    setEnrichment(null);
    setEnrichmentError('');
    api.forensicSessionEnrichment(selectedSid)
      .then(d => { if (reqId === enrichReqRef.current) setEnrichment(d); })
      .catch(e => { if (reqId === enrichReqRef.current) setEnrichmentError(e.message || 'error'); });
  }, [selectedSid]);

  const onQueryChange   = useCallback((e) => setQuery(e.target.value), []);
  const onSortChange    = useCallback((e) => setSortMode(e.target.value), []);
  const onSessionChange = useCallback((e) => setSelectedSid(e.target.value), []);
  const handleClear     = useCallback(() => {
    setQuery('');
    setHpFilter('');
    setSelectedSid('');
  }, []);
  const filtersActive = !!(query || hpFilter);

  if (error) return <div className="alert err">{error}</div>;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{marginBottom:'8px'}}>Forensic Analysis</div>
          <h2 className="page-title">Attack <span>Reconstruction</span></h2>
          <div className="page-sub">Step-by-step reconstruction of the Lockheed Martin kill chain — adapted to each attack's signals.</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={refresh} disabled={refreshing}>
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="card mb-20">
        <div className="card-h">
          <div className="card-t">Session Selection</div>
          <div className="card-sub">Search by IP, session, MITRE technique, or honeypot</div>
        </div>

        <div style={S.searchRow}>
          <input
            type="text"
            className="form-i"
            style={{flex:1}}
            placeholder="e.g. 192.168.1.10 · T1110 · cowrie · ELEVE"
            value={query}
            onChange={onQueryChange}
            aria-label="Search sessions"
          />
          {filtersActive && <button className="btn btn-gh btn-sm" onClick={handleClear}>Clear</button>}
        </div>

        <div style={S.filterRow}>
          <div style={S.filterGroup}>
            <span style={S.filterLabel}>Honeypot:</span>
            {HONEYPOTS.map(hp => (
              <button
                key={hp || 'all'}
                className={`rc-tab${hpFilter === hp ? ' active' : ''}`}
                onClick={() => setHpFilter(hp)}
                aria-pressed={hpFilter === hp}
              >
                {hp ? hp.charAt(0).toUpperCase() + hp.slice(1) : 'All'}
              </button>
            ))}
          </div>
          <div style={S.filterGroup}>
            <span style={S.filterLabel}>Sort:</span>
            <select
              className="form-s"
              value={sortMode}
              onChange={onSortChange}
              style={S.sortSelect}
              aria-label="Sort sessions"
            >
              {SORT_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
        </div>

        <div className="form-g" style={S.sessionGroup}>
          <label className="form-l">
            Session <span className="mono" style={S.sessionCount}>{filtered.length} of {sessions.length}</span>
          </label>
          <select className="form-s" value={selectedSid} onChange={onSessionChange}>
            <option value="">— select —</option>
            {filtered.map(s => (
              <option key={s.session_id} value={s.session_id}>
                [{(s.honeypot_type || '?').toUpperCase()}] {s.source_ip || '?'} · risk {s.risk_score || 0} · {s.session_id}
              </option>
            ))}
          </select>
        </div>
      </div>

      {!sessions.length && (
        <div className="alert info">
          <b>No forensic sessions available.</b><br />
          {endpointMissing
            ? <>Endpoint <span className="mono">/api/reports/forensic/sessions</span> not deployed (Sprint 4) and <span className="mono">/api/sessions</span> is empty.</>
            : 'Run the forensic engine to generate sessions.'}
        </div>
      )}

      {sessions.length > 0 && !selected && (
        <div className="alert info">Select a session to start the reconstruction.</div>
      )}

      {selected && (
        <SessionPanel
          s={selected}
          enrichment={enrichment}
          enrichmentError={enrichmentError}
        />
      )}
    </>
  );
}
