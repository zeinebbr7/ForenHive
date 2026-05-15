import React, { useState, useEffect, useCallback } from 'react';
import api from '../api';
import { fmt, esc } from '../utils';

const SEV_BADGE = { critical: 'red', high: 'red', medium: 'gold', low: 'blue' };

function sevClass(s) {
  return 'sev-' + (s || 'low').toLowerCase();
}

function topSeverity(matches) {
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  return (matches || []).reduce((acc, m) => {
    const s = ((m.meta && m.meta.severity) || 'low').toLowerCase();
    return (order[s] || 1) > (order[acc] || 1) ? s : acc;
  }, 'low');
}

function RuleRow({ m }) {
  const sev = ((m.meta && m.meta.severity) || 'low').toLowerCase();
  const desc = (m.meta && m.meta.description) || '';
  const ref = (m.meta && m.meta.reference) || '';
  const author = (m.meta && m.meta.author) || '';
  return (
    <div className="rule-row">
      <div style={{ fontSize: 22, paddingTop: 2 }}>●</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className={`rule-name ${sevClass(sev)}`}>{m.rule}</div>
        <div className="rule-ns">
          namespace: {m.namespace || '—'}{author ? ' · ' + author : ''}
        </div>
        {desc && <div className="rule-desc">{desc}</div>}
        {ref && <div className="rule-ref">{ref}</div>}
        {(m.strings || []).length > 0 && (
          <div className="rule-strings">
            {(m.strings || []).map((s, i) => (
              <span key={i} className="tag mono" style={{ fontSize: 10 }}>
                offset:{s.offset} <b>{s.identifier}</b>
              </span>
            ))}
          </div>
        )}
      </div>
      <span className={`badge ${SEV_BADGE[sev] || 'blue'}`} style={{ whiteSpace: 'nowrap' }}>{sev}</span>
    </div>
  );
}

function YaraCard({ r, index, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen || false);
  const fname = (r.filepath || '').split('/').pop() || r.sha256;
  const matches = r.matches || [];
  const sev = topSeverity(matches);

  return (
    <div className="yara-card">
      <div className="yara-head" onClick={() => setOpen(o => !o)}>
        <div>
          <div className="flex gap-8 items-c" style={{ flexWrap: 'wrap' }}>
            <span className={`badge ${SEV_BADGE[sev] || 'blue'}`}>● {sev.toUpperCase()}</span>
            <span className="badge gold">{matches.length} règle(s)</span>
          </div>
          <div className="yara-hash">{r.sha256 || '—'}</div>
          <div className="yara-file">{r.filepath || '—'}</div>
        </div>
        <div />
        <span style={{ fontSize: 18, color: 'var(--text3)', paddingLeft: 8 }} className="yara-toggle">
          {open ? '▼' : '▶'}
        </span>
      </div>
      <div className={`yara-body-inner${open ? ' open' : ''}`}>
        {matches.map((m, i) => <RuleRow key={i} m={m} />)}
      </div>
    </div>
  );
}

export default function Yara() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [infected, setInfected] = useState([]);
  const [totalScanned, setTotalScanned] = useState(0);
  const [allRules, setAllRules] = useState([]);
  const [critCount, setCritCount] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.yaraHits({ limit: 200 });
      const results = data.results || [];
      const inf = results.filter(r => r.matched && r.matches && r.matches.length);
      const rules = new Set();
      let crit = 0;
      inf.forEach(r => {
        (r.matches || []).forEach(m => {
          rules.add(m.rule);
          if (((m.meta && m.meta.severity) || '').toLowerCase() === 'critical') crit++;
        });
      });
      setTotalScanned(results.length);
      setInfected(inf);
      setAllRules([...rules]);
      setCritCount(crit);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const topRulesPreview = allRules.slice(0, 3).join(', ') || '—';

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>YARA</div>
          <h2 className="page-title">Détection <span>malware</span></h2>
          <div className="page-sub">
            Scan YARA des binaires capturés par Dionaea ·{' '}
            <span>{loading ? '—' : totalScanned}</span> fichier(s) analysé(s).
          </div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={load} disabled={loading}>
            Actualiser
          </button>
        </div>
      </div>

      <div className="grid-3 mb-20">
        <div className="kpi r">
          <div className="kpi-label">Fichiers infectés</div>
          <div className="kpi-val">{loading ? '—' : infected.length}</div>
          <div className="kpi-delta">{loading ? '—' : `sur ${totalScanned} fichier(s) scanné(s)`}</div>
        </div>
        <div className="kpi p">
          <div className="kpi-label">Règles déclenchées</div>
          <div className="kpi-val">{loading ? '—' : allRules.length}</div>
          <div className="kpi-delta">{loading ? '—' : topRulesPreview}</div>
        </div>
        <div className="kpi b">
          <div className="kpi-label">Critiques</div>
          <div className="kpi-val">{loading ? '—' : critCount}</div>
          <div className="kpi-delta">détections severity=critical</div>
        </div>
      </div>

      <div>
        {loading && <div className="alert info">⟳ Scan en cours…</div>}
        {error && <div className="alert err">Erreur : {error}</div>}
        {!loading && !error && infected.length === 0 && (
          <div className="alert info">Aucun fichier infecté détecté dans les binaires Dionaea.</div>
        )}
        {!loading && !error && infected.map((r, i) => (
          <YaraCard key={r.sha256 || i} r={r} index={i} defaultOpen={i === 0} />
        ))}
      </div>

      <style>{`
        .yara-card {
          background: var(--card-bg);
          border: 1px solid var(--border);
          border-radius: 10px;
          margin-bottom: 14px;
          overflow: hidden;
        }
        .yara-head {
          display: grid;
          grid-template-columns: 1fr auto auto;
          align-items: center;
          gap: 12px;
          padding: 14px 18px;
          cursor: pointer;
          transition: background .15s;
        }
        .yara-head:hover { background: rgba(255,255,255,.03); }
        .yara-hash { font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--text2); margin-top:4px; word-break:break-all; }
        .yara-file { font-family:'Share Tech Mono',monospace; font-size:12px; color:var(--text3); margin-top:2px; }
        .yara-body-inner { border-top:1px solid var(--border); display:none; padding:16px 18px; }
        .yara-body-inner.open { display:block; }
        .rule-row {
          display:flex; align-items:flex-start; gap:12px;
          padding:10px 0; border-bottom:1px solid rgba(255,255,255,.04);
        }
        .rule-row:last-child { border-bottom:none; }
        .rule-name { font-family:'Share Tech Mono',monospace; font-size:13px; color:var(--text1); font-weight:700; }
        .rule-ns   { font-family:'Share Tech Mono',monospace; font-size:10px; color:var(--text3); margin-top:2px; }
        .rule-desc { font-size:12px; color:var(--text2); margin-top:4px; }
        .rule-ref  { font-size:11px; color:var(--blue2); margin-top:3px; font-family:'Share Tech Mono',monospace; }
        .rule-strings { margin-top:8px; display:flex; flex-wrap:wrap; gap:6px; }
        .sev-critical { color:var(--red2); }
        .sev-high     { color:var(--red2); }
        .sev-medium   { color:var(--gold); }
        .sev-low      { color:var(--blue2); }
      `}</style>
    </>
  );
}
