import React, { useState, useEffect, useRef, useCallback } from 'react';
import api from '../api';
import { fmt, esc } from '../utils';
import { RISK_MEDIUM, RISK_HIGH, riskLevel } from '../constants';

/* ── helpers ─────────────────────────────────────────────── */
function scoreCls(s) {
  if (s == null) return 'lo';
  if (s >= RISK_HIGH)   return 'hi';
  if (s >= RISK_MEDIUM) return 'md';
  return 'lo';
}
function scoreLabel(s) {
  return s == null ? '—' : riskLevel(s);
}

/* ── session list row ────────────────────────────────────── */
function SessionRow({ session, active, onSelect }) {
  const sc  = session.risk_score;
  const cls = scoreCls(sc);
  return (
    <div
      className={'rep-row' + (active ? ' active' : '')}
      onClick={() => onSelect(session.session_id)}
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr auto',
        gap: 8,
        padding: '10px 14px',
        borderBottom: '1px solid var(--border)',
        cursor: 'pointer',
        transition: 'background .15s',
        borderLeft: active ? '3px solid var(--gold)' : '3px solid transparent',
        background: active ? 'rgba(140,26,43,.10)' : undefined,
      }}
    >
      <div>
        <div className="rep-ip" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, fontWeight: 700, color: 'var(--text1)' }}>
          {session.source_ip || '—'}
        </div>
        <div className="rep-sid" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--text3)', marginTop: 2 }}>
          {session.session_id}
        </div>
        <div className="rep-meta" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--text3)', marginTop: 3 }}>
          {(session.honeypot_type || '').toUpperCase()} · {session.primary_technique || '—'}
        </div>
      </div>
      <div style={{ textAlign: 'right' }}>
        <span
          className={'rep-score ' + cls}
          style={{
            display: 'inline-block',
            padding: '2px 8px',
            borderRadius: 4,
            fontWeight: 700,
            fontFamily: "'JetBrains Mono',monospace",
            fontSize: 11,
            background: cls === 'hi' ? 'rgba(198,40,40,.12)' : cls === 'md' ? 'rgba(140,26,43,.12)' : 'rgba(21,101,192,.12)',
            color: cls === 'hi' ? 'var(--red2)' : cls === 'md' ? 'var(--gold)' : 'var(--blue2)',
          }}
        >
          {sc == null ? '—' : sc}
        </span>
        <div className="rep-meta" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 10, color: 'var(--text3)', marginTop: 4 }}>
          {session.started_at ? fmt.date(session.started_at) : '—'}
        </div>
      </div>
    </div>
  );
}

/* ── main component ──────────────────────────────────────── */
export default function Reporting() {
  const [sessions,        setSessions]        = useState([]);
  const [selectedSession, setSelectedSession] = useState(null); // full session object
  const [loading,         setLoading]         = useState(false);
  const [previewLoading,  setPreviewLoading]  = useState(false);
  const [status,          setStatus]          = useState(null);  // { text, ok }
  const [kpis,            setKpis]            = useState({ total: '—', crit: '—', elev: '—', avg: '—' });

  const iframeContainerRef = useRef(null);

  /* ── KPI calculation ─────────────────────────────────────── */
  function calcKpis(list) {
    const total  = list.length;
    const crit   = list.filter(s => s.risk_score != null && s.risk_score >= 70).length;
    const elev   = list.filter(s => s.risk_score != null && s.risk_score >= 40 && s.risk_score < 70).length;
    const scored = list.filter(s => s.risk_score != null);
    const avg    = scored.length
      ? Math.round(scored.reduce((a, s) => a + s.risk_score, 0) / scored.length)
      : '—';
    setKpis({ total, crit, elev, avg });
  }

  /* ── Load session list ───────────────────────────────────── */
  const loadList = useCallback(async () => {
    setLoading(true);
    setStatus(null);
    try {
      let list = [];
      let endpointMissing = false;

      try {
        list = await api.forensicSessions(50);
      } catch (e1) {
        if (e1.status === 404) { endpointMissing = true; list = []; }
        else throw e1;
      }

      if (endpointMissing || !list.length) {
        try {
          const ss    = await api.sessions({ page_size: 50 });
          const items = (ss && ss.items) || [];
          if (items.length) {
            list = items.map(s => ({
              session_id:        s.session_id || s.id,
              source_ip:         s.source_ip,
              honeypot_type:     s.honeypot_type || s.honeypot,
              risk_score:        s.risk_score,
              kill_chain_phase:  s.kill_chain_phase,
              kill_chain_stage:  s.kill_chain_stage,
              primary_technique: s.primary_technique,
              started_at:        s.started_at || s.first_event_at || s.created_at,
              country:           s.country,
              city:              s.city,
              organization:      s.organization,
              event_count:       s.event_count,
            }));
          }
        } catch (_) {}
      }

      setSessions(list);
      calcKpis(list);
    } catch (e) {
      setStatus({ text: e.message, ok: false });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadList(); }, [loadList]);

  /* ── Generate preview ────────────────────────────────────── */
  const generatePreview = useCallback(async (sid) => {
    setPreviewLoading(true);
    setStatus(null);

    // Clear iframe container while loading
    if (iframeContainerRef.current) {
      iframeContainerRef.current.innerHTML = '';
    }

    try {
      const tok = api.token();
      const res = await fetch(`/api/reports/forensic/${encodeURIComponent(sid)}/preview`, {
        headers: tok ? { 'Authorization': 'Bearer ' + tok } : {},
      });

      if (!res.ok) {
        const err = await res.text().catch(() => res.statusText);
        throw new Error(`Server returned ${res.status}: ${err}`);
      }

      const html = await res.text();

      // Render in a sandboxed iframe so styles don't leak into the SPA
      const iframe = document.createElement('iframe');
      iframe.style.cssText = 'width:100%;height:100%;min-height:800px;border:none;background:#fff;';
      iframe.setAttribute('sandbox', 'allow-same-origin allow-popups');

      if (iframeContainerRef.current) {
        iframeContainerRef.current.innerHTML = '';
        iframeContainerRef.current.appendChild(iframe);
      }

      const doc = iframe.contentDocument || iframe.contentWindow.document;
      doc.open();
      doc.write(html);
      doc.close();

      iframe.addEventListener('load', () => {
        try {
          const h = iframe.contentDocument.documentElement.scrollHeight;
          if (h > 400) iframe.style.height = h + 'px';
        } catch (_) {}
      });

    } catch (e) {
      if (iframeContainerRef.current) {
        iframeContainerRef.current.innerHTML = '';
        const errDiv = document.createElement('div');
        errDiv.style.cssText = 'padding:32px;text-align:center;color:#ef4444;font-family:\'JetBrains Mono\',monospace;font-size:12px';
        errDiv.innerHTML =
          '<div style="font-size:32px;margin-bottom:12px">⚠</div>' +
          '<div>Preview failed: ' + esc(e.message) + '</div>' +
          '<div style="margin-top:8px;opacity:.6;font-size:11px">Check backend logs — session may not exist in Elasticsearch.</div>';
        iframeContainerRef.current.appendChild(errDiv);
      }
      setStatus({ text: '✗ ' + e.message, ok: false });
    } finally {
      setPreviewLoading(false);
    }
  }, []);

  /* ── Select session ──────────────────────────────────────── */
  function selectSession(sid) {
    const s = sessions.find(x => x.session_id === sid);
    if (!s) return;
    setSelectedSession(s);
    generatePreview(sid);
  }

  /* ── Print ───────────────────────────────────────────────── */
  function handlePrint() {
    if (!selectedSession) return;
    const iframe = iframeContainerRef.current && iframeContainerRef.current.querySelector('iframe');
    if (!iframe) return;
    try {
      iframe.contentWindow.print();
    } catch (_) {
      window.open(`/api/reports/forensic/${encodeURIComponent(selectedSession.session_id)}/preview`, '_blank');
    }
  }

  /* ── Download certified PDF ──────────────────────────────── */
  const [downloading, setDownloading] = useState(false);

  async function handleDownload() {
    if (!selectedSession || downloading) return;
    setDownloading(true);
    setStatus({ text: 'Requesting certified PDF from server…', ok: null });
    try {
      const result = await api.forensicReportDownload(selectedSession.session_id);
      const sha256 = result && result.sha256;
      setStatus({
        text: sha256
          ? `✓ PDF downloaded · SHA-256: ${sha256}`
          : '✓ Certified PDF downloaded successfully',
        ok: true,
      });
    } catch (e) {
      setStatus({ text: `✗ PDF generation failed: ${e.message}`, ok: false });
    } finally {
      setDownloading(false);
    }
  }

  /* ── Derived values for the preview panel header ─────────── */
  const pvTitle = selectedSession ? selectedSession.session_id : 'Report Preview';
  const pvSubParts = selectedSession ? (() => {
    const s   = selectedSession;
    const cls = scoreCls(s.risk_score);
    const color = cls === 'hi' ? 'var(--red2)' : cls === 'md' ? 'var(--gold)' : 'var(--blue2)';
    return (
      <>
        <span className="mono">{s.source_ip || '—'}</span>
        {' · '}
        <span style={{ color, fontWeight: 700 }}>
          {s.risk_score == null ? '—' : s.risk_score}/100
        </span>
        {' · '}
        {s.kill_chain_phase || '—'}
      </>
    );
  })() : 'Select a session to generate the forensic report.';

  /* ── render ──────────────────────────────────────────────── */
  return (
    <>
      {/* Page header */}
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>Reporting</div>
          <h2 className="page-title">Forensic <span>Reports</span></h2>
          <div className="page-sub">
            Select a session · Report generates automatically · Download the SHA-256 certified PDF.
          </div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={loadList} disabled={loading}>
            {loading ? 'Loading…' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div className="fkpi-row">
        <div className="fkpi" style={{ borderColor: '#f0b42955' }}>
          <div className="fkpi-label">Total Sessions</div>
          <div className="fkpi-val" style={{ color: 'var(--gold)' }}>{kpis.total}</div>
          <div className="fkpi-sub">available reports</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#ff505055' }}>
          <div className="fkpi-label">Critical</div>
          <div className="fkpi-val" style={{ color: '#ff5050' }}>{kpis.crit}</div>
          <div className="fkpi-sub">risk score ≥ 70</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#ff993355' }}>
          <div className="fkpi-label">Elevated</div>
          <div className="fkpi-val" style={{ color: '#ff9933' }}>{kpis.elev}</div>
          <div className="fkpi-sub">score 40 – 69</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#2dd4bf55' }}>
          <div className="fkpi-label">Avg Risk Score</div>
          <div className="fkpi-val" style={{ color: '#2dd4bf' }}>{kpis.avg}</div>
          <div className="fkpi-sub">out of 100</div>
        </div>
      </div>

      {/* Two-panel layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, marginBottom: 20 }}>

        {/* Session list panel */}
        <div className="card" style={{ padding: 0, alignSelf: 'start' }}>
          <div className="card-h" style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)' }}>
            <div className="card-t">Available Sessions</div>
            <div className="card-sub">sessions · sorted by risk</div>
          </div>
          <div style={{ maxHeight: 'calc(100vh - 260px)', overflowY: 'auto' }}>
            {loading ? (
              <div className="alert info" style={{ margin: 14 }}>Loading…</div>
            ) : sessions.length === 0 ? (
              <div className="alert info" style={{ margin: 14 }}>
                <b>No sessions found.</b><br />
                Run the forensic engine to generate sessions.
              </div>
            ) : (
              sessions.map(s => (
                <SessionRow
                  key={s.session_id}
                  session={s}
                  active={selectedSession && selectedSession.session_id === s.session_id}
                  onSelect={selectSession}
                />
              ))
            )}
          </div>
        </div>

        {/* Report preview panel */}
        <div className="card" style={{ padding: 0, display: 'flex', flexDirection: 'column', minHeight: 'calc(100vh - 200px)' }}>
          {/* Panel header */}
          <div style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: 12,
            flexShrink: 0,
          }}>
            <div>
              <div className="card-t">{pvTitle}</div>
              <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: "'JetBrains Mono',monospace", marginTop: 2 }}>
                {pvSubParts}
              </div>
            </div>
            <div className="flex gap-8">
              <button
                className="btn btn-gh btn-sm"
                onClick={() => selectedSession && generatePreview(selectedSession.session_id)}
                disabled={!selectedSession || previewLoading}
                title="Regenerate report"
              >
                ↺ Regenerate
              </button>
              <button
                className="btn btn-gh btn-sm"
                onClick={handlePrint}
                disabled={!selectedSession || previewLoading}
                title="Open browser print dialog"
              >
                Print Preview
              </button>
              <button
                className="btn btn-gold btn-sm"
                onClick={handleDownload}
                disabled={!selectedSession || downloading}
                title="Download WeasyPrint certified PDF from server"
              >
                {downloading ? '⏳ Generating…' : '↓ Certified PDF'}
              </button>
            </div>
          </div>

          {/* Preview area */}
          <div style={{ flex: 1, overflowY: 'auto', background: '#f0f0f0', minHeight: 500, position: 'relative' }}>
            {previewLoading && (
              <div style={{
                position: 'absolute', inset: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexDirection: 'column', gap: 16,
                background: '#1a1a1a', color: '#888', zIndex: 2,
              }}>
                <div style={{
                  width: 36, height: 36,
                  border: '3px solid rgba(140,26,43,.2)',
                  borderTopColor: '#374151',
                  borderRadius: '50%',
                  animation: 'spin .8s linear infinite',
                }} />
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12 }}>
                  Génération du rapport forensique…
                </div>
              </div>
            )}

            {!selectedSession && !previewLoading && (
              <div style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexDirection: 'column', gap: 12, color: '#888', padding: 60, height: '100%',
              }}>
                <div style={{ fontSize: 48, opacity: .3 }}>📄</div>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 13 }}>No report selected</div>
                <div style={{ fontSize: 12, opacity: .6 }}>Click a session on the left to preview its forensic report</div>
              </div>
            )}

            {/* iframe is injected here by generatePreview */}
            <div
              ref={iframeContainerRef}
              style={{ width: '100%', height: '100%', minHeight: 500 }}
            />
          </div>

          {/* Status bar */}
          {status && (
            <div style={{
              padding: '7px 16px',
              borderTop: '1px solid var(--border)',
              fontFamily: "'JetBrains Mono',monospace",
              fontSize: 11,
              color: status.ok === true
                ? 'var(--green, #22c55e)'
                : status.ok === false
                  ? 'var(--red2, #ef4444)'
                  : 'var(--text3)',
              flexShrink: 0,
            }}>
              {status.text}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
