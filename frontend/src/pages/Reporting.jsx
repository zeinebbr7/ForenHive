import React, { useState, useEffect, useRef, useCallback } from 'react';
import api from '../api';
import { fmt, esc } from '../utils';
import { RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL, riskLevel } from '../constants';
import { useTranslation } from '../contexts/LanguageContext';

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
        <div className="rep-ip" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 14, fontWeight: 700, color: 'var(--text1)' }}>
          {session.source_ip || '—'}
        </div>
        <div className="rep-sid" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
          {session.session_id}
        </div>
        <div className="rep-meta" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: 'var(--text3)', marginTop: 3 }}>
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
            fontSize: 13,
            background: cls === 'hi' ? 'rgba(198,40,40,.12)' : cls === 'md' ? 'rgba(140,26,43,.12)' : 'rgba(21,101,192,.12)',
            color: cls === 'hi' ? 'var(--red2)' : cls === 'md' ? 'var(--gold)' : 'var(--blue2)',
          }}
        >
          {sc == null ? '—' : sc}
        </span>
        <div className="rep-meta" style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: 'var(--text3)', marginTop: 4 }}>
          {session.started_at ? fmt.date(session.started_at) : '—'}
        </div>
      </div>
    </div>
  );
}

/* ── main component ──────────────────────────────────────── */
export default function Reporting() {
  const { t } = useTranslation();
  const [sessions,        setSessions]        = useState([]);
  const [selectedSession, setSelectedSession] = useState(null); // full session object
  const [loading,         setLoading]         = useState(false);
  const [previewLoading,  setPreviewLoading]  = useState(false);
  const [status,          setStatus]          = useState(null);  // { text, ok }
  const [kpis,            setKpis]            = useState({ total: '—', crit: '—', elev: '—', avg: '—' });
  const [reportLang,      setReportLang]      = useState(() => localStorage.getItem('fh.report.lang') || 'en');

  const iframeContainerRef = useRef(null);

  /* ── KPI calculation ─────────────────────────────────────── */
  function calcKpis(list) {
    const total  = list.length;
    const crit   = list.filter(s => s.risk_score != null && s.risk_score >= RISK_CRITICAL).length;
    const elev   = list.filter(s => s.risk_score != null && s.risk_score >= RISK_HIGH && s.risk_score < RISK_CRITICAL).length;
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
  const generatePreview = useCallback(async (sid, langOverride) => {
    setPreviewLoading(true);
    setStatus(null);

    // Clear iframe container while loading
    if (iframeContainerRef.current) {
      iframeContainerRef.current.innerHTML = '';
    }

    try {
      const tok = api.token();
      const lang = langOverride || reportLang;
      const res = await fetch(`/api/reports/forensic/${encodeURIComponent(sid)}/preview?lang=${encodeURIComponent(lang)}`, {
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
      iframe.setAttribute('sandbox', 'allow-same-origin allow-popups allow-downloads allow-modals');

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
          '<div>' + esc(t('reporting.preview_failed')) + ' ' + esc(e.message) + '</div>' +
          '<div style="margin-top:8px;opacity:.6;font-size:11px">' + esc(t('reporting.preview_failed_hint')) + '</div>';
        iframeContainerRef.current.appendChild(errDiv);
      }
      setStatus({ text: '✗ ' + e.message, ok: false });
    } finally {
      setPreviewLoading(false);
    }
  }, [reportLang, t]);

  function setReportLangAndRegen(lang) {
    setReportLang(lang);
    localStorage.setItem('fh.report.lang', lang);
    if (selectedSession) generatePreview(selectedSession.session_id, lang);
  }

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
    setStatus({ text: t('reporting.status.requesting'), ok: null });
    try {
      const result = await api.forensicReportDownload(selectedSession.session_id, reportLang);
      const sha256 = result && result.sha256;
      setStatus({
        text: sha256
          ? t('reporting.status.dl_ok_sha', { sha: sha256 })
          : t('reporting.status.dl_ok'),
        ok: true,
      });
    } catch (e) {
      setStatus({ text: t('reporting.status.dl_fail', { err: e.message }), ok: false });
    } finally {
      setDownloading(false);
    }
  }

  /* ── Derived values for the preview panel header ─────────── */
  const pvTitle = selectedSession ? selectedSession.session_id : t('reporting.pv_title');
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
  })() : t('reporting.pv_select');

  /* ── render ──────────────────────────────────────────────── */
  return (
    <>
      {/* Page header */}
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>{t('reporting.tag')}</div>
          <h2 className="page-title">{t('reporting.title_html_1')} <span>{t('reporting.title_html_2')}</span></h2>
          <div className="page-sub">
            {t('reporting.subtitle')}
          </div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={loadList} disabled={loading}>
            {loading ? t('common.loading') : t('reporting.refresh')}
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div className="fkpi-row">
        <div className="fkpi" style={{ borderColor: '#f0b42955' }}>
          <div className="fkpi-label">{t('reporting.kpi.total')}</div>
          <div className="fkpi-val" style={{ color: 'var(--gold)' }}>{kpis.total}</div>
          <div className="fkpi-sub">{t('reporting.kpi.total_sub')}</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#ff505055' }}>
          <div className="fkpi-label">{t('reporting.kpi.critical')}</div>
          <div className="fkpi-val" style={{ color: '#ff5050' }}>{kpis.crit}</div>
          <div className="fkpi-sub">{t('reporting.kpi.critical_sub')}</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#ff993355' }}>
          <div className="fkpi-label">{t('reporting.kpi.elevated')}</div>
          <div className="fkpi-val" style={{ color: '#ff9933' }}>{kpis.elev}</div>
          <div className="fkpi-sub">{t('reporting.kpi.elevated_sub')}</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#2dd4bf55' }}>
          <div className="fkpi-label">{t('reporting.kpi.avg')}</div>
          <div className="fkpi-val" style={{ color: '#2dd4bf' }}>{kpis.avg}</div>
          <div className="fkpi-sub">{t('reporting.kpi.avg_sub')}</div>
        </div>
      </div>

      {/* Two-panel layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, marginBottom: 20 }}>

        {/* Session list panel */}
        <div className="card" style={{ padding: 0, alignSelf: 'start' }}>
          <div className="card-h" style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)' }}>
            <div className="card-t">{t('reporting.sessions')}</div>
            <div className="card-sub">{t('reporting.sessions.sub')}</div>
          </div>
          <div style={{ maxHeight: 'calc(100vh - 260px)', overflowY: 'auto' }}>
            {loading ? (
              <div className="alert info" style={{ margin: 14 }}>{t('common.loading')}</div>
            ) : sessions.length === 0 ? (
              <div className="alert info" style={{ margin: 14 }}>
                <b>{t('reporting.no_sessions')}</b><br />
                {t('reporting.run_engine')}
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
            <div className="flex gap-8" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div
                role="group"
                aria-label="Report language"
                title="Report language"
                style={{
                  display: 'inline-flex',
                  border: '1px solid var(--border)',
                  borderRadius: 6,
                  overflow: 'hidden',
                  fontFamily: "'Share Tech Mono',monospace",
                  fontSize: 11,
                  marginRight: 4,
                }}
              >
                {['en', 'fr'].map(code => {
                  const active = reportLang === code;
                  return (
                    <button
                      key={code}
                      type="button"
                      onClick={() => setReportLangAndRegen(code)}
                      aria-pressed={active}
                      disabled={previewLoading || downloading}
                      style={{
                        padding: '6px 10px',
                        background: active ? 'var(--gold)' : 'transparent',
                        color: active ? '#060810' : 'var(--text2)',
                        border: 'none',
                        cursor: 'pointer',
                        fontWeight: active ? 700 : 500,
                        letterSpacing: '1px',
                        textTransform: 'uppercase',
                      }}
                    >
                      {code}
                    </button>
                  );
                })}
              </div>
              <button
                className="btn btn-gh btn-sm"
                onClick={() => selectedSession && generatePreview(selectedSession.session_id)}
                disabled={!selectedSession || previewLoading}
                title={t('reporting.btn.regenerate_tip')}
              >
                {t('reporting.btn.regenerate')}
              </button>
              <button
                className="btn btn-gh btn-sm"
                onClick={handlePrint}
                disabled={!selectedSession || previewLoading}
                title={t('reporting.btn.print_tip')}
              >
                {t('reporting.btn.print')}
              </button>
              <button
                className="btn btn-gold btn-sm"
                onClick={handleDownload}
                disabled={!selectedSession || downloading}
                title={t('reporting.btn.download_tip')}
              >
                {downloading ? t('reporting.btn.generating') : t('reporting.btn.download')}
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
                  {t('reporting.generating_report')}
                </div>
              </div>
            )}

            {!selectedSession && !previewLoading && (
              <div style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexDirection: 'column', gap: 12, color: '#888', padding: 60, height: '100%',
              }}>
                <div style={{ fontSize: 48, opacity: .3 }}>📄</div>
                <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 13 }}>{t('reporting.empty.title')}</div>
                <div style={{ fontSize: 12, opacity: .6 }}>{t('reporting.empty.hint')}</div>
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
