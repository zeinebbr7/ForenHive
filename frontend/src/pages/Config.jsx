import React, { useState, useEffect, useRef } from 'react';
import api from '../api';
import { fmt, esc } from '../utils';
import { SOURCE_META } from '../constants';
import { useAuth } from '../contexts/AuthContext';
import { useModal } from '../contexts/ModalContext';

function Accordion({ title, defaultOpen = false, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className={`acc${open ? ' open' : ''}`}>
      <div className="acc-h" onClick={() => setOpen(o => !o)}>
        <div className="acc-t">{title}</div>
        <div className="acc-i">▶</div>
      </div>
      <div className="acc-b">{children}</div>
    </div>
  );
}

export default function Config() {
  const { user } = useAuth();
  const { openModal } = useModal();
  const [cfg, setCfg] = useState(null);
  const [cfgError, setCfgError] = useState('');
  const [threshold, setThreshold] = useState(80);
  const [email, setEmail] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [history, setHistory] = useState([]);
  const [sources, setSources] = useState([]);
  const [intCfg, setIntCfg] = useState(() => {
    try { return JSON.parse(localStorage.getItem('fh.config.int') || '{}'); } catch { return {}; }
  });

  useEffect(() => {
    if (!user || user.role !== 'admin') return;
    api.alertConfig().then(c => {
      setCfg(c);
      setThreshold(c.threshold ?? c.critical_threshold ?? 80);
      setEmail((c.recipients && c.recipients[0]) || c.email || c.notify_email || '');
      setEnabled(c.enabled !== false);
    }).catch(e => setCfgError(e.message));

    api.alertHistory({ limit: 20 }).then(res => {
      setHistory((res && res.items) || []);
    }).catch(() => {});

    api.geoSplit().then(res => {
      setSources((res && res.split) || []);
    }).catch(() => {});
  }, [user]);

  if (!user || user.role !== 'admin') {
    return <div className="alert err">⊘ Access denied. This page is for administrators only.</div>;
  }

  const handleSaveCfg = async () => {
    try {
      await api.setAlertConfig({
        threshold: parseInt(threshold, 10),
        recipients: email ? [email] : [],
        enabled,
      });
      openModal(
        <div>
          <div className="alert ok">✓ Configuration saved.</div>
          <div className="flex gap-8" style={{justifyContent:'flex-end',marginTop:'12px'}}>
            <button className="btn btn-gold btn-sm" onClick={() => openModal(null)}>OK</button>
          </div>
        </div>
      );
    } catch (e) {
      openModal(
        <div>
          <div className="alert err">{e.message}</div>
          <div className="flex gap-8" style={{justifyContent:'flex-end',marginTop:'12px'}}>
            <button className="btn btn-gold btn-sm" onClick={() => openModal(null)}>OK</button>
          </div>
        </div>
      );
    }
  };

  const handleTestAlert = async () => {
    try {
      await api.alertTest({ message: 'Test from ForenHive UI' });
      openModal(
        <div>
          <div className="alert ok">✓ Test alert sent.</div>
          <div className="flex gap-8" style={{justifyContent:'flex-end',marginTop:'12px'}}>
            <button className="btn btn-gold btn-sm" onClick={() => openModal(null)}>OK</button>
          </div>
        </div>
      );
    } catch (e) {
      openModal(
        <div>
          <div className="alert err">{e.message}</div>
          <div className="flex gap-8" style={{justifyContent:'flex-end',marginTop:'12px'}}>
            <button className="btn btn-gold btn-sm" onClick={() => openModal(null)}>OK</button>
          </div>
        </div>
      );
    }
  };

  const saveIntCfg = () => {
    localStorage.setItem('fh.config.int', JSON.stringify(intCfg));
    openModal(
      <div>
        <div className="alert ok">✓ Saved locally.</div>
        <div className="flex gap-8" style={{justifyContent:'flex-end',marginTop:'12px'}}>
          <button className="btn btn-gold btn-sm" onClick={() => openModal(null)}>OK</button>
        </div>
      </div>
    );
  };

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{marginBottom:'8px'}}>Configuration</div>
          <h2 className="page-title">System <span>Settings</span></h2>
          <div className="page-sub">Backend alerting · local honeypot config.</div>
        </div>
        <div className="page-actions">
          <span className="badge gold">⬡ Admin only</span>
        </div>
      </div>

      <Accordion title="⚑ Alerting (backend)" defaultOpen>
        {cfgError
          ? <div className="alert err">{cfgError}</div>
          : cfg
            ? <div className="alert ok">✓ Alert config loaded from backend</div>
            : <div className="alert info">Loading…</div>
        }
        <div className="grid-2">
          <div className="form-g">
            <label className="form-l">Critical score threshold</label>
            <input className="form-i" type="number" min="0" max="100" value={threshold} onChange={e => setThreshold(e.target.value)} />
          </div>
          <div className="form-g">
            <label className="form-l">Recipient email</label>
            <input className="form-i" type="email" value={email} onChange={e => setEmail(e.target.value)} />
          </div>
        </div>
        <div className="flex items-c" style={{justifyContent:'space-between',marginTop:'14px'}}>
          <div>
            <b>Enable alerting</b>
            <div className="text-3 mono" style={{fontSize:'11px'}}>triggers backend notifications</div>
          </div>
          <label className="toggle">
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
            <span className="toggle-slider" />
          </label>
        </div>
        <div className="flex gap-8" style={{justifyContent:'flex-end',marginTop:'10px'}}>
          <button className="btn btn-gh btn-sm" onClick={handleTestAlert}>⚑ Send test alert</button>
          <button className="btn btn-gold btn-sm" onClick={handleSaveCfg}>✓ Save</button>
        </div>
      </Accordion>

      <Accordion title="⊟ Alert History">
        {history.length ? (
          <table className="tbl">
            <thead><tr><th>Date</th><th>Type</th><th>Target</th><th>Status</th></tr></thead>
            <tbody>
              {history.map((a, i) => (
                <tr key={i}>
                  <td className="mono" style={{fontSize:'11px'}}>{fmt.date(a.timestamp || a.created_at)}</td>
                  <td>{a.type || a.kind || '—'}</td>
                  <td className="mono" style={{fontSize:'11px'}}>{a.target || a.recipient || '—'}</td>
                  <td>{a.status === 'sent'
                    ? <span className="badge teal">✓ sent</span>
                    : a.status === 'failed'
                      ? <span className="badge red">✗ error</span>
                      : <span className="badge gold">{a.status || '—'}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="alert info">No alerts in history.</div>
        )}
      </Accordion>

      <Accordion title="⊛ Active Sources">
        {sources.length ? (
          <table className="tbl">
            <thead><tr><th>Source</th><th>Type</th><th>Description</th><th>Events</th><th>Share</th></tr></thead>
            <tbody>
              {sources.map((x, i) => {
                const meta = SOURCE_META[x.honeypot] || { label: x.honeypot, icon: '', kind: '?', desc: '—' };
                return (
                  <tr key={i}>
                    <td><b>{meta.icon} {meta.label}</b></td>
                    <td><span className={`badge ${meta.kind === 'sensor' ? 'blue' : 'gold'}`}>{meta.kind === 'sensor' ? 'NDR Sensor' : 'Honeypot'}</span></td>
                    <td className="mono" style={{fontSize:'11px'}}>{meta.desc}</td>
                    <td className="mono">{x.count.toLocaleString('en-US')}</td>
                    <td className="mono">{x.percent}%</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div className="alert info">Loading sources…</div>
        )}
      </Accordion>

      <Accordion title="⊕ API Integrations (local preferences)">
        <div className="alert info">These keys are stored locally only (actual configuration is done server-side via <span className="mono">.env</span>).</div>
        <div className="grid-2">
          {[
            ['AbuseIPDB API Key', 'abuseipdb'],
            ['VirusTotal API Key', 'virustotal'],
            ['Shodan API Key', 'shodan'],
            ['MaxMind licence key', 'maxmind'],
          ].map(([label, key]) => (
            <div className="form-g" key={key}>
              <label className="form-l">{label}</label>
              <input className="form-i" type="password" value={intCfg[key] || ''} onChange={e => setIntCfg(c => ({...c, [key]: e.target.value}))} />
            </div>
          ))}
        </div>
        <div className="flex gap-8" style={{justifyContent:'flex-end',marginTop:'10px'}}>
          <button className="btn btn-gold btn-sm" onClick={saveIntCfg}>✓ Save locally</button>
        </div>
      </Accordion>
    </>
  );
}
