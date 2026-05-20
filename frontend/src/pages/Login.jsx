import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

function Counter({ target, duration = 1800, suffix = '' }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = null;
    const step = ts => {
      if (!start) start = ts;
      const p = Math.min((ts - start) / duration, 1);
      setVal(Math.floor(p * target));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, [target, duration]);
  return <>{val.toLocaleString()}{suffix}</>;
}

const FEED = [
  { time: '00:03', src: '185.220.101.47', cc: 'RU', type: 'SSH brute-force',   sev: 'HIGH'     },
  { time: '00:07', src: '45.142.212.100', cc: 'CN', type: 'Telnet scan',        sev: 'MEDIUM'   },
  { time: '00:12', src: '91.108.4.55',    cc: 'IR', type: 'SMB exploit',        sev: 'CRITICAL' },
  { time: '00:19', src: '103.56.32.8',    cc: 'VN', type: 'HTTP flood',         sev: 'HIGH'     },
  { time: '00:24', src: '62.171.167.22',  cc: 'DE', type: 'Port scan',          sev: 'LOW'      },
  { time: '00:31', src: '194.165.16.77',  cc: 'UA', type: 'FTP brute-force',    sev: 'MEDIUM'   },
  { time: '00:38', src: '5.188.86.172',   cc: 'RU', type: 'MySQL injection',    sev: 'CRITICAL' },
  { time: '00:44', src: '218.92.0.204',   cc: 'CN', type: 'Cowrie session',     sev: 'HIGH'     },
  { time: '00:51', src: '185.156.73.9',   cc: 'NL', type: 'Dionaea malware',    sev: 'CRITICAL' },
  { time: '00:57', src: '77.88.55.60',    cc: 'RU', type: 'RDP scan',           sev: 'MEDIUM'   },
];
const SEV_COLOR = { CRITICAL:'#C93D55', HIGH:'#E8B84B', MEDIUM:'#6AB0FF', LOW:'#7d8799' };

function ThreatFeed() {
  const [offset, setOffset] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setOffset(o => (o + 1) % FEED.length), 2200);
    return () => clearInterval(id);
  }, []);
  const visible = [...FEED, ...FEED].slice(offset, offset + 5);
  return (
    <div className="lp-feed">
      <div className="lp-feed-header">
        <span className="lp-feed-title">LIVE THREAT FEED</span>
        <span className="lp-feed-dot" />
      </div>
      <div className="lp-feed-rows">
        {visible.map((row, i) => (
          <div key={i} className="lp-feed-row" style={{ opacity: 1 - i * 0.15 }}>
            <span className="lp-feed-time">{row.time}</span>
            <span className="lp-feed-ip">{row.src}</span>
            <span className="lp-feed-cc">{row.cc}</span>
            <span className="lp-feed-type">{row.type}</span>
            <span className="lp-feed-sev" style={{ color: SEV_COLOR[row.sev] }}>{row.sev}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const FEATURES = [
  { label: 'Honeypot Orchestration', desc: 'Cowrie · Dionaea · Galah LLM' },
  { label: 'Forensic Engine',         desc: 'Timeline · YARA · Reconstruction' },
  { label: 'Threat Intelligence',     desc: 'GeoIP · MITRE ATT&CK · Profiling' },
  { label: 'SIEM Integration',        desc: 'Elasticsearch · Logstash · Zeek' },
];

export default function Login() {
  const { login, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || '/stats';

  const [email,    setEmail]    = useState('');
  const [password, setPassword] = useState('');
  const [showPwd,  setShowPwd]  = useState(false);
  const [error,    setError]    = useState('');
  const [loading,  setLoading]  = useState(false);

  if (user) return <Navigate to={from} replace />;

  const handleSubmit = async e => {
    e.preventDefault();
    setError(''); setLoading(true);
    try { await login(email.trim(), password); navigate(from, { replace: true }); }
    catch (ex) { setError(ex.message || 'Login failed'); }
    finally { setLoading(false); }
  };

  return (
    <div className="lp-root">

      {/* ── LEFT PANEL ── */}
      <div className="lp-left">
        <div className="lp-hex-bg" aria-hidden="true" />
        <div className="lp-left-inner">

          <div className="lp-brand">
            <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
              <polygon points="18,2 33,10 33,26 18,34 3,26 3,10"
                stroke="#8C1A2B" strokeWidth="1.5" fill="rgba(140,26,43,0.15)" />
              <polygon points="18,8 28,14 28,22 18,28 8,22 8,14"
                stroke="#8C1A2B" strokeWidth="1" fill="none" opacity="0.45" />
              <text x="18" y="22" textAnchor="middle" fontSize="10"
                fontFamily="Rajdhani,sans-serif" fontWeight="700" fill="#8C1A2B">FH</text>
            </svg>
            <div>
              <div className="lp-brand-name">FORENHIVE</div>
              <div className="lp-brand-tag">SOC PLATFORM · v1.0</div>
            </div>
          </div>

          <h1 className="lp-h1">Detect fast,<br /><span className="lp-h1-accent">respond faster.</span></h1>
          <p className="lp-desc">
            Open-source SOC platform combining honeypot intelligence,
            forensic analysis, and real-time threat visibility — all in one interface.
          </p>

          <div className="lp-kpis">
            {[
              { label:'Threats Detected', target:12847, suffix:'',    trend:'+3.2%' },
              { label:'Events / sec',     target:340,   suffix:'/s',  trend:'live'  },
              { label:'Honeypots Online', target:3,     suffix:'',    trend:'100%'  },
              { label:'Platform Uptime',  target:99,    suffix:'.9%', trend:'30d'   },
            ].map(k => (
              <div key={k.label} className="lp-kpi">
                <div className="lp-kpi-body">
                  <div className="lp-kpi-val"><Counter target={k.target} suffix={k.suffix} /></div>
                  <div className="lp-kpi-label">{k.label}</div>
                </div>
                <span className="lp-kpi-trend">{k.trend}</span>
              </div>
            ))}
          </div>

          <div className="lp-features">
            {FEATURES.map(f => (
              <div key={f.label} className="lp-feature">
                <span className="lp-feature-label">{f.label}</span>
              </div>
            ))}
          </div>

          <ThreatFeed />
        </div>
      </div>

      {/* ── RIGHT PANEL ── */}
      <div className="lp-right">
        <div className="lp-form-wrap">
          <div className="lp-form-head">
            <h2 className="lp-form-title">Sign in</h2>
            <p className="lp-form-sub">Access the ForenHive SOC dashboard</p>
          </div>

          {error && <div className="alert err" style={{marginBottom:'16px'}}>{error}</div>}

          <form onSubmit={handleSubmit} style={{display:'flex',flexDirection:'column',gap:'14px'}}>
            <div className="form-g" style={{margin:0}}>
              <label className="form-l">Email</label>
              <input className="form-i" type="email" placeholder="admin@forenhive.io"
                value={email} onChange={e => setEmail(e.target.value)} required />
            </div>
            <div className="form-g" style={{margin:0}}>
              <label className="form-l">Password</label>
              <div className="pwd-wrap">
                <input className="form-i" type={showPwd ? 'text' : 'password'}
                  placeholder="••••••••" value={password}
                  onChange={e => setPassword(e.target.value)} required />
                <button type="button" className="pwd-toggle"
                  aria-label={showPwd ? 'Hide' : 'Show'}
                  onClick={() => setShowPwd(v => !v)} />
              </div>
            </div>
            <button type="submit" className="btn btn-gold" disabled={loading}
              style={{width:'100%',justifyContent:'center',marginTop:'8px',padding:'18px 24px',fontSize:'17px',fontWeight:700,letterSpacing:'0.06em',borderRadius:'8px'}}>
              {loading ? 'Signing in…' : 'Sign In'}
            </button>
          </form>

          <div className="lp-tags">
            <span className="lp-tag">TLS 1.3</span>
            <span className="lp-tag-dot">·</span>
            <span className="lp-tag">AES-256</span>
            <span className="lp-tag-dot">·</span>
            <span className="lp-tag">Zero Trust</span>
            <span className="lp-tag-dot">·</span>
            <span className="lp-tag">SIEM Ready</span>
          </div>
        </div>
      </div>
    </div>
  );
}
