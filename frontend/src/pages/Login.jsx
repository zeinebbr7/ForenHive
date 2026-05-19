import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const STATS = [
  { label: 'Threats Detected',   value: '12,847' },
  { label: 'Active Honeypots',   value: '4'       },
  { label: 'Events / sec',       value: '340'     },
  { label: 'Uptime',             value: '99.9%'   },
];

export default function Login() {
  const { login, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || '/stats';

  const [email, setEmail]       = useState('admin@forenhive.io');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd]   = useState(false);
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);

  if (user) { navigate(from, { replace: true }); return null; }

  const handleSubmit = async e => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(email.trim(), password);
      navigate(from, { replace: true });
    } catch (ex) {
      setError(ex.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="lp-root">
      {/* ── LEFT PANEL ── */}
      <div className="lp-left">
        <div className="lp-left-inner">
          {/* brand */}
          <div className="lp-brand">
            <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
              <polygon points="20,2 37,11 37,29 20,38 3,29 3,11"
                stroke="#8C1A2B" strokeWidth="1.5" fill="rgba(140,26,43,0.12)" />
              <polygon points="20,9 31,15 31,25 20,31 9,25 9,15"
                stroke="#8C1A2B" strokeWidth="1" fill="none" opacity="0.5" />
              <text x="20" y="25" textAnchor="middle" fontSize="12"
                fontFamily="Rajdhani,sans-serif" fontWeight="700" fill="#8C1A2B">FH</text>
            </svg>
            <span className="lp-brand-name">FORENHIVE</span>
          </div>

          {/* headline */}
          <div className="lp-headline">
            <h1 className="lp-h1">Detect fast,<br />respond faster.</h1>
            <p className="lp-sub">
              Unified SOC platform — honeypot intelligence,<br />
              forensic analysis, and real-time threat visibility.
            </p>
          </div>

          {/* live stats */}
          <div className="lp-stats">
            {STATS.map(s => (
              <div key={s.label} className="lp-stat">
                <div className="lp-stat-val">{s.value}</div>
                <div className="lp-stat-label">{s.label}</div>
              </div>
            ))}
          </div>

          {/* decorative live indicator */}
          <div className="lp-live">
            <span className="lp-live-dot" />
            System operational · All sensors active
          </div>
        </div>

        {/* decorative hex grid overlay */}
        <div className="lp-hex-bg" aria-hidden="true" />
      </div>

      {/* ── RIGHT PANEL ── */}
      <div className="lp-right">
        <div className="lp-form-wrap">
          <div className="lp-form-head">
            <h2 className="lp-form-title">Sign in</h2>
            <p className="lp-form-sub">Enter your credentials to access the platform</p>
          </div>

          {error && <div className="alert err" style={{marginBottom:'16px'}}>{error}</div>}

          <form onSubmit={handleSubmit} style={{display:'flex',flexDirection:'column',gap:'14px'}}>
            <div className="form-g" style={{margin:0}}>
              <label className="form-l">Email</label>
              <input
                className="form-i"
                type="email"
                placeholder="admin@forenhive.io"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="form-g" style={{margin:0}}>
              <label className="form-l">Password</label>
              <div className="pwd-wrap">
                <input
                  className="form-i"
                  type={showPwd ? 'text' : 'password'}
                  placeholder="••••••••"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="pwd-toggle"
                  aria-label={showPwd ? 'Hide' : 'Show'}
                  onClick={() => setShowPwd(v => !v)}
                />
              </div>
            </div>
            <button
              type="submit"
              className="btn btn-gold btn-lg"
              disabled={loading}
              style={{width:'100%',justifyContent:'center',marginTop:'4px'}}
            >
              {loading ? '⟳ Signing in…' : 'Sign In →'}
            </button>
          </form>

          <div className="lp-hint">
            Default admin: <span style={{color:'var(--gold)'}}>admin@forenhive.io</span>
            {' / '}
            <span style={{color:'var(--gold)'}}>ChangeMe!2026</span>
          </div>

          <div className="lp-tags">
            <span className="lp-tag">TLS 1.3</span>
            <span className="lp-tag-dot">·</span>
            <span className="lp-tag">AES-256</span>
            <span className="lp-tag-dot">·</span>
            <span className="lp-tag">Zero Trust</span>
          </div>
        </div>
      </div>
    </div>
  );
}
