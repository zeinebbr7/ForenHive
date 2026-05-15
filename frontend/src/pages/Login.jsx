import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

export default function Login() {
  const { login, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || '/stats';

  const [email, setEmail] = useState('admin@forenhive.io');
  const [password, setPassword] = useState('');
  const [showPwd, setShowPwd] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  if (user) {
    navigate(from, { replace: true });
    return null;
  }

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
    <div style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center'}}>
      <div className="login-glow" />
      <div className="login-wrap">
        <div className="login-card">
          <div className="login-brand">
            <span className="login-hex" />
            <div className="login-name">FORENHIVE</div>
            <div className="login-sub">SOC PLATFORM · v1.0</div>
          </div>

          {error && <div className="alert err">{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-g">
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
            <div className="form-g">
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
              style={{width:'100%',justifyContent:'center',marginTop:'6px'}}
            >
              {loading ? '⟳ Signing in…' : 'Sign In →'}
            </button>
          </form>

          <div style={{textAlign:'center',marginTop:'16px',fontSize:'11px',color:'var(--text3)',fontFamily:"'JetBrains Mono',monospace",letterSpacing:'1px'}}>
            Default admin: <span className="mono" style={{color:'var(--gold)'}}>admin@forenhive.io</span> / <span className="mono" style={{color:'var(--gold)'}}>ChangeMe!2026</span>
          </div>
        </div>
      </div>
    </div>
  );
}
