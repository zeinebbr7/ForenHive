import React, { useState, useEffect } from 'react';
import api from '../api';
import { fmt, esc } from '../utils';
import { ROLES } from '../constants';

export default function Settings() {
  const [me, setMe] = useState(null);
  const [users, setUsers] = useState([]);
  const [error, setError] = useState('');
  const [prefs, setPrefs] = useState(() => {
    try { return JSON.parse(localStorage.getItem('fh.prefs') || '{}'); } catch { return {}; }
  });

  useEffect(() => {
    api.me().then(u => {
      setMe(u);
      if (u.role === 'admin') {
        api.users().then(res => {
          setUsers(Array.isArray(res) ? res : (res.items || []));
        }).catch(() => {});
      }
    }).catch(e => setError(e.message));
  }, []);

  const setPref = (key, value) => {
    const next = { ...prefs, [key]: value };
    setPrefs(next);
    localStorage.setItem('fh.prefs', JSON.stringify(next));
  };

  if (error) return <div className="alert err">{error}</div>;
  if (!me) return <div className="alert info">Loading…</div>;

  const role = ROLES[me.role] || ROLES.analyst;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{marginBottom:'8px'}}>⚙ Settings</div>
          <h2 className="page-title">User <span>Preferences</span></h2>
          <div className="page-sub">Profile, users (admin), sessions.</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-h"><div className="card-t">Profile</div></div>
          <div className="flex items-c gap-12 mb-20">
            <div className="prof-av" style={{width:'60px',height:'60px',fontSize:'28px'}}>{role.icon}</div>
            <div>
              <div className="card-t">{me.email.split('@')[0]}</div>
              <div className="text-3 mono" style={{fontSize:'11px'}}>{me.email}</div>
            </div>
          </div>
          <div className="form-g"><label className="form-l">Email</label><input className="form-i" value={me.email} disabled /></div>
          <div className="form-g"><label className="form-l">Role</label><input className="form-i" value={role.label} disabled /></div>
          <div className="form-g"><label className="form-l">Created</label><input className="form-i" value={me.created_at ? fmt.date(me.created_at) : '—'} disabled /></div>
        </div>

        <div className="card">
          <div className="card-h"><div className="card-t">Appearance</div></div>
          <div className="flex items-c" style={{justifyContent:'space-between',marginBottom:'14px'}}>
            <div>
              <b>Compact Sidebar</b>
              <div className="text-3 mono" style={{fontSize:'11px'}}>Reduces the width</div>
            </div>
            <label className="toggle">
              <input type="checkbox" checked={!!prefs.compact} onChange={e => setPref('compact', e.target.checked)} />
              <span className="toggle-slider" />
            </label>
          </div>
          <div className="form-g">
            <label className="form-l">Density</label>
            <select className="form-s" value={prefs.density || 'normal'} onChange={e => setPref('density', e.target.value)}>
              <option value="normal">Normal</option>
              <option value="compact">Compact</option>
              <option value="comfortable">Comfortable</option>
            </select>
          </div>
          <div className="form-g">
            <label className="form-l">Auto refresh (s)</label>
            <input className="form-i" type="number" value={prefs.refresh || 30} min="5" max="300"
              onChange={e => setPref('refresh', e.target.value)} />
          </div>
        </div>

        {me.role === 'admin' && (
          <div className="card" style={{gridColumn:'1/-1'}}>
            <div className="card-h">
              <div className="card-t">Users</div>
              <div className="card-sub">{users.length} user{users.length !== 1 ? 's' : ''}</div>
            </div>
            {users.length ? (
              <table className="tbl">
                <thead><tr><th>Email</th><th>Role</th><th>Active</th><th>Created</th><th>Last Login</th></tr></thead>
                <tbody>
                  {users.map(u => {
                    const r = ROLES[u.role] || ROLES.analyst;
                    return (
                      <tr key={u.id || u.email}>
                        <td className="mono">{u.email}</td>
                        <td><span className={`badge ${r.color}`}>{r.icon} {r.label}</span></td>
                        <td>{u.is_active === false
                          ? <span className="badge red">inactive</span>
                          : <span className="badge teal">active</span>}
                        </td>
                        <td className="mono" style={{fontSize:'11px'}}>{u.created_at ? fmt.date(u.created_at) : '—'}</td>
                        <td className="mono" style={{fontSize:'11px'}}>{u.last_login_at ? fmt.ago(u.last_login_at)+' ago' : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="alert info">No users.</div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
