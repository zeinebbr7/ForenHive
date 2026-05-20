import React, { useState, useEffect, useCallback, useRef } from 'react';
import { PieChart, Pie, Cell, Tooltip } from 'recharts';
import api from '../api';
import { fmt } from '../utils';
import { useModal } from '../contexts/ModalContext';
import { useAuth } from '../contexts/AuthContext';

const TOOLTIP_STYLE = {
  backgroundColor: '#0d111e', border: '1px solid #1e2538', borderRadius: '6px',
  fontFamily: "'JetBrains Mono',monospace", fontSize: '11px', color: '#e0e6f0',
};

const PERMS = [
  ['Dashboard',          true,  true ],
  ['Alerts / Incidents', true,  true ],
  ['Sessions',           true,  true ],
  ['Timeline',           true,  true ],
  ['Reconstruction',     true,  true ],
  ['Evidence Logs',      true,  true ],
  ['Profiling',          true,  true ],
  ['Geo Map',            true,  true ],
  ['Statistics',         true,  true ],
  ['Reporting',          true,  true ],
  ['Health Check',       true,  false],
  ['Honeypots',          true,  false],
  ['Access Control',     true,  false],
];

const ROLE_COL   = { ADMIN: '#8C1A2B', ANALYST: '#e8b84b', UNKNOWN: '#8892a4' };
const STATUS_COL = { Active: '#00bfa5', Disabled: '#c93d55' };

function roleBadge(r) {
  const role = (r || '').toLowerCase();
  if (role === 'admin')   return <span className="badge red"> ADMIN</span>;
  if (role === 'analyst') return <span className="badge gold"> ANALYST</span>;
  return <span className="badge gray">{role || '—'}</span>;
}

function initials(u) {
  if (u.full_name) return u.full_name.trim().split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase();
  return u.email[0].toUpperCase();
}

function avatarColor(role) {
  return (role || '').toLowerCase() === 'admin' ? 'var(--red2)' : 'var(--gold)';
}

function AcCharts({ users }) {
  if (!users.length) return null;

  const roleCounts = {};
  users.forEach(u => { const r = (u.role || 'unknown').toLowerCase(); roleCounts[r] = (roleCounts[r] || 0) + 1; });
  const roleData = Object.entries(roleCounts).map(([r, c]) => ({ name: r.toUpperCase(), count: c }));

  const activeCount   = users.filter(u => u.is_active !== false).length;
  const disabledCount = users.length - activeCount;
  const statusData    = [{ name: 'Active', count: activeCount }, ...(disabledCount ? [{ name: 'Disabled', count: disabledCount }] : [])];

  function MiniCard({ title, data, colorMap, donut }) {
    return (
      <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: '14px 16px' }}>
        <div style={{ fontSize: 10, color: 'var(--text3)', fontFamily: "'Share Tech Mono',monospace", textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 10 }}>
          {title}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {donut}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1 }}>
            {data.map((d, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: colorMap[d.name] || '#888', display: 'inline-block', flexShrink: 0 }} />
                <span style={{ fontSize: 12, flex: 1, color: 'var(--text2)' }}>{d.name}</span>
                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 12, color: 'var(--text3)' }}>{d.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  const roleDonut = (
    <PieChart width={110} height={110}>
      <Pie data={roleData} dataKey="count" nameKey="name" cx={50} cy={50} innerRadius={30} outerRadius={48} paddingAngle={2}>
        {roleData.map((d, i) => <Cell key={i} fill={ROLE_COL[d.name] || '#888'} />)}
      </Pie>
      <Tooltip contentStyle={TOOLTIP_STYLE} />
    </PieChart>
  );

  const statusDonut = (
    <PieChart width={110} height={110}>
      <Pie data={statusData} dataKey="count" nameKey="name" cx={50} cy={50} innerRadius={30} outerRadius={48} paddingAngle={2}>
        {statusData.map((d, i) => <Cell key={i} fill={STATUS_COL[d.name] || '#888'} />)}
      </Pie>
      <Tooltip contentStyle={TOOLTIP_STYLE} />
    </PieChart>
  );

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 12, marginBottom: 16 }}>
      <MiniCard title="Role Distribution" data={roleData} colorMap={ROLE_COL} donut={roleDonut} />
      <MiniCard title="Account Status" data={statusData} colorMap={STATUS_COL} donut={statusDonut} />
    </div>
  );
}

function AddUserModal({ onClose, onCreated }) {
  const [email, setEmail]     = useState('');
  const [name, setName]       = useState('');
  const [pass, setPass]       = useState('');
  const [role, setRole]       = useState('analyst');
  const [submitting, setSub]  = useState(false);
  const [error, setError]     = useState(null);

  const ROLE_HINTS = {
    analyst: 'ANALYST — access to forensic analysis, monitoring and reporting modules.',
    admin:   'ADMIN — full platform access including honeypot management and access control.',
  };

  async function handleSubmit(e) {
    e.preventDefault();
    setSub(true);
    setError(null);
    try {
      await api._call('/api/auth/users', {
        method: 'POST',
        body: {
          email:     email.trim(),
          password:  pass,
          full_name: name.trim() || null,
          role,
        },
      });
      onCreated();
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to create user.');
      setSub(false);
    }
  }

  return (
    <div>
      <div className="modal-h">
        <div className="card-t"> New User</div>
        <button className="drawer-close" onClick={onClose}>×</button>
      </div>
      <form onSubmit={handleSubmit} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              Email *
            </label>
            <input
              type="email" required value={email} onChange={e => setEmail(e.target.value)}
              placeholder="analyst@forenhive.io" className="form-i" style={{ fontSize: 13 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              Full Name
            </label>
            <input
              type="text" value={name} onChange={e => setName(e.target.value)}
              placeholder="Jane Doe" className="form-i" style={{ fontSize: 13 }}
            />
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              Password *
            </label>
            <input
              type="password" required value={pass} onChange={e => setPass(e.target.value)}
              placeholder="Min. 8 characters" className="form-i" style={{ fontSize: 13 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              Role
            </label>
            <select value={role} onChange={e => setRole(e.target.value)} className="form-s" style={{ fontSize: 13 }}>
              <option value="analyst">ANALYST</option>
              <option value="admin">ADMIN</option>
            </select>
          </div>
        </div>

        <div style={{ padding: '10px 12px', borderRadius: 6, background: 'rgba(26,79,187,0.08)', border: '1px solid rgba(26,79,187,0.2)', fontSize: 11, color: 'var(--blue2)', fontFamily: "'Share Tech Mono',monospace" }}>
          {ROLE_HINTS[role] || ''}
        </div>

        {error && <div className="alert err">{error}</div>}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4, borderTop: '1px solid var(--border)' }}>
          <button type="button" className="btn btn-gh btn-sm" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-gold btn-sm" disabled={submitting}>
            {submitting ? 'Creating…' : ' Create User'}
          </button>
        </div>
      </form>
    </div>
  );
}

function EditUserModal({ user, onClose, onSaved }) {
  const [email, setEmail]    = useState(user.email || '');
  const [name, setName]      = useState(user.full_name || '');
  const [pass, setPass]      = useState('');
  const [role, setRole]      = useState((user.role || 'analyst').toLowerCase());
  const [active, setActive]  = useState(user.is_active !== false);
  const [submitting, setSub] = useState(false);
  const [error, setError]    = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    setSub(true);
    setError(null);
    try {
      const body = {
        email:     email.trim(),
        full_name: name.trim() || null,
        role,
        is_active: active,
      };
      if (pass) body.password = pass;
      await api.updateUser(user.id, body);
      onSaved();
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to update user.');
      setSub(false);
    }
  }

  return (
    <div>
      <div className="modal-h">
        <div className="card-t"> Edit User</div>
        <button className="drawer-close" onClick={onClose}>×</button>
      </div>
      <form onSubmit={handleSubmit} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>Email *</label>
            <input type="email" required value={email} onChange={e => setEmail(e.target.value)} className="form-i" style={{ fontSize: 13 }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>Full Name</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} className="form-i" style={{ fontSize: 13 }} />
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>New Password</label>
            <input type="password" value={pass} onChange={e => setPass(e.target.value)} placeholder="Leave blank to keep current" className="form-i" style={{ fontSize: 13 }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>Role</label>
            <select value={role} onChange={e => setRole(e.target.value)} className="form-s" style={{ fontSize: 13 }}>
              <option value="analyst">ANALYST</option>
              <option value="admin">ADMIN</option>
            </select>
          </div>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text2)' }}>
          <input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)} />
          Account active
        </label>

        {error && <div className="alert err">{error}</div>}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4, borderTop: '1px solid var(--border)' }}>
          <button type="button" className="btn btn-gh btn-sm" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn btn-gold btn-sm" disabled={submitting}>{submitting ? 'Saving…' : ' Save Changes'}</button>
        </div>
      </form>
    </div>
  );
}

export default function Access() {
  const { user: currentUser } = useAuth();
  const { openModal, closeModal } = useModal();
  const [allItems, setAllItems]   = useState([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState(null);
  const [search, setSearch]       = useState('');
  const [roleFilter, setRoleFilter] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.users();
      setAllItems(Array.isArray(list) ? list : (list.items || []));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const kpiTotal   = allItems.length;
  const kpiAdmin   = allItems.filter(u => (u.role || '').toLowerCase() === 'admin').length;
  const kpiAnalyst = allItems.filter(u => (u.role || '').toLowerCase() === 'analyst').length;

  const filtered = allItems.filter(u => {
    if (roleFilter && (u.role || '').toLowerCase() !== roleFilter) return false;
    const q = search.toLowerCase();
    if (q && !u.email.toLowerCase().includes(q) && !(u.full_name || '').toLowerCase().includes(q)) return false;
    return true;
  });

  function openAddUser() {
    openModal(
      <AddUserModal
        onClose={closeModal}
        onCreated={load}
      />
    );
  }

  function openEditUser(u) {
    openModal(<EditUserModal user={u} onClose={closeModal} onSaved={load} />);
  }

  async function handleDelete(u) {
    if (!window.confirm(`Delete user ${u.email}? This cannot be undone.`)) return;
    try {
      await api.deleteUser(u.id);
      load();
    } catch (e) {
      alert(e.message || 'Failed to delete user.');
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>Access Control</div>
          <h2 className="page-title">Access <span>Control</span></h2>
          <div className="page-sub">
            RBAC · JWT tokens · Roles: <span className="mono">ADMIN</span> — full platform,{' '}
            <span className="mono">ANALYST</span> — forensic + monitoring.
          </div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={load} disabled={loading}>↺ Refresh</button>
          <button className="btn btn-gold btn-sm" onClick={openAddUser}> Add User</button>
        </div>
      </div>

      <div className="fkpi-row">
        <div className="fkpi" style={{ borderColor: '#f0b42955' }}>
          <div className="fkpi-label">Total Users</div>
          <div className="fkpi-val" style={{ color: 'var(--gold)' }}>{loading ? '—' : kpiTotal}</div>
          <div className="fkpi-sub">registered accounts</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#ff505055' }}>
          <div className="fkpi-label">Admins</div>
          <div className="fkpi-val" style={{ color: '#ff5050' }}>{loading ? '—' : kpiAdmin}</div>
          <div className="fkpi-sub">full platform access</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#3b82f655' }}>
          <div className="fkpi-label">Analysts</div>
          <div className="fkpi-val" style={{ color: '#3b82f6' }}>{loading ? '—' : kpiAnalyst}</div>
          <div className="fkpi-sub">forensic + monitoring</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 16, alignItems: 'start' }}>

        {/* Users table */}
        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">Users</div>
              <div className="card-sub">Account list · role · activity</div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                className="form-i" type="search" placeholder="Filter by email or name…"
                value={search} onChange={e => setSearch(e.target.value)}
                style={{ width: 200, padding: '6px 10px', fontSize: 12 }}
              />
              <select
                className="form-s" value={roleFilter} onChange={e => setRoleFilter(e.target.value)}
                style={{ width: 120, padding: '6px 10px', fontSize: 12 }}
              >
                <option value="">All roles</option>
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
              </select>
            </div>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th>User</th><th>Role</th><th>Status</th><th>Created</th><th>Last Login</th><th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text3)' }}>Loading…</td></tr>
              )}
              {error && (
                <tr><td colSpan={6}><div className="alert err" style={{ margin: 8 }}>{error} — user management requires the ADMIN role.</div></td></tr>
              )}
              {!loading && !error && allItems.length === 0 && (
                <tr><td colSpan={6}><div className="alert info" style={{ margin: 8 }}>No users — the admin bootstrap account is created on first backend startup.</div></td></tr>
              )}
              {!loading && !error && filtered.length === 0 && allItems.length > 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text3)', fontSize: 12, fontFamily: "'Share Tech Mono',monospace" }}>No users match the current filter.</td></tr>
              )}
              {!loading && !error && filtered.map((u, i) => {
                const lastLogin = u.last_login_at || u.last_login;
                return (
                  <tr key={u.id || u.email || i}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{
                          width: 32, height: 32, borderRadius: '50%',
                          background: avatarColor(u.role), color: '#060810',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 11, fontWeight: 700, fontFamily: "'Rajdhani',sans-serif", flexShrink: 0,
                        }}>
                          {initials(u)}
                        </div>
                        <div>
                          <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text)' }}>
                            {u.full_name || u.email.split('@')[0]}
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: "'Share Tech Mono',monospace" }}>
                            {u.email}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>{roleBadge(u.role)}</td>
                    <td>
                      <span className={`badge ${u.is_active === false ? 'gray' : 'teal'}`}>
                        {u.is_active === false ? '● Disabled' : '● Active'}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text3)' }}>{fmt.date(u.created_at)}</td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text3)' }}>
                      {lastLogin ? fmt.ago(lastLogin) + ' ago' : '—'}
                    </td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <button
                        className="btn btn-gh btn-sm"
                        style={{ marginRight: 6 }}
                        onClick={() => openEditUser(u)}
                        title="Edit user"
                      >Edit</button>
                      <button
                        className="btn btn-gh btn-sm"
                        onClick={() => handleDelete(u)}
                        disabled={currentUser && (u.id === currentUser.id || u.email === currentUser.email)}
                        title={currentUser && (u.id === currentUser.id || u.email === currentUser.email) ? "You can't delete yourself" : 'Delete user'}
                        style={{ color: 'var(--red2)', borderColor: 'rgba(201,61,85,0.4)' }}
                      >Delete</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Roles & Permissions matrix */}
        <div className="card">
          <div className="card-h">
            <div className="card-t">Roles &amp; Permissions</div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 40px 40px', gap: 4, padding: '6px 0', borderBottom: '1px solid var(--border)', marginBottom: 4 }}>
              <span style={{ fontSize: 9, color: 'var(--text3)', fontFamily: "'Share Tech Mono',monospace", textTransform: 'uppercase', letterSpacing: '1px' }}>Feature</span>
              <span style={{ fontSize: 9, color: 'var(--red2)', fontFamily: "'Share Tech Mono',monospace", textTransform: 'uppercase', textAlign: 'center' }}>ADM</span>
              <span style={{ fontSize: 9, color: 'var(--gold)', fontFamily: "'Share Tech Mono',monospace", textTransform: 'uppercase', textAlign: 'center' }}>ANL</span>
            </div>
            {PERMS.map(([label, adm, anl], i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 40px 40px', gap: 4, padding: '7px 0', borderBottom: '1px solid rgba(140,26,43,0.05)' }}>
                <span style={{ fontSize: 12, color: 'var(--text2)' }}>{label}</span>
                <span style={{ textAlign: 'center', fontSize: 13 }}>
                  {adm ? <span style={{ color: 'var(--blue2)' }}>✓</span> : <span style={{ color: 'var(--border2)' }}>—</span>}
                </span>
                <span style={{ textAlign: 'center', fontSize: 13 }}>
                  {anl ? <span style={{ color: 'var(--blue2)' }}>✓</span> : <span style={{ color: 'var(--border2)' }}>—</span>}
                </span>
              </div>
            ))}
          </div>
        </div>

      </div>
    </>
  );
}
