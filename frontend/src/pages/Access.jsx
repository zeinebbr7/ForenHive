import React, { useState, useEffect, useCallback, useRef } from 'react';
import { PieChart, Pie, Cell, Tooltip } from 'recharts';
import api from '../api';
import { fmt } from '../utils';
import { useModal } from '../contexts/ModalContext';
import { useAuth } from '../contexts/AuthContext';
import { useTranslation } from '../contexts/LanguageContext';

function LanguageToggle() {
  const { lang, setLang } = useTranslation();
  return (
    <div
      role="group"
      aria-label="Language"
      style={{
        display: 'inline-flex',
        border: '1px solid var(--border)',
        borderRadius: 6,
        overflow: 'hidden',
        fontFamily: "'Share Tech Mono',monospace",
        fontSize: 11,
      }}
    >
      {['en', 'fr'].map(code => {
        const active = lang === code;
        return (
          <button
            key={code}
            type="button"
            onClick={() => setLang(code)}
            aria-pressed={active}
            style={{
              padding: '6px 12px',
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
  );
}

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
  const { t } = useTranslation();
  const [email, setEmail]     = useState('');
  const [name, setName]       = useState('');
  const [pass, setPass]       = useState('');
  const [role, setRole]       = useState('analyst');
  const [submitting, setSub]  = useState(false);
  const [error, setError]     = useState(null);

  const roleHint = t('user_modal.hint.' + role);

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
      setError(err.message || t('user_modal.err_create'));
      setSub(false);
    }
  }

  return (
    <div>
      <div className="modal-h">
        <div className="card-t"> {t('user_modal.new')}</div>
        <button className="drawer-close" onClick={onClose}>×</button>
      </div>
      <form onSubmit={handleSubmit} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              {t('user_modal.email')} *
            </label>
            <input
              type="email" required value={email} onChange={e => setEmail(e.target.value)}
              placeholder={t('user_modal.email_placeholder')} className="form-i" style={{ fontSize: 13 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              {t('user_modal.full_name')}
            </label>
            <input
              type="text" value={name} onChange={e => setName(e.target.value)}
              placeholder={t('user_modal.name_placeholder')} className="form-i" style={{ fontSize: 13 }}
            />
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              {t('user_modal.password')} *
            </label>
            <input
              type="password" required value={pass} onChange={e => setPass(e.target.value)}
              placeholder={t('user_modal.pass_placeholder')} className="form-i" style={{ fontSize: 13 }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>
              {t('user_modal.role')}
            </label>
            <select value={role} onChange={e => setRole(e.target.value)} className="form-s" style={{ fontSize: 13 }}>
              <option value="analyst">ANALYST</option>
              <option value="admin">ADMIN</option>
            </select>
          </div>
        </div>

        <div style={{ padding: '10px 12px', borderRadius: 6, background: 'rgba(26,79,187,0.08)', border: '1px solid rgba(26,79,187,0.2)', fontSize: 11, color: 'var(--blue2)', fontFamily: "'Share Tech Mono',monospace" }}>
          {roleHint}
        </div>

        {error && <div className="alert err">{error}</div>}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4, borderTop: '1px solid var(--border)' }}>
          <button type="button" className="btn btn-gh btn-sm" onClick={onClose}>{t('common.cancel')}</button>
          <button type="submit" className="btn btn-gold btn-sm" disabled={submitting}>
            {submitting ? t('common.creating') : ' ' + t('user_modal.create')}
          </button>
        </div>
      </form>
    </div>
  );
}

function EditUserModal({ user, onClose, onSaved }) {
  const { t } = useTranslation();
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
      setError(err.message || t('user_modal.err_update'));
      setSub(false);
    }
  }

  return (
    <div>
      <div className="modal-h">
        <div className="card-t"> {t('user_modal.edit')}</div>
        <button className="drawer-close" onClick={onClose}>×</button>
      </div>
      <form onSubmit={handleSubmit} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>{t('user_modal.email')} *</label>
            <input type="email" required value={email} onChange={e => setEmail(e.target.value)} className="form-i" style={{ fontSize: 13 }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>{t('user_modal.full_name')}</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} className="form-i" style={{ fontSize: 13 }} />
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>{t('user_modal.new_password')}</label>
            <input type="password" value={pass} onChange={e => setPass(e.target.value)} placeholder={t('user_modal.pass_keep')} className="form-i" style={{ fontSize: 13 }} />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 11, fontWeight: 600, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 6 }}>{t('user_modal.role')}</label>
            <select value={role} onChange={e => setRole(e.target.value)} className="form-s" style={{ fontSize: 13 }}>
              <option value="analyst">ANALYST</option>
              <option value="admin">ADMIN</option>
            </select>
          </div>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text2)' }}>
          <input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)} />
          {t('user_modal.account_active')}
        </label>

        {error && <div className="alert err">{error}</div>}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4, borderTop: '1px solid var(--border)' }}>
          <button type="button" className="btn btn-gh btn-sm" onClick={onClose}>{t('common.cancel')}</button>
          <button type="submit" className="btn btn-gold btn-sm" disabled={submitting}>{submitting ? t('common.saving') : ' ' + t('user_modal.save')}</button>
        </div>
      </form>
    </div>
  );
}

export default function Access() {
  const { user: currentUser } = useAuth();
  const { openModal, closeModal } = useModal();
  const { t } = useTranslation();
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
    if (!window.confirm(t('access.confirm_delete', { email: u.email }))) return;
    try {
      await api.deleteUser(u.id);
      load();
    } catch (e) {
      alert(e.message || t('access.delete_failed'));
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}>{t('access.title')}</div>
          <h2 className="page-title">{t('access.title_html_1')} <span>{t('access.title_html_2')}</span></h2>
          <div className="page-sub">
            {t('access.subtitle')} <span className="mono">ADMIN</span> — {t('access.subtitle_admin')},{' '}
            <span className="mono">ANALYST</span> — {t('access.subtitle_analyst')}.
          </div>
        </div>
        <div className="page-actions" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <LanguageToggle />
          <button className="btn btn-gh btn-sm" onClick={load} disabled={loading}>{t('common.refresh')}</button>
          <button className="btn btn-gold btn-sm" onClick={openAddUser}>{t('access.add_user')}</button>
        </div>
      </div>

      <div className="fkpi-row">
        <div className="fkpi" style={{ borderColor: '#f0b42955' }}>
          <div className="fkpi-label">{t('access.kpi.total')}</div>
          <div className="fkpi-val" style={{ color: 'var(--gold)' }}>{loading ? '—' : kpiTotal}</div>
          <div className="fkpi-sub">{t('access.kpi.total_sub')}</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#ff505055' }}>
          <div className="fkpi-label">{t('access.kpi.admins')}</div>
          <div className="fkpi-val" style={{ color: '#ff5050' }}>{loading ? '—' : kpiAdmin}</div>
          <div className="fkpi-sub">{t('access.kpi.admins_sub')}</div>
        </div>
        <div className="fkpi" style={{ borderColor: '#3b82f655' }}>
          <div className="fkpi-label">{t('access.kpi.analysts')}</div>
          <div className="fkpi-val" style={{ color: '#3b82f6' }}>{loading ? '—' : kpiAnalyst}</div>
          <div className="fkpi-sub">{t('access.kpi.analysts_sub')}</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 16, alignItems: 'start' }}>

        {/* Users table */}
        <div className="card">
          <div className="card-h">
            <div>
              <div className="card-t">{t('access.users')}</div>
              <div className="card-sub">{t('access.users.sub')}</div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                className="form-i" type="search" placeholder={t('access.filter.placeholder')}
                value={search} onChange={e => setSearch(e.target.value)}
                style={{ width: 200, padding: '6px 10px', fontSize: 12 }}
              />
              <select
                className="form-s" value={roleFilter} onChange={e => setRoleFilter(e.target.value)}
                style={{ width: 120, padding: '6px 10px', fontSize: 12 }}
              >
                <option value="">{t('access.filter.all_roles')}</option>
                <option value="admin">{t('role.admin')}</option>
                <option value="analyst">{t('role.analyst')}</option>
              </select>
            </div>
          </div>
          <table className="tbl">
            <thead>
              <tr>
                <th>{t('access.col.user')}</th><th>{t('access.col.role')}</th><th>{t('access.col.status')}</th><th>{t('access.col.created')}</th><th>{t('access.col.last_login')}</th><th style={{ textAlign: 'right' }}>{t('access.col.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text3)' }}>{t('common.loading')}</td></tr>
              )}
              {error && (
                <tr><td colSpan={6}><div className="alert err" style={{ margin: 8 }}>{error} — {t('access.err_perm')}</div></td></tr>
              )}
              {!loading && !error && allItems.length === 0 && (
                <tr><td colSpan={6}><div className="alert info" style={{ margin: 8 }}>{t('access.empty')}</div></td></tr>
              )}
              {!loading && !error && filtered.length === 0 && allItems.length > 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text3)', fontSize: 12, fontFamily: "'Share Tech Mono',monospace" }}>{t('access.empty_filtered')}</td></tr>
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
                        {u.is_active === false ? '● ' + t('common.disabled') : '● ' + t('common.active')}
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
                        title={t('common.edit')}
                      >{t('common.edit')}</button>
                      <button
                        className="btn btn-gh btn-sm"
                        onClick={() => handleDelete(u)}
                        disabled={currentUser && (u.id === currentUser.id || u.email === currentUser.email)}
                        title={currentUser && (u.id === currentUser.id || u.email === currentUser.email) ? t('access.delete_self') : t('common.delete')}
                        style={{ color: 'var(--red2)', borderColor: 'rgba(201,61,85,0.4)' }}
                      >{t('common.delete')}</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

      </div>
    </>
  );
}
