import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'

const NAV = [
  { to: '/',          label: 'Dashboard',  icon: '⬛' },
  { to: '/attacks',   label: 'Attacks',    icon: '⚡' },
  { to: '/sessions',  label: 'Sessions',   icon: '🔗' },
  { to: '/forensics', label: 'Forensics',  icon: '🔬' },
  { to: '/reports',   label: 'Reports',    icon: '📄' },
]

export default function Sidebar() {
  const navigate = useNavigate()
  const raw = localStorage.getItem('user')
  const user = raw ? JSON.parse(raw) : null

  function logout() {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    navigate('/login')
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">Foren<span>Hive</span></div>
      <ul className="sidebar-nav">
        {NAV.map(({ to, label, icon }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={to === '/'}
              className={({ isActive }) => isActive ? 'active' : ''}
            >
              <span>{icon}</span>
              {label}
            </NavLink>
          </li>
        ))}
      </ul>
      <div className="sidebar-footer">
        <div className="sidebar-user">{user?.email || 'Analyst'}</div>
        <div className="text-muted" style={{ fontSize: 11, marginTop: 2 }}>{user?.role || ''}</div>
        <button className="logout-btn" onClick={logout}>Sign out</button>
      </div>
    </aside>
  )
}
