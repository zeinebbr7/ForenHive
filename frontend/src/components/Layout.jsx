import React, { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTranslation } from '../contexts/LanguageContext';
import { NAV_GROUPS, NAV, ROLES } from '../constants';

const SECTION_KEYS = {
  'Monitoring':            'nav.section.monitoring',
  'Forensic Analysis':     'nav.section.forensic_analysis',
  'Threat Intelligence':   'nav.section.threat_intel',
  'Reports':               'nav.section.reports',
  'Honeypot Management':   'nav.section.honeypot_mgmt',
  'Access Control':        'nav.section.access_control',
};
function LiveClock() {
  const [time, setTime] = useState(() => new Date().toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}));
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false})), 1000);
    return () => clearInterval(id);
  }, []);
  return <span>{time}</span>;
}

function ThemeToggle() {
  const [theme, setTheme] = useState(() => localStorage.getItem('fh.theme') || 'dark');
  const toggle = () => {
    const next = theme === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('fh.theme', next);
    setTheme(next);
  };
  return (
    <button className="theme-toggle" onClick={toggle} title="Toggle light/dark theme" aria-label="Toggle theme">
      <span className="ic-moon">☾</span><span className="ic-sun">☀</span>
    </button>
  );
}

export default function Layout() {
  const { user, logout } = useAuth();
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    import('./hive-chat.js').catch(() => {});
  }, []);

  const role = ROLES[user?.role] || ROLES.analyst;
  const currentPage = NAV.find(n => location.pathname === '/' + n.id);
  const currentGroup = NAV_GROUPS.find(g => g.items?.some(n => location.pathname === '/' + n.id));

  const visibleGroups = NAV_GROUPS.map(g => ({
    ...g,
    items: g.items.filter(n => n.roles.includes(user?.role)),
  })).filter(g => g.items.length > 0);

  return (
    <div className="app-wrap">
      <aside className={`sidebar${sidebarOpen ? ' open' : ''}`} id="sidebar">
        <div className="sb-brand">
          <span className="sb-brand-name">FORENHIVE</span>
          <span className="sb-brand-badge">v1.0</span>
        </div>
        <div className={`sb-role ${user?.role}`}>
          <span className="sb-role-dot" />
          {t('role.' + (user?.role || 'analyst'))}
        </div>
        <nav className="sb-nav">
          {visibleGroups.map(group => (
            <React.Fragment key={group.label || '__root'}>
              {group.label && <div className="sb-section">{t(SECTION_KEYS[group.label] || group.label)}</div>}
              {group.items.map(n => (
                <NavLink
                  key={n.id}
                  to={'/' + n.id}
                  className={({ isActive }) => 'sb-item' + (isActive ? ' active' : '')}
                  onClick={() => setSidebarOpen(false)}
                >
                  <span className="sb-item-ic">{n.icon}</span>
                  <span>{t('nav.' + n.id)}</span>
                </NavLink>
              ))}
            </React.Fragment>
          ))}
        </nav>
        <button className="sb-logout" onClick={logout}> {t('topbar.signout')}</button>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="tb-left">
            <button className="burger" onClick={() => setSidebarOpen(o => !o)} />
            <div className="tb-page">
              {currentGroup?.label && (
                <div className="tb-group">{t(SECTION_KEYS[currentGroup.label] || currentGroup.label)}</div>
              )}
              <h1 className="tb-title">{currentPage ? t('nav.' + currentPage.id) : 'ForenHive'}</h1>
              {currentPage?.sub && (
                <div className="tb-sub">{t('nav.' + currentPage.id + '.sub')}</div>
              )}
            </div>
          </div>
          <div className="tb-right">
            <ThemeToggle />
            <div className="tb-live">
              <span className="tb-live-dot" />
              {t('topbar.live')} · <LiveClock />
            </div>
            <div className="tb-user">
              <div className="tb-avatar"></div>
              <div className="tb-user-info">
                <div className="tb-name">{user?.email?.split('@')[0] || '—'}</div>
                <div className="tb-role">{t('role.' + (user?.role || 'analyst'))}</div>
              </div>
            </div>
          </div>
        </header>
        <main className="page visible">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
