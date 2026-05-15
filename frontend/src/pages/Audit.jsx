import React, { useState, useEffect, useCallback } from 'react';
import api from '../api';
import { fmt, esc } from '../utils';

const PAGE_SIZE = 25;

const ACTION_ICON = {
  'auth.login': '→', 'auth.logout': '←', 'user.create': '+', 'user.update': 'Edit',
  'user.delete': 'Del', 'report.generate': '⊟', 'report.download': '↓', 'config.update': '⚙',
};
const ROLE_COLORS = { admin: 'gold', analyst: 'blue', viewer: 'purple', user: 'purple' };

export default function Audit() {
  const [users, setUsers] = useState([]);
  const [auditStats, setAuditStats] = useState([]);
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  const loadUsers = async () => {
    try {
      const res = await api._call('/api/auth/users');
      setUsers(Array.isArray(res) ? res : []);
    } catch {}
  };

  const loadAuditStats = async () => {
    try {
      const data = await api._call('/api/audit?limit=50');
      const items = data.items || [];
      const agg = {};
      items.forEach(it => { agg[it.action] = (agg[it.action] || 0) + 1; });
      setAuditStats(Object.entries(agg).sort((a, b) => b[1] - a[1]));
    } catch {}
  };

  const loadAuditPage = useCallback(async (p) => {
    const offset = (p - 1) * PAGE_SIZE;
    try {
      const data = await api._call(`/api/audit?limit=${PAGE_SIZE}&offset=${offset}`);
      setRows(data.items || []);
      setTotal(data.total || 0);
      setPage(p);
    } catch {}
  }, []);

  const loadAll = useCallback(async () => {
    setLoading(true);
    await Promise.all([loadUsers(), loadAuditStats(), loadAuditPage(1)]);
    setLoading(false);
  }, [loadAuditPage]);

  useEffect(() => { loadAll(); }, [loadAll]);

  const pages = Math.ceil(total / PAGE_SIZE);
  const maxBar = auditStats[0]?.[1] || 1;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{marginBottom:'8px'}}>Audit</div>
          <h2 className="page-title">Journal <span>d'audit</span></h2>
          <div className="page-sub">Traçabilité des actions PostgreSQL · <span>{total}</span> entrées.</div>
        </div>
        <div className="page-actions">
          <button className="btn btn-gh btn-sm" onClick={loadAll}>Actualiser</button>
        </div>
      </div>

      <div className="grid-2 mb-20">
        <div className="card">
          <div className="card-h">
            <div className="card-t">Utilisateurs</div>
            <div className="card-sub">comptes enregistrés</div>
          </div>
          {users.length ? (
            <div style={{padding:'0 4px'}}>
              {users.map(u => {
                const roleColor = ROLE_COLORS[u.role] || 'purple';
                return (
                  <div key={u.id || u.email} style={{display:'grid',gridTemplateColumns:'40px 1fr auto',alignItems:'center',gap:'12px',padding:'12px 0',borderBottom:'1px solid rgba(255,255,255,.04)'}}>
                    <div style={{width:'36px',height:'36px',borderRadius:'50%',background:'rgba(255,185,5,.15)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:'16px'}}>
                      {u.role === 'admin' ? '⬡' : '◈'}
                    </div>
                    <div>
                      <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:'12px',color:'var(--text1)'}}>{u.email}</div>
                      <div style={{fontSize:'11px',color:'var(--text3)',marginTop:'2px'}}>{u.full_name || '—'}</div>
                      <div style={{fontSize:'10px',color:'var(--text3)',fontFamily:"'JetBrains Mono',monospace"}}>
                        Dernière connexion: {u.last_login_at ? fmt.ago(u.last_login_at) + ' ago' : 'jamais'}
                      </div>
                    </div>
                    <div style={{display:'flex',flexDirection:'column',gap:'4px',alignItems:'flex-end'}}>
                      <span className={`badge ${roleColor}`}>{u.role}</span>
                      <span className={`badge ${u.is_active ? 'teal' : 'red'}`} style={{fontSize:'9px'}}>{u.is_active ? 'actif' : 'inactif'}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="alert info">Aucun utilisateur.</div>
          )}
        </div>

        <div className="card">
          <div className="card-h">
            <div className="card-t">Actions par type</div>
            <div className="card-sub">résumé des 50 derniers logs</div>
          </div>
          {auditStats.length ? (
            <div style={{padding:'4px 0'}}>
              {auditStats.map(([action, count]) => (
                <div key={action} style={{display:'flex',alignItems:'center',gap:'8px',padding:'6px 0',borderBottom:'1px solid rgba(255,255,255,.04)'}}>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:'11px',color:'var(--text2)',minWidth:'160px'}}>
                    {ACTION_ICON[action] || ''} {action}
                  </div>
                  <div style={{flex:'1',height:'6px',background:'rgba(255,255,255,.06)',borderRadius:'3px',overflow:'hidden'}}>
                    <div style={{height:'100%',borderRadius:'3px',background:'var(--blue2)',width:`${(count/maxBar*100).toFixed(1)}%`}} />
                  </div>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:'11px',color:'var(--text3)',minWidth:'30px',textAlign:'right'}}>{count}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="alert info">Aucune action.</div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-h">
          <div className="card-t">Journal d'audit</div>
          <div className="card-sub">actions traçées depuis la base PostgreSQL</div>
        </div>
        <div style={{overflowX:'auto'}}>
          <table className="tbl">
            <thead>
              <tr><th>Horodatage</th><th>Acteur</th><th>Action</th><th>Méthode</th><th>Chemin</th><th>IP</th></tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6}><div className="alert info">Chargement…</div></td></tr>
              ) : rows.length ? rows.map((it, i) => {
                const icon = ACTION_ICON[it.action] || '';
                const isAuth = it.action.startsWith('auth.');
                return (
                  <tr key={i}>
                    <td className="mono" style={{fontSize:'11px'}}>{fmt.date(it.timestamp)}</td>
                    <td className="mono" style={{fontSize:'11px'}}>{it.actor_email || '—'}</td>
                    <td><span className={`badge ${isAuth ? 'blue' : 'gold'}`}>{icon} {it.action}</span></td>
                    <td className="mono" style={{fontSize:'11px'}}>{it.method || '—'}</td>
                    <td className="mono" style={{fontSize:'11px',maxWidth:'220px',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{it.path || '—'}</td>
                    <td className="mono" style={{fontSize:'11px'}}>{it.ip || '—'}</td>
                  </tr>
                );
              }) : (
                <tr><td colSpan={6}><div className="alert info">Aucun log.</div></td></tr>
              )}
            </tbody>
          </table>
        </div>
        {pages > 1 && (
          <div className="flex gap-8" style={{justifyContent:'center',padding:'14px'}}>
            {Array.from({length: pages}, (_, i) => i + 1).map(p => (
              <button key={p} className={`btn btn-sm ${p === page ? 'btn-gold' : 'btn-out'}`} onClick={() => loadAuditPage(p)}>{p}</button>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
