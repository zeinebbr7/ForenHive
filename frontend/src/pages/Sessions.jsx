import React, { useEffect, useState } from 'react'
import { formatDistanceToNow, format } from 'date-fns'
import api from '../services/api'

export default function Sessions() {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [active, setActive] = useState(0)
  const [loading, setLoading] = useState(true)
  const [activeOnly, setActiveOnly] = useState(false)
  const [selected, setSelected] = useState(null)
  const [detail, setDetail] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    api.get('/sessions', { params: { limit: 200, active_only: activeOnly } })
      .then(({ data }) => {
        setItems(data.items)
        setTotal(data.total)
        setActive(data.active)
      })
      .finally(() => setLoading(false))
  }, [activeOnly])

  useEffect(() => {
    if (!selected) { setDetail(null); return }
    setDetailLoading(true)
    api.get(`/sessions/${selected}`)
      .then(({ data }) => setDetail(data))
      .finally(() => setDetailLoading(false))
  }, [selected])

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Sessions</div>
          <div className="page-sub">{total} sessions · {active} active</div>
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, cursor: 'pointer' }}>
          <input type="checkbox" checked={activeOnly} onChange={e => setActiveOnly(e.target.checked)} />
          Active only
        </label>
      </div>

      <div className="two-col" style={{ alignItems: 'start' }}>
        <div className="card mb-0">
          {loading ? (
            <div className="loading">Loading…</div>
          ) : items.length === 0 ? (
            <div className="empty-state"><p>No sessions found.</p></div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Session ID</th>
                    <th>Honeypot</th>
                    <th>Source IP</th>
                    <th>Status</th>
                    <th>Started</th>
                    <th>Cmds</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map(s => (
                    <tr
                      key={s.session_id}
                      onClick={() => setSelected(s.session_id)}
                      style={{ cursor: 'pointer', background: selected === s.session_id ? 'var(--bg-2)' : '' }}
                    >
                      <td className="mono" style={{ fontSize: 11 }}>{s.session_id.slice(0, 12)}…</td>
                      <td><span className={`badge badge-${s.honeypot}`}>{s.honeypot}</span></td>
                      <td className="ip-link">{s.source_ip || '—'}</td>
                      <td><span className={`badge badge-${s.status}`}>{s.status}</span></td>
                      <td className="text-muted mono" style={{ fontSize: 11 }}>
                        {formatDistanceToNow(new Date(s.started_at), { addSuffix: true })}
                      </td>
                      <td className="mono">{s.command_count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="card mb-0">
          {!selected ? (
            <div className="empty-state"><p>Click a session to inspect it.</p></div>
          ) : detailLoading ? (
            <div className="loading">Loading…</div>
          ) : detail ? (
            <>
              <div className="card-title">Session detail</div>
              <table style={{ marginBottom: 16 }}>
                <tbody>
                  <tr><td className="text-muted" style={{ width: 120 }}>Session ID</td><td className="mono" style={{ fontSize: 11 }}>{detail.session_id}</td></tr>
                  <tr><td className="text-muted">Source IP</td><td className="ip-link">{detail.source_ip || '—'}</td></tr>
                  <tr><td className="text-muted">Honeypot</td><td><span className={`badge badge-${detail.honeypot}`}>{detail.honeypot}</span></td></tr>
                  <tr><td className="text-muted">Status</td><td><span className={`badge badge-${detail.status}`}>{detail.status}</span></td></tr>
                  <tr><td className="text-muted">Started</td><td className="mono" style={{ fontSize: 12 }}>{format(new Date(detail.started_at), 'yyyy-MM-dd HH:mm:ss')}</td></tr>
                  <tr><td className="text-muted">Duration</td><td>{detail.duration_seconds != null ? `${detail.duration_seconds.toFixed(1)} s` : '—'}</td></tr>
                  <tr><td className="text-muted">Username</td><td className="mono">{detail.username || '—'}</td></tr>
                  <tr><td className="text-muted">Auth attempts</td><td>{detail.auth_attempts}</td></tr>
                </tbody>
              </table>

              {detail.commands?.length > 0 && (
                <>
                  <div className="card-title">Commands ({detail.commands.length})</div>
                  <div style={{ background: 'var(--bg-0)', borderRadius: 6, padding: 12, fontFamily: 'monospace', fontSize: 12, maxHeight: 280, overflowY: 'auto' }}>
                    {detail.commands.map((c, i) => (
                      <div key={i} style={{ marginBottom: 4 }}>
                        <span className="text-muted" style={{ fontSize: 11 }}>{format(new Date(c.timestamp), 'HH:mm:ss')} </span>
                        <span style={{ color: c.success === false ? 'var(--red)' : 'var(--green)' }}>$ </span>
                        <span>{c.input}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}

              {detail.downloads?.length > 0 && (
                <>
                  <div className="card-title mt-4">Downloads</div>
                  {detail.downloads.map((d, i) => (
                    <div key={i} className="mono text-muted" style={{ fontSize: 12, marginBottom: 4 }}>{d}</div>
                  ))}
                </>
              )}
            </>
          ) : null}
        </div>
      </div>
    </>
  )
}
