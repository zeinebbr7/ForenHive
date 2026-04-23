import React, { useCallback, useEffect, useState } from 'react'
import { format } from 'date-fns'
import api from '../services/api'

const HONEYPOTS = ['', 'cowrie', 'dionaea', 'galah', 'zeek']
const SEVERITIES = ['', 'low', 'medium', 'high', 'critical']

function riskColor(score) {
  if (score >= 80) return 'var(--purple)'
  if (score >= 60) return 'var(--red)'
  if (score >= 30) return 'var(--orange)'
  return 'var(--green)'
}

export default function Attacks() {
  const [items, setItems] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)

  const [ip, setIp] = useState('')
  const [honeypot, setHoneypot] = useState('')
  const [severity, setSeverity] = useState('')

  const PAGE_SIZE = 50

  const load = useCallback(async (p = 1) => {
    setLoading(true)
    try {
      const params = { page: p, page_size: PAGE_SIZE }
      if (ip) params.ip = ip
      if (honeypot) params.honeypot = honeypot
      if (severity) params.severity = severity
      const { data } = await api.get('/attacks', { params })
      setItems(data.items)
      setTotal(data.total)
      setPage(p)
    } finally {
      setLoading(false)
    }
  }, [ip, honeypot, severity])

  useEffect(() => { load(1) }, [load])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Attack Events</div>
          <div className="page-sub">{total.toLocaleString()} total events</div>
        </div>
      </div>

      <div className="filters">
        <input
          placeholder="Filter by IP…"
          value={ip}
          onChange={e => setIp(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
          style={{ width: 180 }}
        />
        <select value={honeypot} onChange={e => setHoneypot(e.target.value)}>
          {HONEYPOTS.map(h => <option key={h} value={h}>{h || 'All honeypots'}</option>)}
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)}>
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
        </select>
        <button className="btn btn-secondary" onClick={() => load(1)}>Apply</button>
        <button className="btn btn-outline" onClick={() => { setIp(''); setHoneypot(''); setSeverity('') }}>
          Reset
        </button>
      </div>

      <div className="card mb-0">
        {loading ? (
          <div className="loading">Loading…</div>
        ) : items.length === 0 ? (
          <div className="empty-state"><p>No attack events match these filters.</p></div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Honeypot</th>
                  <th>Protocol</th>
                  <th>Dest port</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Event type</th>
                </tr>
              </thead>
              <tbody>
                {items.map(ev => (
                  <tr key={ev.id}>
                    <td className="mono text-muted">
                      {format(new Date(ev.timestamp), 'yyyy-MM-dd HH:mm:ss')}
                    </td>
                    <td>
                      <span className="ip-link">{ev.source_ip || '—'}</span>
                    </td>
                    <td><span className={`badge badge-${ev.honeypot}`}>{ev.honeypot}</span></td>
                    <td className="text-muted">{ev.protocol || '—'}</td>
                    <td className="mono">{ev.dest_port ?? '—'}</td>
                    <td>
                      <span className={`badge badge-${ev.severity}`}>{ev.severity}</span>
                    </td>
                    <td>
                      {ev.risk_score != null ? (
                        <span style={{ color: riskColor(ev.risk_score), fontWeight: 600, fontFamily: 'monospace' }}>
                          {ev.risk_score}
                        </span>
                      ) : '—'}
                    </td>
                    <td className="text-muted" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ev.event_type || ev.http_path || ev.command || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="pagination">
          <button onClick={() => load(page - 1)} disabled={page <= 1}>←</button>
          <span>Page {page} / {totalPages}</span>
          <button onClick={() => load(page + 1)} disabled={page >= totalPages}>→</button>
        </div>
      </div>
    </>
  )
}
