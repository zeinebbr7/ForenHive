import React, { useEffect, useRef, useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
} from 'recharts'
import { format } from 'date-fns'
import api from '../services/api'

const HONEYPOT_COLORS = {
  cowrie: '#58a6ff',
  dionaea: '#3fb950',
  galah: '#d29922',
  zeek: '#a371f7',
}

function severityColor(s) {
  return { low: '#3fb950', medium: '#d29922', high: '#f85149', critical: '#a371f7' }[s] || '#8b949e'
}

export default function Dashboard() {
  const [stats, setStats] = useState({ total: 0, eps: 0 })
  const [hourly, setHourly] = useState([])
  const [countries, setCountries] = useState([])
  const [split, setSplit] = useState([])
  const [recent, setRecent] = useState([])
  const [loading, setLoading] = useState(true)
  const evtSource = useRef(null)

  useEffect(() => {
    Promise.all([
      api.get('/attacks/stats/hourly?hours=24'),
      api.get('/geo/breakdown?top=10'),
      api.get('/geo/honeypot-split'),
      api.get('/attacks?page_size=10'),
    ]).then(([h, g, s, r]) => {
      setHourly(h.data.map(b => ({
        hour: format(new Date(b.hour), 'HH:mm'),
        total: b.count,
        ...b.by_honeypot,
      })))
      setCountries(g.data.countries || [])
      setSplit(
        Object.entries(s.data.split || {}).map(([name, count]) => ({ name, count }))
      )
      setRecent(r.data.items || [])
    }).finally(() => setLoading(false))

    // SSE live counter
    evtSource.current = new EventSource('/api/attacks/stats/live?window=60')
    evtSource.current.addEventListener('tick', e => {
      const d = JSON.parse(e.data)
      setStats({ total: d.count, eps: d.events_per_second })
    })
    return () => evtSource.current?.close()
  }, [])

  if (loading) return <div className="loading">Loading…</div>

  const totalLast24 = hourly.reduce((s, b) => s + (b.total || 0), 0)

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Dashboard</div>
          <div className="page-sub">Live honeypot telemetry</div>
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-2)' }}>
          <span className="live-dot" />
          {stats.eps} events/s
        </div>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">Events last 60 s</div>
          <div className="stat-value blue">{stats.total.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Events last 24 h</div>
          <div className="stat-value">{totalLast24.toLocaleString()}</div>
        </div>
        {split.map(s => (
          <div className="stat-card" key={s.name}>
            <div className="stat-label">{s.name}</div>
            <div className="stat-value" style={{ color: HONEYPOT_COLORS[s.name] || '#8b949e' }}>
              {s.count.toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-title">Attacks — 24 h</div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={hourly} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#58a6ff" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#58a6ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
              <XAxis dataKey="hour" tick={{ fill: '#8b949e', fontSize: 11 }} />
              <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6 }}
                labelStyle={{ color: '#e6edf3' }}
                itemStyle={{ color: '#8b949e' }}
              />
              <Area type="monotone" dataKey="total" stroke="#58a6ff" fill="url(#ga)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="card-title">By honeypot</div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={split} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#30363d" />
              <XAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 12 }} />
              <YAxis tick={{ fill: '#8b949e', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6 }}
                itemStyle={{ color: '#8b949e' }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {split.map(s => (
                  <Cell key={s.name} fill={HONEYPOT_COLORS[s.name] || '#58a6ff'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="two-col">
        <div className="card">
          <div className="card-title">Top source countries</div>
          {countries.length === 0 ? (
            <div className="empty-state"><p>No data</p></div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Country</th>
                  <th style={{ textAlign: 'right' }}>Events</th>
                </tr>
              </thead>
              <tbody>
                {countries.slice(0, 10).map(c => (
                  <tr key={c.country_iso || c.country_name}>
                    <td>{c.country_name || c.country_iso || '—'}</td>
                    <td style={{ textAlign: 'right', fontFamily: 'monospace' }}>{c.count?.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-title">Recent attacks</div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Honeypot</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {recent.map(ev => (
                  <tr key={ev.id}>
                    <td className="text-muted mono">{format(new Date(ev.timestamp), 'HH:mm:ss')}</td>
                    <td><span className="ip-link">{ev.source_ip || '—'}</span></td>
                    <td>
                      <span className={`badge badge-${ev.honeypot}`}>{ev.honeypot}</span>
                    </td>
                    <td>
                      <span
                        className="badge"
                        style={{ background: severityColor(ev.severity) + '22', color: severityColor(ev.severity) }}
                      >
                        {ev.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}
