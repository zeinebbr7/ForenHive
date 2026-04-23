import React, { useEffect, useState } from 'react'
import { format } from 'date-fns'
import api from '../services/api'

const SCOPES = ['ip', 'session', 'time_range']

function fmtBytes(b) {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(1)} MB`
}

export default function Reports() {
  const [reports, setReports] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [error, setError] = useState('')

  const [scope, setScope] = useState('ip')
  const [ip, setIp] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [title, setTitle] = useState('')
  const [includeStix, setIncludeStix] = useState(false)

  const user = (() => { try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} } })()

  function loadReports() {
    setLoading(true)
    api.get('/reports')
      .then(({ data }) => { setReports(data.items); setTotal(data.total) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadReports() }, [])

  async function generate(e) {
    e.preventDefault()
    setError('')
    setGenerating(true)
    try {
      const body = { scope, include_stix: includeStix, analyst: user.email }
      if (title) body.title = title
      if (scope === 'ip') body.ip = ip
      if (scope === 'session') body.session_id = sessionId
      if (scope === 'time_range') { body.date_from = dateFrom; body.date_to = dateTo }
      await api.post('/reports/generate', body)
      setShowForm(false)
      loadReports()
    } catch (err) {
      setError(err.response?.data?.detail || 'Generation failed')
    } finally {
      setGenerating(false)
    }
  }

  async function downloadStix(id) {
    const { data } = await api.post(`/reports/${id}/stix`)
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `${id}.stix.json`; a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Reports</div>
          <div className="page-sub">{total} forensic reports</div>
        </div>
        <button className="btn btn-primary" onClick={() => setShowForm(f => !f)}>
          {showForm ? '✕ Cancel' : '+ New report'}
        </button>
      </div>

      {showForm && (
        <div className="card">
          <div className="card-title">Generate report</div>
          <form onSubmit={generate} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, alignItems: 'end' }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label>Scope</label>
              <select value={scope} onChange={e => setScope(e.target.value)}
                style={{ width: '100%', background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '10px 14px', borderRadius: 7, fontSize: 14 }}>
                {SCOPES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label>Title (optional)</label>
              <input value={title} onChange={e => setTitle(e.target.value)} placeholder="Auto-generated if empty"
                style={{ width: '100%', background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '10px 14px', borderRadius: 7, fontSize: 14 }} />
            </div>

            {scope === 'ip' && (
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Source IP</label>
                <input value={ip} onChange={e => setIp(e.target.value)} required placeholder="1.2.3.4"
                  style={{ width: '100%', background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '10px 14px', borderRadius: 7, fontSize: 14 }} />
              </div>
            )}

            {scope === 'session' && (
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label>Session ID</label>
                <input value={sessionId} onChange={e => setSessionId(e.target.value)} required
                  style={{ width: '100%', background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '10px 14px', borderRadius: 7, fontSize: 14 }} />
              </div>
            )}

            {scope === 'time_range' && (
              <>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label>From</label>
                  <input type="datetime-local" value={dateFrom} onChange={e => setDateFrom(e.target.value)} required
                    style={{ width: '100%', background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '10px 14px', borderRadius: 7, fontSize: 14 }} />
                </div>
                <div className="form-group" style={{ marginBottom: 0 }}>
                  <label>To</label>
                  <input type="datetime-local" value={dateTo} onChange={e => setDateTo(e.target.value)} required
                    style={{ width: '100%', background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '10px 14px', borderRadius: 7, fontSize: 14 }} />
                </div>
              </>
            )}

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
              <input type="checkbox" id="stix" checked={includeStix} onChange={e => setIncludeStix(e.target.checked)} />
              <label htmlFor="stix">Include STIX 2.1 bundle</label>
            </div>

            <div>
              {error && <div className="form-error" style={{ marginBottom: 8 }}>{error}</div>}
              <button type="submit" className="btn btn-primary" disabled={generating}>
                {generating ? 'Generating…' : 'Generate PDF'}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="card mb-0">
        {loading ? (
          <div className="loading">Loading…</div>
        ) : reports.length === 0 ? (
          <div className="empty-state"><p>No reports generated yet.</p></div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Scope</th>
                  <th>Created</th>
                  <th>Events</th>
                  <th>Size</th>
                  <th>SHA-256</th>
                  <th>TSA</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.id}>
                    <td style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.title}</td>
                    <td><span className="badge badge-cowrie">{r.scope}</span></td>
                    <td className="mono text-muted" style={{ fontSize: 11 }}>
                      {format(new Date(r.created_at), 'yyyy-MM-dd HH:mm')}
                    </td>
                    <td className="mono">{r.event_count}</td>
                    <td className="text-muted">{fmtBytes(r.size_bytes)}</td>
                    <td className="mono text-muted" style={{ fontSize: 10 }}>{r.sha256?.slice(0, 16)}…</td>
                    <td>
                      {r.tsa_timestamp ? (
                        <span className="text-green" title={r.tsa_timestamp}>✓ TSA</span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <a
                          href={`/api/reports/${r.id}/download`}
                          target="_blank"
                          rel="noreferrer"
                          className="btn btn-secondary"
                          style={{ padding: '4px 10px', fontSize: 12 }}
                        >
                          PDF
                        </a>
                        {r.stix_path && (
                          <button
                            className="btn btn-outline"
                            style={{ padding: '4px 10px', fontSize: 12 }}
                            onClick={() => downloadStix(r.id)}
                          >
                            STIX
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
