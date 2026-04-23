import React, { useEffect, useState } from 'react'
import { format } from 'date-fns'
import api from '../services/api'

const MITRE_TACTIC_COLORS = {
  'Reconnaissance': '#a371f7',
  'Initial Access': '#f85149',
  'Execution': '#d29922',
  'Credential Access': '#f0883e',
  'Lateral Movement': '#58a6ff',
  'Command and Control': '#3fb950',
  'Impact': '#ff7b72',
  'Discovery': '#79c0ff',
}

function tacticColor(tactic) {
  return MITRE_TACTIC_COLORS[tactic] || '#8b949e'
}

export default function Forensics() {
  const [yaraResults, setYaraResults] = useState([])
  const [yaraLoading, setYaraLoading] = useState(true)
  const [timelineIp, setTimelineIp] = useState('')
  const [timeline, setTimeline] = useState([])
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [profile, setProfile] = useState(null)
  const [profileLoading, setProfileLoading] = useState(false)
  const [profileIp, setProfileIp] = useState('')

  useEffect(() => {
    api.get('/forensics/yara?limit=100')
      .then(({ data }) => setYaraResults(data.results || []))
      .finally(() => setYaraLoading(false))
  }, [])

  async function loadTimeline() {
    if (!timelineIp.trim()) return
    setTimelineLoading(true)
    setTimeline([])
    try {
      const { data } = await api.get('/forensics/timeline', {
        params: { ip: timelineIp.trim(), limit: 200 },
      })
      setTimeline(data.events || [])
    } finally {
      setTimelineLoading(false)
    }
  }

  async function loadProfile() {
    if (!profileIp.trim()) return
    setProfileLoading(true)
    setProfile(null)
    try {
      const { data } = await api.get(`/profiling/${profileIp.trim()}`)
      setProfile(data)
    } finally {
      setProfileLoading(false)
    }
  }

  const detections = yaraResults.filter(r => r.matched)

  return (
    <>
      <div className="page-header">
        <div>
          <div className="page-title">Forensics</div>
          <div className="page-sub">YARA · MITRE ATT&CK · Timeline · Attacker Profiling</div>
        </div>
      </div>

      {/* YARA */}
      <div className="card">
        <div className="card-title">YARA scan results — Dionaea malware binaries</div>
        {yaraLoading ? (
          <div className="loading">Scanning…</div>
        ) : yaraResults.length === 0 ? (
          <div className="empty-state"><p>No binaries captured yet.</p></div>
        ) : (
          <>
            <div className="stat-grid" style={{ marginBottom: 16 }}>
              <div className="stat-card">
                <div className="stat-label">Files scanned</div>
                <div className="stat-value">{yaraResults.length}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Detections</div>
                <div className="stat-value red">{detections.length}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Clean</div>
                <div className="stat-value green">{yaraResults.length - detections.length}</div>
              </div>
            </div>

            {detections.length > 0 && (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>SHA-256</th>
                      <th>Rules matched</th>
                      <th>Namespace</th>
                      <th>VT result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detections.map(r => (
                      <tr key={r.sha256}>
                        <td className="mono" style={{ fontSize: 11 }}>{r.sha256?.slice(0, 20)}…</td>
                        <td>
                          {(r.matches || []).map((m, i) => (
                            <span key={i} className="badge badge-high" style={{ marginRight: 4 }}>{m.rule}</span>
                          ))}
                        </td>
                        <td className="text-muted">{r.matches?.[0]?.namespace || '—'}</td>
                        <td>
                          {r.virustotal ? (
                            <span className="text-red">
                              {r.virustotal.malicious ?? '?'} / {r.virustotal.total ?? '?'} engines
                            </span>
                          ) : (
                            <span className="text-muted">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>

      <div className="two-col" style={{ alignItems: 'start' }}>
        {/* Timeline */}
        <div className="card mb-0">
          <div className="card-title">Forensic timeline</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <input
              placeholder="Source IP…"
              value={timelineIp}
              onChange={e => setTimelineIp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && loadTimeline()}
              className="filters"
              style={{ flex: 1, background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '7px 12px', borderRadius: 6, fontSize: 13, outline: 'none' }}
            />
            <button className="btn btn-secondary" onClick={loadTimeline} disabled={timelineLoading}>
              {timelineLoading ? 'Loading…' : 'Load'}
            </button>
          </div>

          {timeline.length === 0 && !timelineLoading ? (
            <div className="empty-state" style={{ padding: 24 }}><p>Enter an IP to view its timeline.</p></div>
          ) : (
            <div className="timeline" style={{ maxHeight: 500, overflowY: 'auto' }}>
              {timeline.map((ev, i) => (
                <div className="timeline-item" key={i}>
                  <div>
                    <div className="timeline-ts">{format(new Date(ev.timestamp), 'MM-dd HH:mm:ss')}</div>
                    <div className="timeline-event">
                      <span className={`badge badge-${ev.honeypot}`} style={{ marginRight: 6 }}>{ev.honeypot}</span>
                      {ev.event_type}
                    </div>
                    {ev.detail && <div className="timeline-detail">{ev.detail}</div>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Attacker profile */}
        <div className="card mb-0">
          <div className="card-title">Attacker profile</div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <input
              placeholder="Source IP…"
              value={profileIp}
              onChange={e => setProfileIp(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && loadProfile()}
              style={{ flex: 1, background: 'var(--bg-0)', border: '1px solid var(--border)', color: 'var(--text-1)', padding: '7px 12px', borderRadius: 6, fontSize: 13, outline: 'none' }}
            />
            <button className="btn btn-secondary" onClick={loadProfile} disabled={profileLoading}>
              {profileLoading ? 'Loading…' : 'Profile'}
            </button>
          </div>

          {!profile && !profileLoading && (
            <div className="empty-state" style={{ padding: 24 }}><p>Enter an IP to build its profile.</p></div>
          )}

          {profileLoading && <div className="loading">Enriching IP…</div>}

          {profile && (
            <>
              <table style={{ marginBottom: 16 }}>
                <tbody>
                  <tr><td className="text-muted" style={{ width: 140 }}>IP</td><td className="ip-link">{profile.ip}</td></tr>
                  <tr><td className="text-muted">Country</td><td>{profile.country || '—'} {profile.country_iso ? `(${profile.country_iso})` : ''}</td></tr>
                  <tr><td className="text-muted">ASN</td><td className="text-muted">{profile.as_org || profile.asn || '—'}</td></tr>
                  <tr><td className="text-muted">Tor / VPN</td>
                    <td>
                      {profile.is_tor && <span className="badge badge-high" style={{ marginRight: 4 }}>TOR</span>}
                      {profile.is_vpn && <span className="badge badge-medium">VPN</span>}
                      {!profile.is_tor && !profile.is_vpn && <span className="text-muted">—</span>}
                    </td>
                  </tr>
                  <tr>
                    <td className="text-muted">AbuseIPDB</td>
                    <td>
                      {profile.abuseipdb_score != null ? (
                        <span style={{ color: profile.abuseipdb_score > 50 ? 'var(--red)' : 'var(--orange)', fontWeight: 600 }}>
                          {profile.abuseipdb_score}% ({profile.abuseipdb_reports} reports)
                        </span>
                      ) : <span className="text-muted">—</span>}
                    </td>
                  </tr>
                  <tr>
                    <td className="text-muted">Risk score</td>
                    <td>
                      <span style={{ fontSize: 20, fontWeight: 700, color: profile.risk_score >= 80 ? 'var(--purple)' : profile.risk_score >= 60 ? 'var(--red)' : profile.risk_score >= 30 ? 'var(--orange)' : 'var(--green)' }}>
                        {profile.risk_score}
                      </span>
                      <span className="text-muted" style={{ fontSize: 12 }}> / 100</span>
                    </td>
                  </tr>
                  <tr><td className="text-muted">Events</td><td>{profile.event_count?.toLocaleString()}</td></tr>
                  <tr><td className="text-muted">Sessions</td><td>{profile.session_count}</td></tr>
                  <tr><td className="text-muted">Honeypots</td><td>{(profile.honeypots || []).join(', ') || '—'}</td></tr>
                </tbody>
              </table>

              {profile.mitre_techniques?.length > 0 && (
                <>
                  <div className="card-title">MITRE ATT&CK techniques</div>
                  <div style={{ marginBottom: 12 }}>
                    {profile.mitre_techniques.map(t => (
                      <span key={t} className="technique">
                        <span className="technique-id">{t}</span>
                      </span>
                    ))}
                  </div>
                </>
              )}

              {profile.yara_matches?.length > 0 && (
                <>
                  <div className="card-title">YARA matches</div>
                  <div style={{ marginBottom: 12 }}>
                    {profile.yara_matches.map(r => (
                      <span key={r} className="badge badge-high" style={{ marginRight: 4 }}>{r}</span>
                    ))}
                  </div>
                </>
              )}

              {profile.ioc_hashes?.length > 0 && (
                <>
                  <div className="card-title">SHA-256 IoCs</div>
                  {profile.ioc_hashes.map(h => (
                    <div key={h} className="mono text-muted" style={{ fontSize: 11, marginBottom: 3 }}>{h}</div>
                  ))}
                </>
              )}

              {profile.mistral_analysis && (
                <>
                  <div className="card-title">Mistral 7B analysis</div>
                  <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.7 }}>{profile.mistral_analysis}</p>
                </>
              )}
            </>
          )}
        </div>
      </div>
    </>
  )
}
