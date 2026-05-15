import { useState, useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  ResponsiveContainer, Tooltip, Cell,
} from 'recharts';
import api from '../api';
import { flag, evNormalize } from '../utils';
import { SOURCE_META } from '../constants';

const TOOLTIP_STYLE = {
  backgroundColor: '#0d111e',
  border: '1px solid #1e2538',
  borderRadius: '6px',
  fontFamily: "'JetBrains Mono',monospace",
  fontSize: '11px',
  color: '#e0e6f0',
};
const AXIS_TICK = { fontSize: 10, fill: '#8892a4', fontFamily: "'JetBrains Mono',monospace" };
const HP_COLORS = { dionaea: '#ff5050', cowrie: '#8C1A2B', galah: '#b464ff', zeek: '#50a0ff' };

function extractGeo(n) {
  const raw = n.raw || {};
  const sg = raw['source.geo'];
  if (!sg || typeof sg !== 'object') return null;
  const geo = (sg.location ? sg : sg.geo) || sg;
  if (!geo || typeof geo !== 'object') return null;
  const loc = geo.location;
  if (!loc) return null;
  const lat = parseFloat(loc.lat), lon = parseFloat(loc.lon);
  if (isNaN(lat) || isNaN(lon)) return null;
  return {
    lat, lon,
    country_code: geo.country_iso_code || '',
    country_name: geo.country_name || '',
    city: geo.city_name || geo.region_name || '',
  };
}

function markerColor(hp) {
  const m = {
    dionaea: { fill: 'rgba(255,80,80,.8)', stroke: '#ff5050' },
    cowrie:  { fill: 'rgba(140,26,43,.8)', stroke: '#8C1A2B' },
    galah:   { fill: 'rgba(180,100,255,.8)', stroke: '#b464ff' },
    zeek:    { fill: 'rgba(80,160,255,.8)', stroke: '#50a0ff' },
  };
  return m[hp] || { fill: 'rgba(120,200,120,.8)', stroke: '#78c878' };
}

export default function GeoMap() {
  const mapContainerRef = useRef(null);
  const mapRef = useRef(null);
  const markerMapRef = useRef({});
  const [badge, setBadge] = useState('Loading…');
  const [countries, setCountries] = useState([]);
  const [ipList, setIpList] = useState([]);
  const [countryError, setCountryError] = useState(null);
  const [ipError, setIpError] = useState(null);

  // Initialize Leaflet map
  useEffect(() => {
    if (!mapContainerRef.current || mapRef.current) return;
    const map = L.map(mapContainerRef.current, {
      center: [20, 10], zoom: 2, zoomControl: true, attributionControl: false,
      worldCopyJump: false, maxBounds: [[-90, -200], [90, 200]], maxBoundsViscosity: 0.8,
    });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18, subdomains: 'abcd' }).addTo(map);
    mapRef.current = map;
    setTimeout(() => map.invalidateSize(), 100);
    return () => {
      map.remove();
      mapRef.current = null;
    };
  }, []);

  // Load data and populate map
  useEffect(() => {
    async function fetchGeoEvents() {
      const results = await Promise.allSettled([
        api.attacks({ page_size: 100, page: 1, honeypot: 'cowrie' }),
        api.attacks({ page_size: 100, page: 1, honeypot: 'dionaea' }),
        api.attacks({ page_size: 100, page: 1, honeypot: 'galah' }),
      ]);
      const seen = new Set();
      const all = [];
      for (const r of results) {
        if (r.status !== 'fulfilled') continue;
        for (const item of ((r.value && r.value.items) || [])) {
          if (!seen.has(item.id)) { seen.add(item.id); all.push(item); }
        }
      }
      return all.map(evNormalize);
    }

    async function fetchPgGeoSessions() {
      try {
        const data = await api._call('/api/geo/forensic-sessions?limit=200');
        return (data && data.sessions) || [];
      } catch (_) { return []; }
    }

    async function loadAll() {
      try {
        const [normalized, pgSessions] = await Promise.all([fetchGeoEvents(), fetchPgGeoSessions()]);
        const byIP = {};
        normalized.forEach(n => {
          const geo = extractGeo(n);
          if (!geo) return;
          const ip = n.source_ip || (n.raw && n.raw['source.ip']) || '?';
          if (!byIP[ip]) byIP[ip] = { ip, geo, honeypot: n.honeypot, count: 0 };
          byIP[ip].count++;
        });
        pgSessions.forEach(s => {
          const ip = s.source_ip;
          if (!ip || isNaN(s.lat) || isNaN(s.lon)) return;
          const geo = { lat: s.lat, lon: s.lon, country_code: s.country_code || '', country_name: s.country_name || '', city: s.city || '' };
          if (byIP[ip]) {
            byIP[ip].geo = geo;
            byIP[ip].risk_score = s.risk_score;
            byIP[ip].risk_level = s.risk_level;
            if (s.honeypot_type && s.honeypot_type !== 'unified') byIP[ip].honeypot = s.honeypot_type;
          } else {
            byIP[ip] = { ip, geo, honeypot: s.honeypot_type || 'cowrie', count: s.sessions || 1, risk_score: s.risk_score, risk_level: s.risk_level, fromPg: true };
          }
        });

        const list = Object.values(byIP).sort((a, b) => (b.risk_score || b.count) - (a.risk_score || a.count));
        const totalGeo = list.length;
        const pgCount = pgSessions.length;
        setBadge(`${totalGeo} geolocated IP${totalGeo > 1 ? 's' : ''}${pgCount ? ' (' + pgCount + ' enriched)' : ''}`);

        if (!list.length) {
          setCountryError('No geolocated IPs in the last 7 days.\nLocal 172.16.x.x traffic is not processed by GeoIP.');
          setIpError('No data.');
          return;
        }

        // Add markers to map when it's ready
        const addMarkers = () => {
          const map = mapRef.current;
          if (!map) return;
          const bounds = [];
          const mm = {};
          list.forEach(d => {
            const clr = markerColor(d.honeypot);
            const r = Math.max(8, Math.min(26, 8 + Math.log2(d.count + 1) * 3));
            bounds.push([d.geo.lat, d.geo.lon]);
            const circle = L.circleMarker([d.geo.lat, d.geo.lon], {
              radius: r, fillColor: clr.fill, color: clr.stroke, weight: 1.5, fillOpacity: 0.85,
            });
            const meta = SOURCE_META[d.honeypot] || { label: d.honeypot || '?', icon: '' };
            const riskColor = d.risk_score >= 80 ? '#C62828' : d.risk_score >= 60 ? '#b36000' : d.risk_score >= 40 ? '#1565C0' : '#388E3C';
            circle.bindPopup(`<div style="font-family:'JetBrains Mono',monospace;font-size:12px;min-width:180px">
              <div style="font-size:14px;font-weight:700;margin-bottom:6px">${flag(d.geo.country_code)} ${d.ip}</div>
              <div style="color:#aaa;margin-bottom:4px">${d.geo.country_name}${d.geo.city ? ' · ' + d.geo.city : ''}</div>
              <div style="margin-bottom:4px">${meta.icon} ${meta.label}</div>
              ${d.risk_score != null
                ? `<div style="color:${riskColor};font-weight:700;">Risk: ${d.risk_score}/100 ${d.risk_level || ''}</div>`
                : `<div style="color:#8C1A2B"><b>${d.count}</b> event${d.count > 1 ? 's' : ''}</div>`}
            </div>`, { maxWidth: 240 });
            circle.addTo(map);
            mm[d.ip] = circle;
          });
          markerMapRef.current = mm;
          if (bounds.length) {
            map.fitBounds(bounds, { padding: [60, 60], maxZoom: 7, minZoom: 2 });
            if (map.getZoom() < 2) map.setZoom(2);
          }
        };

        if (mapRef.current) {
          addMarkers();
        } else {
          // Wait for map to mount
          const interval = setInterval(() => {
            if (mapRef.current) { clearInterval(interval); addMarkers(); }
          }, 100);
          setTimeout(() => clearInterval(interval), 5000);
        }

        // Country breakdown
        const byCountry = {};
        list.forEach(d => {
          const k = d.geo.country_code || '??';
          if (!byCountry[k]) byCountry[k] = { code: k, name: d.geo.country_name || k, count: 0, ips: 0 };
          byCountry[k].count += d.count; byCountry[k].ips++;
        });
        setCountries(Object.values(byCountry).sort((a, b) => b.count - a.count));
        setIpList(list);
      } catch (e) {
        console.error('GeoMap error:', e);
        setBadge('Error');
        setCountryError(e.message);
        setIpError(e.message);
      }
    }

    loadAll();
  }, []);

  const countryBarData = countries.slice(0, 12).map(c => ({
    name: flag(c.code) + ' ' + c.name.slice(0, 12),
    count: c.count,
    ips: c.ips,
  }));

  const ipBarData = ipList.slice(0, 8).map(d => ({
    ip: flag(d.geo.country_code) + ' ' + d.ip,
    count: d.count,
    color: HP_COLORS[d.honeypot] || '#888',
    rawIp: d.ip,
  }));

  function flyToIp(rawIp) {
    const marker = markerMapRef.current[rawIp];
    if (!marker || !mapRef.current) return;
    const ll = marker.getLatLng();
    mapRef.current.flyTo([ll.lat, ll.lng], 6, { duration: 1 });
    setTimeout(() => marker.openPopup(), 1100);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="section-tag" style={{ marginBottom: 8 }}> Geo Map</div>
          <h2 className="page-title">Attacker <span>Map</span></h2>
          <div className="page-sub">Real geographic positions · MaxMind GeoIP enrichment.</div>
        </div>
        <div className="page-actions">
          <span className="badge blue" style={{ fontSize: 12 }}>{badge}</span>
        </div>
      </div>

      <div style={{ position: 'relative', borderRadius: 12, overflow: 'hidden', border: '1px solid var(--border)', marginBottom: 16 }}>
        <div ref={mapContainerRef} style={{ height: 520, background: '#0a0e1a' }} />
        <div style={{
          position: 'absolute', bottom: 24, right: 12, zIndex: 1000,
          background: 'rgba(10,14,26,.9)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '10px 14px', fontSize: 11,
          fontFamily: "'JetBrains Mono',monospace", color: 'var(--text2)',
          pointerEvents: 'none',
        }}>
          <div style={{ marginBottom: 6, fontSize: 10, color: 'var(--text3)', letterSpacing: '.06em' }}>LEGEND</div>
          {[
            { fill: 'rgba(255,80,80,.8)', stroke: '#ff5050', label: 'Dionaea' },
            { fill: 'rgba(140,26,43,.8)', stroke: '#8C1A2B', label: 'Cowrie' },
            { fill: 'rgba(180,100,255,.8)', stroke: '#b464ff', label: 'Galah' },
            { fill: 'rgba(80,160,255,.8)', stroke: '#50a0ff', label: 'Zeek NDR' },
          ].map(({ fill, stroke, label }) => (
            <div key={label} className="flex items-c gap-8" style={{ marginBottom: 4 }}>
              <svg width="12" height="12"><circle cx="6" cy="6" r="5" fill={fill} stroke={stroke} strokeWidth="1.5" /></svg>
              {label}
            </div>
          ))}
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-h"><div className="card-t">Top Countries</div></div>
          {countryError ? (
            <div className="alert err">{countryError}</div>
          ) : countryBarData.length === 0 ? (
            <div className="alert info">No geolocated IPs in the last 7 days.</div>
          ) : (
            <ResponsiveContainer width="100%" height={Math.max(180, countryBarData.length * 30 + 20)}>
              <BarChart data={countryBarData} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={160} tick={{ ...AXIS_TICK, fill: '#e0e6f0' }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v, n, p) => [v + ' events (' + p.payload.ips + ' IPs)', 'Events']} />
                <Bar
                  dataKey="count" name="Events" radius={[0, 3, 3, 0]} barSize={16} fill="#8C1A2Bbb"
                  label={{ position: 'right', style: { fill: '#8892a4', fontSize: 10, fontFamily: "'JetBrains Mono',monospace" }, formatter: v => v }}
                />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="card">
          <div className="card-h">
            <div className="card-t">Top Geolocated IPs</div>
            <div className="card-sub">click to center map</div>
          </div>
          {ipError ? (
            <div className="alert err">{ipError}</div>
          ) : ipList.length === 0 ? (
            <div className="alert info">No data.</div>
          ) : (
            <>
              {ipBarData.length > 0 && (
                <ResponsiveContainer width="100%" height={Math.max(120, ipBarData.length * 24 + 20)} style={{ marginBottom: 12 }}>
                  <BarChart data={ipBarData} layout="vertical" margin={{ top: 0, right: 20, bottom: 0, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" horizontal={false} />
                    <XAxis type="number" tick={AXIS_TICK} tickLine={false} axisLine={false} allowDecimals={false} />
                    <YAxis type="category" dataKey="ip" width={155} tick={{ ...AXIS_TICK, fill: '#e0e6f0' }} tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} formatter={v => [v + ' events', 'Count']} />
                    <Bar dataKey="count" name="Events" radius={[0, 3, 3, 0]} barSize={12}>
                      {ipBarData.map((e, i) => <Cell key={i} fill={e.color + 'bb'} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
              <table className="tbl">
                <thead>
                  <tr><th>IP</th><th>Location</th><th>Events</th></tr>
                </thead>
                <tbody>
                  {ipList.slice(0, 15).map(d => (
                    <tr
                      key={d.ip}
                      style={{ cursor: 'pointer' }}
                      onClick={() => flyToIp(d.ip)}
                    >
                      <td className="mono" style={{ fontSize: 11 }}>{d.ip}</td>
                      <td style={{ fontSize: 11 }}>{flag(d.geo.country_code)} {d.geo.country_name}{d.geo.city ? ' · ' + d.geo.city : ''}</td>
                      <td>
                        <span className={`badge ${d.honeypot === 'zeek' ? 'blue' : d.honeypot === 'dionaea' ? 'red' : 'gold'}`}>{d.count}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      </div>
    </>
  );
}
