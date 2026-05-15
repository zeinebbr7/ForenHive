import { ALL_SOURCES, COUNTRIES_ISO, COUNTRY_LATLNG } from './constants';

export const fmt = {
  date(ts){ const d = new Date(ts); return isNaN(d) ? '—' : d.toLocaleString('en-US', {year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'}); },
  time(ts){ const d = new Date(ts); return isNaN(d) ? '—' : d.toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}); },
  ago(ts){ const t = typeof ts === 'number' ? ts : +new Date(ts);
    const s = Math.max(1, Math.floor((Date.now()-t)/1000));
    if (s < 60) return s+'s';
    if (s < 3600) return Math.floor(s/60)+'m';
    if (s < 86400) return Math.floor(s/3600)+'h';
    return Math.floor(s/86400)+'d'; },
  dur(sec){ if (sec<60) return sec+'s'; if (sec<3600) return Math.floor(sec/60)+'m'+(sec%60)+'s'; return Math.floor(sec/3600)+'h'+Math.floor((sec%3600)/60)+'m'; },
  num(n){ if (n == null) return '—'; if (n >= 1e6) return (n/1e6).toFixed(1)+'M'; if (n >= 1e3) return (n/1e3).toFixed(1)+'k'; return String(n); },
  shortHash(h){ return h && h.length > 18 ? h.slice(0,10)+'…'+h.slice(-6) : (h || '—'); },
  scoreClass(s){ if (s == null) return 'lo'; return s<40 ? 'lo' : (s<70 ? 'md' : 'hi'); },
  sevToClass(s){ return {critical:'crit',high:'hi',medium:'md',low:'lo'}[String(s).toLowerCase()] || 'lo'; },
};

export const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));

export const flag = iso => COUNTRIES_ISO[iso] || '';
export const countryLL = iso => COUNTRY_LATLNG[iso] || [0, 0];

export function evField(ev, ...candidates) {
  for (const k of candidates) {
    const parts = k.split('.');
    let v = ev;
    for (const p of parts) { if (v == null) break; v = v[p]; }
    if (v != null && v !== '') return v;
  }
  return null;
}

export function evNormalize(ev) {
  const raw = ev.raw || {};
  const tags = raw.tags || [];
  const hp = ev.honeypot && ev.honeypot !== 'unknown'
    ? ev.honeypot
    : (raw['honeypot.type'] || tags.find(t => ALL_SOURCES.includes(t)) || 'unknown');
  return {
    id: ev.id,
    timestamp: ev.timestamp || raw['@timestamp'],
    honeypot: hp,
    source_ip: ev.source_ip || raw['source.ip'] || raw.src_ip || raw.remote_host,
    dest_ip: raw['destination.ip'] || raw.dst_ip,
    dest_port: ev.dest_port || raw['destination.port'] || raw.dst_port,
    source_port: ev.source_port || raw['source.port'],
    protocol: ev.protocol || raw['network.transport'] || raw.service || raw.protocol,
    severity: ev.severity || 'low',
    risk_score: ev.risk_score,
    session_id: ev.session_id || raw['session.id'] || raw.session,
    username: ev.username || raw['user.name'] || raw.username,
    password: ev.password || raw['user.password'] || raw.password,
    command: ev.command || raw['process.command_line'] || raw.input || raw.command,
    event_action: ev.event_type || raw['event.action'] || raw['event.id'],
    event_category: raw['event.category'],
    message: raw.message || (raw.event && raw.event.original),
    dionaea_msg: raw['dionaea.msg'],
    dionaea_module: raw['dionaea.module'],
    http_method: ev.http_method || raw['http.request.method'],
    http_path: ev.http_path || raw['http.request.uri'] || raw['http.request.path'] || raw.url || (raw.http && raw.http.path),
    user_agent: ev.user_agent || raw['http.request.user_agent'] || raw['user_agent.original'] || raw['http.request.headers.user-agent'],
    country: (ev.geo && ev.geo.country_iso) || (raw['source.geo'] && (raw['source.geo'].country_iso_code || (raw['source.geo'].geo && raw['source.geo'].geo.country_iso_code))) || null,
    raw,
  };
}
