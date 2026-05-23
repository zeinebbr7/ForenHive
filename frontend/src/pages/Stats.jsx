import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  ResponsiveContainer, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, PieChart, Pie, Cell, Legend,
} from 'recharts';
import api from '../api';
import { SOURCE_META, HONEYPOTS, SENSORS } from '../constants';
import { fmt, flag, evNormalize } from '../utils';
import { useAuth } from '../contexts/AuthContext';

/* ─── tokens ─────────────────────────────────────────────────────── */
const HP   = { cowrie:'#C93D55', dionaea:'#ff7055', galah:'#7b68ee', zeek:'#50a0ff' };
const SEV  = { critical:'#ff5050', high:'#ff9933', medium:'#C93D55', low:'#2dd4bf' };
const TT   = {
  backgroundColor:'#0d111e', border:'1px solid #1e2538',
  borderRadius:6, fontFamily:"'JetBrains Mono',monospace",
  fontSize:11, color:'#e0e6f0',
};
const AX = { fontSize:10, fill:'#8892a4', fontFamily:"'JetBrains Mono',monospace" };

const PORT_NAMES = {
  '22/tcp':'SSH','23/tcp':'Telnet','445/tcp':'SMB','3306/tcp':'MySQL',
  '8080/tcp':'HTTP','80/tcp':'HTTP','443/tcp':'HTTPS','21/tcp':'FTP',
  '1433/tcp':'MSSQL','27017/tcp':'MongoDB',
};

/* ─── icons ──────────────────────────────────────────────────────── */
const I = {
  Activity: ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  Clock:    ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
  Shield:   ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  AlertTri: ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  Search:   ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  User:     ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
  File:     ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>,
  Refresh:  ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>,
  Database: ()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>,
};

/* ─── data ───────────────────────────────────────────────────────── */
async function load() {
  const [hourly, split, topIps, topPorts, recent, profiling, yara, sessions, health, alerts] =
    await Promise.all([
      api.statsHourly().catch(()=>[]),
      api.geoSplit().catch(()=>({split:[]})),
      api.statsTopIps(10).catch(()=>({items:[]})),
      api.statsTopPorts(10).catch(()=>({items:[]})),
      api.attacks({page_size:20}).catch(()=>({items:[]})),
      api.profilingStats().catch(()=>null),
      api.yaraHits({limit:1}).catch(()=>null),
      api.sessions({page_size:6}).catch(()=>null),
      api.health().catch(()=>({status:'unknown'})),
      api.alertHistory({limit:5}).catch(()=>null),
    ]);

  const hourlyArr = Array.isArray(hourly) ? hourly : [];
  const last24    = hourlyArr.slice(-24);
  const lastHour  = last24[last24.length-1];

  const areaData  = last24.map(e=>({
    h:      new Date(e.hour).getUTCHours().toString().padStart(2,'0')+':00',
    cowrie: (e.by_honeypot||{}).cowrie  || 0,
    dionaea:(e.by_honeypot||{}).dionaea || 0,
    galah:  (e.by_honeypot||{}).galah   || 0,
    zeek:   (e.by_honeypot||{}).zeek    || 0,
  }));

  const splitRaw   = (split?.split||[]).sort((a,b)=>b.count-a.count);
  const splitTotal = splitRaw.reduce((s,x)=>s+x.count,0)||1;
  const sourceData = splitRaw.filter(x=>x.count>0).map(x=>({
    key:x.honeypot, name:SOURCE_META[x.honeypot]?.label||x.honeypot,
    value:x.count, pct:+((x.count/splitTotal)*100).toFixed(1),
  }));

  const grandTotal = splitRaw.filter(x=>HONEYPOTS.includes(x.honeypot)).reduce((s,x)=>s+x.count,0);
  const hpActive   = splitRaw.filter(x=>HONEYPOTS.includes(x.honeypot)&&x.count>0).length;

  const items = (recent?.items||[]).map(evNormalize);
  const sev   = {critical:0,high:0,medium:0,low:0};
  items.forEach(n=>{ const s=(n.severity||'low').toLowerCase(); if(s in sev) sev[s]++; });

  const sevData = Object.entries(sev).filter(([,v])=>v>0).map(([k,v])=>({
    name:k.charAt(0).toUpperCase()+k.slice(1), value:v, key:k,
  }));

  const ipsData   = (topIps?.items||[]).slice(0,8).map(x=>({
    ip:(x.country?flag(x.country)+' ':'')+x.ip,
    count:x.count, fill:HP[x.honeypot]||'#8892a4',
  }));
  const portsData = (topPorts?.items||[]).slice(0,8).map(x=>({
    port:PORT_NAMES[`${x.port}/${x.protocol||'tcp'}`]?`${PORT_NAMES[`${x.port}/${x.protocol||'tcp'}`]} :${x.port}`:`${x.port}/${x.protocol||'tcp'}`,
    count:x.count, fill:HP[x.honeypot]||'#50a0ff',
  }));

  return {
    grandTotal, hpActive,
    lastHourCount:   lastHour?.count||0,
    criticalHigh:    sev.critical+sev.high,
    profTotal:       profiling?.total ?? null,
    yaraTotal:       yara?.total ?? yara?.count ?? null,
    areaData, sourceData, sevData, ipsData, portsData,
    items, sev,
    sessions:   sessions?.items||sessions?.sessions||[],
    health:     health||{status:'unknown'},
    alertItems: alerts?.items||alerts?.history||[],
  };
}

/* ═══════════════════════════════════════════════════════════════════ */
export default function Stats() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [data,      setData]      = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [runStatus, setRunStatus] = useState('idle');
  const [clock,     setClock]     = useState('');

  const reload = useCallback(()=>{
    setLoading(true); setError(null);
    load().then(d=>{ setData(d); setLoading(false); })
          .catch(e=>{ setError(e.message); setLoading(false); });
  },[]);

  useEffect(()=>{ reload(); },[reload]);

  useEffect(()=>{
    const tick=()=>{
      const n=new Date(), p=v=>String(v).padStart(2,'0');
      setClock(`${p(n.getUTCHours())}:${p(n.getUTCMinutes())}:${p(n.getUTCSeconds())} UTC`);
    };
    tick(); const id=setInterval(tick,1000); return ()=>clearInterval(id);
  },[]);

  const runAnalysis=useCallback(async()=>{
    setRunStatus('running');
    try{
      const r=await api.forensicRunNow();
      if(!r?.triggered) setRunStatus('warn');
      setTimeout(()=>setRunStatus('idle'),r?.triggered?8000:3000);
    }catch{ setRunStatus('warn'); setTimeout(()=>setRunStatus('idle'),3000); }
  },[]);

  const kpis = [
    { label:'Total events',    val:data?data.grandTotal.toLocaleString('en-US'):'—', color:'var(--gold)',     Icon:I.Activity },
    { label:'Critical / High', val:data?(data.criticalHigh).toString():'—',          color:'#ff5050',        Icon:I.AlertTri },
    { label:'Active honeypots',val:data?`${data.hpActive} / 3`:'—',                  color:'var(--teal)',    Icon:I.Shield   },
    { label:'AI Profiles',     val:data?(data.profTotal!=null?data.profTotal.toLocaleString('en-US'):'—'):'—', color:'var(--blue2)',   Icon:I.User   },
    { label:'YARA matches',    val:data?(data.yaraTotal!=null?data.yaraTotal.toLocaleString('en-US'):'—'):'—', color:'var(--purple2)', Icon:I.Search },
    { label:'Last hour',       val:data?data.lastHourCount.toLocaleString('en-US'):'—', color:'var(--text)', Icon:I.Clock    },
  ];

  return (
    <div style={{width:'100%',paddingTop:4}}>

      {/* HEADER */}
      <div className="page-head" style={{marginBottom:16}}>
        <div>
          <div className="section-tag" style={{marginBottom:6}}>SOC Overview</div>
          <h2 className="page-title">Dash<span>board</span></h2>
          <div className="page-sub" style={{display:'flex',alignItems:'center',gap:8}}>
            <span className="dot warn" style={{marginRight:0}}/>
            LIVE &nbsp;·&nbsp;
            <span className="mono" style={{fontSize:11}}>{clock}</span>
          </div>
        </div>
        <div className="page-actions" style={{gap:8}}>
          <button className="btn btn-gh btn-sm" onClick={runAnalysis} disabled={runStatus!=='idle'}>
            {runStatus==='running'?'⟳ Running…':runStatus==='warn'?'Already running':'Run Analysis'}
          </button>
          <button className="btn btn-gh btn-sm" onClick={reload} disabled={loading}>
            <I.Refresh/>
          </button>
          <Link to="/reporting" className="btn btn-out btn-sm">
            <I.File/>&nbsp;Generate report
          </Link>
        </div>
      </div>

      {error && <div className="alert err" style={{margin:'0 0 12px'}}>Error: {error}</div>}

      {/* KPI BAND */}
      <div style={{
        display:'grid', gridTemplateColumns:'repeat(6,1fr)',
        background:'var(--surface)', border:'1px solid var(--border)',
        borderRadius:10, marginBottom:14, overflow:'hidden',
        opacity:loading?0.55:1, transition:'opacity .3s',
      }}>
        {kpis.map((k,i)=>(
          <div key={i} style={{
            padding:'16px 18px', textAlign:'center',
            borderRight:i<kpis.length-1?'1px solid var(--border)':undefined,
          }}>
            <div style={{
              display:'flex',alignItems:'center',justifyContent:'center',gap:6,
              fontSize:10,color:'var(--text3)',fontFamily:"'JetBrains Mono',monospace",
              textTransform:'uppercase',letterSpacing:'.07em',marginBottom:8,
            }}>
              <span style={{color:k.color,opacity:.7}}><k.Icon/></span>
              {k.label}
            </div>
            <div style={{fontFamily:"'Rajdhani',sans-serif",fontSize:32,fontWeight:700,color:k.color,lineHeight:1}}>
              {loading?'…':k.val}
            </div>
          </div>
        ))}
      </div>

      {/* ROW 1: area chart | source donut */}
      <div style={{display:'grid',gridTemplateColumns:'1.55fr 1fr',gap:14,marginBottom:14}}>
        {data ? <AlertsEvolution areaData={data.areaData}/> : <Skeleton h={280}/>}
        {data ? <MitrePanel sourceData={data.sourceData}/> : <Skeleton h={280}/>}
      </div>

      {/* ROW 2: severity donut | top IPs | top ports */}
      <div style={{display:'grid',gridTemplateColumns:'0.7fr 1fr 1fr',gap:14,marginBottom:14}}>
        {data ? <SeverityPanel sevData={data.sevData}/> : <Skeleton h={260}/>}
        {data ? <TopIpsPanel ipsData={data.ipsData}/> : <Skeleton h={260}/>}
        {data ? <TopPortsPanel portsData={data.portsData}/> : <Skeleton h={260}/>}
      </div>

      {/* ROW 3: [admin-only: health] | sessions | alerts | live timeline */}
      <div style={{display:'grid',gridTemplateColumns:isAdmin?'1fr 1fr 1fr 1fr':'1fr 1fr 1fr',gap:14,marginBottom:14}}>
        {isAdmin && (data ? <HealthPanel health={data.health}/> : <Skeleton h={220}/>)}
        {data ? <SessionsPanel sessions={data.sessions}/> : <Skeleton h={220}/>}
        {data ? <AlertsPanel alertItems={data.alertItems}/> : <Skeleton h={220}/>}
        {data ? <TimelineWidget items={data.items}/> : <Skeleton h={220}/>}
      </div>
    </div>
  );
}

/* ─── Skeleton ───────────────────────────────────────────────────── */
function Skeleton({h}) {
  return (
    <div className="card" style={{height:h,display:'flex',alignItems:'center',justifyContent:'center'}}>
      <span style={{color:'var(--text3)',fontSize:12,fontFamily:"'JetBrains Mono',monospace"}}>Loading…</span>
    </div>
  );
}

/* ═══ Alerts Evolution (area chart) ══════════════════════════════════ */
function AlertsEvolution({areaData}) {
  const hasData = areaData.some(d=>d.cowrie||d.dionaea||d.galah||d.zeek);
  const sources = [
    {key:'cowrie',  name:'Cowrie',  color:HP.cowrie  },
    {key:'dionaea', name:'Dionaea', color:HP.dionaea },
    {key:'galah',   name:'Galah',   color:HP.galah   },
    {key:'zeek',    name:'Zeek',    color:HP.zeek    },
  ];
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <div className="card-t">Activity evolution</div>
          <div className="card-sub">Events per source · last 24h</div>
        </div>
        <div style={{display:'flex',gap:14,alignItems:'center'}}>
          {sources.map(s=>(
            <div key={s.key} style={{display:'flex',alignItems:'center',gap:5}}>
              <span style={{width:8,height:8,borderRadius:2,background:s.color,display:'inline-block'}}/>
              <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:'var(--text3)'}}>{s.name}</span>
            </div>
          ))}
        </div>
      </div>
      {!hasData
        ? <div className="alert info">No hourly data available.</div>
        : (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={areaData} margin={{top:4,right:4,bottom:0,left:-20}}>
              <defs>
                {sources.map(s=>(
                  <linearGradient key={s.key} id={`grad-${s.key}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={s.color} stopOpacity={0.35}/>
                    <stop offset="95%" stopColor={s.color} stopOpacity={0.04}/>
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false}/>
              <XAxis dataKey="h" tick={AX} tickLine={false} axisLine={false} interval={3}/>
              <YAxis tick={AX} tickLine={false} axisLine={false} allowDecimals={false}/>
              <Tooltip contentStyle={TT} cursor={{stroke:'rgba(255,255,255,0.08)',strokeWidth:1}}/>
              {sources.map((s,i)=>(
                <Area key={s.key} type="monotone" dataKey={s.key} name={s.name}
                  stackId="1"
                  stroke={s.color} strokeWidth={1.5}
                  fill={`url(#grad-${s.key})`}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        )
      }
    </div>
  );
}

/* ═══ Source / "MITRE" panel ══════════════════════════════════════════ */
function MitrePanel({sourceData}) {
  const COLORS = sourceData.map(d=>HP[d.key]||'#8892a4');
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <div className="card-t">Source distribution</div>
          <div className="card-sub">Events by honeypot</div>
        </div>
      </div>
      {sourceData.length===0
        ? <div className="alert info">No data.</div>
        : (
          <div style={{display:'flex',alignItems:'center',gap:20}}>
            <PieChart width={160} height={200}>
              <Pie data={sourceData} dataKey="value" nameKey="name"
                cx={78} cy={90} innerRadius={52} outerRadius={76} paddingAngle={3}>
                {sourceData.map((d,i)=>(
                  <Cell key={i} fill={COLORS[i]+'cc'} stroke={COLORS[i]} strokeWidth={1}/>
                ))}
              </Pie>
              <Tooltip contentStyle={TT} formatter={v=>[v.toLocaleString('en-US'),'Events']}/>
            </PieChart>
            <div style={{flex:1,display:'flex',flexDirection:'column',gap:10}}>
              {sourceData.map((d,i)=>(
                <div key={i} style={{display:'flex',alignItems:'center',gap:10}}>
                  <span style={{width:10,height:10,borderRadius:'50%',background:COLORS[i],flexShrink:0}}/>
                  <span style={{fontSize:13,color:'var(--text2)',flex:1}}>{d.name}</span>
                  <span style={{fontFamily:"'Rajdhani',sans-serif",fontSize:18,fontWeight:700,color:COLORS[i]}}>{d.pct}%</span>
                </div>
              ))}
            </div>
          </div>
        )
      }
    </div>
  );
}

/* ═══ Severity donut ══════════════════════════════════════════════════ */
function SeverityPanel({sevData}) {
  const COLORS = sevData.map(d=>SEV[d.key]||'#8892a4');
  const total  = sevData.reduce((s,d)=>s+d.value,0);
  return (
    <div className="card" style={{display:'flex',flexDirection:'column',alignItems:'center'}}>
      <div className="card-h" style={{width:'100%'}}>
        <div>
          <div className="card-t">Severity</div>
          <div className="card-sub">Last 20 events</div>
        </div>
      </div>
      {sevData.length===0
        ? <div className="alert info">No events.</div>
        : (
          <>
            <PieChart width={140} height={140}>
              <Pie data={sevData} dataKey="value" nameKey="name"
                cx={68} cy={65} innerRadius={42} outerRadius={62} paddingAngle={3}>
                {sevData.map((d,i)=><Cell key={i} fill={COLORS[i]+'cc'} stroke={COLORS[i]} strokeWidth={1}/>)}
              </Pie>
              <Tooltip contentStyle={TT} formatter={v=>[v,'Events']}/>
            </PieChart>
            <div style={{width:'100%',display:'flex',flexDirection:'column',gap:8,marginTop:8}}>
              {sevData.map((d,i)=>(
                <div key={i} style={{display:'flex',alignItems:'center',gap:8}}>
                  <span style={{width:8,height:8,borderRadius:'50%',background:COLORS[i],flexShrink:0}}/>
                  <span style={{fontSize:11,color:'var(--text2)',flex:1,textTransform:'capitalize'}}>{d.name}</span>
                  <span style={{fontFamily:"'Rajdhani',sans-serif",fontSize:15,fontWeight:700,color:COLORS[i]}}>{d.value}</span>
                  <span style={{fontSize:10,color:'var(--text3)',fontFamily:"'JetBrains Mono',monospace",width:28,textAlign:'right'}}>
                    {total?((d.value/total)*100).toFixed(0)+'%':''}
                  </span>
                </div>
              ))}
            </div>
          </>
        )
      }
    </div>
  );
}

/* ═══ Top IPs ══════════════════════════════════════════════════════════ */
function TopIpsPanel({ipsData}) {
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <div className="card-t">Top attacking IPs</div>
          <div className="card-sub">Top 8 · all sources</div>
        </div>
        <Link to="/geomap" className="btn btn-out btn-sm">Geo map</Link>
      </div>
      {ipsData.length===0
        ? <div className="alert info">No data.</div>
        : (
          <ResponsiveContainer width="100%" height={ipsData.length*32+8}>
            <BarChart data={ipsData} layout="vertical" margin={{top:0,right:20,bottom:0,left:8}}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false}/>
              <XAxis type="number" tick={AX} tickLine={false} axisLine={false} allowDecimals={false}/>
              <YAxis type="category" dataKey="ip" width={155}
                tick={{...AX,fill:'var(--text2)',fontSize:11}} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TT} formatter={v=>[v.toLocaleString('en-US'),'Events']}/>
              <Bar dataKey="count" radius={[0,3,3,0]} barSize={13}>
                {ipsData.map((e,i)=><Cell key={i} fill={e.fill+'bb'}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )
      }
    </div>
  );
}

/* ═══ Top Ports ════════════════════════════════════════════════════════ */
function TopPortsPanel({portsData}) {
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <div className="card-t">Top targeted ports</div>
          <div className="card-sub">Most attacked services</div>
        </div>
      </div>
      {portsData.length===0
        ? <div className="alert info">No data.</div>
        : (
          <ResponsiveContainer width="100%" height={portsData.length*32+8}>
            <BarChart data={portsData} layout="vertical" margin={{top:0,right:20,bottom:0,left:8}}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false}/>
              <XAxis type="number" tick={AX} tickLine={false} axisLine={false} allowDecimals={false}/>
              <YAxis type="category" dataKey="port" width={120}
                tick={{...AX,fill:'var(--text2)',fontSize:11}} tickLine={false} axisLine={false}/>
              <Tooltip contentStyle={TT} formatter={v=>[v.toLocaleString('en-US'),'Hits']}/>
              <Bar dataKey="count" radius={[0,3,3,0]} barSize={13}>
                {portsData.map((e,i)=><Cell key={i} fill={e.fill+'bb'}/>)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )
      }
    </div>
  );
}

/* ═══ Health Panel ════════════════════════════════════════════════════ */
const SVCS=[
  {name:'Elasticsearch',   k:'elasticsearch',   color:'#50a0ff'},
  {name:'Forensic Engine', k:'forensic_engine', color:'var(--gold)'},
  {name:'Cowrie',          k:'cowrie',          color:HP.cowrie},
  {name:'Dionaea',         k:'dionaea',         color:HP.dionaea},
  {name:'Galah',           k:'galah',           color:HP.galah},
  {name:'Logstash',        k:'logstash',        color:'#2dd4bf'},
];
function svcSt(h,k){
  const v=h?.[k]||h?.services?.[k]||h?.components?.[k];
  if(!v) return 'unknown';
  return (typeof v==='string'?v:v.status)||'unknown';
}

function HealthPanel({health}) {
  const ok=s=>['ok','healthy','up'].includes(s);
  const overall=health?.status||'unknown';
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <div className="card-t">Platform health</div>
          <div className="card-sub">
            <span className={`dot ${ok(overall)?'up':'down'}`}/>
            {ok(overall)?'Operational':'Degraded'}
          </div>
        </div>
        <Link to="/health" className="btn btn-out btn-sm">Details</Link>
      </div>
      {SVCS.map(({name,k,color})=>{
        const s=svcSt(health,k);
        const isOk=ok(s);
        const isWarn=['degraded','warn','warning'].includes(s);
        const dotCls=isOk?'up':isWarn?'warn':'down';
        return (
          <div key={k} style={{
            display:'flex', alignItems:'center', justifyContent:'space-between',
            padding:'8px 0', borderBottom:'1px solid var(--border)',
          }}>
            <div style={{display:'flex',alignItems:'center',gap:8}}>
              <span style={{width:3,height:16,background:color,borderRadius:2,flexShrink:0}}/>
              <span style={{fontSize:12,color:'var(--text2)'}}>{name}</span>
            </div>
            <div style={{display:'flex',alignItems:'center',gap:6}}>
              <span className={`dot ${dotCls}`} style={{marginRight:0,width:6,height:6}}/>
              <span style={{
                fontFamily:"'JetBrains Mono',monospace", fontSize:9, textTransform:'uppercase',
                color:isOk?'#2dd4bf':isWarn?'#ff9933':'#ff5050',
              }}>{s}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ═══ Sessions Panel ══════════════════════════════════════════════════ */
function SessionsPanel({sessions}) {
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <div className="card-t">Recent sessions</div>
          <div className="card-sub">Risk-scored attack sessions</div>
        </div>
        <Link to="/reconstruction" className="btn btn-out btn-sm">Reconstruct</Link>
      </div>
      {sessions.length===0
        ? <div className="alert info">No sessions yet.</div>
        : sessions.slice(0,5).map((s,i)=>{
          const risk=s.risk_score??s.score??null;
          const rc=risk==null?'#8892a4':risk>=80?'#ff5050':risk>=60?'#ff9933':risk>=40?'#C93D55':'#2dd4bf';
          const sc=risk==null?'lo':risk>=80?'hi':risk>=60?'md':'lo';
          return (
            <Link to="/reconstruction" key={s.id||i} style={{
              display:'flex', alignItems:'center', justifyContent:'space-between',
              padding:'9px 0', borderBottom:'1px solid var(--border)',
              textDecoration:'none',
            }}>
              <div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:12,color:'var(--text2)'}}>
                  {s.source_ip||s.ip||'—'}
                  {s.country&&<span style={{marginLeft:6,fontSize:12}}>{flag(s.country)}</span>}
                </div>
                <div style={{fontSize:10,color:'var(--text3)',marginTop:2}}>
                  {s.honeypot||'—'} · {fmt.ago(s.start_time||s.first_seen||s.timestamp)}
                </div>
              </div>
              {risk!=null && <span className={`score ${sc}`}>{risk}</span>}
            </Link>
          );
        })
      }
    </div>
  );
}

/* ═══ Alerts Panel ════════════════════════════════════════════════════ */
function AlertsPanel({alertItems}) {
  return (
    <div className="card">
      <div className="card-h">
        <div>
          <div className="card-t">Recent alerts</div>
          <div className="card-sub">Email &amp; WhatsApp notifications</div>
        </div>
        <Link to="/alerts" className="btn btn-out btn-sm">All alerts</Link>
      </div>
      {alertItems.length===0
        ? <div className="alert info">No alerts sent yet.</div>
        : alertItems.slice(0,5).map((a,i)=>{
          const hi=(a.risk_score||0)>=60;
          const sc=(a.risk_score||0)>=80?'hi':'md';
          return (
            <div key={a.id||i} style={{
              display:'flex', alignItems:'center', justifyContent:'space-between',
              padding:'9px 0', borderBottom:'1px solid var(--border)',
            }}>
              <div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:12,color:'var(--text2)'}}>
                  {a.source_ip||a.ip||'—'}
                </div>
                <div style={{fontSize:10,color:'var(--text3)',marginTop:2}}>
                  {a.channel||a.type||'alert'} · {fmt.ago(a.sent_at||a.timestamp||a.created_at)}
                </div>
              </div>
              {a.risk_score!=null && <span className={`score ${sc}`}>{a.risk_score}</span>}
            </div>
          );
        })
      }
    </div>
  );
}

/* ═══ Timeline Widget ═════════════════════════════════════════════════ */
function TimelineWidget({items}) {
  return (
    <div className="card" style={{display:'flex',flexDirection:'column'}}>
      <div className="card-h">
        <div>
          <div className="card-t">Live events</div>
          <div className="card-sub"><span className="dot warn"/>Last 20</div>
        </div>
        <Link to="/timeline" className="btn btn-out btn-sm">Stream</Link>
      </div>
      <div style={{flex:1,overflowY:'auto',maxHeight:320}}>
        {items.length===0
          ? <div className="alert info">No events.</div>
          : items.map((ev,i)=>{
            const meta=SOURCE_META[ev.honeypot]||{label:ev.honeypot,kind:'honeypot'};
            const sc=fmt.sevToClass(ev.severity);
            const srcColor={cowrie:'var(--gold)',dionaea:'var(--red2)',galah:'var(--purple2)',zeek:'var(--blue2)'}[ev.honeypot]||'var(--text3)';
            return (
              <div key={ev.id||i} style={{
                padding:'7px 0', borderBottom:'1px solid var(--border)',
              }}>
                <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:2}}>
                  <span style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:'var(--text3)'}}>{fmt.time(ev.timestamp)}</span>
                  <span style={{
                    fontSize:10,fontWeight:600,color:srcColor,
                    fontFamily:"'JetBrains Mono',monospace",
                    background:`${srcColor}18`,borderRadius:3,padding:'1px 5px',
                  }}>{meta.label}</span>
                </div>
                <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,color:'var(--text2)'}}>
                  {ev.source_ip||'—'}
                  {ev.country&&<span style={{marginLeft:5}}>{flag(ev.country)}</span>}
                </div>
                <div style={{fontSize:10,color:'var(--text3)',marginTop:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                  {ev.command||ev.http_path||ev.protocol||ev.event_action||'—'}
                </div>
              </div>
            );
          })
        }
      </div>
    </div>
  );
}
