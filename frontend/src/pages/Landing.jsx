import React, { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import './landing.css';

const LOGS = [
  { src: 'cowrie',   ip: '185.220.101.5',   msg: 'SSH brute → root/mongo123',   c: 'var(--gold)'  },
  { src: 'dionaea',  ip: '45.33.32.156',    msg: 'EternalBlue probe :445',       c: 'var(--red2)'  },
  { src: 'galah',    ip: '192.241.x.x',     msg: 'GET /wp-admin HTTP/1.1',       c: 'var(--blue2)' },
  { src: 'zeek',     ip: '10.212.x.x',      msg: 'TCP SYN scan detected',        c: 'var(--text2)' },
  { src: 'profiler', ip: '185.220.101.5',   msg: '[AI] Organised 87%',           c: 'var(--teal)'  },
  { src: 'cowrie',   ip: '91.108.4.55',     msg: 'CMD: wget http://mirai.sh',    c: 'var(--gold)'  },
  { src: 'dionaea',  ip: '185.234.218.1',   msg: 'SMB login attempt',            c: 'var(--red2)'  },
  { src: 'galah',    ip: '198.54.x.x',      msg: 'POST /.env HTTP/1.1',          c: 'var(--blue2)' },
  { src: 'zeek',     ip: '77.88.x.x',       msg: 'DNS tunnel detected',          c: 'var(--text2)' },
  { src: 'profiler', ip: '45.33.32.156',    msg: '[AI] Disorganised 61%',        c: 'var(--teal)'  },
];

export default function Landing() {
  const navRef  = useRef(null);
  const feedRef = useRef(null);

  useEffect(() => {
    const handleScroll = () => navRef.current?.classList.toggle('scrolled', window.scrollY > 50);
    window.addEventListener('scroll', handleScroll);

    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e, i) => { if (e.isIntersecting) setTimeout(() => e.target.classList.add('visible'), i * 80); });
    }, { threshold: 0.1 });
    document.querySelectorAll('.lnd-fade-in').forEach(el => obs.observe(el));

    const tick = () => {
      const n = new Date(), pad = v => String(v).padStart(2,'0');
      const el = document.getElementById('lnd-live-clock');
      if (el) el.textContent = `${pad(n.getHours())}:${pad(n.getMinutes())}:${pad(n.getSeconds())}`;
    };
    const clockId = setInterval(tick, 1000); tick();

    let logIdx = 0;
    const makeRow = (e) => {
      const n = new Date(), pad = v => String(v).padStart(2,'0');
      const r = document.createElement('div');
      r.className = 'lnd-log-row in';
      r.innerHTML = `<span class="lnd-lt">${pad(n.getHours())}:${pad(n.getMinutes())}:${pad(n.getSeconds())}</span><span class="lnd-ls" style="color:${e.c}">${e.src}</span><span class="lnd-li">${e.ip}</span><span class="lnd-lm">${e.msg}</span>`;
      return r;
    };
    const feed = feedRef.current;
    if (feed) {
      for (let i = 0; i < 5; i++) { const r = makeRow(LOGS[logIdx % LOGS.length]); r.classList.remove('in'); feed.appendChild(r); logIdx++; }
    }
    const feedId = setInterval(() => {
      if (!feed) return;
      const r = makeRow(LOGS[logIdx++ % LOGS.length]);
      feed.insertBefore(r, feed.firstChild);
      if (feed.children.length > 5) feed.removeChild(feed.lastChild);
    }, 2200);

    let sv = 48, rv = 7, pv = 14;
    const counterId = setInterval(() => {
      if (Math.random() > .6) { sv++; const el = document.getElementById('cnt-s'); if (el) { el.textContent = sv; el.style.transform='scale(1.25)'; setTimeout(()=>el.style.transform='',300); } }
      if (Math.random() > .75) { rv = Math.max(5, rv+(Math.random()>.5?1:-1)); const el = document.getElementById('cnt-r'); if (el) el.textContent = rv; }
      if (Math.random() > .8)  { pv++; const el = document.getElementById('cnt-p'); if (el) el.textContent = pv; }
    }, 4000);

    const tiltHandlers = [];
    document.querySelectorAll('.lnd-tilt').forEach(card => {
      const onMove = (e) => {
        const r = card.getBoundingClientRect();
        const x = (e.clientX-r.left)/r.width-.5, y = (e.clientY-r.top)/r.height-.5;
        card.style.transform = `perspective(700px) rotateY(${x*12}deg) rotateX(${-y*10}deg) translateZ(6px)`;
        card.style.setProperty('--mx', `${((e.clientX-r.left)/r.width*100).toFixed(1)}%`);
        card.style.setProperty('--my', `${((e.clientY-r.top)/r.height*100).toFixed(1)}%`);
      };
      const onLeave = () => { card.style.transform = 'perspective(700px) rotateY(0) rotateX(0) translateZ(0)'; };
      card.addEventListener('mousemove', onMove);
      card.addEventListener('mouseleave', onLeave);
      tiltHandlers.push({ card, onMove, onLeave });
    });

    return () => {
      window.removeEventListener('scroll', handleScroll);
      clearInterval(clockId); clearInterval(feedId); clearInterval(counterId);
      obs.disconnect();
      tiltHandlers.forEach(({ card, onMove, onLeave }) => { card.removeEventListener('mousemove', onMove); card.removeEventListener('mouseleave', onLeave); });
    };
  }, []);

  const toggleTheme = () => {
    const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('fh.theme', next);
  };

  return (
    <div className="lnd-root">

      {/* NAV */}
      <nav ref={navRef} className="lnd-nav">
        <Link to="/" className="lnd-nav-logo">
          <svg className="lnd-nav-logomark" viewBox="0 0 42 46" fill="none">
            <polygon points="21,2 39,12 39,34 21,44 3,34 3,12" stroke="currentColor" strokeWidth="1.8" fill="rgba(140,26,43,0.08)"/>
            <line x1="14" y1="14" x2="14" y2="32" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round"/>
            <line x1="14" y1="14" x2="28" y2="14" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round"/>
            <line x1="14" y1="23" x2="25" y2="23" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"/>
          </svg>
          <span className="lnd-nav-logo-name">FORENHIVE</span>
        </Link>
        <div className="lnd-nav-links">
          <a href="#platform">Platform</a>
          <a href="#honeypots">Honeypots</a>
          <a href="#forensics">Forensics</a>
          <a href="#reporting">Reporting</a>
          <a href="#github">GitHub</a>
        </div>
        <div className="lnd-nav-cta">
          <button className="lnd-theme-toggle" onClick={toggleTheme} aria-label="Toggle theme">
            <span className="lnd-ic-moon">☽</span><span className="lnd-ic-sun">☀</span>
          </button>
          <Link to="/login" className="lnd-btn-ghost">Sign In</Link>
        </div>
      </nav>

      {/* HERO */}
      <section className="lnd-hero">
        <div className="lnd-hero-glow" />
        <div className="lnd-hero-tag">
          <span className="lnd-hero-tag-dot" />
          Open Source &nbsp;·&nbsp; Honeypot &amp; Forensics Platform
        </div>
        <h1 className="lnd-hero-h1">Open Source Honeypot<br /><em>&amp; Forensics Platform.</em></h1>
        <p className="lnd-hero-sub">ForenHive captures attacker activity through honeypots, analyzes it with local AI, and produces certified forensic reports — fully self-hosted.</p>
        <div className="lnd-hero-btns">
          <Link to="/login" className="lnd-btn-lg gold">Access the Platform</Link>
        </div>

        <div className="lnd-hero-mockup">
          <div className="lnd-mockup-frame">
            <div className="lnd-mockup-bar">
              <div className="lnd-mockup-dot" style={{background:'#ff5f57'}} />
              <div className="lnd-mockup-dot" style={{background:'#febc2e'}} />
              <div className="lnd-mockup-dot" style={{background:'#28c840'}} />
              <div className="lnd-mockup-url">forenhive.local / dashboard</div>
            </div>
            <div className="lnd-mockup-body">
              <div className="lnd-mock-sidebar">
                <div className="lnd-mock-logo-row">
                  <svg width="14" height="15" viewBox="0 0 42 46" fill="none" style={{color:'var(--gold)'}}>
                    <polygon points="21,2 39,12 39,34 21,44 3,34 3,12" stroke="currentColor" strokeWidth="2.2" fill="rgba(140,26,43,0.12)"/>
                    <line x1="14" y1="14" x2="14" y2="32" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round"/>
                    <line x1="14" y1="14" x2="28" y2="14" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round"/>
                    <line x1="14" y1="23" x2="24" y2="23" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round"/>
                  </svg>
                  <span className="lnd-mock-logo-name">FORENHIVE</span>
                </div>
                {[['var(--gold)','Dashboard',true],['var(--blue2)','Suspect Profiler'],['var(--red2)','Sessions'],['var(--teal)','Geo Map'],['var(--gold2)','MITRE ATT&CK'],['var(--text3)','PDF Report']].map(([c,label,active])=>(
                  <div key={label} className={`lnd-mock-nav-item${active?' lnd-active':''}`}>
                    <div className="lnd-mdot" style={{background:c}} />{label}
                  </div>
                ))}
              </div>
              <div className="lnd-mock-main">
                <div className="lnd-mock-topbar">
                  <div className="lnd-mock-title">Dashboard — Overview</div>
                  <div className="lnd-mock-live"><span className="lnd-mock-live-dot" />LIVE · <span id="lnd-live-clock">--:--:--</span></div>
                </div>
                <div className="lnd-mock-cards">
                  <div className="lnd-mock-card g"><div className="lnd-mock-cl">Sessions</div><div className="lnd-mock-cv g" id="cnt-s">48</div><div className="lnd-mock-cs">this month</div></div>
                  <div className="lnd-mock-card r"><div className="lnd-mock-cl">Risk ≥80</div><div className="lnd-mock-cv r" id="cnt-r">7</div><div className="lnd-mock-cs">critical</div></div>
                  <div className="lnd-mock-card b"><div className="lnd-mock-cl">Suspects</div><div className="lnd-mock-cv b" id="cnt-p">14</div><div className="lnd-mock-cs">AI profiles</div></div>
                  <div className="lnd-mock-card t"><div className="lnd-mock-cl">YARA hits</div><div className="lnd-mock-cv t">4</div><div className="lnd-mock-cs">Mirai · XMRig</div></div>
                </div>
                <div className="lnd-mock-grid">
                  <div className="lnd-mock-panel">
                    <div className="lnd-mock-ph">Risk Score / Source</div>
                    {[['Cowrie','82%','var(--red2)','82'],['Dionaea','64%','var(--gold)','64'],['Galah','41%','var(--blue2)','41'],['Zeek','27%','var(--teal)','27']].map(([l,w,c,v])=>(
                      <div key={l} className="lnd-mock-bar-row">
                        <div className="lnd-mock-bl">{l}</div>
                        <div className="lnd-mock-bt"><div className="lnd-mock-bf" style={{width:w,background:c}} /></div>
                        <div className="lnd-mock-bv">{v}</div>
                      </div>
                    ))}
                  </div>
                  <div className="lnd-mock-panel">
                    <div className="lnd-mock-ph">Live Event Feed</div>
                    <div className="lnd-log-feed" ref={feedRef} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* STATS */}
      <div className="lnd-stats-band">
        <div className="lnd-stats-grid">
          {[['2.1','M+','Logs indexed'],['3','','Active honeypots'],['100','%','Local AI — zero cloud'],['0','€','License cost']].map(([n,s,l])=>(
            <div key={l} className="lnd-stat-item lnd-fade-in">
              <div className="lnd-stat-num">{n}<span>{s}</span></div>
              <div className="lnd-stat-label">{l}</div>
            </div>
          ))}
        </div>
      </div>

      {/* PLATFORM */}
      <section id="platform" className="lnd-platform">
        <div className="lnd-fade-in" style={{textAlign:'center'}}>
          <div className="lnd-section-tag">Platform</div>
          <h2 className="lnd-section-h2">Capture. Analyze. <em>Profile.</em></h2>
          <p className="lnd-section-sub" style={{margin:'0 auto'}}>A four-layer architecture — from raw threat capture to certified forensic reports.</p>
        </div>
        <div className="lnd-platform-grid">
          <div className="lnd-plat-card lnd-fade-in" style={{'--acc':'var(--gold)'}}>
            <div className="lnd-plat-icon-wrap">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--gold)" strokeWidth="1.8"><path d="M3 9c0-3 9-6 9-6s9 3 9 6-4 3-9 3-9-3-9-3zm0 6c0 3 9 6 9 6s9-3 9-6"/><path d="M3 9v6m18-6v6"/></svg>
            </div>
            <div className="lnd-plat-name">Threat Capture</div>
            <div className="lnd-plat-desc">Three specialized honeypots and a passive network analyzer covering all attack vectors.</div>
            <div className="lnd-plat-tags">{['Cowrie','Dionaea','Galah','Zeek IDS'].map(t=><span key={t} className="lnd-plat-tag">{t}</span>)}</div>
          </div>
          <div className="lnd-plat-card lnd-fade-in" style={{'--acc':'var(--red2)'}}>
            <div className="lnd-plat-icon-wrap" style={{background:'rgba(201,61,85,0.08)',borderColor:'rgba(201,61,85,0.25)'}}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--red2)" strokeWidth="1.8"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/><path d="M11 8v3l2 2"/></svg>
            </div>
            <div className="lnd-plat-name">Forensic Intelligence</div>
            <div className="lnd-plat-desc">IP enrichment, YARA scanning, VirusTotal and risk scoring 0–100 for every captured event.</div>
            <div className="lnd-plat-tags">{['YARA','VirusTotal','AbuseIPDB','GeoIP'].map(t=><span key={t} className="lnd-plat-tag">{t}</span>)}</div>
          </div>
          <div className="lnd-plat-card lnd-fade-in" style={{'--acc':'var(--blue2)'}}>
            <div className="lnd-plat-icon-wrap" style={{background:'rgba(26,79,187,0.08)',borderColor:'rgba(26,79,187,0.25)'}}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--blue2)" strokeWidth="1.8"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18"/></svg>
            </div>
            <div className="lnd-plat-name">Behavioral Profiling</div>
            <div className="lnd-plat-desc">Local Mistral 7B generates attacker profiles with MITRE ATT&amp;CK kill chains and case memory.</div>
            <div className="lnd-plat-tags">{['Mistral 7B','MITRE ATT&CK','Ollama'].map(t=><span key={t} className="lnd-plat-tag">{t}</span>)}</div>
          </div>
          <div className="lnd-plat-card lnd-fade-in" style={{'--acc':'var(--teal)'}}>
            <div className="lnd-plat-icon-wrap" style={{background:'rgba(0,191,165,0.08)',borderColor:'rgba(0,191,165,0.25)'}}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--teal)" strokeWidth="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
            </div>
            <div className="lnd-plat-name">Certified Evidence</div>
            <div className="lnd-plat-desc">RFC 3161 timestamped PDF reports, SHA-256 integrity and STIX 2.1 export for legal admissibility.</div>
            <div className="lnd-plat-tags">{['RFC 3161','SHA-256','STIX 2.1'].map(t=><span key={t} className="lnd-plat-tag">{t}</span>)}</div>
          </div>
        </div>
      </section>

      {/* FORENSIC ENGINE */}
      <div className="lnd-feat-section" id="forensics">
        <div className="lnd-feat-inner">
          <div className="lnd-fade-in">
            <div className="lnd-section-tag">Forensic Engine</div>
            <h3 className="lnd-feat-h3">AI-powered<br /><em>attacker profiling</em></h3>
            <p className="lnd-feat-desc">Mistral 7B runs entirely on your server via Ollama. Every attacker receives a full behavioral profile — sophistication, objective, organised score — grounded in FBI criminological methodology (Ressler &amp; Douglas, 1988).</p>
            <Link to="/login" className="lnd-feat-link">Learn more →</Link>
          </div>
          <div className="lnd-fade-in">
            <div className="lnd-fv-card">
              <div className="lnd-fv-header">
                <div className="lnd-fv-title">Suspect Profile — 185.220.101.5</div>
                <span className="lnd-fv-badge crit">CRITICAL</span>
              </div>
              <div className="lnd-fv-row"><span className="lnd-fv-label">sophistication</span><div className="lnd-fv-bar-wrap"><div className="lnd-fv-bar" style={{width:'78%',background:'var(--red2)'}} /></div><span className="lnd-fv-val" style={{color:'var(--red2)'}}>HIGH</span></div>
              <div className="lnd-fv-row"><span className="lnd-fv-label">organised_score</span><div className="lnd-fv-bar-wrap"><div className="lnd-fv-bar" style={{width:'85%',background:'var(--gold)'}} /></div><span className="lnd-fv-val">85/100</span></div>
              <div className="lnd-fv-row"><span className="lnd-fv-label">confidence</span><div className="lnd-fv-bar-wrap"><div className="lnd-fv-bar" style={{width:'87%',background:'var(--teal)'}} /></div><span className="lnd-fv-val" style={{color:'var(--teal)'}}>87%</span></div>
              <div className="lnd-fv-quote">"Organised attacker, structured MO. SSH recon → MongoDB pivot. Tor node — deliberate anti-forensics."</div>
              <div className="lnd-tag-row">{['T1110','T1078','T1105','Tor Node'].map(t=><span key={t} className="lnd-fv-tag">{t}</span>)}</div>
            </div>
          </div>
        </div>
      </div>

      {/* MITRE */}
      <div className="lnd-feat-section alt">
        <div className="lnd-feat-inner rev">
          <div className="lnd-fade-in">
            <div className="lnd-section-tag">MITRE ATT&amp;CK</div>
            <h3 className="lnd-feat-h3">Kill chain<br /><em>automatically reconstructed</em></h3>
            <p className="lnd-feat-desc">Every session is classified against MITRE ATT&amp;CK by Mistral 7B. Cross-honeypot correlation within ±24h links Cowrie, Dionaea, Galah and Zeek to rebuild the attacker's full path.</p>
            <Link to="/login" className="lnd-feat-link">Explore the mapping →</Link>
          </div>
          <div className="lnd-fade-in">
            <div className="lnd-fv-card">
              <div className="lnd-fv-header"><div className="lnd-fv-title">Kill Chain — 185.220.101.5</div><span className="lnd-fv-badge info">MAPPED</span></div>
              {[
                ['Reconnaissance','T1595 · T1592','Zeek','rgba(140,26,43,0.08)','var(--border2)','var(--gold)'],
                ['Initial Access','T1110 · T1078','Cowrie','rgba(201,61,85,0.10)','rgba(201,61,85,0.25)','var(--red2)'],
                ['Execution','T1059 · T1106','Cowrie','rgba(26,79,187,0.10)','rgba(26,79,187,0.25)','var(--blue2)'],
                ['Lateral Movement','T1021 · T1550','Dionaea','rgba(0,191,165,0.08)','rgba(0,191,165,0.20)','var(--teal)'],
                ['C2 Transfer','T1105 · T1071','Zeek','rgba(140,26,43,0.06)','var(--border)','var(--gold)'],
              ].map(([label,tech,src,bg,border,color])=>(
                <div key={label} className="lnd-kc-row" style={{background:bg,border:`1px solid ${border}`}}>
                  <span className="lnd-kc-label">{label}</span>
                  <span className="lnd-kc-tech" style={{color}}>{tech}</span>
                  <span className="lnd-kc-src">{src}</span>
                </div>
              ))}
              <div style={{marginTop:10,textAlign:'center',fontSize:10,fontFamily:"'JetBrains Mono',monospace",color:'var(--text3)'}}>5 tactics · ±24h correlation window</div>
            </div>
          </div>
        </div>
      </div>

      {/* ALERTS */}
      <div className="lnd-feat-section" id="alerts">
        <div className="lnd-feat-inner rev">
          <div className="lnd-fade-in">
            <div className="lnd-section-tag">Real-Time Alerts</div>
            <h3 className="lnd-feat-h3">Instant notifications<br /><em>via Email &amp; WhatsApp</em></h3>
            <p className="lnd-feat-desc">The moment a critical threat is detected, ForenHive sends a structured alert directly to your inbox and WhatsApp — with IP, risk score, honeypot source, and a direct link to the forensic report.</p>
            <p className="lnd-feat-desc" style={{marginTop:-12}}>No polling. No dashboard watching. You get notified the instant an attacker crosses the threshold.</p>
            <div className="lnd-tag-row" style={{marginTop:0}}>
              {['Risk ≥ threshold','SMTP / TLS','WhatsApp API','Instant delivery'].map(t=><span key={t} className="lnd-fv-tag">{t}</span>)}
            </div>
          </div>
          <div className="lnd-fade-in">
            <div style={{display:'flex',flexDirection:'column',gap:14}}>
              {/* Email alert mockup */}
              <div className="lnd-alert-card">
                <div className="lnd-alert-card-header">
                  <div className="lnd-alert-icon lnd-alert-icon-mail">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                  </div>
                  <div>
                    <div className="lnd-alert-card-title">Email Alert</div>
                    <div className="lnd-alert-card-sub">zeineb.benrhouma@iset-rades.tn</div>
                  </div>
                  <span className="lnd-fv-badge crit" style={{marginLeft:'auto'}}>CRITICAL</span>
                </div>
                <div className="lnd-alert-subject">🚨 [ForenHive] Critical threat detected — 185.220.101.5</div>
                <div className="lnd-alert-body">
                  <div className="lnd-alert-row"><span className="lnd-alert-key">Source IP</span><span className="lnd-alert-val">185.220.101.5 (RU · Tor exit)</span></div>
                  <div className="lnd-alert-row"><span className="lnd-alert-key">Risk Score</span><span className="lnd-alert-val" style={{color:'var(--red2)',fontWeight:700}}>82 / 100</span></div>
                  <div className="lnd-alert-row"><span className="lnd-alert-key">Honeypot</span><span className="lnd-alert-val">Cowrie SSH :2222</span></div>
                  <div className="lnd-alert-row"><span className="lnd-alert-key">YARA</span><span className="lnd-alert-val" style={{color:'var(--red2)'}}>Mirai.B — MATCH</span></div>
                  <div className="lnd-alert-row"><span className="lnd-alert-key">Timestamp</span><span className="lnd-alert-val">2026-05-20 03:14:52 UTC</span></div>
                </div>
                <div className="lnd-alert-footer">View full forensic report →</div>
              </div>
              {/* WhatsApp alert mockup */}
              <div className="lnd-alert-card lnd-wapp-card">
                <div className="lnd-alert-card-header">
                  <div className="lnd-alert-icon lnd-alert-icon-wapp">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 0C5.373 0 0 5.373 0 12c0 2.127.555 4.126 1.526 5.863L0 24l6.335-1.507A11.945 11.945 0 0 0 12 24c6.627 0 12-5.373 12-12S18.627 0 12 0zm0 21.818a9.8 9.8 0 0 1-5.013-1.376l-.36-.214-3.722.885.933-3.618-.235-.372A9.77 9.77 0 0 1 2.182 12C2.182 6.57 6.57 2.182 12 2.182c5.43 0 9.818 4.388 9.818 9.818 0 5.43-4.388 9.818-9.818 9.818z"/></svg>
                  </div>
                  <div>
                    <div className="lnd-alert-card-title">WhatsApp Alert</div>
                    <div className="lnd-alert-card-sub">ForenHive Bot</div>
                  </div>
                  <span style={{marginLeft:'auto',fontSize:10,fontFamily:"'JetBrains Mono',monospace",color:'var(--text3)'}}>03:14</span>
                </div>
                <div className="lnd-wapp-bubble">
                  <div style={{fontWeight:700,marginBottom:6,color:'var(--red2)'}}>🚨 CRITICAL ALERT</div>
                  <div style={{marginBottom:4}}><b>IP:</b> 185.220.101.5 (RU)</div>
                  <div style={{marginBottom:4}}><b>Risk:</b> 82/100 — Mirai.B detected</div>
                  <div style={{marginBottom:4}}><b>Source:</b> Cowrie SSH honeypot</div>
                  <div style={{marginBottom:4}}><b>Time:</b> 2026-05-20 03:14 UTC</div>
                  <div style={{marginTop:8,color:'var(--teal)',fontSize:11}}>→ forenhive.local/reporting</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* REPORTING */}
      <div className="lnd-feat-section alt" id="reporting">
        <div className="lnd-feat-inner">
          <div className="lnd-fade-in">
            <div className="lnd-section-tag">Forensic Reporting</div>
            <h3 className="lnd-feat-h3">Tamper-evident<br /><em>forensic reporting</em></h3>
            <p className="lnd-feat-desc">Every analysis is sealed with an RFC 3161 trusted timestamp, a SHA-256 integrity hash and chain-of-custody documentation — so each artifact can be proven byte-identical to what was collected. Reports render as structured PDFs via WeasyPrint and export as STIX 2.1 bundles for CTI platforms.</p>
            <p className="lnd-feat-desc" style={{marginTop:-12}}>Deterministic findings — YARA, the 18-signal risk score, MITRE mapping — are recorded as <strong>evidence</strong>. The AI-assisted suspect profile is flagged as an <strong>investigative lead</strong>, never offered as standalone proof. The whole chain is preserved and reproducible.</p>
            <Link to="/login" className="lnd-feat-link">View a sample report →</Link>
          </div>
          <div className="lnd-fade-in">
            <div className="lnd-report-card">
              <div className="lnd-report-header">
                <div className="lnd-report-title">FORENHIVE — FORENSIC REPORT</div>
                <div className="lnd-report-meta">Generated 2026-04-26 13:47 UTC</div>
              </div>
              <div className="lnd-report-body">
                <div className="lnd-report-section">
                  <div className="lnd-report-section-title">
                    Deterministic Findings&nbsp;&nbsp;<span className="lnd-report-section-sub">— reproducible evidence</span>
                  </div>
                  {[
                    ['Source IP', <span>185.220.101.5 <span className="lnd-report-note">(Tor exit)</span></span>, null],
                    ['Risk score', '82 / 100', 'var(--red2)'],
                    ['MITRE tactics', '5 mapped (conf. 1.0)', null],
                    ['YARA', 'Mirai variant — MATCH', 'var(--red2)'],
                  ].map(([k,v,c])=>(
                    <div key={k} className="lnd-report-row"><span className="lnd-report-key">{k}</span><span className="lnd-report-val" style={c?{color:c,fontWeight:700}:{}}>{v}</span></div>
                  ))}
                </div>
                <div className="lnd-report-section">
                  <div className="lnd-report-section-title lnd-report-section-title-lead">
                    Assessment&nbsp;&nbsp;<span className="lnd-report-section-sub lnd-report-section-sub-lead">— AI-assisted lead — not evidence</span>
                  </div>
                  {[
                    ['Profile', 'Organised attacker', null],
                    ['Confidence', <span>71% <span className="lnd-report-note">(Mistral 7B)</span></span>, null],
                  ].map(([k,v,c])=>(
                    <div key={k} className="lnd-report-row"><span className="lnd-report-key">{k}</span><span className="lnd-report-val" style={c?{color:c}:{}}>{v}</span></div>
                  ))}
                </div>
                <div className="lnd-report-section" style={{marginBottom:0}}>
                  <div className="lnd-report-section-title">Evidence Integrity</div>
                  <div className="lnd-report-hash">SHA-256: a3f8d21c...e94b7701</div>
                  <div className="lnd-report-ts">Timestamp: RFC 3161 token <span className="lnd-report-note">(freeTSA, fallback TSA on failure)</span></div>
                  <div className="lnd-report-stamps">
                    <span className="lnd-report-stamp lnd-stamp-rfc">RFC 3161 TSA</span>
                    <span className="lnd-report-stamp lnd-stamp-sha">SHA-256</span>
                    <span className="lnd-report-stamp lnd-stamp-stix">STIX 2.1</span>
                    <span className="lnd-report-stamp lnd-stamp-pdf">WeasyPrint PDF</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* HONEYPOTS */}
      <section id="honeypots" className="lnd-honeypots">
        <div className="lnd-fade-in" style={{textAlign:'center'}}>
          <div className="lnd-section-tag">Honeypots</div>
          <h2 className="lnd-section-h2">Three specialized <em>honeypots.</em></h2>
          <p className="lnd-section-sub" style={{margin:'0 auto'}}>Each honeypot captures a distinct attack vector and feeds the correlation pipeline automatically.</p>
        </div>
        <div className="lnd-hp-grid">
          <div className="lnd-hp-card lnd-tilt lnd-fade-in" style={{'--acc':'var(--gold)','--glow-color':'rgba(140,26,43,0.12)'}}>
            <div className="lnd-hp-logo-wrap">
              <svg width="120" height="36" viewBox="0 0 120 36" fill="none">
                <ellipse cx="18" cy="18" rx="16" ry="12" stroke="#8C1A2B" strokeWidth="1.6"/>
                <ellipse cx="18" cy="18" rx="10" ry="7" stroke="#8C1A2B" strokeWidth="1.2" strokeDasharray="2 2"/>
                <path d="M8 14 Q18 10 28 14" stroke="#8C1A2B" strokeWidth="1.2" fill="none"/>
                <path d="M8 22 Q18 26 28 22" stroke="#8C1A2B" strokeWidth="1.2" fill="none"/>
                <text x="38" y="23" fontFamily="'Rajdhani',sans-serif" fontWeight="700" fontSize="17" fill="#C93D55" letterSpacing="2">COWRIE</text>
              </svg>
            </div>
            <div className="lnd-hp-proto">SSH :2222 · Telnet :2223</div>
            <div className="lnd-hp-name">SSH / Telnet Honeypot</div>
            <div className="lnd-hp-desc">Medium-interaction honeypot. Captures interactive sessions, executed commands and files downloaded by attackers. Customized as a fake MongoDB banking server.</div>
          </div>
          <div className="lnd-hp-card lnd-tilt lnd-fade-in" style={{'--acc':'var(--red2)','--glow-color':'rgba(201,61,85,0.10)'}}>
            <div className="lnd-hp-logo-wrap">
              <svg width="130" height="36" viewBox="0 0 130 36" fill="none">
                <path d="M18 28 Q8 20 10 10 Q18 4 18 14" fill="none" stroke="#C93D55" strokeWidth="1.8" strokeLinecap="round"/>
                <path d="M18 28 Q28 20 26 10 Q18 4 18 14" fill="none" stroke="#C93D55" strokeWidth="1.8" strokeLinecap="round"/>
                <line x1="18" y1="14" x2="18" y2="32" stroke="#C93D55" strokeWidth="1.6" strokeLinecap="round"/>
                <circle cx="9" cy="10" r="1.5" fill="#C93D55"/><circle cx="27" cy="10" r="1.5" fill="#C93D55"/><circle cx="13" cy="8" r="1" fill="#C93D55"/><circle cx="23" cy="8" r="1" fill="#C93D55"/>
                <text x="36" y="23" fontFamily="'Rajdhani',sans-serif" fontWeight="700" fontSize="15" fill="#C93D55" letterSpacing="1.5">DIONAEA</text>
              </svg>
            </div>
            <div className="lnd-hp-proto">SMB :445 · MySQL :3306</div>
            <div className="lnd-hp-name">Multi-Protocol Honeypot</div>
            <div className="lnd-hp-desc">Captures malware, network exploits and in-memory binaries across 11 exposed services including SMB, MySQL, FTP, MongoDB and MSSQL.</div>
          </div>
          <div className="lnd-hp-card lnd-tilt lnd-fade-in" style={{'--acc':'var(--blue2)','--glow-color':'rgba(106,176,255,0.08)'}}>
            <div className="lnd-hp-logo-wrap">
              <svg width="110" height="36" viewBox="0 0 110 36" fill="none">
                <path d="M20 30 Q12 24 13 16 Q16 8 22 10 Q26 12 24 18 Q28 16 30 12 Q32 8 28 6 Q24 4 20 8" stroke="#6AB0FF" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M22 10 Q26 6 30 4 Q28 8 26 10" stroke="#6AB0FF" strokeWidth="1.4" fill="none" strokeLinecap="round"/>
                <ellipse cx="16" cy="15" rx="2" ry="2.5" stroke="#6AB0FF" strokeWidth="1.2"/>
                <circle cx="15.5" cy="14.5" r=".8" fill="#6AB0FF"/>
                <path d="M20 30 Q16 32 14 34" stroke="#6AB0FF" strokeWidth="1.6" strokeLinecap="round"/>
                <path d="M20 30 Q22 32 21 34" stroke="#6AB0FF" strokeWidth="1.6" strokeLinecap="round"/>
                <text x="34" y="23" fontFamily="'Rajdhani',sans-serif" fontWeight="700" fontSize="17" fill="#6AB0FF" letterSpacing="2">GALAH</text>
              </svg>
            </div>
            <div className="lnd-hp-proto">HTTP :8080 · :8888</div>
            <div className="lnd-hp-name">LLM HTTP Honeypot</div>
            <div className="lnd-hp-desc">LLM-powered HTTP honeypot. Generates realistic, context-aware responses via Mistral 7B to trap bots, web scanners and automated exploits.</div>
          </div>
        </div>
      </section>

      {/* ZEEK */}
      <div className="lnd-zeek-band">
        <div className="lnd-zeek-inner">
          <div className="lnd-zeek-logo-wrap">
            <svg width="80" height="40" viewBox="0 0 80 40" fill="none">
              <path d="M8 10 L48 10 L12 30 L52 30" stroke="var(--gold)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/>
              <path d="M56 20 Q64 14 72 20 Q64 26 56 20Z" fill="var(--gold)" opacity=".8"/>
              <path d="M56 20 L50 20" stroke="var(--gold)" strokeWidth="2" strokeLinecap="round"/>
              <circle cx="64" cy="18" r="1.2" fill="var(--bg2)"/>
            </svg>
          </div>
          <div className="lnd-zeek-sep" />
          <div>
            <div className="lnd-zeek-title">Zeek — Passive Network Analyzer (not a honeypot)</div>
            <div className="lnd-zeek-desc">Zeek passively monitors incoming traffic on eno8303 / eno12399 and enriches cross-honeypot correlation: SYN scans, NTLM sessions, suspicious DNS queries.</div>
            <div className="lnd-zeek-tags">{['Passive IDS','SYN scan','NTLM','DNS','network_mode: host'].map(t=><span key={t} className="lnd-zeek-tag">{t}</span>)}</div>
          </div>
        </div>
      </div>

      {/* GITHUB */}
      <div className="lnd-github-band" id="github">
        <div className="lnd-github-inner">
          <div className="lnd-fade-in">
            <div className="lnd-section-tag">Open Source</div>
            <h2 className="lnd-section-h2">100% open,<br /><em>zero lock-in.</em></h2>
            <p>Self-hosted via Docker Compose in under 15 minutes. Every line of code is public, auditable and free — no license, no vendor dependency.</p>
            <a href="https://github.com/zeinebbr7/forenhive" target="_blank" rel="noreferrer" className="lnd-btn-lg gh">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
              View on GitHub
            </a>
          </div>
          <div className="lnd-github-visual lnd-fade-in">
            <div className="lnd-gh-bar">
              <div className="lnd-gh-dot" style={{background:'#ff5f57'}} /><div className="lnd-gh-dot" style={{background:'#febc2e'}} /><div className="lnd-gh-dot" style={{background:'#28c840'}} />
              <span style={{fontSize:11,fontFamily:"'JetBrains Mono',monospace",color:'var(--text3)',marginLeft:8}}>github.com / zeinebbr7 / forenhive</span>
            </div>
            <div className="lnd-gh-body">
              <div className="lnd-gh-repo-header">
                <div className="lnd-gh-repo-icon">
                  <svg width="16" height="16" viewBox="0 0 42 46" fill="none" style={{color:'var(--gold)'}}>
                    <polygon points="21,2 39,12 39,34 21,44 3,34 3,12" stroke="currentColor" strokeWidth="2.2" fill="rgba(140,26,43,0.12)"/>
                    <line x1="14" y1="14" x2="14" y2="32" stroke="currentColor" strokeWidth="3" strokeLinecap="round"/>
                    <line x1="14" y1="14" x2="28" y2="14" stroke="currentColor" strokeWidth="3" strokeLinecap="round"/>
                    <line x1="14" y1="23" x2="24" y2="23" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"/>
                  </svg>
                </div>
                <div>
                  <div className="lnd-gh-repo-name">zeinebbr7 / forenhive</div>
                  <div className="lnd-gh-repo-sub">Open Source · Python · Docker</div>
                </div>
              </div>
              <div className="lnd-gh-desc">Unified honeypot and forensics platform — threat capture, AI attacker profiling, certified PDF reports.</div>
              <div className="lnd-gh-lang-row">
                <span className="lnd-gh-lang" style={{color:'var(--blue2)',borderColor:'rgba(106,176,255,0.25)'}}>Python</span>
                <span className="lnd-gh-lang" style={{color:'var(--teal)',borderColor:'rgba(0,191,165,0.25)'}}>Docker</span>
                <span className="lnd-gh-lang" style={{color:'var(--gold)',borderColor:'var(--border2)'}}>Elasticsearch</span>
                <span className="lnd-gh-lang" style={{color:'var(--red2)',borderColor:'rgba(201,61,85,0.25)'}}>FastAPI</span>
              </div>
              <div className="lnd-gh-meta">
                <span className="lnd-gh-meta-item">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
                  Open Source
                </span>
                <span className="lnd-gh-meta-item">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/></svg>
                  ISET Rades 2026
                </span>
                <span className="lnd-gh-meta-item">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>
                  PFE Project
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* CTA */}
      <section className="lnd-cta">
        <div className="lnd-section-tag" style={{margin:'0 auto 24px'}}>Get Started</div>
        <h2 className="lnd-cta-h2">Ready to deploy <em>ForenHive</em>?</h2>
        <p className="lnd-cta-sub">100% open source. Docker Compose. Local AI. RFC 3161 certified evidence.</p>
        <div className="lnd-cta-btns">
          <Link to="/login" className="lnd-btn-lg gold">Access the Platform</Link>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="lnd-footer">
        <div className="lnd-footer-inner">
          <div className="lnd-footer-top">
            <div className="lnd-footer-brand">
              <svg className="lnd-footer-logomark" viewBox="0 0 42 46" fill="none">
                <polygon points="21,2 39,12 39,34 21,44 3,34 3,12" stroke="currentColor" strokeWidth="1.8" fill="rgba(140,26,43,0.08)"/>
                <line x1="14" y1="14" x2="14" y2="32" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"/>
                <line x1="14" y1="14" x2="28" y2="14" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"/>
                <line x1="14" y1="23" x2="25" y2="23" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"/>
              </svg>
              <span className="lnd-footer-brand-name">FORENHIVE</span>
            </div>
            <div className="lnd-footer-col">
              <h4>Contact</h4>
              <a href="https://github.com/zeinebbr7/forenhive" target="_blank" rel="noreferrer">
                <svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
                github.com/zeinebbr7/forenhive
              </a>
              <a href="mailto:zeineb.benrhouma@iset-rades.tn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                zeineb.benrhouma@iset-rades.tn
              </a>
              <a href="mailto:ismail.cherif@iset-rades.tn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
                ismail.cherif@iset-rades.tn
              </a>
            </div>
          </div>
          <div className="lnd-footer-bottom">
            <span>© 2026 ForenHive · Open Source Security Platform</span>
            <span>Made in Tunisia</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
