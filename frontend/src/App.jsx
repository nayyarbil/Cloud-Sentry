import { useAuth } from "react-oidc-context";
import { useState, useRef } from "react";

function App() {
  const auth = useAuth();
  const [target, setTarget] = useState("");
  
  const [loadingDns, setLoadingDns] = useState(false);
  const [loadingNetwork, setLoadingNetwork] = useState(false);
  const [loadingWeb, setLoadingWeb] = useState(false);
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);

  const [dnsResults, setDnsResults] = useState(null);
  const [networkResults, setNetworkResults] = useState(null);
  const [webResults, setWebResults] = useState(null);
  const [attackVectors, setAttackVectors] = useState(null);

  const dnsRef = useRef(null);
  const networkRef = useRef(null);
  const webRef = useRef(null);
  const analysisRef = useRef(null);

  const launchModule = async (moduleName, setLoading, setResults, scrollRef) => {
    if (!target) return alert("Target Required");
    setLoading(true);
    setResults(null); 

    try {
      const response = await fetch(`http://localhost:8000/scan/${moduleName}?target=${target}`, {
        method: "POST",
        headers: { "Authorization": `Bearer ${auth.user?.access_token}` },
      });
      const data = await response.json();
      if (response.ok) {
        setResults(data.results);
        setTimeout(() => {
          scrollRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 150);
      }
    } catch (err) {
      alert("Backend Offline or Timeout");
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async () => {
    if (!dnsResults && !networkResults && !webResults) return alert("Run at least one intel module first.");
    setLoadingAnalysis(true);
    setAttackVectors(null);

    try {
      const response = await fetch(`http://localhost:8000/scan/analyze`, {
        method: "POST",
        headers: { 
          "Authorization": `Bearer ${auth.user?.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ dns: dnsResults, network: networkResults, web: webResults })
      });
      const data = await response.json();
      if (response.ok) {
        setAttackVectors(data.results);
        setTimeout(() => {
          analysisRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 150);
      }
    } catch (err) {
      alert("Analysis Engine Failed");
    } finally {
      setLoadingAnalysis(false);
    }
  };

  const getSeverityStyle = (sev) => {
    if (sev === "CRITICAL") return { bg: 'rgba(225, 29, 72, 0.1)', border: '#e11d48', text: '#fda4af' }; 
    if (sev === "HIGH") return { bg: 'rgba(234, 88, 12, 0.1)', border: '#ea580c', text: '#fdba74' }; 
    if (sev === "MEDIUM") return { bg: 'rgba(202, 138, 4, 0.1)', border: '#ca8a04', text: '#fde047' }; 
    if (sev === "LOW") return { bg: 'rgba(37, 99, 235, 0.1)', border: '#2563eb', text: '#93c5fd' }; 
    return { bg: 'rgba(16, 185, 129, 0.1)', border: '#10b981', text: '#6ee7b7' }; 
  };

  const globalCss = `
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');
    body { 
      margin: 0; 
      background-color: #020617;
      background-image: radial-gradient(circle at 15% 50%, rgba(59, 130, 246, 0.1), transparent 25%), radial-gradient(circle at 85% 30%, rgba(225, 29, 72, 0.1), transparent 25%);
      font-family: 'Inter', sans-serif; 
      color: #f8fafc; 
      min-height: 100vh; 
      scroll-behavior: smooth; 
      overflow-x: hidden;
    }
    
    /* ANIMATED CYBER GRID BACKGROUND */
    .bg-grid {
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 100vh;
      z-index: -2;
      background-image: 
        linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      animation: gridMove 20s linear infinite;
    }
    @keyframes gridMove {
      0% { transform: translateY(0); }
      100% { transform: translateY(40px); }
    }

    /* SWEEPING SCANNER LINE */
    .scanner-line {
      position: fixed;
      top: 0; left: 0; width: 100vw; height: 3px;
      background: linear-gradient(to right, transparent, rgba(59, 130, 246, 0.8), rgba(167, 139, 250, 0.8), transparent);
      box-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
      z-index: -1;
      opacity: 0.6;
      animation: scanSweep 6s ease-in-out infinite;
    }
    @keyframes scanSweep {
      0% { top: -10%; opacity: 0; }
      20% { opacity: 0.6; }
      80% { opacity: 0.6; }
      100% { top: 110%; opacity: 0; }
    }

    .glass-panel { background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.7); }
    .btn { transition: all 0.2s ease; font-family: 'Inter', sans-serif; letter-spacing: 0.5px; }
    .btn:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 8px 20px -6px rgba(59, 130, 246, 0.6); }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .input-glow:focus { outline: none; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.3); border-color: #3b82f6; }
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); border-radius: 10px; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 10px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.3); }
    .mono { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; }
  `;

  if (!auth.isAuthenticated) {
    return (
      <div style={{ height: '100vh', width: '100vw', display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
        <style>{globalCss}</style>
        <div className="bg-grid"></div>
        <div className="scanner-line"></div>
        
        <div className="glass-panel" style={{padding: '50px', textAlign: 'center', maxWidth: '500px', width: '90%', zIndex: 10}}>
          <h1 style={{fontSize: '2.5rem', fontWeight: '800', margin: '0 0 10px 0', background: 'linear-gradient(to right, #60a5fa, #a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent'}}>CLOUD-SENTRY</h1>
          <p style={{color: '#94a3b8', marginBottom: '40px', lineHeight: '1.6'}}>State-level reconnaissance and tactical threat analysis platform.</p>
          <button className="btn" style={{...styles.primaryBtn, padding: '15px 40px', fontSize: '1.1rem'}} onClick={() => auth.signinRedirect()}>Initiate Access</button>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <style>{globalCss}</style>
      <div className="bg-grid"></div>
      
      <header className="glass-panel" style={styles.header}>
        <div style={{fontWeight: '600', color: '#cbd5e1'}}>Operator: <span style={{color: '#fff'}}>{auth.user?.profile.email}</span></div>
        <button style={styles.logoutBtn} onClick={() => auth.removeUser()}>Terminate Session</button>
      </header>
      
      <div className="glass-panel" style={styles.controlCenter}>
        <input 
          className="input-glow" 
          style={styles.input} 
          placeholder="Enter target domain or IP..." 
          value={target} 
          onChange={(e) => setTarget(e.target.value)} 
        />
        
        <div style={styles.actionGrid}>
          <button className="btn" style={styles.moduleBtn} onClick={() => launchModule('dns', setLoadingDns, setDnsResults, dnsRef)} disabled={loadingDns}>
            {loadingDns ? "Mapping Infra..." : "1. DNS & Infra"}
          </button>
          <button className="btn" style={styles.moduleBtn} onClick={() => launchModule('network', setLoadingNetwork, setNetworkResults, networkRef)} disabled={loadingNetwork}>
            {loadingNetwork ? "Knocking Ports..." : "2. Network Scan"}
          </button>
          <button className="btn" style={styles.moduleBtn} onClick={() => launchModule('web', setLoadingWeb, setWebResults, webRef)} disabled={loadingWeb}>
            {loadingWeb ? "Crawling Surface..." : "3. Web Intel"}
          </button>
        </div>
        
        <button className="btn" style={styles.tacticianBtn} onClick={runAnalysis} disabled={loadingAnalysis}>
          {loadingAnalysis ? "Correlating Intelligence..." : "4. Generate Attack Paths"}
        </button>
      </div>

      <div style={styles.dashboard}>
        {/* ATTACK VECTORS PANEL */}
        {attackVectors && (
          <div ref={analysisRef} className="glass-panel" style={{marginBottom: '30px', padding: '30px', border: '1px solid rgba(225, 29, 72, 0.3)', scrollMarginTop: '100px'}}>
            <h3 style={{marginTop: 0, marginBottom: '20px', fontSize: '1.2rem', fontWeight: '600', display: 'flex', alignItems: 'center', gap: '10px'}}>
              <div style={{width: '8px', height: '8px', borderRadius: '50%', background: '#e11d48', boxShadow: '0 0 10px #e11d48'}}></div>
              Tactical Attack Vectors
            </h3>
            <div style={{display: 'flex', flexDirection: 'column', gap: '15px'}}>
              {attackVectors.map((v, i) => {
                const style = getSeverityStyle(v.severity);
                return (
                  <div key={i} style={{padding: '15px 20px', background: style.bg, borderLeft: `4px solid ${style.border}`, borderRadius: '0 8px 8px 0'}}>
                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px'}}>
                      <span style={{color: style.text, fontWeight: '600', fontSize: '1.05rem'}}>{v.title}</span>
                      <span style={{fontSize: '0.75rem', padding: '3px 8px', borderRadius: '12px', background: style.border, color: '#fff', fontWeight: '800', letterSpacing: '1px'}}>{v.severity}</span>
                    </div>
                    <p style={{margin: 0, color: '#cbd5e1', fontSize: '0.95rem', lineHeight: '1.5'}}>{v.action}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <div style={styles.grid}>
          {/* DNS PANEL */}
          {dnsResults && (
            <div ref={dnsRef} className="glass-panel" style={{...styles.intelCard, scrollMarginTop: '100px'}}>
              <h3 style={styles.cardTitle}>Infrastructure Topology</h3>
              <p style={{margin: '0 0 15px 0', color: '#94a3b8', fontSize: '0.9rem'}}>Base IP: <span className="mono" style={{color: '#fff'}}>{dnsResults.base_ip}</span></p>
              <ul style={{...styles.list, maxHeight: '350px', overflowY: 'auto', paddingRight: '10px'}}>
                {dnsResults.subdomains?.map((sub, i) => (
                  <li key={i} style={{display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,0.05)'}}>
                    <span className="mono" style={{color: '#cbd5e1', wordBreak: 'break-all', paddingRight: '10px'}}>{sub.host}</span>
                    <span style={{fontSize: '0.7rem', padding: '2px 6px', borderRadius: '4px', background: sub.status.includes('TAKEOVER') ? 'rgba(225, 29, 72, 0.2)' : 'rgba(255,255,255,0.1)', color: sub.status.includes('TAKEOVER') ? '#fda4af' : '#94a3b8', whiteSpace: 'nowrap', height: 'fit-content'}}>{sub.status}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* NETWORK PANEL */}
          {networkResults && (
            <div ref={networkRef} className="glass-panel" style={{...styles.intelCard, scrollMarginTop: '100px'}}>
              <h3 style={styles.cardTitle}>Network Services</h3>
              <div style={{maxHeight: '350px', overflowY: 'auto', paddingRight: '10px'}}>
                <table style={styles.table}>
                  <thead><tr><th>Port</th><th>Service</th><th>Fingerprint</th></tr></thead>
                  <tbody>
                    {networkResults.open_ports?.map((p, i) => (
                      <tr key={i}>
                        <td className="mono" style={{color: '#38bdf8', padding: '8px 0'}}>{p.port}</td>
                        <td style={{color: '#cbd5e1', padding: '8px 0'}}>{p.service}</td>
                        <td className="mono" style={{color: '#94a3b8', padding: '8px 0'}}>{p.version || '-'}</td>
                      </tr>
                    ))}
                    {networkResults.open_ports?.length === 0 && <tr><td colSpan="3" style={{textAlign: 'center', color: '#64748b', padding: '15px 0'}}>No exposed ports detected.</td></tr>}
                  </tbody>
                </table>
              </div>
              {networkResults.cves?.length > 0 && (
                <div style={{marginTop: '20px'}}>
                  <h4 style={{fontSize: '0.85rem', color: '#f87171', margin: '0 0 10px 0', textTransform: 'uppercase'}}>Known CVEs</h4>
                  <div style={{display: 'flex', flexWrap: 'wrap', gap: '6px', maxHeight: '100px', overflowY: 'auto'}}>
                    {networkResults.cves.map((cve, i) => (
                      <span key={i} className="mono" style={{background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#fca5a5', padding: '4px 8px', borderRadius: '6px', fontSize: '0.75rem'}}>{cve}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* WEB SURFACE PANEL */}
          {webResults && (
            <div ref={webRef} className="glass-panel" style={{...styles.intelCard, scrollMarginTop: '100px'}}>
              <h3 style={styles.cardTitle}>Web Surface & Bundles</h3>
              <div style={{maxHeight: '350px', overflowY: 'auto', paddingRight: '10px'}}>
                <p style={{fontSize: '0.9rem', color: '#94a3b8', margin: '0 0 10px 0'}}>Stack: <span style={{color: '#fff', fontWeight: '600'}}>{webResults.tech_stack?.join(', ')}</span></p>
                
                <h4 style={styles.sectionSubTitle}>Exposed Endpoints</h4>
                <ul style={{...styles.list, marginBottom: '20px'}}>
                  {webResults.exposed_endpoints?.map((e, i) => (
                    <li key={i} className="mono" style={{padding: '6px 0', color: e.status === 200 ? '#34d399' : '#facc15'}}>
                      {e.path} <span style={{opacity: 0.7, fontSize: '0.75rem'}}>[{e.status}]</span>
                    </li>
                  ))}
                  {webResults.exposed_endpoints?.length === 0 && <li style={{color: '#64748b', fontSize: '0.9rem'}}>No critical endpoints exposed.</li>}
                </ul>

                {webResults.js_intel?.secrets?.length > 0 && (
                  <div style={{background: 'rgba(225, 29, 72, 0.1)', border: '1px solid rgba(225, 29, 72, 0.3)', borderRadius: '8px', padding: '12px', marginBottom: '15px'}}>
                    <strong style={{color: '#fda4af', fontSize: '0.85rem', display: 'block', marginBottom: '8px'}}>Leaked Bundle Secrets</strong>
                    <ul style={{listStyle: 'none', padding: 0, margin: 0, gap: '5px', display: 'flex', flexDirection: 'column'}}>
                      {webResults.js_intel.secrets.map((sec, i) => <li key={i} className="mono" style={{color: '#f8fafc', fontSize: '0.8rem', wordBreak: 'break-all'}}>{sec}</li>)}
                    </ul>
                  </div>
                )}

                <h4 style={styles.sectionSubTitle}>Hidden Internal Routes</h4>
                <ul style={styles.list}>
                  {webResults.js_intel?.hidden_routes?.map((route, i) => <li key={i} className="mono" style={{color: '#cbd5e1', padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.02)', wordBreak: 'break-all'}}>{route}</li>)}
                  {webResults.js_intel?.hidden_routes?.length === 0 && <li style={{color: '#64748b', fontSize: '0.9rem'}}>No internal routes extracted.</li>}
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const styles = {
  container: { display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '40px 20px', boxSizing: 'border-box' },
  header: { position: 'fixed', top: '20px', width: '90%', maxWidth: '1400px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '15px 25px', zIndex: 100 },
  logoutBtn: { background: 'transparent', border: 'none', color: '#ef4444', fontWeight: '600', cursor: 'pointer', transition: 'color 0.2s' },
  controlCenter: { width: '100%', maxWidth: '700px', padding: '30px', marginTop: '100px', display: 'flex', flexDirection: 'column', gap: '20px' },
  input: { background: 'rgba(15, 23, 42, 0.6)', border: '1px solid rgba(255, 255, 255, 0.1)', color: '#fff', padding: '16px 20px', borderRadius: '12px', fontSize: '1.1rem', textAlign: 'center', width: '100%', boxSizing: 'border-box' },
  actionGrid: { display: 'flex', gap: '15px', width: '100%' },
  primaryBtn: { background: '#3b82f6', color: '#fff', border: 'none', borderRadius: '8px', cursor: 'pointer', fontWeight: '600' },
  moduleBtn: { flex: 1, background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.3)', color: '#60a5fa', padding: '12px', borderRadius: '8px', cursor: 'pointer', fontWeight: '600', fontSize: '0.9rem' },
  tacticianBtn: { width: '100%', background: 'linear-gradient(to right, #e11d48, #be123c)', color: '#fff', border: 'none', padding: '16px', borderRadius: '8px', cursor: 'pointer', fontWeight: '700', fontSize: '1rem', letterSpacing: '0.5px' },
  dashboard: { width: '100%', maxWidth: '1400px', marginTop: '40px' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '25px', alignItems: 'start' },
  intelCard: { padding: '25px', display: 'flex', flexDirection: 'column' },
  cardTitle: { margin: '0 0 15px 0', fontSize: '1.2rem', fontWeight: '600', color: '#f8fafc', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '10px' },
  sectionSubTitle: { fontSize: '0.85rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '1px', margin: '15px 0 10px 0' },
  list: { listStyle: 'none', padding: 0, margin: 0 },
  table: { width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '0.9rem' },
};

export default App;