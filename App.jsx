import { useState, useEffect, useRef } from "react";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";

// ── Simulated Data Engine ─────────────────────────────────────────────────────

const USERS    = ["alice", "root", "admin", "jenkins", "bob", "guest"];
const SERVICES = ["sshd", "sudo", "apache2", "nginx", "postgresql", "vsftpd"];
const IPS      = ["192.168.1.12","10.0.0.1","172.16.0.5","192.168.100.99","10.10.5.23","203.0.113.44","198.51.100.7"];
const BAD_IPS  = new Set(["192.168.100.99", "203.0.113.44"]);
const ACTIONS  = [
  { msg: "Failed password for root",     sev: "HIGH"     },
  { msg: "Accepted password for alice",  sev: "INFO"     },
  { msg: "Invalid user admin",           sev: "MEDIUM"   },
  { msg: "session opened for root",      sev: "MEDIUM"   },
  { msg: "Connection closed by peer",    sev: "INFO"     },
  { msg: "sudo: authentication failure", sev: "HIGH"     },
  { msg: "PAM: auth failure",            sev: "CRITICAL" },
  { msg: "Disconnected from invalid",    sev: "LOW"      },
  { msg: "New session for jenkins",      sev: "INFO"     },
  { msg: "chmod 777 /etc/passwd",        sev: "CRITICAL" },
];

function randomEntry() {
  const ip  = IPS[Math.floor(Math.random() * IPS.length)];
  const act = ACTIONS[Math.floor(Math.random() * ACTIONS.length)];
  const sev = BAD_IPS.has(ip) ? "CRITICAL" : act.sev;
  return {
    id:        Math.random().toString(36).slice(2),
    timestamp: new Date().toLocaleTimeString(),
    ip,
    user:    USERS[Math.floor(Math.random() * USERS.length)],
    service: SERVICES[Math.floor(Math.random() * SERVICES.length)],
    action:  act.msg,
    severity: sev,
  };
}

function generateHistory() {
  const result = [];
  const now    = new Date();
  for (let i = 29; i >= 0; i--) {
    const t = new Date(now - i * 60000);
    result.push({
      time:     t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      events:   Math.floor(Math.random() * 80) + 20,
      threats:  Math.floor(Math.random() * 15),
      critical: Math.floor(Math.random() * 5),
    });
  }
  return result;
}

const SEVERITY_CFG = {
  CRITICAL: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)",  label: "CRIT"  },
  HIGH:     { color: "#ff9f0a", bg: "rgba(255,159,10,0.12)", label: "HIGH"  },
  MEDIUM:   { color: "#ffd60a", bg: "rgba(255,214,10,0.10)", label: "MED"   },
  LOW:      { color: "#30d158", bg: "rgba(48,209,88,0.10)",  label: "LOW"   },
  INFO:     { color: "#48cae4", bg: "rgba(72,202,228,0.08)", label: "INFO"  },
};

const PIE_COLORS = ["#ff2d55","#ff9f0a","#ffd60a","#30d158","#48cae4"];

// ── Sub-components ────────────────────────────────────────────────────────────

function SeverityBadge({ sev }) {
  const cfg = SEVERITY_CFG[sev] || SEVERITY_CFG.INFO;
  return (
    <span style={{
      fontSize: "10px", fontWeight: 700, letterSpacing: "0.08em",
      padding: "2px 7px", borderRadius: "3px",
      color: cfg.color, background: cfg.bg,
      border: `1px solid ${cfg.color}40`,
      fontFamily: "'JetBrains Mono', monospace",
    }}>{cfg.label}</span>
  );
}

function StatCard({ label, value, sub, accent, icon }) {
  return (
    <div style={{
      background: "linear-gradient(135deg, #0d1117 0%, #161b22 100%)",
      border: `1px solid ${accent}30`,
      borderRadius: "10px", padding: "18px 22px",
      position: "relative", overflow: "hidden",
      boxShadow: `0 0 24px ${accent}10`,
      flex: 1, minWidth: "140px",
    }}>
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: "2px",
        background: `linear-gradient(90deg, transparent, ${accent}, transparent)`,
      }} />
      <div style={{ fontSize: "22px", marginBottom: "6px" }}>{icon}</div>
      <div style={{ fontSize: "30px", fontWeight: 800, color: accent, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
        {value}
      </div>
      <div style={{ fontSize: "11px", color: "#8b949e", marginTop: "4px", fontWeight: 600, letterSpacing: "0.06em" }}>
        {label}
      </div>
      {sub && <div style={{ fontSize: "10px", color: accent + "aa", marginTop: "2px" }}>{sub}</div>}
    </div>
  );
}

function AlertItem({ alert }) {
  const cfg = SEVERITY_CFG[alert.severity] || SEVERITY_CFG.INFO;
  return (
    <div style={{
      display: "flex", alignItems: "flex-start", gap: "10px",
      padding: "10px 14px",
      background: cfg.bg,
      borderLeft: `3px solid ${cfg.color}`,
      borderRadius: "0 6px 6px 0",
      marginBottom: "6px",
      animation: "fadeSlide 0.3s ease",
    }}>
      <div style={{ minWidth: 6, height: 6, borderRadius: "50%", background: cfg.color, marginTop: 5, boxShadow: `0 0 6px ${cfg.color}` }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: "12px", color: "#e6edf3", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {alert.action}
          </span>
          <SeverityBadge sev={alert.severity} />
        </div>
        <div style={{ fontSize: "10px", color: "#8b949e", marginTop: 3, fontFamily: "'JetBrains Mono', monospace" }}>
          {alert.timestamp} · {alert.ip} · {alert.user}@{alert.service}
        </div>
      </div>
    </div>
  );
}

function LogRow({ log }) {
  const cfg = SEVERITY_CFG[log.severity] || SEVERITY_CFG.INFO;
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "70px 1fr 110px 70px 80px",
      gap: "8px", padding: "6px 10px", borderBottom: "1px solid #21262d",
      fontSize: "11px", color: "#c9d1d9", fontFamily: "'JetBrains Mono', monospace",
      alignItems: "center", transition: "background 0.2s",
    }}
    onMouseEnter={e => e.currentTarget.style.background = "#161b22"}
    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
    >
      <span style={{ color: "#8b949e" }}>{log.timestamp}</span>
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{log.action}</span>
      <span style={{ color: "#79c0ff" }}>{log.ip}</span>
      <span style={{ color: "#d2a8ff" }}>{log.user}</span>
      <SeverityBadge sev={log.severity} />
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#161b22", border: "1px solid #30363d", borderRadius: 8, padding: "10px 14px" }}>
      <div style={{ fontSize: 11, color: "#8b949e", marginBottom: 4, fontFamily: "monospace" }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ fontSize: 12, color: p.color, fontFamily: "monospace" }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
};

// ── Main Dashboard ────────────────────────────────────────────────────────────

export default function SOCDashboard() {
  const [logs,      setLogs]      = useState(() => Array.from({ length: 20 }, randomEntry));
  const [alerts,    setAlerts]    = useState(() => Array.from({ length: 6  }, randomEntry).filter(l => l.severity !== "INFO"));
  const [history,   setHistory]   = useState(generateHistory);
  const [counts,    setCounts]    = useState({ total: 0, critical: 0, high: 0, blocked: 0 });
  const [live,      setLive]      = useState(true);
  const [tab,       setTab]       = useState("logs"); // logs | alerts
  const intervalRef = useRef(null);

  // Severity distribution for pie
  const severityDist = Object.entries(
    logs.reduce((acc, l) => { acc[l.severity] = (acc[l.severity] || 0) + 1; return acc; }, {})
  ).map(([name, value]) => ({ name, value }));

  // Top IPs bar chart
  const ipCounts = Object.entries(
    logs.reduce((acc, l) => { acc[l.ip] = (acc[l.ip] || 0) + 1; return acc; }, {})
  ).sort((a,b) => b[1]-a[1]).slice(0,5).map(([ip, count]) => ({ ip: ip.split(".").slice(-2).join("."), count }));

  useEffect(() => {
    if (!live) { clearInterval(intervalRef.current); return; }
    intervalRef.current = setInterval(() => {
      const entry = randomEntry();

      setLogs(prev => [entry, ...prev].slice(0, 60));

      if (entry.severity === "CRITICAL" || entry.severity === "HIGH") {
        setAlerts(prev => [entry, ...prev].slice(0, 20));
        setCounts(prev => ({
          ...prev,
          total:    prev.total    + 1,
          critical: prev.critical + (entry.severity === "CRITICAL" ? 1 : 0),
          high:     prev.high     + (entry.severity === "HIGH"     ? 1 : 0),
          blocked:  prev.blocked  + (BAD_IPS.has(entry.ip)         ? 1 : 0),
        }));
      } else {
        setCounts(prev => ({ ...prev, total: prev.total + 1 }));
      }

      setHistory(prev => {
        const last = { ...prev[prev.length - 1] };
        last.events++;
        if (entry.severity !== "INFO") last.threats++;
        if (entry.severity === "CRITICAL") last.critical++;
        return [...prev.slice(0, -1), last];
      });
    }, 1200);

    return () => clearInterval(intervalRef.current);
  }, [live]);

  const styles = {
    root: {
      minHeight: "100vh",
      background: "#0d1117",
      color: "#e6edf3",
      fontFamily: "'Syne', 'JetBrains Mono', sans-serif",
      padding: "0",
    },
    header: {
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "14px 28px",
      background: "linear-gradient(90deg, #0d1117, #161b22)",
      borderBottom: "1px solid #21262d",
      position: "sticky", top: 0, zIndex: 100,
    },
    logo: {
      display: "flex", alignItems: "center", gap: "12px",
    },
    logoIcon: {
      width: 36, height: 36, borderRadius: 8,
      background: "linear-gradient(135deg, #ff2d55, #ff6b35)",
      display: "flex", alignItems: "center", justifyContent: "center",
      fontSize: 18, boxShadow: "0 0 16px rgba(255,45,85,0.4)",
    },
    logoText: {
      fontSize: 16, fontWeight: 800, letterSpacing: "0.1em",
      color: "#e6edf3",
    },
    logoSub: {
      fontSize: 10, color: "#8b949e", letterSpacing: "0.12em", marginTop: 1,
    },
    liveBtn: {
      display: "flex", alignItems: "center", gap: 8,
      padding: "7px 16px", borderRadius: 6,
      border: live ? "1px solid #30d15850" : "1px solid #30363d",
      background: live ? "rgba(48,209,88,0.1)" : "#161b22",
      color: live ? "#30d158" : "#8b949e",
      cursor: "pointer", fontSize: 11, fontWeight: 700, letterSpacing: "0.08em",
      transition: "all 0.2s",
    },
    dot: {
      width: 7, height: 7, borderRadius: "50%",
      background: live ? "#30d158" : "#8b949e",
      boxShadow: live ? "0 0 8px #30d158" : "none",
      animation: live ? "pulse 1.5s infinite" : "none",
    },
    main: {
      padding: "20px 28px",
      display: "flex", flexDirection: "column", gap: "20px",
      maxWidth: 1400,
    },
    statsRow: {
      display: "flex", gap: "14px", flexWrap: "wrap",
    },
    section: {
      background: "linear-gradient(135deg, #0d1117 0%, #161b22 100%)",
      border: "1px solid #21262d",
      borderRadius: "12px", overflow: "hidden",
    },
    sectionHeader: {
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "14px 18px",
      borderBottom: "1px solid #21262d",
    },
    sectionTitle: {
      fontSize: 12, fontWeight: 700, letterSpacing: "0.1em",
      color: "#8b949e", textTransform: "uppercase",
      display: "flex", alignItems: "center", gap: 8,
    },
    chartsRow: {
      display: "grid", gridTemplateColumns: "2fr 1fr 1fr", gap: "16px",
    },
    tabRow: {
      display: "flex", gap: 0, marginBottom: 0,
    },
    tab: (active) => ({
      padding: "9px 18px", fontSize: 11, fontWeight: 700, letterSpacing: "0.08em",
      cursor: "pointer", border: "none", outline: "none",
      background: active ? "#161b22" : "transparent",
      color: active ? "#e6edf3" : "#8b949e",
      borderBottom: active ? "2px solid #ff2d55" : "2px solid transparent",
      transition: "all 0.2s",
    }),
    logHeader: {
      display: "grid", gridTemplateColumns: "70px 1fr 110px 70px 80px",
      gap: 8, padding: "8px 10px", borderBottom: "1px solid #30363d",
      fontSize: 10, color: "#8b949e", fontWeight: 700, letterSpacing: "0.08em",
      fontFamily: "'JetBrains Mono', monospace", textTransform: "uppercase",
    },
  };

  return (
    <>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; }
        ::-webkit-scrollbar { width: 4px; } 
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
        @keyframes fadeSlide { from { opacity:0; transform:translateY(-6px); } to { opacity:1; transform:translateY(0); } }
      `}</style>

      <div style={styles.root}>
        {/* ── Header ── */}
        <header style={styles.header}>
          <div style={styles.logo}>
            <div style={styles.logoIcon}>🛡️</div>
            <div>
              <div style={styles.logoText}>SOC MONITOR</div>
              <div style={styles.logoSub}>SECURITY OPERATIONS CENTER</div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{ fontSize: 11, color: "#8b949e", fontFamily: "monospace" }}>
              {new Date().toLocaleString()}
            </div>
            <button style={styles.liveBtn} onClick={() => setLive(v => !v)}>
              <span style={styles.dot} />
              {live ? "LIVE" : "PAUSED"}
            </button>
          </div>
        </header>

        <div style={styles.main}>

          {/* ── Stats Row ── */}
          <div style={styles.statsRow}>
            <StatCard label="TOTAL EVENTS"    value={counts.total + logs.length}   icon="📡" accent="#48cae4" sub="last session" />
            <StatCard label="CRITICAL ALERTS" value={counts.critical + alerts.filter(a=>a.severity==="CRITICAL").length} icon="🔴" accent="#ff2d55" sub="needs attention" />
            <StatCard label="HIGH SEVERITY"   value={counts.high + alerts.filter(a=>a.severity==="HIGH").length}    icon="🟠" accent="#ff9f0a" sub="review required"  />
            <StatCard label="IPs FLAGGED"     value={logs.filter(l=>BAD_IPS.has(l.ip)).length}  icon="🚫" accent="#bf5af2" sub="known malicious"  />
            <StatCard label="SERVICES ACTIVE" value={[...new Set(logs.map(l=>l.service))].length} icon="⚙️" accent="#30d158" sub="monitored" />
          </div>

          {/* ── Charts Row ── */}
          <div style={styles.chartsRow}>

            {/* Area chart */}
            <div style={styles.section}>
              <div style={styles.sectionHeader}>
                <span style={styles.sectionTitle}>
                  <span style={{ color: "#30d158", fontSize: 14 }}>▲</span> Event Timeline (30 min)
                </span>
              </div>
              <div style={{ padding: "12px 8px 8px" }}>
                <ResponsiveContainer width="100%" height={160}>
                  <AreaChart data={history}>
                    <defs>
                      <linearGradient id="evGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#48cae4" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#48cae4" stopOpacity={0}   />
                      </linearGradient>
                      <linearGradient id="thGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#ff9f0a" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#ff9f0a" stopOpacity={0}   />
                      </linearGradient>
                      <linearGradient id="crGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%"  stopColor="#ff2d55" stopOpacity={0.5} />
                        <stop offset="95%" stopColor="#ff2d55" stopOpacity={0}   />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" tick={{ fontSize: 9, fill: "#8b949e" }} interval={4} />
                    <YAxis tick={{ fontSize: 9, fill: "#8b949e" }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="events"   stroke="#48cae4" fill="url(#evGrad)" strokeWidth={1.5} name="Events"   />
                    <Area type="monotone" dataKey="threats"  stroke="#ff9f0a" fill="url(#thGrad)" strokeWidth={1.5} name="Threats"  />
                    <Area type="monotone" dataKey="critical" stroke="#ff2d55" fill="url(#crGrad)" strokeWidth={1.5} name="Critical" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Pie chart */}
            <div style={styles.section}>
              <div style={styles.sectionHeader}>
                <span style={styles.sectionTitle}>
                  <span style={{ color: "#bf5af2", fontSize: 14 }}>◉</span> Severity Mix
                </span>
              </div>
              <div style={{ padding: "12px 8px 8px", display: "flex", flexDirection: "column", alignItems: "center" }}>
                <ResponsiveContainer width="100%" height={130}>
                  <PieChart>
                    <Pie data={severityDist} cx="50%" cy="50%" innerRadius={38} outerRadius={58}
                         dataKey="value" nameKey="name" paddingAngle={3}>
                      {severityDist.map((entry, i) => (
                        <Cell key={i} fill={SEVERITY_CFG[entry.name]?.color || PIE_COLORS[i % PIE_COLORS.length]}
                              stroke="none" />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap", justifyContent: "center", marginTop: 4 }}>
                  {severityDist.map((e, i) => (
                    <div key={e.name} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 10 }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: SEVERITY_CFG[e.name]?.color || PIE_COLORS[i] }} />
                      <span style={{ color: "#8b949e" }}>{e.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Bar chart - Top IPs */}
            <div style={styles.section}>
              <div style={styles.sectionHeader}>
                <span style={styles.sectionTitle}>
                  <span style={{ color: "#ff2d55", fontSize: 14 }}>⚡</span> Top Source IPs
                </span>
              </div>
              <div style={{ padding: "12px 8px 8px" }}>
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={ipCounts} layout="vertical" barSize={12}>
                    <XAxis type="number" tick={{ fontSize: 9, fill: "#8b949e" }} />
                    <YAxis type="category" dataKey="ip" tick={{ fontSize: 9, fill: "#8b949e" }} width={55} />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="count" name="Events" radius={[0,3,3,0]}>
                      {ipCounts.map((entry, i) => {
                        const fullIp = IPS.find(ip => ip.endsWith(entry.ip));
                        const isBad  = fullIp && BAD_IPS.has(fullIp);
                        return <Cell key={i} fill={isBad ? "#ff2d55" : "#48cae4"} />;
                      })}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>

          {/* ── Bottom Row: Alerts + Log Feed ── */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1.6fr", gap: "16px" }}>

            {/* Alerts */}
            <div style={styles.section}>
              <div style={styles.sectionHeader}>
                <span style={styles.sectionTitle}>
                  <span style={{ color: "#ff2d55" }}>🚨</span>&nbsp; Active Alerts
                </span>
                <span style={{
                  fontSize: 10, background: "rgba(255,45,85,0.15)", color: "#ff2d55",
                  padding: "2px 8px", borderRadius: 10, fontWeight: 700,
                  border: "1px solid #ff2d5530",
                }}>{alerts.length}</span>
              </div>
              <div style={{ padding: "12px", maxHeight: 340, overflowY: "auto" }}>
                {alerts.length === 0
                  ? <div style={{ textAlign: "center", color: "#30d158", padding: 32, fontSize: 12 }}>✅ No active alerts</div>
                  : alerts.map(a => <AlertItem key={a.id} alert={a} />)
                }
              </div>
            </div>

            {/* Log Feed */}
            <div style={styles.section}>
              <div style={styles.sectionHeader}>
                <div style={{ display: "flex", alignItems: "center", gap: 0 }}>
                  <button style={styles.tab(tab === "logs")}   onClick={() => setTab("logs")}>LOG FEED</button>
                  <button style={styles.tab(tab === "alerts")} onClick={() => setTab("alerts")}>THREAT EVENTS</button>
                </div>
                <span style={{
                  fontSize: 10, color: "#8b949e",
                  fontFamily: "monospace",
                }}>{logs.length} entries</span>
              </div>

              {tab === "logs" ? (
                <>
                  <div style={styles.logHeader}>
                    <span>TIME</span><span>ACTION</span><span>IP</span><span>USER</span><span>SEV</span>
                  </div>
                  <div style={{ maxHeight: 300, overflowY: "auto" }}>
                    {logs.map(l => <LogRow key={l.id} log={l} />)}
                  </div>
                </>
              ) : (
                <div style={{ padding: 12, maxHeight: 320, overflowY: "auto" }}>
                  {logs.filter(l => l.severity === "CRITICAL" || l.severity === "HIGH")
                       .map(l => <AlertItem key={l.id} alert={l} />)}
                </div>
              )}
            </div>

          </div>

          {/* Footer */}
          <div style={{ textAlign: "center", fontSize: 10, color: "#30363d", paddingBottom: 8, fontFamily: "monospace" }}>
            SOC Log Analysis & Monitoring · Academic Project · Live simulation mode
          </div>

        </div>
      </div>
    </>
  );
}