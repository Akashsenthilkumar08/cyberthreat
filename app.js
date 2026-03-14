// CyberGuard Dashboard — Live Frontend
// Author: Deerandaran M (Frontend Dev)

const API_BASE = window.location.origin;
const POLL_INTERVAL = 2000;

let knownIds = new Set();
let stats = { critical: 0, high: 0, medium: 0, low: 0 };

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById("utc-time").textContent =
    now.toUTCString().replace("GMT", "UTC");
}
setInterval(updateClock, 1000);
updateClock();

// ── Fetch events from agent API ───────────────────────────────────────────────
async function fetchEvents() {
  try {
    const res = await fetch(`${API_BASE}/api/events`);
    if (!res.ok) return;
    const events = await res.json();
    renderNewEvents(events);
  } catch (e) {
    // API not reachable (running as static demo)
    simulateEvent();
  }
}

async function fetchStats() {
  try {
    const res = await fetch(`${API_BASE}/api/stats`);
    if (!res.ok) return;
    const data = await res.json();
    updateMetrics(data);
  } catch (e) {}
}

async function fetchBlocked() {
  try {
    const res = await fetch(`${API_BASE}/api/blocked`);
    if (!res.ok) return;
    const data = await res.json();
    renderBlockedIPs(data.blocked_ips || []);
  } catch (e) {}
}

// ── Render events ─────────────────────────────────────────────────────────────
function renderNewEvents(events) {
  const feed = document.getElementById("feed");

  // Remove empty placeholder
  const empty = feed.querySelector(".empty-feed");
  if (empty) empty.remove();

  let added = 0;
  events.forEach(evt => {
    if (knownIds.has(evt.id)) return;
    knownIds.add(evt.id);
    const row = buildEventRow(evt);
    feed.insertBefore(row, feed.firstChild);
    added++;
    // Update local stats
    if (evt.severity) stats[evt.severity] = (stats[evt.severity] || 0) + 1;
  });

  if (added > 0) {
    document.getElementById("event-count").textContent = `${knownIds.size} events`;
    updateBars();
  }

  // Keep feed under 200 rows
  while (feed.children.length > 200) {
    feed.removeChild(feed.lastChild);
  }
}

function buildEventRow(evt) {
  const row = document.createElement("div");
  row.className = "event-row";
  row.id = evt.id;

  const time = evt.timestamp ? evt.timestamp.split(" ")[1] || evt.timestamp : "--:--:--";
  const sev = evt.severity || "low";
  const type = evt.threat_type || "Unknown";
  const src = evt.src_ip || "—";
  const action = evt.action_taken || (evt.is_threat ? "logged" : "safe");
  const blocked = evt.blocked;

  const actionLabel = blocked ? "BLOCKED" : action.toUpperCase().replace(/_/g, " ");
  const actionClass = blocked ? "action-blocked"
    : action === "isolate_host" ? "action-isolated"
    : evt.is_threat ? "action-logged"
    : "action-safe";

  row.innerHTML = `
    <span class="event-time">${time}</span>
    <span><span class="sev-badge sev-${sev}">${sev.toUpperCase()}</span></span>
    <span class="event-type">${type}</span>
    <span class="event-src">${src}</span>
    <span><span class="event-action ${actionClass}">${actionLabel}</span></span>
  `;
  return row;
}

// ── Metrics ───────────────────────────────────────────────────────────────────
function updateMetrics(data) {
  document.getElementById("m-total").textContent = data.total_events || 0;
  const threats = (data.critical || 0) + (data.high || 0) + (data.medium || 0);
  document.getElementById("m-threats").textContent = data.threats_detected || threats;
  document.getElementById("m-blocked").textContent = data.threats_blocked || 0;
  document.getElementById("m-critical").textContent = data.critical || 0;

  stats.critical = data.critical || stats.critical;
  stats.high     = data.high     || stats.high;
  stats.medium   = data.medium   || stats.medium;
  stats.low      = data.low      || stats.low;
  updateBars();
}

function updateBars() {
  const max = Math.max(1, stats.critical, stats.high, stats.medium, stats.low);
  ["critical", "high", "medium", "low"].forEach(sev => {
    const val = stats[sev] || 0;
    const bar = document.getElementById(`bar-${sev}`);
    const cnt = document.getElementById(`cnt-${sev}`);
    if (bar) bar.style.width = (val / max * 100) + "%";
    if (cnt) cnt.textContent = val;
  });
}

// ── Blocked IPs ───────────────────────────────────────────────────────────────
const shownIPs = new Set();
function renderBlockedIPs(ips) {
  const list = document.getElementById("blocked-list");
  ips.forEach(ip => {
    if (shownIPs.has(ip)) return;
    shownIPs.add(ip);
    const empty = list.querySelector(".empty-text");
    if (empty) empty.remove();
    const div = document.createElement("div");
    div.className = "blocked-ip";
    div.textContent = ip;
    list.appendChild(div);
  });
}

// ── Report Download ───────────────────────────────────────────────────────────
async function downloadReport() {
  try {
    const res = await fetch(`${API_BASE}/api/report`);
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cyberguard_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert("Connect the agent backend (python main.py) to generate reports.");
  }
}

// ── Clear Feed ────────────────────────────────────────────────────────────────
function clearFeed() {
  document.getElementById("feed").innerHTML = '<div class="empty-feed">Feed cleared. Waiting for new events...</div>';
  knownIds.clear();
  stats = { critical: 0, high: 0, medium: 0, low: 0 };
  updateBars();
  document.getElementById("event-count").textContent = "0 events";
}

// ── Demo Simulation (when backend not running) ────────────────────────────────
const DEMO_EVENTS = [
  { id: null, timestamp: "", threat_type: "SSH-Bruteforce",      severity: "critical", src_ip: "185.220.101.47", action_taken: "block_ip",        blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "Ransomware",          severity: "critical", src_ip: "10.0.0.21",      action_taken: "isolate_host",     blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "DDoS",                severity: "high",     src_ip: "Multiple",       action_taken: "rate_limit",       blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "SQL-Injection",       severity: "critical", src_ip: "91.108.56.112",  action_taken: "waf_rule",         blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "PortScan",            severity: "medium",   src_ip: "203.0.113.88",   action_taken: "log_alert",        blocked: false, is_threat: true },
  { id: null, timestamp: "", threat_type: "BENIGN",              severity: "low",      src_ip: "10.0.0.5",       action_taken: "none",             blocked: false, is_threat: false },
  { id: null, timestamp: "", threat_type: "Malware-C2",          severity: "critical", src_ip: "45.142.212.9",   action_taken: "block_domain",     blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "DNS-Tunneling",       severity: "high",     src_ip: "10.0.0.14",      action_taken: "block_dns",        blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "GeoAnomaly",          severity: "medium",   src_ip: "77.91.124.55",   action_taken: "mfa_challenge",    blocked: false, is_threat: true },
  { id: null, timestamp: "", threat_type: "DataExfiltration",    severity: "critical", src_ip: "10.0.0.88",      action_taken: "block_egress",     blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "ARP-Spoofing",        severity: "high",     src_ip: "10.0.0.77",      action_taken: "isolate_port",     blocked: true,  is_threat: true },
  { id: null, timestamp: "", threat_type: "XSS",                 severity: "medium",   src_ip: "77.91.124.55",   action_taken: "sanitize_request", blocked: false, is_threat: true },
  { id: null, timestamp: "", threat_type: "PrivilegeEscalation", severity: "high",     src_ip: "10.0.0.33",      action_taken: "kill_session",     blocked: true,  is_threat: true },
];

let demoIdx = 0;
function simulateEvent() {
  const template = DEMO_EVENTS[demoIdx % DEMO_EVENTS.length];
  demoIdx++;
  const evt = {
    ...template,
    id: "demo_" + Date.now() + "_" + Math.random(),
    timestamp: new Date().toISOString().replace("T", " ").slice(0, 19),
  };
  renderNewEvents([evt]);

  // Update stats manually for demo
  const stat = {
    total_events: knownIds.size,
    threats_detected: [...document.querySelectorAll(".sev-badge:not(.sev-low)")].length,
    threats_blocked: [...document.querySelectorAll(".action-blocked")].length,
    critical: stats.critical, high: stats.high, medium: stats.medium, low: stats.low,
  };
  document.getElementById("m-total").textContent = stat.total_events;
  document.getElementById("m-threats").textContent = stat.threats_detected;
  document.getElementById("m-blocked").textContent = stat.threats_blocked;
  document.getElementById("m-critical").textContent = stats.critical || 0;

  if (evt.blocked && evt.src_ip && evt.src_ip !== "Multiple") {
    renderBlockedIPs([evt.src_ip]);
  }
}

// ── Polling Loop ─────────────────────────────────────────────────────────────
async function poll() {
  await fetchEvents();
  await fetchStats();
  await fetchBlocked();
}

// Start polling
setInterval(poll, POLL_INTERVAL);
poll(); // immediate first call
