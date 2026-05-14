/** @typedef {{ summary?: object, devices?: object[], alerts?: object[], anomalies?: object }} Cache */

const packetLabels = [
  ["total", "Total"],
  ["arp", "ARP"],
  ["tcp", "TCP"],
  ["udp", "UDP"],
  ["icmp", "ICMP"],
  ["dns", "DNS"],
  ["http", "HTTP"],
  ["tls", "TLS"],
];

/** @type {Cache} */
const cache = {};

/** @type {boolean} */
let paused = false;

/**
 * Collect the summary text of every open <details> inside a container.
 * @param {Element} container
 * @returns {Set<string>}
 */
function saveDetailsState(container) {
  const open = new Set();
  container.querySelectorAll("details[open]").forEach((d) => {
    const s = d.querySelector("summary");
    if (s) open.add(s.textContent.trim());
  });
  return open;
}

/**
 * Re-open <details> whose summary text is in the saved set.
 * @param {Element} container
 * @param {Set<string>} open
 */
function restoreDetailsState(container, open) {
  if (!open.size) return;
  container.querySelectorAll("details").forEach((d) => {
    const s = d.querySelector("summary");
    if (s && open.has(s.textContent.trim())) d.open = true;
  });
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function parseRoute() {
  const raw = (location.hash || "#/").replace(/^#/, "");
  const path = raw.startsWith("/") ? raw : `/${raw}`;
  const segs = path.split("/").filter(Boolean);
  if (segs.length === 0) return { page: "overview" };
  if (segs[0] === "devices") return { page: "devices" };
  if (segs[0] === "device" && segs[1]) {
    try {
      return { page: "device", mac: decodeURIComponent(segs[1]) };
    } catch {
      return { page: "devices" };
    }
  }
  if (segs[0] === "alerts") return { page: "alerts" };
  if (segs[0] === "anomalies") return { page: "anomalies" };
  if (segs[0] === "raw") return { page: "raw", raw: segs[1] || "summary" };
  return { page: "overview" };
}

function deviceHref(mac) {
  return `#/device/${encodeURIComponent(mac)}`;
}

function activateNav() {
  const { page, raw } = parseRoute();
  document.querySelectorAll(".app-nav a").forEach((a) => {
    const href = a.getAttribute("href") || "";
    const active =
      (page === "overview" && href === "#/") ||
      ((page === "devices" || page === "device") && href === "#/devices") ||
      (page === "alerts" && href === "#/alerts") ||
      (page === "anomalies" && href === "#/anomalies") ||
      (page === "raw" && href.startsWith("#/raw"));
    a.classList.toggle("is-active", !!active);
  });
  if (page === "raw") {
    const sel = document.getElementById("raw-endpoint");
    if (sel && ["summary", "devices", "alerts", "anomalies"].includes(raw)) {
      sel.value = raw;
    }
  }
}

function showPage(name) {
  document.querySelectorAll(".page").forEach((el) => {
    el.classList.toggle("is-active", el.id === `page-${name}`);
  });
}

function renderCurrentRoute() {
  const r = parseRoute();
  activateNav();
  if (r.page === "overview") {
    showPage("overview");
    renderOverviewFromCache();
  } else if (r.page === "devices") {
    showPage("devices");
    renderDevicesPage();
  } else if (r.page === "device") {
    showPage("device");
    renderDevicePage(r.mac);
  } else if (r.page === "alerts") {
    showPage("alerts");
    renderAlertsPage();
  } else if (r.page === "anomalies") {
    showPage("anomalies");
    renderAnomaliesPage();
  } else if (r.page === "raw") {
    showPage("raw");
    renderRawPage(r.raw);
  }
}

function renderStats(packetStats, deviceCount) {
  const root = document.getElementById("stats-grid");
  if (!root) return;
  const cards = packetLabels
    .map(([key, label]) => {
      const value = packetStats[key] || 0;
      return `<article class="stat"><div class="stat-label">${label}</div><div class="stat-value">${value}</div></article>`;
    })
    .join("");
  root.innerHTML =
    cards +
    `<article class="stat"><div class="stat-label">Devices</div><div class="stat-value">${deviceCount}</div></article>`;
}

function renderRankList(id, values) {
  const root = document.getElementById(id);
  if (!root) return;
  const entries = Object.entries(values || {});
  if (!entries.length) {
    root.innerHTML = "<li><span>No data yet</span><span class='badge'>0</span></li>";
    return;
  }
  root.innerHTML = entries
    .map(([name, count]) => `<li><span>${escapeHtml(name)}</span><span class="badge">${count}</span></li>`)
    .join("");
}

function renderRecentDevices(items) {
  const root = document.getElementById("recent-devices");
  if (!root) return;
  if (!items.length) {
    root.innerHTML = "<p class='muted'>No devices observed yet.</p>";
    return;
  }
  root.innerHTML = items
    .map(
      (d) => `
      <article class="device">
        <strong><a href="${deviceHref(d.mac)}">${escapeHtml(d.ip)} · ${escapeHtml(d.vendor || "Unknown")}</a></strong>
        <div class="line"><span>MAC ${escapeHtml(d.mac)}</span><span>DNS ${d.dns_queries}</span></div>
        <div class="line"><span>HTTP ${d.http_requests}</span><span>TLS ${d.tls}</span></div>
      </article>
    `,
    )
    .join("");
}

function renderAnomalyPanel(snapshot, ids) {
  const statusRoot = document.getElementById(ids.status);
  const insightRoot = document.getElementById(ids.insight);
  const metricsRoot = document.getElementById(ids.metrics);
  const alertsRoot = document.getElementById(ids.alerts);
  if (!statusRoot || !metricsRoot || !alertsRoot) return;
  if (!snapshot) {
    statusRoot.textContent = "No anomaly data available.";
    if (insightRoot) insightRoot.innerHTML = "";
    metricsRoot.innerHTML = "";
    alertsRoot.innerHTML = "<li><span>No anomalies yet</span><span class='badge'>0</span></li>";
    return;
  }
  statusRoot.textContent =
    snapshot.status === "active"
      ? `Model active (${snapshot.baseline_windows} baseline windows)`
      : `Model warming up (${snapshot.baseline_windows || 0}/${Math.max(snapshot.baseline_windows || 1, 20)} baseline windows)`;
  if (insightRoot) {
    const plain = snapshot.last_summary || "";
    const detail = snapshot.last_summary_detail || "";
    if (!plain) {
      insightRoot.innerHTML = "";
    } else {
      insightRoot.innerHTML = formatAnomalyInsightBlock(plain, detail);
    }
  }
  const vals = [
    ["Score", (snapshot.current_score || 0).toFixed(2)],
    ["Robust Z", (snapshot.robust_z_score || 0).toFixed(2)],
    ["Centroid", (snapshot.centroid_distance || 0).toFixed(2)],
    ["Packet/s", (snapshot.last_features?.packet_rate || 0).toFixed(2)],
    ["Entropy", (snapshot.last_features?.port_entropy || 0).toFixed(2)],
    ["Unusual Ports", (snapshot.last_features?.unusual_port_count || 0).toFixed(0)],
  ];
  metricsRoot.innerHTML = vals
    .map(
      ([label, value]) =>
        `<article class="stat"><div class="stat-label">${label}</div><div class="stat-value">${value}</div></article>`,
    )
    .join("");
  const alerts = snapshot.recent_alerts || [];
  if (!alerts.length) {
    alertsRoot.innerHTML = "<li><span>No anomalies yet</span><span class='badge'>0</span></li>";
    return;
  }
  const max = ids.maxAlerts ?? 6;
  alertsRoot.innerHTML = alerts.slice(0, max).map(formatAnomalyAlertLi).join("");
}

function formatAnomalyInsightBlock(plain, detail) {
  const body = detail
    ? `<details class="anomaly-details">
        <summary class="anomaly-details-summary">Technical details behind the reasoning</summary>
        <div class="anomaly-details-body">
          <p class="anomaly-details-technical">${escapeHtml(detail)}</p>
        </div>
      </details>`
    : "";
  return `<p class="anomaly-insight-plain"><strong>What it means:</strong> ${escapeHtml(plain)}</p>${body}`;
}

function formatAnomalyAlertLi(a) {
  const when = new Date(a.observed_at).toLocaleString();
  const score = (a.score || 0).toFixed(2);
  const plain = a.summary || a.reason || "Anomaly flagged.";
  const detail = a.detail || "";
  const contrib = (a.contributions || [])
    .slice(0, 8)
    .map(
      (c) =>
        `<li>${escapeHtml(c.label)}: ${c.value.toFixed(2)} vs typical ${c.baseline_median.toFixed(2)} (≈${c.robust_z.toFixed(
          1,
        )}σ)</li>`,
    )
    .join("");
  const technicalBlock =
    detail || contrib
      ? `<details class="anomaly-details">
        <summary class="anomaly-details-summary">Technical details behind the reasoning</summary>
        <div class="anomaly-details-body">
          ${detail ? `<p class="anomaly-details-technical">${escapeHtml(detail)}</p>` : ""}
          ${contrib ? `<ul class="anomaly-contrib">${contrib}</ul>` : ""}
        </div>
      </details>`
      : "";
  return `<li>
      <div class="anomaly-alert-head">
        <span class="anomaly-alert-meta">${when} · <strong>${escapeHtml(a.severity)}</strong></span>
        <span class="badge">${score}</span>
      </div>
      <p class="anomaly-alert-summary">${escapeHtml(plain)}</p>
      ${technicalBlock}
    </li>`;
}

function renderOverviewFromCache() {
  const data = cache.summary;
  if (!data) return;
  const el = document.getElementById("generated-at");
  if (el) {
    el.textContent = `Last refresh: ${new Date(data.generated_at).toLocaleTimeString()}`;
  }
  renderStats(data.packet_stats, data.device_count);
  renderRankList("top-services", data.top_services);
  renderRankList("top-vendors", data.top_vendors);
  renderRankList("dns-query-types", data.dns_query_types);
  renderRankList("dns-response-codes", data.dns_response_codes);
  renderRecentDevices(data.recent_devices || []);
  renderAnomalyPanel(cache.anomalies, {
    status: "anomaly-status",
    insight: "anomaly-insight",
    metrics: "anomaly-metrics",
    alerts: "anomaly-alerts",
    maxAlerts: 6,
  });
}

function renderMapTable(title, obj) {
  const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    return `<h3>${escapeHtml(title)}</h3><p class="muted">No data.</p>`;
  }
  const rows = entries
    .map(
      ([k, v]) =>
        `<tr><td>${escapeHtml(k)}</td><td style="text-align:right">${escapeHtml(String(v))}</td></tr>`,
    )
    .join("");
  return `<h3>${escapeHtml(title)}</h3><table class="map-table"><thead><tr><th>Name</th><th>Count</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/** @type {{ col: string, dir: 1 | -1 }} */
let devicesSort = { col: "last_seen", dir: -1 };

function sortDevices(devices) {
  const { col, dir } = devicesSort;
  return [...devices].sort((a, b) => {
    const av = a[col] ?? "";
    const bv = b[col] ?? "";
    if (av < bv) return -dir;
    if (av > bv) return dir;
    return (a.mac || "").localeCompare(b.mac || ""); // stable tie-break by MAC
  });
}

function renderDevicesPage() {
  const root = document.getElementById("devices-browser");
  if (!root) return;
  const devices = cache.devices;
  if (!devices) {
    root.innerHTML = "<p class='muted'>Loading…</p>";
    return;
  }
  if (!devices.length) {
    root.innerHTML = "<p class='muted'>No devices yet.</p>";
    return;
  }

  const savedScrollY = window.scrollY;

  const colDefs = [
    ["mac", "MAC"],
    ["ip", "IP"],
    ["vendor", "Vendor"],
    ["dns_queries", "DNS"],
    ["http_requests", "HTTP"],
    ["tls_connections", "TLS"],
    ["last_seen", "Last seen"],
  ];

  const sortedDevices = sortDevices(devices);

  const headers = colDefs
    .map(([col, label]) => {
      const active = devicesSort.col === col;
      const arrow = active ? (devicesSort.dir === 1 ? " ▲" : " ▼") : "";
      return `<th class="sortable${active ? " sort-active" : ""}" data-col="${col}">${label}${arrow}</th>`;
    })
    .join("");

  const rows = sortedDevices
    .map((d) => {
      const mac = escapeHtml(d.mac);
      return `<tr>
        <td><a href="${deviceHref(d.mac)}">${mac}</a></td>
        <td>${escapeHtml(d.ip || "")}</td>
        <td>${escapeHtml(d.vendor || "")}</td>
        <td>${d.dns_queries ?? 0}</td>
        <td>${d.http_requests ?? 0}</td>
        <td>${d.tls_connections ?? 0}</td>
        <td>${d.last_seen ? new Date(d.last_seen).toLocaleString() : ""}</td>
      </tr>`;
    })
    .join("");

  root.innerHTML = `<table class="device-table sortable-table">
    <thead><tr>${headers}</tr></thead>
    <tbody>${rows}</tbody></table>`;

  // Wire up header clicks for sorting
  root.querySelectorAll("th.sortable").forEach((th) => {
    th.style.cursor = "pointer";
    th.addEventListener("click", () => {
      const col = th.dataset.col;
      if (devicesSort.col === col) {
        devicesSort.dir = /** @type {1 | -1} */ (devicesSort.dir * -1);
      } else {
        devicesSort.col = col;
        devicesSort.dir = col === "last_seen" ? -1 : 1;
      }
      renderDevicesPage();
    });
  });

  // Restore scroll position so the view doesn't jump on each refresh
  window.scrollTo({ top: savedScrollY, behavior: "instant" });
}

function renderDevicePage(mac) {
  const title = document.getElementById("device-detail-title");
  const root = document.getElementById("device-detail");
  if (!title || !root) return;
  const devices = cache.devices;
  if (!devices) {
    title.textContent = "Device";
    root.innerHTML = "<p class='muted'>Loading…</p>";
    return;
  }
  const d = devices.find((x) => x.mac === mac);
  if (!d) {
    title.textContent = "Device not found";
    root.innerHTML = `<p class="muted">No device with MAC <code>${escapeHtml(mac)}</code>. <a href="#/devices">Back to list</a></p>`;
    return;
  }
  title.textContent = `${d.ip || "?"} · ${d.vendor || "Unknown"}`;
  const scalars = [
    ["MAC", d.mac],
    ["IP", d.ip],
    ["Vendor", d.vendor],
    ["Interface", d.interface],
    ["Geo country", d.geo_country],
    ["Geo code", d.geo_country_code],
    ["Geo city", d.geo_city],
    ["First seen", d.first_seen ? new Date(d.first_seen).toLocaleString() : ""],
    ["Last seen", d.last_seen ? new Date(d.last_seen).toLocaleString() : ""],
    ["ARP requests", d.request_count],
    ["ARP replies", d.reply_count],
    ["TCP connections", d.tcp_connections],
    ["UDP connections", d.udp_connections],
    ["ICMP packets", d.icmp_packets],
    ["DNS queries", d.dns_queries],
    ["HTTP requests", d.http_requests],
    ["TLS connections", d.tls_connections],
    ["DNS correlated", d.dns_correlated_connections],
  ];
  const kv = scalars
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(
      ([k, v]) =>
        `<div class="kv-card"><div class="k">${escapeHtml(k)}</div><div class="v">${escapeHtml(String(v))}</div></div>`,
    )
    .join("");
  const targets =
    (d.targets && d.targets.length
      ? `<h3>Recent targets</h3><ul class="rank-list">${d.targets
          .slice(-40)
          .map((t) => `<li><span>${escapeHtml(t)}</span><span class="badge">·</span></li>`)
          .join("")}</ul>`
      : "") + "";
  const maps =
    renderMapTable("Services", d.services) +
    renderMapTable("DNS domains (queries)", d.dns_domains) +
    renderMapTable("DNS response domains", d.dns_response_domains) +
    renderMapTable("DNS query types", d.dns_query_types) +
    renderMapTable("DNS response codes", d.dns_response_codes) +
    renderMapTable("Encrypted DNS modes", d.encrypted_dns) +
    renderMapTable("Correlated domains", d.correlated_domains) +
    renderMapTable("HTTP hosts", d.http_hosts) +
    renderMapTable("TLS SNIs / labels", d.tls_snis) +
    renderMapTable("TLS versions", d.tls_versions) +
    renderMapTable("Traffic type counts", d.traffic_type_counts);
  root.innerHTML = `<div class="kv-grid">${kv}</div>${targets}<div style="margin-top:18px">${maps}</div>
    <p class="muted" style="margin-top:16px"><a href="#/raw/devices">View raw device JSON</a></p>`;
}

function renderAlertsPage() {
  const root = document.getElementById("alerts-browser");
  if (!root) return;
  const alerts = cache.alerts;
  if (!alerts) {
    root.innerHTML = "<p class='muted'>Loading…</p>";
    return;
  }
  if (!alerts.length) {
    root.innerHTML = "<p class='muted'>No rule-based alerts yet.</p>";
    return;
  }
  const rows = alerts
    .map((a) => {
      const t = new Date(a.observed_at).toLocaleString();
      return `<tr>
        <td>${escapeHtml(t)}</td>
        <td>${escapeHtml(a.severity || "")}</td>
        <td><code>${escapeHtml(a.rule || "")}</code></td>
        <td>${escapeHtml(a.device_mac || "")}</td>
        <td>${escapeHtml(a.device_ip || "")}</td>
        <td>${escapeHtml(a.message || "")}</td>
      </tr>`;
    })
    .join("");
  root.innerHTML = `<table class="device-table">
    <thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Device MAC</th><th>Device IP</th><th>Message</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}

function renderAnomaliesPage() {
  const snap = cache.anomalies;
  const contrib = document.getElementById("anomaly-last-contrib");
  const list = document.getElementById("anomaly-full-alerts");
  if (!list) return;

  // Preserve which <details> the user has expanded before re-rendering
  const openInsight = saveDetailsState(document.getElementById("anomaly-full-insight") || document.createElement("div"));
  const openAlerts = saveDetailsState(list);

  renderAnomalyPanel(snap, {
    status: "anomaly-full-status",
    insight: "anomaly-full-insight",
    metrics: "anomaly-full-metrics",
    alerts: "anomaly-full-alerts",
    maxAlerts: 200,
  });

  restoreDetailsState(document.getElementById("anomaly-full-insight") || document.createElement("div"), openInsight);
  restoreDetailsState(list, openAlerts);

  if (!contrib) return;
  if (snap && (snap.last_contributions || []).length) {
    const rows = snap.last_contributions
      .map(
        (c) =>
          `<tr><td>${escapeHtml(c.label)}</td><td>${c.value.toFixed(3)}</td><td>${c.baseline_median.toFixed(
            3,
          )}</td><td>${c.robust_z.toFixed(2)}</td></tr>`,
      )
      .join("");
    contrib.innerHTML = `<table class="map-table"><thead><tr><th>Feature</th><th>This window</th><th>Baseline median</th><th>Robust σ (capped)</th></tr></thead><tbody>${rows}</tbody></table>`;
  } else {
    contrib.innerHTML = "<p class='muted'>No contributor breakdown for this window.</p>";
  }
}

async function renderRawPage(endpoint) {
  const pre = document.getElementById("raw-json");
  const sel = document.getElementById("raw-endpoint");
  if (!pre || !sel) return;
  const ep = ["summary", "devices", "alerts", "anomalies"].includes(endpoint) ? endpoint : "summary";
  sel.value = ep;
  const path =
    ep === "summary"
      ? "/api/v1/summary"
      : ep === "devices"
        ? "/api/v1/devices"
        : ep === "alerts"
          ? "/api/v1/alerts"
          : "/api/v1/anomalies";
  pre.textContent = "Loading…";
  try {
    const res = await fetch(path, { headers: { Accept: "application/json" } });
    const body = await res.text();
    if (!res.ok) {
      pre.textContent = `HTTP ${res.status}\n\n${body}`;
      return;
    }
    try {
      pre.textContent = JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      pre.textContent = body;
    }
  } catch (e) {
    pre.textContent = String(e);
  }
}

async function refreshData() {
  const [sRes, dRes, aRes, mRes] = await Promise.all([
    fetch("/api/v1/summary", { headers: { Accept: "application/json" } }),
    fetch("/api/v1/devices", { headers: { Accept: "application/json" } }),
    fetch("/api/v1/alerts", { headers: { Accept: "application/json" } }),
    fetch("/api/v1/anomalies", { headers: { Accept: "application/json" } }),
  ]);
  if (sRes.ok) cache.summary = await sRes.json();
  if (dRes.ok) cache.devices = await dRes.json();
  if (aRes.ok) cache.alerts = await aRes.json();
  if (mRes.ok) cache.anomalies = await mRes.json();
}

async function tick() {
  await refreshData();
  if (!paused) {
    renderCurrentRoute();
  }
}

function updatePausedIndicators() {
  const devNote = document.getElementById("devices-paused-note");
  const anomNote = document.getElementById("anomalies-paused-note");
  if (devNote) devNote.hidden = !paused;
  if (anomNote) anomNote.hidden = !paused;
}

function setupPauseToggle() {
  const btn = document.getElementById("pause-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    paused = !paused;
    btn.textContent = paused ? "Resume Updates" : "Pause Updates";
    btn.classList.toggle("is-paused", paused);
    updatePausedIndicators();
    if (!paused) {
      // Immediately refresh so the user sees current data
      tick();
    }
  });
}

function setupThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  btn.addEventListener("click", () => {
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    document.documentElement.setAttribute("data-theme", isDark ? "light" : "dark");
    btn.textContent = isDark ? "Dark Mode" : "Light Mode";
  });
}

function setupRouter() {
  window.addEventListener("hashchange", () => {
    renderCurrentRoute();
  });
  document.getElementById("raw-refresh")?.addEventListener("click", () => {
    const v = document.getElementById("raw-endpoint")?.value || "summary";
    location.hash = `#/raw/${v}`;
    renderRawPage(v);
  });
  document.getElementById("raw-endpoint")?.addEventListener("change", (e) => {
    const v = /** @type {HTMLSelectElement} */ (e.target).value;
    location.hash = `#/raw/${v}`;
  });
}

// Build info only needs to be fetched once — the binary's version is static
// for the life of the page.
async function renderBuildInfo() {
  const el = document.getElementById("build-info");
  if (!el) return;
  try {
    const res = await fetch("/api/v1/version", { headers: { Accept: "application/json" } });
    if (!res.ok) {
      el.textContent = "Build: unknown";
      return;
    }
    const v = await res.json();
    const commit = v && v.commit ? v.commit : "unknown";
    const date = v && v.date ? v.date : "unknown";
    el.textContent = `Build: ${commit} (${date})`;
  } catch {
    el.textContent = "Build: unknown";
  }
}

setupThemeToggle();
setupPauseToggle();
setupRouter();
renderBuildInfo();
tick();
setInterval(tick, 3000);
