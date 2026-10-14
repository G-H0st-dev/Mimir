/*
 * MIMIR // frontend — single-page, no build step, no framework.
 *
 * Split into four plain <script src> files (no bundler, no modules) for
 * maintainability as this grew — they all share one global scope like a
 * single inline script would, so load order only matters for this file:
 * core.js must load first, since it holds the shared state (`configCache`,
 * `el`, etc.) and utility functions every other file calls directly at
 * the top level in places (e.g. onclick handlers wired up immediately
 * on load, not just inside functions). company.js/report.js/settings.js
 * can load in any order relative to each other.
 *
 * Two top-level views, toggled by switchView(): #viewScan (the live
 * run-a-scan workflow: domain input, Fast/Full tabs, terminal log,
 * progress bar, results panels) and #viewScans (the report browser: scan
 * list + a sub-tabbed report with search and validation).
 *
 * State lives in a handful of top-level `let`s rather than a framework
 * store — this file re-renders whole sections (innerHTML = ...) on data
 * change rather than diffing, which keeps things simple at this scale.
 * Key ones: `mode`/`currentScanId` (Scan view), `selectedReportScanId`/
 * `reportActiveTab` (Scans view), `configCache` (Settings + Tools sidebar
 * data, refetched via loadConfig() after any config change).
 *
 * Two modals share one pattern (overlay div, .open class toggle, click-
 * outside-to-close): #settingsOverlay, #toolCommandOverlay (per-tool
 * command + cheat sheet + variants). Company Profile used to be a third
 * (#profileOverlay) but is now its own persistent tab instead — see
 * switchView/loadCompanyTab.
 */

const TAB_INFO = {
  fast: { desc: "Passive subdomain discovery (subfinder, crt.sh, Shodan), WHOIS, DNS resolution, HTTP probing, a quick nmap port scan (top 100, -Pn), IP geolocation, homepage social scan." },
  full: { desc: "Everything in Fast, plus amass, assetfinder, theHarvester, naabu, a deeper nmap scan (top 1000 ports, version detection + default scripts, -Pn), and Shodan host enrichment." }
};

let mode = "fast";            // currently selected Fast/Full tab (Scan view)
let currentScanId = null;     // scan shown in the Scan view's main panel
let ws = null;                // websocket for the currently-running scan's live log
let configCache = null;       // last /api/config response — tools, variants, custom sources, keys

const el = (id) => document.getElementById(id);

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Naming-pattern heuristic for likely shadow IT / forgotten
// infrastructure — dev/staging/backup-style environments the org often
// doesn't actively track the way production is tracked. Deliberately a
// loose, best-effort signal rather than a precise classifier: a false
// positive here just means an extra badge to glance past, but a missed
// one defeats the entire point of flagging this at all.
const SHADOW_IT_KEYWORDS = [
  "dev", "development", "staging", "stage", "test", "testing", "uat", "qa",
  "demo", "old", "legacy", "backup", "bak", "internal", "intranet", "admin",
  "temp", "tmp", "sandbox", "beta", "preprod", "poc", "playground",
  "archive", "deprecated", "unused", "personal",
];

function isLikelyShadowIT(subdomain, rootDomain) {
  let prefix = subdomain;
  if (rootDomain && subdomain.toLowerCase().endsWith("." + rootDomain.toLowerCase())) {
    prefix = subdomain.slice(0, subdomain.length - rootDomain.length - 1);
  } else if (subdomain.toLowerCase() === rootDomain.toLowerCase()) {
    return false; // the root domain itself is never "shadow IT"
  }
  const labels = prefix.toLowerCase().split(/[.\-_]+/).filter(Boolean);
  return SHADOW_IT_KEYWORDS.some(kw => labels.includes(kw));
}

async function loadConfig() {
  const res = await fetch("/api/config");
  configCache = await res.json();
  renderToolPills();
  renderSettings();
  renderToolsList();
  renderWordlistsList();
  renderModuleToolsList("companyToolsList", COMPANY_MODULE_TOOLS);
  renderModuleToolsList("vulnToolsList", VULNERABILITY_MODULE_TOOLS);
  if (el("toolCommandOverlay").classList.contains("open") && currentToolModalName) {
    renderToolCommandModal();
  }
}

// shodan is deliberately not in either list below — it has genuinely dual
// behavior sharing one tool registration: subdomain discovery (still
// automatic, in both Fast and Full) and host enrichment (now part of the
// independent Company module, triggered via run_company_scan). Listing
// it under Company specifically would be misleading about the half that
// still runs automatically, so it stays configurable only from the Scan
// tab's Tools sidebar, with a note about this explained in the Company
// tab itself instead.
const COMPANY_MODULE_TOOLS = ["social-scan", "company-lookup", "crosslinked", "xposedornot", "news"];
const VULNERABILITY_MODULE_TOOLS = ["nuclei", "ffuf", "wpscan", "dalfox", "cisa-kev", "epss", "axfr", "email-auth", "secrets", "buckets"];

// Same item template as renderToolsList's Fast/Full sidebar, reused here
// for an arbitrary, explicit list of tool names rather than a mode
// filter — these tools no longer belong to either mode, they're
// configured from within their own module's tab instead.
function renderModuleToolsList(listElId, toolNames) {
  const listEl = el(listElId);
  if (!listEl || !configCache) return;
  const tools = configCache.builtin_tools.filter(t => toolNames.includes(t.name));
  if (!tools.length) {
    listEl.innerHTML = `<div class="hint" style="padding:6px 0;">No tools registered.</div>`;
    return;
  }
  listEl.innerHTML = tools.map(t => {
    const hasActive = (configCache.tool_variants || []).some(v => v.tool_name === t.name && v.active);
    return `
      <div class="tool-list-item ${t.enabled ? '' : 'tool-disabled'}">
        <span onclick="openToolCommand('${t.name}')" style="cursor:pointer; flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis;">
          ${t.name}${hasActive ? '<span class="tool-active-dot">●</span>' : ''}
          <span class="tl-kind">${t.is_cli ? "CLI" : "API"}</span>
        </span>
        <label class="switch tool-list-switch" onclick="event.stopPropagation();" title="${t.enabled ? 'Disable' : 'Enable'} ${t.name}">
          <input type="checkbox" ${t.enabled ? "checked" : ""} onchange="toggleTool('${t.name}', this.checked)">
          <span class="slider"></span>
        </label>
      </div>
    `;
  }).join("");
}

function toolsForMode() {
  if (!configCache) return [];
  return configCache.builtin_tools.filter(t => t.modes.includes(mode));
}

function renderToolPills() {
  if (!configCache) return;
  const pills = toolsForMode().map(t => {
    let cls = t.enabled ? (t.available ? 'ok' : 'missing') : 'off';
    let note = !t.enabled ? ' (disabled)' : (t.available ? '' : ' (missing)');
    return `<span class="tool-pill ${cls}">${t.name}${note}</span>`;
  });
  const customPills = (configCache.custom_tools || []).filter(t => t.enabled).map(t => {
    if (t.shell) return `<span class="tool-pill ok">${t.name}</span>`;
    const cls = t.available ? 'ok' : 'missing';
    return `<span class="tool-pill ${cls}">${t.name}${t.available ? '' : ' (missing)'}</span>`;
  });
  const apiPills = (configCache.custom_api_sources || []).filter(t => t.enabled).map(t => {
    return `<span class="tool-pill ok">${t.name}</span>`;
  });
  el("toolPills").innerHTML = pills.concat(customPills).concat(apiPills).join("");
}

function setMode(m) {
  mode = m;
  el("tabFast").classList.toggle("active", m === "fast");
  el("tabFull").classList.toggle("active", m === "full");
  el("tabDesc").textContent = TAB_INFO[m].desc;
  el("runBtn").className = "run" + (m === "full" ? " full" : "");
  renderToolPills();
  renderToolsList();
}

el("tabFast").onclick = () => setMode("fast");
el("tabFull").onclick = () => setMode("full");

// Starts one scan and attaches the live terminal/progress view to it.
// Used both by the normal single-domain Run scan button and, once per
// selected domain, by the TLD-variant bulk-start flow below — same
// request, same live-view wiring either way. Returns the response data
// (or null on a rejected/failed request) so a caller launching several
// of these can tell which ones actually started.
async function startScan(domain, mode, companyName) {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, mode, company_name: companyName || null })
  });
  const data = await res.json();
  if (!res.ok) return { ok: false, domain, error: data.error || "failed to start" };
  currentScanId = data.scan_id;
  attachWs(data.scan_id);
  el("terminal").innerHTML = "";
  clearWhyPanel();
  terminalLinesBuffer = [];
  terminalBackfilledFor = data.scan_id;
  el("scanLabel").textContent = `— ${data.domain} (${data.mode})`;
  el("scanControls").style.display = "flex";
  setProgress(0, "Starting…", mode, "running");
  pollScanUntilDone(data.scan_id);
  return { ok: true, ...data };
}

el("runBtn").onclick = async () => {
  const domain = el("domainInput").value.trim();
  if (!domain) { el("domainInput").focus(); return; }
  const companyName = el("companyNameInput").value.trim();
  el("runBtn").disabled = true;
  const result = await startScan(domain, mode, companyName);
  if (!result.ok) {
    alert(result.error);
    el("runBtn").disabled = false;
    return;
  }
  loadHistory();
};

// ---------------------------------------------------------------------------
// TLD-variant check — "can I just enter a wildcard domain" comes up
// naturally (people reach for `acme.*` expecting every TLD to get
// checked), but no tool downstream understands that syntax. This is the
// actual answer: a real existence check across a curated TLD list
// (backend: /api/domain-variants/check, reusing company.py's own
// discover_tld_variants — the same check that already runs inside every
// Company scan), surfaced here so it's available before a scan even
// starts, not just after the fact in a Company profile.
// ---------------------------------------------------------------------------
let tldCheckResults = [];

async function checkDomainVariants() {
  const domain = el("domainInput").value.trim();
  if (!domain) { el("domainInput").focus(); return; }
  const btn = el("tldCheckBtn");
  const panel = el("tldCheckPanel");
  btn.disabled = true;
  btn.textContent = "Checking…";
  panel.style.display = "block";
  panel.innerHTML = `<div class="hint">Checking ${escapeHtml(domain)} against ~90 TLDs worldwide…</div>`;
  try {
    const res = await fetch("/api/domain-variants/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    if (!res.ok) {
      panel.innerHTML = `<div class="hint" style="color:var(--red);">${escapeHtml(data.error || "check failed")}</div>`;
      return;
    }
    tldCheckResults = data.results;
    renderTldCheckResults();
  } catch (e) {
    panel.innerHTML = `<div class="hint" style="color:var(--red);">check failed: ${escapeHtml(String(e))}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "🌐 Check other TLDs";
  }
}

function renderTldCheckResults() {
  const panel = el("tldCheckPanel");
  const live = tldCheckResults.filter(r => r.resolves);
  if (!live.length) {
    panel.innerHTML = `<div class="hint">Checked ${tldCheckResults.length} TLD(s) worldwide — nothing else resolves, only what's already in the domain field, or nothing at all.</div>`;
    return;
  }

  const renderRow = (r) => `
    <label class="tool-row" style="cursor:pointer; padding:4px 0;">
      <input type="checkbox" data-tld-idx="${tldCheckResults.indexOf(r)}" checked>
      <span style="margin-left:6px;">${escapeHtml(r.domain)}</span>
      ${r.is_original ? '<span class="tl-kind" style="margin-left:6px;">already in the field above</span>' : ''}
    </label>
  `;

  // The original domain (if any) stays pinned at the top; every actual
  // variant found is grouped by continent/region below it — global TLDs
  // (.com, .io, .app, .online, etc.) get their own "Global" group rather
  // than being attached to any one region, since they're not
  // region-specific at all.
  const original = live.find(r => r.is_original);
  const variants = live.filter(r => !r.is_original);
  const groups = [];
  const groupIdx = {};
  for (const r of variants) {
    const key = r.continent || "Other";
    if (!(key in groupIdx)) {
      groupIdx[key] = groups.length;
      groups.push({ continent: key, items: [] });
    }
    groups[groupIdx[key]].items.push(r);
  }

  panel.innerHTML = `
    <div class="hint" style="margin-bottom:6px;">checked ${tldCheckResults.length} TLD(s) across the globe — ${live.length} resolve; pick which to scan:</div>
    ${original ? renderRow(original) : ""}
    ${groups.map(g => `
      <div class="tld-group-heading">${escapeHtml(g.continent)} (${g.items.length})</div>
      ${g.items.map(renderRow).join("")}
    `).join("")}
    <button class="run" style="margin-top:8px;" onclick="runSelectedTldScans()">Run scan${live.length > 1 ? "s" : ""} for checked domains</button>
  `;
}

async function runSelectedTldScans() {
  const panel = el("tldCheckPanel");
  const checked = Array.from(panel.querySelectorAll('input[type="checkbox"]:checked'))
    .map(cb => tldCheckResults[parseInt(cb.dataset.tldIdx, 10)].domain);
  if (!checked.length) return;
  const companyName = el("companyNameInput").value.trim();
  panel.innerHTML = `<div class="hint">Starting ${checked.length} scan(s)…</div>`;
  el("runBtn").disabled = true;

  const started = [];
  const failed = [];
  for (const domain of checked) {
    const result = await startScan(domain, mode, companyName);
    if (result.ok) started.push(result.domain); else failed.push(`${domain} (${result.error})`);
  }
  el("runBtn").disabled = false;
  loadHistory();

  let summary = started.length
    ? `Started ${started.length} scan(s): ${started.join(", ")}. Live output above is following "${started[started.length - 1]}" — check Scan History for the others.`
    : "";
  if (failed.length) summary += (summary ? " " : "") + `Failed to start: ${failed.join(", ")}.`;
  panel.innerHTML = `<div class="hint">${escapeHtml(summary)}</div>`;
}

// ---------------------------------------------------------------------------
// Subdomain-prefix check — the "front side" counterpart to the TLD check
// above: a curated, category-grouped list of prefixes a pentester would
// specifically think to check by hand (admin panels, VPN/remote-access
// gateways, staging environments, mail infra) rather than the suffix.
// Doesn't replace the real subdomain enumeration the normal scan does —
// this is the same kind of quick, no-scan-required peek the TLD button
// gives, just on the other side of the domain (backend:
// /api/subdomain-prefixes/check, reusing company.py's own
// discover_subdomain_prefixes).
// ---------------------------------------------------------------------------
let subdomainCheckResults = [];

async function checkSubdomainPrefixes() {
  const domain = el("domainInput").value.trim();
  if (!domain) { el("domainInput").focus(); return; }
  const btn = el("subdomainCheckBtn");
  const panel = el("subdomainCheckPanel");
  btn.disabled = true;
  btn.textContent = "Checking…";
  panel.style.display = "block";
  panel.innerHTML = `<div class="hint">Checking common subdomain prefixes against ${escapeHtml(domain)}…</div>`;
  try {
    const res = await fetch("/api/subdomain-prefixes/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain }),
    });
    const data = await res.json();
    if (!res.ok) {
      panel.innerHTML = `<div class="hint" style="color:var(--red);">${escapeHtml(data.error || "check failed")}</div>`;
      return;
    }
    subdomainCheckResults = data.results;
    renderSubdomainCheckResults();
  } catch (e) {
    panel.innerHTML = `<div class="hint" style="color:var(--red);">check failed: ${escapeHtml(String(e))}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "🔎 Check common subdomains";
  }
}

function renderSubdomainCheckResults() {
  const panel = el("subdomainCheckPanel");
  const live = subdomainCheckResults.filter(r => r.resolves);
  if (!live.length) {
    panel.innerHTML = `<div class="hint">Checked ${subdomainCheckResults.length} common prefix(es) — none of them resolve for this domain.</div>`;
    return;
  }

  const renderRow = (r) => `
    <label class="tool-row" style="cursor:pointer; padding:4px 0;">
      <input type="checkbox" data-sub-idx="${subdomainCheckResults.indexOf(r)}" checked>
      <span style="margin-left:6px;">${escapeHtml(r.domain)}</span>
    </label>
  `;

  const groups = [];
  const groupIdx = {};
  for (const r of live) {
    const key = r.category || "Other";
    if (!(key in groupIdx)) {
      groupIdx[key] = groups.length;
      groups.push({ category: key, items: [] });
    }
    groups[groupIdx[key]].items.push(r);
  }

  panel.innerHTML = `
    <div class="hint" style="margin-bottom:6px;">checked ${subdomainCheckResults.length} common prefix(es) — ${live.length} resolve; pick which to scan:</div>
    ${groups.map(g => `
      <div class="tld-group-heading">${escapeHtml(g.category)} (${g.items.length})</div>
      ${g.items.map(renderRow).join("")}
    `).join("")}
    <button class="run" style="margin-top:8px;" onclick="runSelectedSubdomainScans()">Run scan${live.length > 1 ? "s" : ""} for checked subdomains</button>
  `;
}

async function runSelectedSubdomainScans() {
  const panel = el("subdomainCheckPanel");
  const checked = Array.from(panel.querySelectorAll('input[type="checkbox"]:checked'))
    .map(cb => subdomainCheckResults[parseInt(cb.dataset.subIdx, 10)].domain);
  if (!checked.length) return;
  const companyName = el("companyNameInput").value.trim();
  panel.innerHTML = `<div class="hint">Starting ${checked.length} scan(s)…</div>`;
  el("runBtn").disabled = true;

  const started = [];
  const failed = [];
  for (const domain of checked) {
    const result = await startScan(domain, mode, companyName);
    if (result.ok) started.push(result.domain); else failed.push(`${domain} (${result.error})`);
  }
  el("runBtn").disabled = false;
  loadHistory();

  let summary = started.length
    ? `Started ${started.length} scan(s): ${started.join(", ")}. Live output above is following "${started[started.length - 1]}" — check Scan History for the others.`
    : "";
  if (failed.length) summary += (summary ? " " : "") + `Failed to start: ${failed.join(", ")}.`;
  panel.innerHTML = `<div class="hint">${escapeHtml(summary)}</div>`;
}

function setProgress(percent, stage, modeForColor, status) {
  el("progressWrap").style.display = "block";
  const fill = el("progressFill");
  fill.style.width = Math.max(0, Math.min(100, percent)) + "%";
  fill.classList.toggle("full", modeForColor === "full");
  fill.classList.toggle("stopped", status === "stopped" || status === "failed");
  el("progressStageLabel").textContent = stage || "—";
  el("progressPercentLabel").textContent = percent + "%";
}

async function skipCurrentStep() {
  if (!currentScanId) return;
  await fetch(`/api/scans/${currentScanId}/skip`, { method: "POST" });
}

async function stopScan() {
  if (!currentScanId) return;
  await fetch(`/api/scans/${currentScanId}/stop`, { method: "POST" });
}

function levelClass(level) {
  return { cmd: "l-cmd", meta: "l-meta", warn: "l-warn", error: "l-error", out: "l-out", why: "l-why" }[level] || "l-out";
}

// Full text of the current scan's live output, kept in memory alongside
// (but independent of) whatever's actually rendered in the terminal DOM
// — this is what the copy button copies from. Plain strings in an array
// are cheap to accumulate; it's DOM nodes that get expensive, which is
// exactly what the rendering cap below addresses separately.
let terminalLinesBuffer = [];
const MAX_TERMINAL_DOM_LINES = 500;

function appendTerminalLine(line, level) {
  const term = el("terminal");
  terminalLinesBuffer.push(line);
  const div = document.createElement("div");
  div.className = "l " + levelClass(level);
  div.textContent = line;
  term.appendChild(div);
  // A full-mode scan across a dozen-plus tools can produce tens of
  // thousands of output lines over its run — appending without any cap
  // meant the terminal's DOM node count grew unboundedly, and each
  // append got progressively more expensive as that count climbed. This
  // bounds what's actually rendered to a recent-history "tail" without
  // losing anything: the complete text is still in terminalLinesBuffer
  // (for copying) and in the database regardless (for a completed scan's
  // full report).
  while (term.children.length > MAX_TERMINAL_DOM_LINES) {
    term.removeChild(term.firstChild);
  }
  term.scrollTop = term.scrollHeight;

  if (level === "why") appendWhyLine(line);
}

// Pulls the same "[why] tool: explanation" lines the terminal already
// shows (as italic l-why lines) into their own persistent panel below
// it. The terminal scrolls past at whatever rate the current tool is
// producing output, which for a chatty tool is fast enough that a
// one-line note is gone before it's readable — this panel just keeps
// every one of them visible for the whole scan instead, no cap needed
// since a scan only ever produces a few dozen of these at most (one per
// command actually run, not one per output line).
function appendWhyLine(line) {
  const panel = el("whyPanel");
  const emptyMsg = panel.querySelector(".empty");
  if (emptyMsg) emptyMsg.remove();

  // Matches the exact shape _log_rationale/log_line write in core.py:
  // "[why] <label>: <explanation>". Falls back to showing the raw line
  // if anything ever doesn't match that shape, rather than dropping it.
  const m = line.match(/^\[why\]\s*([^:]+):\s*(.*)$/s);
  const div = document.createElement("div");
  div.className = "why-entry";
  // title= gives a hover tooltip with the full text as an alternative to
  // scrolling the row sideways — same info, whichever's quicker to hand.
  div.title = line.replace(/^\[why\]\s*/, "");
  if (m) {
    div.innerHTML = `<span class="why-tool">${escapeHtml(m[1].trim())}:</span><span class="why-text">${escapeHtml(m[2].trim())}</span>`;
  } else {
    div.innerHTML = `<span class="why-text">${escapeHtml(line)}</span>`;
  }
  panel.appendChild(div);
  panel.scrollTop = panel.scrollHeight;
}

function clearWhyPanel() {
  el("whyPanel").innerHTML = `<div class="empty">Nothing yet — these fill in as the scan runs.</div>`;
}

// Standalone from the main scan's attachWs/appendTerminalLine above —
// deliberately not sharing that function's global terminalLinesBuffer or
// hardcoded #terminal reference, so this can't interfere with the main
// Scan view if both happen to be relevant at once. Company and
// Vulnerability module runs already call log_line() internally
// throughout (company.py/vulnerability.py, same as the main pipeline),
// which already broadcasts over this same /ws/{scan_id} channel — that
// was already happening, nothing backend-side needed to change, only
// something to actually display it was missing. Returns the socket so
// the caller can close it once it's done with it.
//
// onProgress is optional — the Company module's backend runs as a
// background task with its own ProgressTracker, broadcasting
// "company_progress" messages (percent/stage) as it moves through each
// stage; the Vulnerability module's backend is still fully synchronous
// and never emits these, so passing no callback there is correct, not
// a gap — this just never fires for it.
// ---------------------------------------------------------------------------
// user-scanner trigger — shared between company.js (per-employee, next to
// each CrossLinked name) and report.js (per-email, in the Emails tab).
// Always manual, always one identity at a time — see
// company.user_scanner_lookup's own docstring for why this never runs on
// its own: it's hundreds of active requests against third-party sites per
// person, a meaningfully louder technique than anything else this app
// triggers automatically. Breadth (curated core set vs. every module) is
// this tool's own Profile picker in Settings, not asked here.
// ---------------------------------------------------------------------------
async function runUserScanner(scanId, identityType, identityValue, btnEl, resultEl) {
  const originalLabel = btnEl.textContent;
  btnEl.disabled = true;
  btnEl.textContent = "Checking…";
  resultEl.style.display = "block";
  resultEl.innerHTML = `<span style="color:var(--text-dim);">Checking ${escapeHtml(identityValue)} against third-party platforms…</span>`;
  try {
    const res = await fetch(`/api/scans/${scanId}/user-scanner`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ identity_type: identityType, identity_value: identityValue }),
    });
    const data = await res.json();
    if (!res.ok) {
      resultEl.innerHTML = `<span style="color:var(--red);">${escapeHtml(data.error || "check failed")}</span>`;
      return;
    }
    const hits = data.hits || [];
    resultEl.innerHTML = hits.length
      ? hits.map(h => `<a href="${escapeHtml(h.url || "#")}" target="_blank" rel="noopener" class="employee-title" style="color:var(--accent); margin-right:8px;">${escapeHtml(h.site_name || "?")} ↗</a>`).join("")
      : `<span style="color:var(--text-dim);">No accounts found on the checked platforms.</span>`;
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--red);">check failed: ${escapeHtml(String(e))}</span>`;
  } finally {
    btnEl.disabled = false;
    btnEl.textContent = originalLabel;
  }
}

function attachModuleWs(scanId, containerId, onProgress) {
  const container = el(containerId);
  container.innerHTML = "";
  container.style.display = "block";
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${proto}://${location.host}/ws/${scanId}`);
  socket.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "company_progress" || msg.type === "vulnerability_progress") {
      if (onProgress) onProgress(msg.percent, msg.stage);
      return;
    }
    if (msg.type !== "log") return;
    const div = document.createElement("div");
    div.className = "l " + levelClass(msg.level);
    div.textContent = msg.line;
    container.appendChild(div);
    while (container.children.length > 300) {
      container.removeChild(container.firstChild);
    }
    container.scrollTop = container.scrollHeight;
  };
  return socket;
}

async function copyTerminalOutput() {
  const btn = el("copyTerminalBtn");
  const text = terminalLinesBuffer.join("\n");
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    const original = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = original; }, 1500);
  } catch (e) {
    alert("Couldn't copy — your browser may be blocking clipboard access on this page.");
  }
}

// Company/Vulnerability module terminals (attachModuleWs above) don't
// keep an external line buffer the way the main scan's terminalLinesBuffer
// does — there's only ever one of those, and now two module terminals —
// so this reads straight off the DOM container instead. Same idea as
// copyTerminalOutput, just without a dedicated buffer to read from.
async function copyModuleTerminalOutput(containerId, btnId) {
  const btn = el(btnId);
  const text = el(containerId).innerText.trim();
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    const original = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => { btn.textContent = original; }, 1500);
  } catch (e) {
    alert("Couldn't copy — your browser may be blocking clipboard access on this page.");
  }
}

function attachWs(scanId) {
  if (ws) ws.close();
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/${scanId}`);
  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    if (msg.type === "log") {
      appendTerminalLine(msg.line, msg.level);
    } else if (msg.type === "progress") {
      setProgress(msg.percent, msg.stage, mode, "running");
    } else if (msg.type === "scan_finished") {
      el("runBtn").disabled = false;
      el("scanControls").style.display = "none";
      loadScan(scanId);
      loadHistory();
    }
  };
}

async function pollScanUntilDone(scanId) {
  const interval = setInterval(async () => {
    // Live panels (Tools grid, Hosts/Intel/Emails/Screenshots) refresh on
    // every tick now, not just once at the very end — that's what
    // actually makes them "populate as they run" instead of staying
    // empty until the scan completes. loadScan() does its own fetch and
    // returns the data, so the status check below doesn't need a second one.
    const data = await loadScan(scanId);
    if (!data || !data.scan) return;
    if (data.scan.status !== "running") {
      clearInterval(interval);
      el("runBtn").disabled = false;
      el("scanControls").style.display = "none";
      loadHistory();
    }
  }, 1500);
}

async function loadHistory() {
  const res = await fetch("/api/scans");
  const scans = await res.json();
  el("history").innerHTML = scans.map(s => `
    <div class="history-item ${s.id === currentScanId ? 'active' : ''}" onclick="selectScan(${s.id})">
      <span><span class="status-dot status-${s.status}"></span><span class="domain-link" onclick="event.stopPropagation(); switchToCompanyView(${s.id})" title="View company profile">${s.domain}</span> <span style="opacity:0.6">[${s.mode}]</span></span>
      <span>#${s.id}</span>
    </div>
  `).join("") || `<div class="empty">No scans yet</div>`;
}

async function selectScan(id) {
  currentScanId = id;
  await loadScan(id);
  await loadHistory();
}

function statusClass(code) {
  if (!code) return "";
  if (code < 300) return "status-2xx";
  if (code < 400) return "status-3xx";
  return "status-4xx";
}

let terminalBackfilledFor = null;  // which scan_id's full log history is currently rendered

async function loadScan(id) {
  const res = await fetch(`/api/scans/${id}`);
  const data = await res.json();
  if (!data.scan) return data;

  el("scanLabel").textContent = `— ${data.scan.domain} (${data.scan.mode}) — ${data.scan.status}`;
  el("scanControls").style.display = data.scan.status === "running" ? "flex" : "none";
  const label = data.scan.progress_stage || (data.scan.status === "completed" ? "Complete" : data.scan.status);
  setProgress(data.scan.progress_percent || 0, label, data.scan.mode, data.scan.status);

  // Only replay the full log history once per scan, not on every call.
  // While a scan is actively running, pollScanUntilDone calls this every
  // 1.5s, and the websocket (see attachWs) is already delivering new log
  // lines live, one at a time, as they happen. Re-wiping and rebuilding
  // the entire terminal from the complete (ever-growing) log list on
  // every single poll tick meant a full DOM teardown+rebuild every 1.5
  // seconds, getting more expensive as the scan produced more output —
  // this was the dominant cause of the browser performance problem, not
  // just the lack of a line cap on its own.
  if (terminalBackfilledFor !== id) {
    el("terminal").innerHTML = "";
    clearWhyPanel();
    terminalLinesBuffer = [];
    data.logs.forEach(l => appendTerminalLine(l.line, l.level));
    terminalBackfilledFor = id;
  }

  const assetsByHost = {};
  data.http_assets.forEach(a => { assetsByHost[a.subdomain] = a; });
  const portsByHost = {};
  data.ports.forEach(p => {
    portsByHost[p.host] = portsByHost[p.host] || [];
    portsByHost[p.host].push(`${p.port}`);
  });

  el("resultsBody").innerHTML = data.subdomains.map(s => {
    const a = assetsByHost[s.subdomain];
    const ports = (portsByHost[s.subdomain] || portsByHost[s.ip] || []).join(", ");
    return `<tr>
      <td>${s.subdomain}</td>
      <td>${s.ip || "-"}</td>
      <td style="color:var(--text-dim)">${s.sources}</td>
      <td class="${statusClass(a && a.status_code)}">${a && a.status_code ? a.status_code : "-"}</td>
      <td>${a && a.title ? a.title : "-"}</td>
      <td style="color:var(--text-dim)">${a && a.tech ? a.tech : "-"}</td>
      <td>${ports || "-"}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="7" class="empty">No results yet</td></tr>`;

  const countries = new Set(
    data.host_intel.filter(i => i.field === "country" || i.field === "countryCode" || i.field === "registrant_country")
      .map(i => i.value)
  );

  el("statRow").innerHTML = `
    <div class="stat stat-clickable" onclick="scrollToPanel('hostsPanel')"><div class="num">${data.subdomains.length}</div><div class="lbl">Hosts</div></div>
    <div class="stat stat-clickable" onclick="scrollToPanel('hostsPanel')"><div class="num">${data.http_assets.length}</div><div class="lbl">Live HTTP</div></div>
    <div class="stat stat-clickable" onclick="scrollToPanel('hostsPanel')"><div class="num">${Object.keys(portsByHost).length}</div><div class="lbl">Open ports</div></div>
    <div class="stat ${data.emails.length ? 'stat-clickable' : ''}" ${data.emails.length ? 'onclick="scrollToPanel(\'emailsPanel\')"' : ''}><div class="num">${data.emails.length}</div><div class="lbl">Emails</div></div>
    <div class="stat ${data.host_intel.length ? 'stat-clickable' : ''}" ${data.host_intel.length ? 'onclick="scrollToPanel(\'intelPanel\')"' : ''}><div class="num">${countries.size}</div><div class="lbl">Countries</div></div>
  `;

  el("exportRow").innerHTML = `
    <a href="/api/scans/${id}/export/json">JSON</a>
    <a href="/api/scans/${id}/export/csv">CSV</a>
    <a href="/api/scans/${id}/export/report">Report</a>
    <a href="/api/scans/${id}/export/docs">Docs .txt</a>
  `;

  if (data.host_intel && data.host_intel.length) {
    el("intelPanel").style.display = "block";
    el("intelBody").innerHTML = data.host_intel.map(i => `
      <tr><td>${i.host}</td><td>${i.source}</td><td>${i.field}</td><td>${i.value}</td></tr>
    `).join("");
  } else {
    el("intelPanel").style.display = "none";
  }

  if (data.emails && data.emails.length) {
    el("emailsPanel").style.display = "block";
    el("emailsBody").innerHTML = data.emails.map(e => `
      <tr><td><a href="mailto:${escapeHtml(e.email)}" style="color:var(--cyan); text-decoration:none;">${escapeHtml(e.email)}</a></td><td style="color:var(--text-dim)">${escapeHtml(e.source)}</td></tr>
    `).join("");
  } else {
    el("emailsPanel").style.display = "none";
  }

  // Live tools breakdown — the same command/output view the post-scan
  // report has, populated as each stage finishes rather than only once
  // the whole scan completes. Only shown once there's at least one log
  // line to build a breakdown from (nothing to show before a scan starts).
  if (data.logs && data.logs.length && configCache) {
    el("liveToolsPanel").style.display = "block";
    el("liveToolsGrid").innerHTML = buildToolsRunSummary(data, "live");
  } else {
    el("liveToolsPanel").style.display = "none";
  }

  if (data.screenshots && data.screenshots.length) {
    el("liveScreenshotsPanel").style.display = "block";
    el("liveScreenshotsGrid").innerHTML = buildScreenshotsGrid(data.screenshots, data.scan.id);
  } else {
    el("liveScreenshotsPanel").style.display = "none";
  }
  return data;
}

// ---------------------------------------------------------------------------
// Settings modal
// ---------------------------------------------------------------------------
function intelBy(intel, source, field) {
  const hit = intel.find(i => i.source === source && i.field === field);
  return hit ? hit.value : null;
}
function intelSetBy(intel, source, field) {
  return new Set(intel.filter(i => i.source === source && i.field === field).map(i => i.value));
}

// Most frequent value in an array — used to pick one headline "location"
// out of possibly-several ip-geo hits (one per resolved IP) instead of
// just showing the first one found.
function modeOf(arr) {
  if (!arr.length) return null;
  const counts = {};
  arr.forEach(v => { counts[v] = (counts[v] || 0) + 1; });
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
}

// One "City, Country" string per host that had an ip-geo hit — city/country
// are stored as separate host_intel rows, so this re-pairs them per host
// before modeOf() picks the most common pairing.
function ipGeoLocations(intel) {
  const byHost = {};
  intel.filter(i => i.source === "ip-geo").forEach(i => {
    byHost[i.host] = byHost[i.host] || {};
    byHost[i.host][i.field] = i.value;
  });
  return Object.values(byHost).map(h => [h.city, h.country].filter(Boolean).join(", ")).filter(Boolean);
}

function extractHost(url) {
  try { return new URL(url).hostname; } catch (e) { return url; }
}

// Builds the Company Profile modal body from a scan's already-fetched
// host_intel/subdomains/etc — no network calls happen here, it's pure
// client-side synthesis of data the scan already gathered.
function techKbLookup(name) {
  if (!configCache || !configCache.tech_knowledge_base) return null;
  let key = name.trim().toLowerCase();
  key = key.split(/\/\d/)[0];
  const spaceMatch = key.match(/^([a-z][a-z0-9.\s\-]*?)\s+\d/);
  if (spaceMatch) key = spaceMatch[1];
  key = key.trim().replace(/[\/\-]+$/, "");
  key = (configCache.tech_kb_aliases && configCache.tech_kb_aliases[key]) || key;
  return configCache.tech_knowledge_base[key] || null;
}

// Same reasoning as toggleToolRunDetail/togglePortDetail — scoped to
// the clicked row itself rather than a positional-index id lookup, so
// this can't collide with another copy of this same profile section
// anywhere else on the page.
function toggleWhatwebTechDetail(rowEl) {
  const detailEl = rowEl.querySelector(".whatweb-tech-detail");
  if (!detailEl) return;
  detailEl.style.display = detailEl.style.display === "none" ? "block" : "none";
}

// Takes the clicked row itself, not a positional index — same reasoning
// as toggleToolRunDetail: an index-based id lookup breaks the moment
// more than one copy of this table could exist in the DOM at once. The
// detail panel is a sibling <tr>, not a nested element (HTML tables
// don't allow arbitrary nesting inside a <tr>), so this walks to the
// next sibling rather than using closest()/querySelector() the way the
// tool-run-detail fix does.
function togglePortDetail(rowEl) {
  const detailEl = rowEl.nextElementSibling;
  if (!detailEl || !detailEl.classList.contains("port-detail-row")) return;
  detailEl.style.display = detailEl.style.display === "none" ? "table-row" : "none";
}

function buildProfileStats(subs, assets, ports, emails, countries) {
  const liveCount = assets.filter(a => a.status_code).length;
  return `
    <div class="profile-stats">
      <div class="pstat"><div class="pnum">${subs.length}</div><div class="plbl">Hosts</div></div>
      <div class="pstat"><div class="pnum">${liveCount}</div><div class="plbl">Live</div></div>
      <div class="pstat"><div class="pnum">${ports.length}</div><div class="plbl">Open ports</div></div>
      <div class="pstat"><div class="pnum">${emails.length}</div><div class="plbl">Emails</div></div>
      <div class="pstat"><div class="pnum">${countries.size}</div><div class="plbl">Countries</div></div>
    </div>
  `;
}

function row(label, value) {
  return `<div class="profile-row"><span>${escapeHtml(label)}</span><span>${escapeHtml(value)}</span></div>`;
}

// ---------------------------------------------------------------------------
// Top-level view switching (Scan / Scans)
// ---------------------------------------------------------------------------
function switchView(view) {
  el("navScan").classList.toggle("active", view === "scan");
  el("navScans").classList.toggle("active", view === "scans");
  el("navCompany").classList.toggle("active", view === "company");
  el("navVulnerability").classList.toggle("active", view === "vulnerability");
  el("viewScan").style.display = view === "scan" ? "block" : "none";
  el("viewScans").style.display = view === "scans" ? "block" : "none";
  el("viewCompany").style.display = view === "company" ? "block" : "none";
  el("viewVulnerability").style.display = view === "vulnerability" ? "block" : "none";
  if (view === "scans") loadScansListView();
  if (view === "company") loadCompanyTab();
  if (view === "vulnerability") loadVulnerabilityTab();
}

// Opens the Company tab already showing a specific scan — used by the
// "view company profile" links elsewhere, so clicking one doesn't just
// land on an empty picker requiring a second click.
function fmtDate(iso) {
  if (!iso) return "-";
  try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
}

// ---------------------------------------------------------------------------
// Scans tab report: sub-tabbed (Hosts/Ports/Intel/Emails), one search box
// scoped to whichever tab is active, plus manual verify + live validate.
// ---------------------------------------------------------------------------
function confidenceBadge(score, status) {
  if (score === null || score === undefined) {
    return `<span class="confidence-unset">not validated</span>`;
  }
  const cls = score >= 75 ? "high" : (score >= 45 ? "medium" : "low");
  return `<span class="confidence-badge ${cls}">${score}% ${escapeHtml(status || "")}</span>`;
}

// Renders the whole report from one /api/scans/{id} response: header +
// request card + commands log, then four sub-tab tables (hosts/ports/
// intel/emails). Rebuilt wholesale on every load/refresh rather than
// patched incrementally — simpler at this scale, see file-header note.
// Every tool applicable to this scan's mode, cross-referenced against its
// logs and results, so "why is this empty" never has to be guessed at —
// not installed, disabled, ran but found nothing, and found-N are all
// visibly different states rather than one blank tab.
function severityColor(sev) {
  switch ((sev || "").toLowerCase()) {
    case "critical": case "high": return "var(--red)";
    case "medium": return "var(--amber)";
    case "low": return "var(--cyan)";
    default: return "var(--text-dim)";
  }
}

const TRIAGE_LABELS = {
  open: "Open",
  false_positive: "False Positive",
  reported: "Reported to Client",
  risk_accepted: "Risk Accepted",
  fixed: "Fixed",
};

function buildTriageControls(findingId, findingType, currentStatus, currentNote) {
  currentStatus = currentStatus || "open";
  return `
    <div class="triage-controls" onclick="event.stopPropagation();">
      <select onchange="updateTriage(this, '${findingType}', ${findingId})">
        ${Object.entries(TRIAGE_LABELS).map(([val, label]) =>
          `<option value="${val}" ${val === currentStatus ? "selected" : ""}>${label}</option>`
        ).join("")}
      </select>
      <input type="text" class="triage-note-input" placeholder="Add a note…"
             value="${escapeHtml(currentNote || "")}"
             onblur="updateTriage(this, '${findingType}', ${findingId})">
    </div>
  `;
}

async function updateTriage(triggerEl, findingType, findingId) {
  const controls = triggerEl.closest(".triage-controls");
  const status = controls.querySelector("select").value;
  const note = controls.querySelector(".triage-note-input").value.trim();
  const endpoint = findingType === "vulnerability"
    ? `/api/vulnerabilities/${findingId}/triage`
    : `/api/leaks/${findingId}/triage`;
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ triage_status: status, triage_note: note || null }),
    });
    if (!res.ok) throw new Error("save failed");
    const card = controls.closest(".vuln-card");
    if (card) {
      card.classList.toggle("vuln-card-resolved", status === "false_positive" || status === "fixed");
    }
  } catch (e) {
    alert("Couldn't save triage status — try again.");
  }
}

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function scrollToPanel(panelId) {
  const target = document.getElementById(panelId);
  if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
}

function applyThemeButtonIcon() {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  const btn = el("themeToggleBtn");
  if (btn) {
    btn.textContent = isLight ? "☀️" : "🌙";
    btn.title = isLight ? "Switch to dark mode" : "Switch to light mode";
  }
}

function toggleTheme() {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  if (isLight) {
    document.documentElement.removeAttribute("data-theme");
    try { localStorage.setItem("mimir-theme", "dark"); } catch (e) {}
  } else {
    document.documentElement.setAttribute("data-theme", "light");
    try { localStorage.setItem("mimir-theme", "light"); } catch (e) {}
  }
  applyThemeButtonIcon();
}

// ---------------------------------------------------------------------------
// Collapsible panels — every .panel can be folded shut by clicking its
// title, anywhere except an interactive child (a button, link, input,
// select — the Copy output / export / scan-control buttons that already
// live inside several panel-titles). One delegated click listener covers
// every panel rather than wiring each one individually, including panels
// Company/Vulnerability/Report build dynamically via innerHTML — those
// don't exist yet when this runs, so a MutationObserver re-applies any
// stored collapsed state to panels as they're added, rather than this
// only working for the panels present at page load.
//
// State is keyed by the panel-title's own static text (its direct text
// nodes, ignoring nested dynamic spans like a live scan label or percent
// — using the full text as a fallback when a title has no direct text
// node of its own, e.g. "Hosts & assets" wrapped in its own <span>
// alongside the export-row span). Shared across scans/views by design —
// collapsing "Live output" once reasonably means "I don't want to see
// this by default" everywhere that title appears, not just this scan.
// ---------------------------------------------------------------------------

function panelTitleKey(titleEl) {
  let text = "";
  titleEl.childNodes.forEach((n) => { if (n.nodeType === 3) text += n.textContent; });
  text = text.trim();
  if (!text) text = titleEl.textContent.trim();
  return "panelCollapsed:" + text.slice(0, 60);
}

function applyStoredPanelCollapse(panel) {
  const title = panel.querySelector(":scope > .panel-title");
  if (!title) return;
  try {
    if (localStorage.getItem(panelTitleKey(title)) === "1") panel.classList.add("collapsed");
  } catch (e) { /* storage unavailable — panels just stay expanded */ }
}

function initCollapsiblePanels() {
  document.querySelectorAll(".panel").forEach(applyStoredPanelCollapse);

  document.addEventListener("click", (e) => {
    const title = e.target.closest(".panel-title");
    if (!title) return;
    if (e.target.closest("button, a, input, select, textarea, label")) return;
    const panel = title.closest(".panel");
    if (!panel) return;
    panel.classList.toggle("collapsed");
    try {
      localStorage.setItem(panelTitleKey(title), panel.classList.contains("collapsed") ? "1" : "0");
    } catch (e) { /* best-effort only */ }
  });

  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== 1) continue;
        if (node.matches && node.matches(".panel")) applyStoredPanelCollapse(node);
        if (node.querySelectorAll) node.querySelectorAll(".panel").forEach(applyStoredPanelCollapse);
      }
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

initCollapsiblePanels();

// --- Bootstrap sequence lives in index.html's own trailing inline
// <script> tag, not here — it calls functions (renderSettings,
// renderToolsList, etc.) defined in company.js/report.js/settings.js,
// which haven't loaded yet at the point core.js itself finishes
// executing. Confirmed directly: loadConfig() alone calls four
// functions defined outside this file.
