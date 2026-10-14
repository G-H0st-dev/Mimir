// Scan report building — Hosts/Ports/Endpoints/OSINT/Intel/Vulnerabilities/
// Leaks/Screenshots tabs, the Scans list, and scan comparison. Depends on
// core.js (loaded first) for shared state and utilities.

// A large target can genuinely produce thousands of host_intel rows
// (whatweb tech tags, nmap script output, gau/katana URLs, and more,
// all per host, across potentially hundreds of hosts) — confirmed
// directly, a moderate 200-host scan produced tens of thousands of DOM
// nodes with no cap in place, a real, measured crash risk in Firefox
// specifically, not just theoretical. Caps what's rendered per report
// tab by default, the same way the live terminal's line count is
// capped, for the same reason — but a non-empty search term re-renders
// from the FULL underlying dataset (see currentReportData below), so
// this cap only ever limits the unfiltered default view, never what a
// specific search can actually find.
const MAX_REPORT_ROWS = 500;

// The current report's full, uncapped arrays — kept here specifically
// so search can re-render from everything a scan found, not just the
// capped subset rendered by default. Set once per loadScanReport call,
// read by filterReportRows on every keystroke.
let currentReportData = null;

// Deep-scan host selection — a plain global Set rather than per-row
// DOM state, since the Hosts table re-renders entirely on every search
// keystroke (see filterReportRows) and a selection made before typing
// a search term needs to survive that re-render. Reset whenever a
// different scan's report loads — see loadScanReport.
let selectedDeepScanHosts = new Set();

let scansCache = [];

async function loadScansListView() {
  const res = await fetch("/api/scans");
  scansCache = await res.json();
  renderScansList();
}

let selectedScanIds = new Set();

function renderScansList() {
  const filterVal = (el("scansFilterInput").value || "").trim().toLowerCase();
  const filtered = filterVal ? scansCache.filter(s => s.domain.toLowerCase().includes(filterVal)) : scansCache;
  // Selection is pruned to whatever's currently visible under the filter,
  // so "select all" naturally means "select all matching this filter" —
  // e.g. filter to one domain, select all, and only that domain's scans
  // are selected, without a separate "select all for this domain" control.
  el("scansList").innerHTML = filtered.map(s => `
    <div class="history-item ${s.id === selectedReportScanId ? 'active' : ''}" onclick="loadScanReport(${s.id})">
      <span>
        <input type="checkbox" onclick="event.stopPropagation(); toggleScanSelection(${s.id}, this.checked)" ${selectedScanIds.has(s.id) ? "checked" : ""} style="vertical-align:middle; margin-right:6px;">
        <span class="status-dot status-${s.status}"></span>${escapeHtml(s.domain)} <span style="opacity:0.6">[${s.mode}]</span>
      </span>
      <span>#${s.id}</span>
    </div>
  `).join("") || `<div class="empty">No scans match "${escapeHtml(filterVal)}"</div>`;

  updateScansBulkBar(filtered);
}

function toggleScanSelection(scanId, checked) {
  if (checked) selectedScanIds.add(scanId);
  else selectedScanIds.delete(scanId);
  updateScansBulkBar();
}

function toggleSelectAllScans(checked) {
  const filterVal = (el("scansFilterInput").value || "").trim().toLowerCase();
  const filtered = filterVal ? scansCache.filter(s => s.domain.toLowerCase().includes(filterVal)) : scansCache;
  if (checked) filtered.forEach(s => selectedScanIds.add(s.id));
  else filtered.forEach(s => selectedScanIds.delete(s.id));
  renderScansList();
}

function updateScansBulkBar(filtered) {
  filtered = filtered || (() => {
    const filterVal = (el("scansFilterInput").value || "").trim().toLowerCase();
    return filterVal ? scansCache.filter(s => s.domain.toLowerCase().includes(filterVal)) : scansCache;
  })();
  const count = selectedScanIds.size;
  el("scansBulkBar").style.display = count > 0 ? "flex" : "none";
  el("scansSelectedCount").textContent = count > 0 ? `${count} selected` : "";
  const allVisibleSelected = filtered.length > 0 && filtered.every(s => selectedScanIds.has(s.id));
  const selectAllCb = el("scansSelectAll");
  if (selectAllCb) selectAllCb.checked = allVisibleSelected;
}

async function bulkDeleteScans() {
  const ids = [...selectedScanIds];
  if (!ids.length) return;
  const sure = confirm(`Delete ${ids.length} scan(s)?\n\nThis permanently removes each scan and everything found in it. There's no undo short of restoring a backup.`);
  if (!sure) return;
  const res = await fetch("/api/scans/bulk-delete", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_ids: ids }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    alert(data.error || "Bulk delete failed.");
    return;
  }
  selectedScanIds.clear();
  if (ids.includes(selectedReportScanId)) {
    selectedReportScanId = null;
    el("scanReportMain").innerHTML = `<div class="empty" style="padding:60px 20px;">Select a scan to view its report.</div>`;
  }
  await loadScansListView();
}

async function bulkExportScans() {
  const ids = [...selectedScanIds];
  if (!ids.length) return;
  const res = await fetch("/api/scans/bulk-export", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_ids: ids }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    alert(data.error || "Bulk export failed.");
    return;
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match ? match[1] : "mimir_scans_export.zip";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Compare two scans — a manual picker, diffed entirely client-side against
// the same /api/scans/{id} payload everything else already uses. Screenshots
// are deliberately not diffed (a pixel/image diff isn't meaningfully
// "added/removed" the way a host or port is); everything else is.
// ---------------------------------------------------------------------------
function openCompare() {
  const options = scansCache.map(s =>
    `<option value="${s.id}">#${s.id} ${escapeHtml(s.domain)} (${s.mode}, ${s.status}) — ${new Date(s.started_at).toLocaleString()}</option>`
  ).join("");
  el("compareScanA").innerHTML = options;
  el("compareScanB").innerHTML = options;
  // Default to the two most recent scans if there are at least two —
  // scansCache comes back newest-first, so that's simply the first two.
  if (scansCache.length >= 2) {
    el("compareScanA").value = scansCache[1].id;
    el("compareScanB").value = scansCache[0].id;
  }
  el("compareResults").innerHTML = "";
  el("compareOverlay").classList.add("open");
}
function closeCompare() {
  el("compareOverlay").classList.remove("open");
}
el("compareOverlay").addEventListener("click", (e) => {
  if (e.target.id === "compareOverlay") closeCompare();
});

async function runCompare() {
  const idA = parseInt(el("compareScanA").value, 10);
  const idB = parseInt(el("compareScanB").value, 10);
  if (!idA || !idB) return;
  if (idA === idB) {
    el("compareResults").innerHTML = `<div class="hint" style="color:var(--amber);">Pick two different scans to compare.</div>`;
    return;
  }
  el("compareResults").innerHTML = `<div class="empty">Loading…</div>`;
  const [resA, resB] = await Promise.all([fetch(`/api/scans/${idA}`), fetch(`/api/scans/${idB}`)]);
  const dataA = await resA.json();
  const dataB = await resB.json();
  if (!dataA.scan || !dataB.scan) {
    el("compareResults").innerHTML = `<div class="empty">One or both scans couldn't be loaded.</div>`;
    return;
  }
  const diff = computeScanDiff(dataA, dataB);
  el("compareResults").innerHTML = buildCompareResultsHtml(dataA, dataB, diff);
}

function computeScanDiff(dataA, dataB) {
  const hostsA = new Set((dataA.subdomains || []).map(s => s.subdomain));
  const hostsB = new Set((dataB.subdomains || []).map(s => s.subdomain));
  const hosts = {
    added: [...hostsB].filter(h => !hostsA.has(h)).sort(),
    removed: [...hostsA].filter(h => !hostsB.has(h)).sort(),
  };

  const portKey = p => `${p.host}:${p.port}`;
  const portsMapA = new Map((dataA.ports || []).map(p => [portKey(p), p]));
  const portsMapB = new Map((dataB.ports || []).map(p => [portKey(p), p]));
  const ports = {
    added: [...portsMapB.keys()].filter(k => !portsMapA.has(k)).map(k => portsMapB.get(k)).sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port),
    removed: [...portsMapA.keys()].filter(k => !portsMapB.has(k)).map(k => portsMapA.get(k)).sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port),
  };

  const emailsA = new Set((dataA.emails || []).map(e => e.email));
  const emailsB = new Set((dataB.emails || []).map(e => e.email));
  const emails = {
    added: [...emailsB].filter(e => !emailsA.has(e)).sort(),
    removed: [...emailsA].filter(e => !emailsB.has(e)).sort(),
  };

  // Intel covers everything stored as host_intel — whois, geo, social,
  // company data, and whatweb's technology findings all live there, so
  // this single diff naturally includes "new technology detected" as
  // well as everything else, without a separate special-cased section.
  const intelKey = i => `${i.host}::${i.source}::${i.field}`;
  const intelMapA = new Map((dataA.host_intel || []).map(i => [intelKey(i), i]));
  const intelMapB = new Map((dataB.host_intel || []).map(i => [intelKey(i), i]));
  const intelAdded = [], intelChanged = [];
  for (const [k, v] of intelMapB) {
    if (!intelMapA.has(k)) intelAdded.push(v);
    else if (intelMapA.get(k).value !== v.value) intelChanged.push({ from: intelMapA.get(k), to: v });
  }
  const intelRemoved = [...intelMapA.entries()].filter(([k]) => !intelMapB.has(k)).map(([, v]) => v);
  const sortIntel = arr => arr.sort((a, b) => (a.host || a.to.host).localeCompare(b.host || b.to.host));
  const intel = { added: sortIntel(intelAdded), removed: sortIntel(intelRemoved), changed: sortIntel(intelChanged) };

  return { hosts, ports, emails, intel };
}

function diffRow(icon, color, html) {
  return `<div class="compare-row"><span class="compare-icon" style="color:${color};">${icon}</span><span>${html}</span></div>`;
}

function buildCompareResultsHtml(dataA, dataB, diff) {
  const total = diff.hosts.added.length + diff.hosts.removed.length +
    diff.ports.added.length + diff.ports.removed.length +
    diff.emails.added.length + diff.emails.removed.length +
    diff.intel.added.length + diff.intel.removed.length + diff.intel.changed.length;

  let html = `
    <div class="hint" style="margin-bottom:14px;">
      <b style="color:var(--text);">#${dataA.scan.id} ${escapeHtml(dataA.scan.domain)}</b>
      (${new Date(dataA.scan.started_at).toLocaleString()})
      → <b style="color:var(--text);">#${dataB.scan.id} ${escapeHtml(dataB.scan.domain)}</b>
      (${new Date(dataB.scan.started_at).toLocaleString()})
    </div>
  `;

  if (total === 0) {
    return html + `<div class="empty">No differences found between these two scans.</div>`;
  }

  const portLabel = p => `${escapeHtml(p.host)}:${p.port}${p.service ? " (" + escapeHtml(p.service) + ")" : ""} <span style="color:var(--text-dim);">via ${escapeHtml(p.source)}</span>`;
  const intelLabel = i => `${escapeHtml(i.host)} <span style="color:var(--text-dim);">· ${escapeHtml(i.source)} · ${escapeHtml(i.field)}</span>: ${escapeHtml(i.value)}`;

  const section = (title, addedCount, removedCount, changedCount, bodyFn) => {
    if (addedCount + removedCount + changedCount === 0) return "";
    const parts = [];
    if (addedCount) parts.push(`${addedCount} added`);
    if (removedCount) parts.push(`${removedCount} removed`);
    if (changedCount) parts.push(`${changedCount} changed`);
    return `
      <div class="settings-section-title" style="margin-top:14px;">${title} (${parts.join(", ")})</div>
      <div class="compare-section">${bodyFn()}</div>
    `;
  };

  html += section("Hosts", diff.hosts.added.length, diff.hosts.removed.length, 0, () =>
    diff.hosts.added.map(h => diffRow("+", "var(--green)", escapeHtml(h))).join("") +
    diff.hosts.removed.map(h => diffRow("−", "var(--red)", escapeHtml(h))).join("")
  );

  html += section("Ports", diff.ports.added.length, diff.ports.removed.length, 0, () =>
    diff.ports.added.map(p => diffRow("+", "var(--green)", portLabel(p))).join("") +
    diff.ports.removed.map(p => diffRow("−", "var(--red)", portLabel(p))).join("")
  );

  html += section("Emails", diff.emails.added.length, diff.emails.removed.length, 0, () =>
    diff.emails.added.map(e => diffRow("+", "var(--green)", escapeHtml(e))).join("") +
    diff.emails.removed.map(e => diffRow("−", "var(--red)", escapeHtml(e))).join("")
  );

  html += section("Intel", diff.intel.added.length, diff.intel.removed.length, diff.intel.changed.length, () =>
    diff.intel.added.map(i => diffRow("+", "var(--green)", intelLabel(i))).join("") +
    diff.intel.removed.map(i => diffRow("−", "var(--red)", intelLabel(i))).join("") +
    diff.intel.changed.map(c => diffRow("~", "var(--amber)",
      `${escapeHtml(c.to.host)} <span style="color:var(--text-dim);">· ${escapeHtml(c.to.source)} · ${escapeHtml(c.to.field)}</span>: "${escapeHtml(c.from.value)}" → "${escapeHtml(c.to.value)}"`
    )).join("")
  );

  return html;
}

// ---------------------------------------------------------------------------
// Scan report — the "Scans" tab's main view: request details, full
// searchable results, and per-host validation checkboxes.
// ---------------------------------------------------------------------------
let selectedReportScanId = null;

async function loadScanReport(scanId) {
  selectedReportScanId = scanId;
  selectedDeepScanHosts = new Set();
  renderScansList();
  el("scanReportMain").innerHTML = `<div class="empty" style="padding:60px 20px;">Loading…</div>`;
  const res = await fetch(`/api/scans/${scanId}`);
  const data = await res.json();
  if (!data.scan) {
    el("scanReportMain").innerHTML = `<div class="empty" style="padding:60px 20px;">Scan not found.</div>`;
    return;
  }
  el("scanReportMain").innerHTML = buildScanReportHtml(data);
  filterReportRows();
}

let reportActiveTab = "hosts";          // which sub-tab is currently shown
let lastValidateSummary = null;         // text shown above the tabs after Validate runs
let lastValidateSummaryScanId = null;   // which scan that summary belongs to, so switching
                                         // scans doesn't show a stale validation result

function buildToolsRunSummary(data, context) {
  context = context || "report";
  if (!configCache) return "";
  const scan = data.scan;
  const logs = data.logs || [];
  const subs = data.subdomains || [];
  const ports = data.ports || [];
  const intel = data.host_intel || [];
  const emails = data.emails || [];
  const screenshots = data.screenshots || [];
  const vulnerabilities = data.vulnerabilities || [];
  const leaks = data.leaks || [];

  // Independent tools (Company/Vulnerability modules) are always
  // included regardless of scan.mode — their static "modes" no longer
  // reflects fast/full at all since they don't run automatically as
  // part of either. Whether one actually ran for THIS scan is exactly
  // what the log-parsing further down already determines correctly
  // (did a "$ toolname ..." command line show up in this scan's logs);
  // excluding them here based on scan.mode would just hide that real
  // answer, showing "0 found" for a company/vuln scan that was
  // genuinely just triggered and found something.
  const applicable = configCache.builtin_tools.filter(t => t.modes.includes(scan.mode) || t.modes.includes("independent"));

  const countFor = (toolName) => {
    switch (toolName) {
      case "subfinder": case "amass": case "assetfinder": case "crtsh": case "theharvester":
        return subs.filter(s => (s.sources || "").split(",").some(src => src.startsWith(toolName))).length;
      case "naabu": case "nmap":
        return ports.filter(p => (p.source || "").split(",").some(src => src.startsWith(toolName))).length;
      case "whatweb":
        return intel.filter(i => i.source === "whatweb").length;
      case "company-lookup":
        return intel.filter(i => i.source === "company").length;
      case "ip-geo": case "social-scan": case "whois":
        return intel.filter(i => i.source === toolName).length;
      case "shodan":
        return intel.filter(i => i.source === "shodan").length + subs.filter(s => (s.sources || "").includes("shodan")).length;
      case "crosslinked":
        return emails.filter(e => e.source === "crosslinked").length + intel.filter(i => i.source === "crosslinked").length;
      case "gowitness":
        return screenshots.length;
      case "nuclei": case "ffuf": case "wpscan": case "dalfox": case "axfr": case "email-auth": case "secrets": case "buckets":
        return vulnerabilities.filter(v => v.source === toolName).length;
      case "xposedornot":
        return leaks.filter(l => l.source === "xposedornot").length;
      case "dnsx": case "httpx":
        return null; // these resolve/probe everything rather than attributing discrete "finds" to themselves
      default:
        return null;
    }
  };

  // Which report tab actually holds this tool's data — computed from the
  // real results rather than a fixed table, so a tool that could produce
  // more than one kind of output (crosslinked: emails or intel;
  // theharvester: hosts or emails) lands wherever it actually has
  // something to show, not a guess.
  const tabFor = (toolName) => {
    if (toolName === "gowitness") return "screenshots";
    if (vulnerabilities.some(v => v.source === toolName)) return "vulnerabilities";
    if (leaks.some(l => l.source === toolName)) return "leaks";
    if (subs.some(s => (s.sources || "").split(",").some(src => src.trim().startsWith(toolName)))) return "hosts";
    if (ports.some(p => (p.source || "").split(",").some(src => src.trim().startsWith(toolName)))) return "ports";
    if (emails.some(e => e.source === toolName)) return "emails";
    if (intel.some(i => i.source === toolName || (toolName === "company-lookup" && i.source === "company"))) return "intel";
    const defaults = { naabu: "ports", nmap: "ports", crosslinked: "emails", theharvester: "hosts" };
    return defaults[toolName] || "intel";
  };

  // Groups this tool's log lines into "invocation blocks" — a matching
  // `$ <command>` line plus every line that follows until the next `$ `
  // command starts (that's the natural stage boundary the pipeline
  // already produces). A tool can have more than one block in the same
  // scan (dnsx runs both a bruteforce pass and its normal resolution
  // pass, for example), so this returns a list, not a single block.
  const getToolLogBlocks = (toolName) => {
    const blocks = [];
    let current = null;
    for (const l of logs) {
      if (l.level === "cmd") {
        const cmdText = l.line.replace(/^\$\s*/, "");
        const firstToken = (cmdText.split(/\s+/)[0] || "");
        const binaryName = firstToken.split("/").pop().toLowerCase();
        if (binaryName === toolName.toLowerCase()) {
          if (current) blocks.push(current);
          current = { cmd: l.line, lines: [] };
          continue;
        } else if (current) {
          blocks.push(current);
          current = null;
        }
      }
      if (current) current.lines.push(l);
    }
    if (current) blocks.push(current);
    return blocks;
  };

  // For non-CLI (API-based) tools there's no "$ command" line at all —
  // instead pull any log line that explicitly mentions the tool in
  // brackets, e.g. "[whois] parsed 4 fields" or "[ip-geo] 1.2.3.4: ...".
  const getApiToolLogLines = (toolName) => logs.filter(l => l.line.toLowerCase().includes(`[${toolName.toLowerCase()}]`));

  const rows = applicable.map((t, idx) => {
    const skipped = logs.some(l => l.level === "warn" && l.line.toLowerCase().includes(`[skip] ${t.name.toLowerCase()}`));
    const disabled = t.enabled === false;
    const count = countFor(t.name);

    // Any other warn-level line mentioning this tool by name — this is
    // exactly the specific, human-written reason each skip condition
    // already logs at the point it happens (e.g. "[wpscan] no WordPress
    // detected", "[ffuf] no wordlist assigned"). Surfacing that
    // existing message directly, rather than re-deriving the same
    // reasoning a second time here, means this can never drift out of
    // sync with what the backend actually decided and why.
    const ownWarnLine = logs.find(l => l.level === "warn" && l.line.toLowerCase().includes(`[${t.name.toLowerCase()}]`));
    const moduleNotRun = t.modes.includes("independent") && t.name !== "cisa-kev" && t.name !== "epss"
      ? (["nuclei", "ffuf", "wpscan", "dalfox", "axfr", "email-auth", "secrets", "buckets"].includes(t.name)
          ? !scan.vulnerability_scanned_at
          : !scan.company_scanned_at)
      : false;

    // Actual data always wins as ground truth — a stale/contradictory log
    // line should never override a real finding that's sitting right
    // there in the database.
    let icon, label, color;
    if (count !== null && count > 0) {
      icon = "✓"; label = `${count} found`; color = "var(--green)";
    } else if (disabled) {
      icon = "⊘"; label = "disabled in Settings"; color = "var(--text-dim)";
    } else if (skipped) {
      icon = "⊘"; label = "not installed"; color = "var(--text-dim)";
    } else if (ownWarnLine) {
      // A specific, real reason nothing was produced — checked before
      // the generic "ran, found nothing" / "didn't run" fallbacks below
      // since it's always more informative when available. Without
      // this check first, a tool with a countable result type (0, not
      // null) would hit "ran, found nothing" even when the real reason
      // is e.g. "no WordPress detected", which implies it never
      // meaningfully ran at all.
      icon = "⊘"; color = "var(--text-dim)";
      label = ownWarnLine.line.replace(new RegExp(`^\\[${t.name}\\]\\s*`, "i"), "");
    } else if (moduleNotRun) {
      icon = "—"; label = "module not yet run — see Company/Vulnerability tab"; color = "var(--text-dim)";
    } else if (count !== null) {
      icon = "○"; label = "ran, found nothing"; color = "var(--text-dim)";
    } else if (!t.is_cli) {
      icon = "✓"; label = "ran"; color = "var(--green)";
    } else {
      // Plain substring match against the tool's registered name breaks
      // for any tool whose own log messages spell its name differently
      // than its internal key — confirmed directly: crt.sh is
      // registered as "crtsh" (no dot) but its own log line says
      // "crt.sh certificate transparency lookup" (with a dot), so
      // "crt.sh".includes("crtsh") is false. Stripping non-alphanumeric
      // characters from both sides before comparing makes this
      // resilient to that whole class of naming mismatch, not just
      // this one case.
      const normalize = s => s.toLowerCase().replace(/[^a-z0-9]/g, "");
      const normalizedName = normalize(t.name);
      const ran = logs.some(l => l.level === "cmd" && normalize(l.line).includes(normalizedName));
      icon = ran ? "✓" : "—";
      label = ran ? "ran" : "didn't run this scan";
      color = ran ? "var(--green)" : "var(--text-dim)";
    }

    const resultsClickable = count !== null && count > 0;
    const blocks = t.is_cli ? getToolLogBlocks(t.name) : [];
    const apiLines = !t.is_cli ? getApiToolLogLines(t.name) : [];
    const hasBreakdown = blocks.length > 0 || apiLines.length > 0;

    const levelColor = (lvl) => lvl === "error" ? "var(--red)" : lvl === "warn" ? "var(--amber)" : lvl === "cmd" ? "var(--cyan)" : "var(--text-dim)";

    const detailHtml = hasBreakdown ? `
      <div class="tool-run-detail" style="display:none;" onclick="event.stopPropagation();">
        ${blocks.length ? blocks.map(b => `
          <div class="tool-run-block">
            <div class="tool-run-block-cmd">${escapeHtml(b.cmd)}</div>
            <div class="tool-run-block-lines">
              ${b.lines.map(l => `<div style="color:${levelColor(l.level)};">${escapeHtml(l.line)}</div>`).join("")}
            </div>
          </div>
        `).join("") : `
          <div class="tool-run-block">
            <div class="tool-run-block-lines">
              ${apiLines.map(l => `<div style="color:${levelColor(l.level)};">${escapeHtml(l.line)}</div>`).join("")}
            </div>
          </div>
        `}
        ${resultsClickable ? `<div class="tool-run-view-results" onclick="event.stopPropagation(); jumpToToolResults('${t.name}', '${tabFor(t.name)}', '${context}')">View ${escapeHtml(t.name)}'s results in ${tabFor(t.name)} →</div>` : ""}
      </div>
    ` : "";

    const rowClickAttr = hasBreakdown ? ` onclick="toggleToolRunDetail(this)" style="cursor:pointer;" title="What did ${escapeHtml(t.name)} actually do?"` : "";
    return `
      <div class="tool-run-row${hasBreakdown ? " tool-run-clickable" : ""}"${rowClickAttr}>
        <span style="color:${color};">${icon}</span> <span class="tool-run-name">${escapeHtml(t.name)}</span> <span class="tool-run-label" style="color:${color};">${label}</span>
        ${detailHtml}
      </div>
    `;
  }).join("");

  return `<div class="tool-run-grid">${rows}</div>`;
}

// Takes the clicked row itself, not a positional index — this grid
// renders in two places that can genuinely coexist in the DOM at once
// (the live in-progress scan view and a loaded report), each starting
// its own index count from 0. An index-based id="toolRunDetail-N"
// lookup was confirmed to silently toggle the WRONG container's panel
// whenever both happened to have a tool with a breakdown at the same
// list position — reproduced directly, not just theoretical. Scoping
// to the clicked element's own row via closest() makes this correct
// regardless of how many copies of this grid exist on the page.
function toggleToolRunDetail(rowEl) {
  const detailEl = rowEl.closest(".tool-run-row").querySelector(".tool-run-detail");
  if (!detailEl) return;
  detailEl.style.display = detailEl.style.display === "none" ? "block" : "none";
}


function buildVulnerabilitiesTab(vulnerabilities, scan) {
  if (!vulnerabilities.length) {
    return `<div class="empty" style="padding:40px 18px;">No vulnerabilities found. This checks known CVEs/misconfigurations via nuclei, WordPress-specific CVEs via wpscan (only if WordPress was actually detected), and active XSS testing via dalfox — it's not a guarantee nothing exists, just that nothing matched this time.</div>`;
  }

  const takeovers = vulnerabilities.filter(v => v.is_takeover);
  const kevFindings = vulnerabilities.filter(v => v.is_kev);

  // Severity breakdown up front — the whole point is being able to tell
  // "how bad is this" at a glance, before scrolling through every card.
  const bySeverity = {};
  vulnerabilities.forEach(v => {
    const sev = (v.severity || "unknown").toLowerCase();
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;
  });
  const severityOrder = ["critical", "high", "medium", "low", "info", "unknown"];
  const summaryParts = severityOrder
    .filter(s => bySeverity[s])
    .map(s => `<span style="color:${severityColor(s)}; font-weight:bold;">${bySeverity[s]} ${s}</span>`);

  const sourceLabels = { nuclei: "nuclei", wpscan: "wpscan", dalfox: "dalfox", internetdb: "internetdb", shodan: "shodan" };

  return `
    <div class="vuln-tab-root" style="padding:10px 18px;">
      <div class="vuln-summary-bar">
        <b>${vulnerabilities.length}</b> finding${vulnerabilities.length === 1 ? "" : "s"} — ${summaryParts.join(", ")}
      </div>
      ${!scan.vulnerability_scanned_at ? `
        <div class="hint" style="padding:4px 0 10px;">
          From the main scan's own nuclei/ffuf run — the dedicated Vulnerability module (Vulnerability tab) hasn't done its own revalidated pass on this scan yet, which re-checks asset liveness first and can find more.
        </div>
      ` : ""}
      ${takeovers.length ? `
        <div class="vuln-takeover-banner">
          ⚠️ ${takeovers.length} possible subdomain takeover${takeovers.length === 1 ? "" : "s"} found — these deserve immediate attention over everything else here. A dangling DNS record pointing at a deprovisioned cloud resource can let someone else claim and serve content under this domain right now.
        </div>
      ` : ""}
      ${kevFindings.length ? `
        <div class="vuln-takeover-banner">
          ⚠️ ${kevFindings.length} finding${kevFindings.length === 1 ? "" : "s"} confirmed in CISA's Known Exploited Vulnerabilities catalog — these CVEs are under active exploitation in the wild right now, not just theoretically severe.
        </div>
      ` : ""}
      <div class="vuln-search-wrap">
        <input type="text" class="vuln-search-input" placeholder="Filter by host, name, source, severity…" oninput="filterVulnRows(this)">
      </div>
      <div class="vuln-list">
        ${vulnerabilities.map(v => {
          const searchText = [v.host, v.name, v.source, v.severity, v.template_id, v.is_kev ? "kev exploited" : ""].filter(Boolean).join(" ").toLowerCase();
          const isUrl = v.matched_at && /^https?:\/\//i.test(v.matched_at);
          const hasDetail = !!v.detail;
          const hasEpss = v.epss_score !== null && v.epss_score !== undefined;
          const epssPct = hasEpss ? (v.epss_score * 100) : null;
          // EPSS color scale — this is a probability, not a severity
          // rating, so it gets its own scale rather than reusing
          // severityColor: 50%+ is a genuinely high real-world risk
          // regardless of what the finding's own severity tag says.
          const epssColor = hasEpss ? (epssPct >= 50 ? "var(--red)" : epssPct >= 10 ? "var(--amber)" : "var(--text-dim)") : "var(--text-dim)";
          return `
          <div class="vuln-card ${(v.is_takeover || v.is_kev) ? "vuln-card-urgent" : ""} ${(v.triage_status === "false_positive" || v.triage_status === "fixed") ? "vuln-card-resolved" : ""}" data-vuln-search="${escapeHtml(searchText)}">
            <div class="vuln-card-header" ${hasDetail ? `onclick="toggleVulnDetail(this)" style="cursor:pointer;"` : ""}>
              <span class="vuln-severity-badge" style="background:${severityColor(v.severity)};">${v.is_takeover ? "TAKEOVER" : escapeHtml((v.severity || "unknown").toUpperCase())}</span>
              ${v.is_kev ? `<span class="vuln-severity-badge" style="background:var(--red);" title="Confirmed in CISA's Known Exploited Vulnerabilities catalog">KEV</span>` : ""}
              <span class="vuln-source-badge">${escapeHtml(sourceLabels[v.source] || v.source)}</span>
              <span class="vuln-name">${escapeHtml(v.name)}</span>
              ${hasEpss ? `<span class="vuln-source-badge" style="color:${epssColor}; border-color:${epssColor};" title="FIRST.org EPSS — modeled probability of exploitation in the next 30 days">EPSS ${epssPct.toFixed(1)}%</span>` : ""}
              ${hasDetail ? `<span class="vuln-expand-hint">▾ details</span>` : ""}
            </div>
            <div class="vuln-card-body">
              <div class="vuln-detail-row"><span class="vuln-detail-label">Host</span><span>${escapeHtml(v.host)}</span></div>
              ${v.matched_at ? `<div class="vuln-detail-row"><span class="vuln-detail-label">Matched at</span><span>${isUrl ? `<a href="${escapeHtml(v.matched_at)}" target="_blank" rel="noopener">${escapeHtml(v.matched_at)} ↗</a>` : escapeHtml(v.matched_at)}</span></div>` : ""}
              ${v.template_id ? `<div class="vuln-detail-row"><span class="vuln-detail-label">Template</span><span style="color:var(--text-dim); font-family:var(--mono);">${escapeHtml(v.template_id)}</span></div>` : ""}
              ${buildTriageControls(v.id, "vulnerability", v.triage_status, v.triage_note)}
            </div>
            ${hasDetail ? `<div class="vuln-detail-expand" style="display:none;">${escapeHtml(v.detail)}</div>` : ""}
          </div>
        `;
        }).join("")}
      </div>
    </div>
  `;
}

// Both use DOM-relative traversal (closest/querySelectorAll from the
// element that triggered them) rather than global IDs, deliberately —
// this same rendering function is used in two places that can exist in
// the DOM at once (the persistent Vulnerability tab and a scan report's
// own Vulnerabilities sub-tab), and fixed IDs would collide between
// them, causing a click or search in one to silently affect the other.
function toggleVulnDetail(headerEl) {
  const card = headerEl.closest(".vuln-card");
  const detail = card && card.querySelector(".vuln-detail-expand");
  if (!detail) return;
  detail.style.display = detail.style.display === "none" ? "block" : "none";
}

// Findings triage — shared between the Vulnerabilities and Leaks tabs.
// findingType is "vulnerability" or "leak", matching the two backend
// endpoints (/api/vulnerabilities/{id}/triage, /api/leaks/{id}/triage).
function filterVulnRows(inputEl) {
  const term = inputEl.value.trim().toLowerCase();
  const container = inputEl.closest(".vuln-tab-root");
  if (!container) return;
  container.querySelectorAll(".vuln-card").forEach(card => {
    const match = !term || card.dataset.vulnSearch.includes(term);
    card.style.display = match ? "" : "none";
  });
}

function buildEndpointsTab(endpoints) {
  if (!endpoints.length) {
    return `<div class="empty" style="padding:40px 18px;">No endpoints found. This comes from gau (historical/archived URLs from Wayback/CommonCrawl/OTX) and katana (crawled from live pages) — both only run in Full mode.</div>`;
  }
  const paramCount = endpoints.filter(u => u.includes("?")).length;
  // Same rendering cap as the other report tabs, and for the same
  // reason — gau/katana can together surface up to 600 URLs before
  // deduplication, and this stays consistent with the app-wide
  // convention rather than being a one-off number.
  const MAX_ENDPOINT_ROWS = 500;
  const truncated = endpoints.length > MAX_ENDPOINT_ROWS;
  const shown = endpoints.slice(0, MAX_ENDPOINT_ROWS);
  return `
    <div class="endpoint-tab-root" style="padding:10px 18px;">
      <div class="vuln-summary-bar">
        <b>${endpoints.length}</b> unique endpoint${endpoints.length === 1 ? "" : "s"} found (gau + katana, deduplicated)${paramCount ? ` — <b>${paramCount}</b> with query parameters` : ""}
      </div>
      ${truncated ? `<div class="hint" style="margin-bottom:10px;">Showing the first ${MAX_ENDPOINT_ROWS.toLocaleString()} of ${endpoints.length.toLocaleString()} — filter/copy only covers what's shown here. Export the scan for the complete list.</div>` : ""}
      <div class="vuln-search-wrap" style="display:flex; gap:8px; align-items:center;">
        <input type="text" class="vuln-search-input" placeholder="Filter endpoints…" oninput="filterEndpointRows(this)" style="flex:1;">
        <button class="btn-sm" onclick="copyEndpointList(this)">📋 Copy visible</button>
      </div>
      <div class="table-wrap" style="max-height:460px;">
        <table>
          <tbody>
            ${shown.map(u => {
              // Only ever a clickable link for http(s) — katana extracts
              // links directly from crawled page HTML with no scheme
              // filtering of its own, so a malformed or malicious page
              // could in principle hand back something like a
              // javascript: pseudo-URL. escapeHtml alone doesn't stop
              // that from executing on click (it's not an HTML-escaping
              // problem, it's a URL scheme), so anything that isn't
              // http(s) renders as plain, non-clickable text instead.
              const isHttpUrl = /^https?:\/\//i.test(u);
              return `
              <tr class="endpoint-row" data-endpoint-search="${escapeHtml(u.toLowerCase())}">
                <td style="font-family:var(--mono); font-size:11.5px; word-break:break-all; padding:5px 8px;">
                  ${isHttpUrl
                    ? `<a href="${escapeHtml(u)}" target="_blank" rel="noopener">${escapeHtml(u)}</a>`
                    : `<span title="Not an http(s) URL — shown as text only">${escapeHtml(u)}</span>`}
                  ${u.includes("?") ? `<span class="vuln-source-badge" style="margin-left:6px;">has params</span>` : ""}
                </td>
              </tr>
            `;
            }).join("")}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function buildOsintTab(findings) {
  if (!findings.length) {
    return `<div class="empty" style="padding:40px 18px;">No SpiderFoot findings. SpiderFoot only runs in Full mode, and needs to actually be installed — check Settings/Tools if you expected results here.</div>`;
  }
  const byCategory = {};
  findings.forEach(f => {
    (byCategory[f.category] = byCategory[f.category] || []).push(f);
  });
  // Fixed, meaningful order rather than however categories happened to
  // first appear — "Other" always last, everything else roughly in
  // descending order of how actionable it tends to be.
  const categoryOrder = ["Leaks & breaches", "Social & personal", "Infrastructure & network", "Domains & hosting", "Physical & geographic", "Other"];
  const orderedCategories = categoryOrder.filter(c => byCategory[c]);

  return `
    <div class="endpoint-tab-root" style="padding:10px 18px;">
      <div class="vuln-summary-bar">
        <b>${findings.length}</b> SpiderFoot finding${findings.length === 1 ? "" : "s"} across <b>${orderedCategories.length}</b> categor${orderedCategories.length === 1 ? "y" : "ies"}
      </div>
      <div class="vuln-search-wrap">
        <input type="text" class="vuln-search-input" placeholder="Filter findings…" oninput="filterOsintRows(this)">
      </div>
      ${orderedCategories.map(category => `
        <div style="margin-top:14px;">
          <div style="font-size:10px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); margin-bottom:6px; padding:0 2px;">
            ${escapeHtml(category)} <span class="tab-count">${byCategory[category].length}</span>
            ${category === "Leaks & breaches" ? `<span style="text-transform:none; letter-spacing:0; font-size:10px; color:var(--text-dim);"> — these also appear in the dedicated Leaks tab, which additionally covers LeakIX/XposedOrNot</span>` : ""}
          </div>
          <div class="table-wrap" style="max-height:260px;">
            <table>
              <tbody>
                ${byCategory[category].map(f => {
                  const searchText = [f.host, f.eventType, f.value, category].join(" ").toLowerCase();
                  return `
                  <tr data-osint-search="${escapeHtml(searchText)}">
                    <td style="width:110px; color:var(--text-dim); font-family:var(--mono); font-size:10.5px;">${escapeHtml(f.host)}</td>
                    <td style="width:160px; color:var(--text-dim); font-family:var(--mono); font-size:10.5px;">${escapeHtml(f.eventType)}</td>
                    <td style="font-size:11.5px; word-break:break-word;">${escapeHtml(f.value)}</td>
                  </tr>
                `;
                }).join("")}
              </tbody>
            </table>
          </div>
        </div>
      `).join("")}
    </div>
  `;
}

function filterOsintRows(inputEl) {
  const term = inputEl.value.trim().toLowerCase();
  const container = inputEl.closest(".endpoint-tab-root");
  if (!container) return;
  container.querySelectorAll("tr[data-osint-search]").forEach(row => {
    row.style.display = row.dataset.osintSearch.includes(term) ? "" : "none";
  });
}

// Same DOM-relative pattern as the Vulnerability tab's helpers, same
// reason — no fixed IDs, scoped via closest(), so this stays safe even
// if this rendering function is ever shown in more than one place at once.
function filterEndpointRows(inputEl) {
  const term = inputEl.value.trim().toLowerCase();
  const container = inputEl.closest(".endpoint-tab-root");
  if (!container) return;
  container.querySelectorAll(".endpoint-row").forEach(row => {
    row.style.display = (!term || row.dataset.endpointSearch.includes(term)) ? "" : "none";
  });
}

async function copyEndpointList(btnEl) {
  const container = btnEl.closest(".endpoint-tab-root");
  const visibleLinks = [...container.querySelectorAll(".endpoint-row")]
    .filter(row => row.style.display !== "none")
    .map(row => {
      // Not every row has an <a> — a non-http(s) entry renders as plain
      // text instead (see buildEndpointsTab), so fall back to that
      // text rather than assume an anchor tag is always present.
      const link = row.querySelector("a");
      return link ? link.href : row.querySelector("td").textContent.trim();
    });
  if (!visibleLinks.length) return;
  try {
    await navigator.clipboard.writeText(visibleLinks.join("\n"));
    const original = btnEl.textContent;
    btnEl.textContent = "Copied!";
    setTimeout(() => { btnEl.textContent = original; }, 1500);
  } catch (e) {
    alert("Couldn't copy — your browser may be blocking clipboard access on this page.");
  }
}

function buildLeaksTab(leaks) {
  // "No leak findings" (below) already lists all three sources; this
  // note is about the *overlap*, not the sourcing — SpiderFoot's own
  // leak-keyword-flagged findings land in both this tab and the OSINT
  // tab's "Leaks & breaches" category (confirmed directly in the
  // backend: the same finding gets stored in both places at once) — the
  // OSINT tab additionally shows the rest of SpiderFoot's findings that
  // didn't match a leak keyword, and this tab additionally shows LeakIX/
  // XposedOrNot findings that never touch SpiderFoot at all. Neither is
  // a subset of the other.
  const overlapNote = `<div class="hint" style="padding:0 18px 10px;">SpiderFoot's own leak-flagged findings also appear under the OSINT tab's "Leaks &amp; breaches" category, alongside its other, non-leak findings. LeakIX and XposedOrNot findings here don't have an OSINT-tab counterpart.</div>`;
  if (!leaks.length) {
    return overlapNote + `<div class="empty" style="padding:40px 18px;">No leak/exposure findings from LeakIX, XposedOrNot, or SpiderFoot's passive modules for this scan.</div>`;
  }
  return overlapNote + `
    <div style="padding:10px 18px;">
      <div class="vuln-list">
        ${leaks.map(l => `
          <div class="vuln-card vuln-card-urgent ${(l.triage_status === "false_positive" || l.triage_status === "fixed") ? "vuln-card-resolved" : ""}">
            <div class="vuln-card-header">
              <span class="vuln-severity-badge" style="background:var(--red);">${escapeHtml((l.leak_type || "leak").toUpperCase())}</span>
              <span class="vuln-name">${escapeHtml(l.host)}</span>
            </div>
            <div class="vuln-card-body">
              <div class="vuln-detail-row"><span class="vuln-detail-label">Source</span><span>${escapeHtml(l.source)}</span></div>
              <div class="vuln-detail-row"><span class="vuln-detail-label">Detail</span><span>${escapeHtml(l.detail)}</span></div>
              ${buildTriageControls(l.id, "leak", l.triage_status, l.triage_note)}
            </div>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

// A plain-English synthesis of scan size/scope — the "how big is this"
// answer the rest of the report leaves you to piece together yourself
// from separate tabs. Entirely computed from data already returned by
// this scan, no new backend endpoint needed.
function buildAttackSurfaceSummary(data) {
  const subs = data.subdomains || [];
  const assets = data.http_assets || [];
  const ports = data.ports || [];
  const intel = data.host_intel || [];
  const emails = data.emails || [];
  const vulnerabilities = data.vulnerabilities || [];
  const leaks = data.leaks || [];
  const scan = data.scan;

  if (!subs.length) return "";

  const liveAssets = assets.filter(a => a.status_code).length;
  const techs = new Set(
    intel.filter(i => i.source === "whatweb").map(i => i.field.replace(/^tech:/, "").toLowerCase())
  );
  const countries = new Set(intel.filter(i => i.source === "ip-geo" && i.field === "country").map(i => i.value));
  const orgs = new Set(intel.filter(i => i.source === "ip-geo" && i.field === "org").map(i => i.value));
  const takeoverCount = vulnerabilities.filter(v => v.is_takeover).length;
  const critHighCount = vulnerabilities.filter(v => ["critical", "high"].includes((v.severity || "").toLowerCase())).length;
  const shadowItCount = subs.filter(s => isLikelyShadowIT(s.subdomain, scan.domain)).length;

  // Employee count and parent-org — both come from the independent
  // Company module (see run_company_scan), not this scan's own
  // enumeration, so both are conditional on it actually having been
  // triggered (scan.company_scanned_at set) rather than assumed present.
  const employeeCount = intel.filter(i => i.source === "crosslinked" && i.field.startsWith("employee:")).length;
  const parentOrg = (intel.find(i => i.source === "company" && i.field === "parent_organization") || {}).value;

  const parts = [];
  parts.push(`<b>${subs.length}</b> host${subs.length === 1 ? "" : "s"} discovered`);
  if (liveAssets) parts.push(`<b>${liveAssets}</b> live web asset${liveAssets === 1 ? "" : "s"}`);
  if (ports.length) parts.push(`<b>${ports.length}</b> open port${ports.length === 1 ? "" : "s"}`);
  if (techs.size) parts.push(`<b>${techs.size}</b> distinct technolog${techs.size === 1 ? "y" : "ies"}`);
  if (countries.size) parts.push(`hosted across <b>${countries.size}</b> countr${countries.size === 1 ? "y" : "ies"}`);
  if (orgs.size > 1) parts.push(`<b>${orgs.size}</b> different hosting providers`);
  if (emails.length) parts.push(`<b>${emails.length}</b> email address${emails.length === 1 ? "" : "es"} found`);
  if (employeeCount) parts.push(`<b>${employeeCount}</b> employee${employeeCount === 1 ? "" : "s"} found via LinkedIn search`);
  if (parentOrg) parts.push(`part of <b>${escapeHtml(parentOrg)}</b>`);

  let riskLine = "";
  // Vulnerability and Company are independent modules now — neither runs
  // automatically as part of a scan, so "0 findings" and "never checked"
  // are genuinely different statements, and this needs to say which one
  // is actually true rather than let a scan look cleaner than it's
  // actually been verified to be.
  if (!scan.vulnerability_scanned_at) {
    riskLine = `<div class="surface-summary-risk">Vulnerability scan not yet run for this scan — see the Vulnerability tab.</div>`;
  } else if (takeoverCount) {
    riskLine = `<div class="surface-summary-risk surface-summary-risk-critical">⚠️ <b>${takeoverCount} possible subdomain takeover${takeoverCount === 1 ? "" : "s"}</b> found — immediate attention warranted.</div>`;
  } else if (critHighCount) {
    riskLine = `<div class="surface-summary-risk surface-summary-risk-high">⚠️ <b>${critHighCount} critical/high severity vulnerabilit${critHighCount === 1 ? "y" : "ies"}</b> found.</div>`;
  } else if (vulnerabilities.length) {
    riskLine = `<div class="surface-summary-risk">${vulnerabilities.length} lower-severity finding${vulnerabilities.length === 1 ? "" : "s"} — see the Vulnerabilities tab.</div>`;
  } else {
    riskLine = `<div class="surface-summary-risk surface-summary-risk-clean">Vulnerability scan ran — no vulnerabilities matched.</div>`;
  }
  if (leaks.length) {
    riskLine += `<div class="surface-summary-risk surface-summary-risk-critical">⚠️ <b>${leaks.length} leak/exposure finding${leaks.length === 1 ? "" : "s"}</b> — see the Leaks tab.</div>`;
  }
  if (shadowItCount) {
    riskLine += `<div class="surface-summary-risk surface-summary-risk-high">⚠️ <b>${shadowItCount} host${shadowItCount === 1 ? "" : "s"}</b> with naming patterns suggesting dev/staging/backup infrastructure — worth confirming these are known and intentional (see the ⚠ badges in the Hosts tab).</div>`;
  }
  if (!scan.company_scanned_at) {
    riskLine += `<div class="surface-summary-risk">Company profile not yet built for this scan — see the Company tab for employee counts, breach exposure, and organizational context.</div>`;
  }

  return `
    <div class="surface-summary">
      <div class="surface-summary-headline">External attack surface: ${parts.join(", ")}.</div>
      ${riskLine}
    </div>
  `;
}

function portKbLookup(port) {
  if (!configCache || !configCache.port_knowledge_base) return null;
  return configCache.port_knowledge_base[String(port)] || null;
}

// Each of these three takes the FULL, uncapped dataset plus a search
// term (empty string for the default view) and returns
// {rows, truncated, matchedCount, totalCount} — truncation is checked
// against how many actually MATCH the search, not the original total,
// which is the actual fix: a specific search term naturally narrows
// the pool before the cap ever matters, so search reaches everything a
// scan found, not just whatever the default capped view happened to
// include. Search text is computed once per item alongside the other
// derived fields, then reused for both the filter and the render pass
// rather than recomputed twice.
function renderHostsRows(subs, ctx, searchTerm) {
  const { assetsByHost, portsByHost, intel, scan } = ctx;
  const term = (searchTerm || "").toLowerCase();
  const enriched = subs.map(s => {
    const a = assetsByHost[s.subdomain];
    const portList = (portsByHost[s.subdomain] || portsByHost[s.ip] || []).join(", ");
    const shadowIT = isLikelyShadowIT(s.subdomain, scan.domain);
    const osGuessRow = intel.find(i => (i.host === s.subdomain || i.host === s.ip) && i.source === "nmap" && i.field === "os_guess");
    const techParts = [];
    if (a && a.tech) techParts.push(a.tech);
    if (a && a.server) techParts.push(`server: ${a.server}`);
    if (osGuessRow) techParts.push(`OS: ${osGuessRow.value}`);
    const techCell = techParts.length ? techParts.join(" · ") : "-";
    const searchText = [s.subdomain, s.ip, s.sources, a && a.status_code, a && a.title, techCell, portList, shadowIT ? "shadow-it" : ""]
      .filter(Boolean).join(" ").toLowerCase();
    return { s, a, portList, shadowIT, techCell, searchText };
  });
  const matched = term ? enriched.filter(e => e.searchText.includes(term)) : enriched;
  const truncated = matched.length > MAX_REPORT_ROWS;
  const rows = matched.slice(0, MAX_REPORT_ROWS).map(({ s, a, portList, shadowIT, techCell }) => {
    const subEsc = s.subdomain.replace(/'/g, "\\'").replace(/"/g, "&quot;");
    return `<tr class="${s.verified ? 'row-verified' : ''}">
      <td><input type="checkbox" class="verify-check" ${s.verified ? "checked" : ""} onchange="toggleVerify(${scan.id}, '${subEsc}', this)"></td>
      <td><input type="checkbox" class="deep-scan-check" ${selectedDeepScanHosts.has(s.subdomain) ? "checked" : ""} onchange="toggleDeepScanSelection('${subEsc}', this.checked)"></td>
      <td>${escapeHtml(s.subdomain)}${shadowIT ? `<span class="shadow-it-badge" title="Naming pattern suggests this might be dev/staging/backup infrastructure the org isn't actively tracking — worth confirming it's known and intentional.">⚠ possible shadow IT</span>` : ""}</td>
      <td>${escapeHtml(s.ip || "-")}</td>
      <td style="color:var(--text-dim)">${escapeHtml(s.sources)}</td>
      <td class="${statusClass(a && a.status_code)}">${a && a.status_code ? a.status_code : "-"}</td>
      <td>${a && a.title ? escapeHtml(a.title) : "-"}</td>
      <td style="color:var(--text-dim)">${escapeHtml(techCell)}</td>
      <td>${portList || "-"}</td>
      <td>${confidenceBadge(s.confidence, s.validation_status)}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="10" class="empty">No results</td></tr>`;
  return { rows, truncated, matchedCount: matched.length, totalCount: subs.length };
}

function renderPortsRows(ports, ctx, searchTerm) {
  const { intel } = ctx;
  const term = (searchTerm || "").toLowerCase();
  const enriched = ports.map(p => {
    const searchText = [p.host, p.port, p.service, p.source].filter(Boolean).join(" ").toLowerCase();
    const kb = portKbLookup(p.port);
    const nmapScripts = intel.filter(i => i.host === p.host && i.source === "nmap" && i.field.startsWith(`script:${p.port}:`));
    return { p, searchText, kb, nmapScripts };
  });
  const matched = term ? enriched.filter(e => e.searchText.includes(term)) : enriched;
  const truncated = matched.length > MAX_REPORT_ROWS;
  const rows = matched.slice(0, MAX_REPORT_ROWS).map(({ p, kb, nmapScripts }) => {
    return `<tr class="port-row-clickable" onclick="togglePortDetail(this)">
      <td>${escapeHtml(p.host)}</td>
      <td>${p.port}${kb ? ` <span class="tech-kb-badge">${escapeHtml(kb.service)}</span>` : ""}</td>
      <td style="color:var(--text-dim)">${p.service ? escapeHtml(p.service) : "-"}</td>
      <td style="color:var(--text-dim)">${escapeHtml(p.source)}</td>
      <td>${confidenceBadge(p.confidence, p.validation_status)}</td>
    </tr>
    <tr class="port-detail-row" style="display:none;">
      <td colspan="5">
        ${kb ? `
          <div class="tech-kb-panel">
            <div class="tech-kb-row"><span class="tech-kb-icon">ℹ️</span><span>${escapeHtml(kb.description)}</span></div>
            <div class="tech-kb-row tech-kb-security"><span class="tech-kb-icon">⚠️</span><span>${escapeHtml(kb.security_notes)}</span></div>
          </div>
        ` : `
          <div class="tech-kb-panel tech-kb-panel-empty">No specific guidance in this app's knowledge base for port ${p.port} yet — that's just a gap in the reference list, not a signal either way.</div>
        `}
        ${nmapScripts.length ? `
          <div class="tech-kb-panel" style="margin-top:8px;">
            <div class="tech-kb-row"><span class="tech-kb-icon">🔍</span><span style="font-weight:bold;">nmap script output</span></div>
            ${nmapScripts.map(s => `
              <div class="tech-kb-row"><span style="color:var(--text-dim); font-family:var(--mono); font-size:11px;">${escapeHtml(s.field.split(":").slice(2).join(":"))}</span></div>
              <div class="tech-kb-row" style="white-space:pre-wrap; font-family:var(--mono); font-size:11px;">${escapeHtml(s.value)}</div>
            `).join("")}
          </div>
        ` : ""}
      </td>
    </tr>`;
  }).join("") || `<tr><td colspan="5" class="empty">No open ports found</td></tr>`;
  return { rows, truncated, matchedCount: matched.length, totalCount: ports.length };
}

function renderIntelRows(intel, searchTerm) {
  const term = (searchTerm || "").toLowerCase();
  const enriched = intel.map(i => ({ i, searchText: [i.host, i.source, i.field, i.value].join(" ").toLowerCase() }));
  const matched = term ? enriched.filter(e => e.searchText.includes(term)) : enriched;
  const truncated = matched.length > MAX_REPORT_ROWS;
  const rows = matched.slice(0, MAX_REPORT_ROWS).map(({ i }) =>
    `<tr><td>${escapeHtml(i.host)}</td><td>${escapeHtml(i.source)}</td><td>${escapeHtml(i.field)}</td><td>${escapeHtml(i.value)}</td></tr>`
  ).join("") || `<tr><td colspan="4" class="empty">No intel gathered</td></tr>`;
  return { rows, truncated, matchedCount: matched.length, totalCount: intel.length };
}

// Confirmed as a real gap: the top search box's own placeholder claims
// "emails" as part of its scope, but nothing ever actually filtered
// this tab from it — emailRows was built once at initial render and
// never touched again. Same pattern as renderIntelRows above, so
// filterReportRows can drive this the same way it already does hosts/
// ports/intel.
function renderEmailsRows(emails, searchTerm) {
  const term = (searchTerm || "").toLowerCase();
  const enriched = emails.map(e => ({ e, searchText: [e.email, e.source].join(" ").toLowerCase() }));
  const matched = term ? enriched.filter(x => x.searchText.includes(term)) : enriched;
  const truncated = matched.length > MAX_REPORT_ROWS;
  const scanId = currentReportData ? currentReportData.scan.id : null;
  const rows = matched.slice(0, MAX_REPORT_ROWS).map(({ e }) => {
    const isGuess = e.source === "pattern-guess";
    const sourceLabel = isGuess
      ? `<span style="color:var(--amber);" title="Derived from a naming-pattern match against another known email — not independently confirmed.">${escapeHtml(e.source)} (unverified)</span>`
      : `<span style="color:var(--text-dim);">${escapeHtml(e.source)}</span>`;
    return `<tr>
      <td><a href="mailto:${escapeHtml(e.email)}" style="color:${isGuess ? "var(--amber)" : "var(--cyan)"}; text-decoration:none;">${escapeHtml(e.email)}</a></td>
      <td>${sourceLabel}</td>
      <td>
        ${scanId != null ? `<button class="btn-sm" data-identity="${escapeHtml(e.email)}" onclick="runUserScanner(${scanId}, 'email', this.dataset.identity, this, this.nextElementSibling)">🔎 Check accounts</button>` : ""}
        <div class="user-scanner-result" style="display:none; margin-top:4px; font-size:11px;"></div>
      </td>
    </tr>`;
  }).join("") || `<tr><td colspan="3" class="empty">No emails found</td></tr>`;
  return { rows, truncated, matchedCount: matched.length, totalCount: emails.length };
}

function buildScanReportHtml(data) {
  const scan = data.scan;
  const subs = data.subdomains || [];
  const assets = data.http_assets || [];
  const ports = data.ports || [];
  const intel = data.host_intel || [];
  const emails = data.emails || [];
  const logs = data.logs || [];
  const screenshots = data.screenshots || [];
  const vulnerabilities = data.vulnerabilities || [];
  const leaks = data.leaks || [];

  // Endpoints — gau (historical/archived URLs) and katana (crawled from
  // live pages) both discover real, individual endpoints, but previously
  // had no dedicated display at all — only visible as unstructured rows
  // in the generic Intel table below, easy to miss entirely given
  // there can be hundreds of them. Deduplicated since the same URL can
  // legitimately show up from both sources.
  const endpoints = [...new Set(
    intel.filter(i => i.source === "gau" || i.source === "katana").map(i => i.value)
  )].sort();

  // SpiderFoot findings — grouped by keyword-matched category, not an
  // exhaustive event-type mapping. SpiderFoot has 200+ modules and no
  // single source enumerates every possible event type string it can
  // produce, so this groups by recognizable fragments in the type name
  // rather than claim complete coverage — anything unmatched lands in
  // "Other" visibly, never silently dropped. Previously these findings
  // had zero dedicated display at all, only visible buried in the raw
  // Intel tab as e.g. "INTERNET_NAME:0".
  const SPIDERFOOT_CATEGORIES = [
    ["Leaks & breaches", ["leak", "breach", "compromis", "darkweb", "paste", "blacklist", "malicious", "vulnerab"]],
    ["Social & personal", ["social", "email", "username", "human_name", "phone", "account"]],
    ["Infrastructure & network", ["ip_address", "netblock", "asn", "bgp", "port", "webserver", "ssl", "certificate", "software", "banner", "cloud"]],
    ["Domains & hosting", ["domain", "internet_name", "co_hosted", "similardomain", "affiliate"]],
    ["Physical & geographic", ["geo", "physical", "coordinate", "country"]],
  ];
  function categorizeSpiderfootEvent(eventType) {
    const lower = eventType.toLowerCase();
    for (const [category, keywords] of SPIDERFOOT_CATEGORIES) {
      if (keywords.some(kw => lower.includes(kw))) return category;
    }
    return "Other";
  }
  const spiderfootFindings = intel
    .filter(i => i.source === "spiderfoot")
    .map(i => {
      const eventType = i.field.split(":")[0];
      return { eventType, category: categorizeSpiderfootEvent(eventType), value: i.value, host: i.host };
    });

  const assetsByHost = {};
  assets.forEach(a => { assetsByHost[a.subdomain] = a; });
  const portsByHost = {};
  ports.forEach(p => {
    portsByHost[p.host] = portsByHost[p.host] || [];
    portsByHost[p.host].push(`${p.port}`);
  });

  // Stored so filterReportRows can re-render Hosts/Ports/Intel/Emails
  // from the FULL dataset on every keystroke, not just toggle
  // visibility on the capped default view above.
  currentReportData = { subs, ports, intel, emails, assetsByHost, portsByHost, scan };

  // Pairs each "$ ..." command with its rationale line, which — when one
  // exists at all — is always logged immediately before it (see
  // _log_rationale in core.py). Not every command has one (custom
  // user-configured API sources don't get an app-authored rationale,
  // since the person who configured them already knows why).
  const commands = [];
  logs.forEach((l, i) => {
    if (l.level !== "cmd") return;
    const prev = logs[i - 1];
    commands.push({ line: l.line, why: (prev && prev.level === "why") ? prev.line.replace(/^\[why\]\s*/, "") : null });
  });
  // Port-scanning-specific commands + their meta summary lines (host/port
  // counts), pulled straight from the log so the Ports tab shows exactly
  // what actually ran (including any bespoke variant's extra args) rather
  // than a generic description that could drift from reality.
  const portScanLines = logs.filter(l =>
    (l.level === "cmd" && (l.line.includes("naabu") || l.line.includes("nmap"))) ||
    (l.level === "meta" && (l.line.includes("naabu:") || l.line.includes("nmap:") || l.line.includes("[naabu]") || l.line.includes("[nmap]")))
  ).map(l => ({ text: l.line, isCmd: l.level === "cmd" }));

  let duration = "-";
  if (scan.started_at && scan.completed_at) {
    const ms = new Date(scan.completed_at) - new Date(scan.started_at);
    if (ms > 0) duration = ms < 60000 ? `${Math.round(ms / 1000)}s` : `${Math.round(ms / 6000) / 10}m`;
  }

  const hostsResult = renderHostsRows(subs, { assetsByHost, portsByHost, intel, scan }, "");
  const hostsRows = hostsResult.rows;
  const hostsTruncated = hostsResult.truncated;

  const portsResult = renderPortsRows(ports, { intel }, "");
  const portsRows = portsResult.rows;
  const portsTruncated = portsResult.truncated;

  const intelResult = renderIntelRows(intel, "");
  const intelRows = intelResult.rows;
  const intelTruncated = intelResult.truncated;

  const emailsResult = renderEmailsRows(emails, "");
  const emailRows = emailsResult.rows;

  const validateSummaryHtml = (lastValidateSummaryScanId === scan.id && lastValidateSummary)
    ? escapeHtml(lastValidateSummary)
    : "Re-checks DNS/HTTP/port reachability right now and scores a 0–100 confidence rating per finding.";

  // Lands on Vulnerabilities first when there's actually something there
  // to see — the whole point of pulling these out of the generic Intel
  // tab was so they're not something you have to go looking for. A clean
  // scan with nothing found still opens on Hosts as before, since an
  // empty Vulnerabilities tab isn't a useful first thing to land on.
  reportActiveTab = vulnerabilities.length ? "vulnerabilities" : "hosts";

  return `
    <div class="panel" style="padding:18px 20px;">
      <div class="report-header">
        <div>
          <div class="report-title">${escapeHtml(scan.domain)}</div>
          <div class="report-meta">Scan #${scan.id} · ${escapeHtml(scan.mode)} mode</div>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="status-badge status-${scan.status}">${scan.status}</span>
          <button class="btn-sm" onclick="switchToCompanyView(${scan.id})">🏢 Company profile</button>
        </div>
      </div>
      ${buildAttackSurfaceSummary(data)}
      <div class="request-card" style="margin-top:16px;">
        <div class="request-field"><div class="k">Started</div><div class="v">${fmtDate(scan.started_at)}</div></div>
        <div class="request-field"><div class="k">Completed</div><div class="v">${fmtDate(scan.completed_at)}</div></div>
        <div class="request-field"><div class="k">Duration</div><div class="v">${duration}</div></div>
        <div class="request-field"><div class="k">Hosts found</div><div class="v">${subs.length}</div></div>
      </div>
      <div class="stat-row" style="margin-top:14px;">
        <div class="stat stat-clickable" onclick="switchReportTab('vulnerabilities')" style="${vulnerabilities.length ? 'border-color:var(--red);' : ''}"><div class="num" style="${vulnerabilities.length ? 'color:var(--red);' : ''}">${vulnerabilities.length}</div><div class="lbl">Vulnerabilities</div></div>
        <div class="stat stat-clickable" onclick="switchReportTab('leaks')" style="${leaks.length ? 'border-color:var(--red);' : ''}"><div class="num" style="${leaks.length ? 'color:var(--red);' : ''}">${leaks.length}</div><div class="lbl">Leaks</div></div>
        <div class="stat stat-clickable" onclick="switchReportTab('hosts')"><div class="num">${subs.length}</div><div class="lbl">Hosts</div></div>
        <div class="stat stat-clickable" onclick="switchReportTab('ports')"><div class="num">${ports.length}</div><div class="lbl">Ports</div></div>
        <div class="stat stat-clickable" onclick="switchReportTab('intel')"><div class="num">${intel.length}</div><div class="lbl">Intel</div></div>
        <div class="stat stat-clickable" onclick="switchReportTab('emails')"><div class="num">${emails.length}</div><div class="lbl">Emails</div></div>
        <div class="stat stat-clickable" onclick="switchReportTab('screenshots')"><div class="num">${screenshots.length}</div><div class="lbl">Screenshots</div></div>
      </div>
      <details style="margin-top:16px;">
        <summary style="font-size:10px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); margin-bottom:6px; cursor:pointer;">Tools this scan — what ran and what it found (click to expand)</summary>
        <div style="margin-top:8px;">${buildToolsRunSummary(data)}</div>
      </details>
      ${commands.length ? `
        <details style="margin-top:16px;">
          <summary style="font-size:10px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); margin-bottom:6px; cursor:pointer;">Commands run (the exact request)</summary>
          <div class="commands-list" style="margin-top:8px;">${commands.map(c => `
            <div class="cmd-entry">
              ${c.why ? `<div class="cmd-why">${escapeHtml(c.why)}</div>` : ""}
              <div class="cmd-line">${escapeHtml(c.line)}</div>
            </div>
          `).join("")}</div>
        </details>
      ` : ""}
    </div>

    <div class="panel" style="padding:14px 18px;">
      <div class="search-row">
        <input id="reportSearchInput" type="text" placeholder="Search hosts, ports, intel, emails, vulnerabilities, OSINT, endpoints..." oninput="filterReportRows()">
        <span class="search-count" id="reportSearchCount"></span>
      </div>
      <div class="validate-row">
        <button class="btn-sm" id="validateBtn" onclick="validateFindings(${scan.id})">✅ Validate findings</button>
        <span class="hint" style="margin:0;">${validateSummaryHtml}</span>
      </div>
    </div>

    <div class="panel" style="padding:0;">
      <div class="report-tabs">
        <button class="report-tab ${reportActiveTab === 'vulnerabilities' ? 'active' : ''}" data-tab="vulnerabilities" onclick="switchReportTab('vulnerabilities')">Vulnerabilities <span class="tab-count" style="${vulnerabilities.length ? 'color:var(--red);' : ''}">${vulnerabilities.length}</span></button>
        <button class="report-tab ${reportActiveTab === 'leaks' ? 'active' : ''}" data-tab="leaks" onclick="switchReportTab('leaks')">Leaks <span class="tab-count" style="${leaks.length ? 'color:var(--red);' : ''}">${leaks.length}</span></button>
        <button class="report-tab ${reportActiveTab === 'hosts' ? 'active' : ''}" data-tab="hosts" onclick="switchReportTab('hosts')">Hosts <span class="tab-count">${subs.length}</span></button>
        <button class="report-tab" data-tab="ports" onclick="switchReportTab('ports')">Ports <span class="tab-count">${ports.length}</span></button>
        <button class="report-tab" data-tab="endpoints" onclick="switchReportTab('endpoints')">Endpoints <span class="tab-count">${endpoints.length}</span></button>
        <button class="report-tab" data-tab="osint" onclick="switchReportTab('osint')">OSINT <span class="tab-count">${spiderfootFindings.length}</span></button>
        <button class="report-tab" data-tab="intel" onclick="switchReportTab('intel')">Intel <span class="tab-count">${intel.length}</span></button>
        <button class="report-tab" data-tab="emails" onclick="switchReportTab('emails')">Emails <span class="tab-count">${emails.length}</span></button>
        <button class="report-tab" data-tab="screenshots" onclick="switchReportTab('screenshots')">Screenshots <span class="tab-count">${screenshots.length}</span></button>
      </div>

      <div class="report-tab-content" data-tab-content="vulnerabilities" style="${reportActiveTab === 'vulnerabilities' ? '' : 'display:none;'}">
        ${buildVulnerabilitiesTab(vulnerabilities, data.scan)}
      </div>

      <div class="report-tab-content" data-tab-content="leaks" style="${reportActiveTab === 'leaks' ? '' : 'display:none;'}">
        ${buildLeaksTab(leaks)}
      </div>

      <div class="report-tab-content" data-tab-content="hosts" style="${reportActiveTab === 'hosts' ? '' : 'display:none;'}">
        <div style="display:flex; justify-content:space-between; align-items:center; padding:10px 18px;">
          <span style="color:var(--text-dim); font-size:11.5px;">check ✓ to mark a host as manually validated</span>
          <span class="export-row">
            <a href="/api/scans/${scan.id}/export/json">JSON</a>
            <a href="/api/scans/${scan.id}/export/csv">CSV</a>
            <a href="/api/scans/${scan.id}/export/report">Report</a>
            <a href="/api/scans/${scan.id}/export/docs">Docs .txt</a>
          </span>
        </div>
        <div style="display:flex; justify-content:space-between; align-items:center; padding:0 18px 10px; gap:10px;">
          <span style="color:var(--text-dim); font-size:11.5px;">
            check the second box to select hosts for a deeper scan — recursive subdomain brute-forcing, run from the Scans page only, never automatically
          </span>
          <button class="btn-sm" id="deepScanBtn" onclick="runDeepScan(${scan.id})" disabled>Deep-scan selected (<span id="deepScanCount">0</span>)</button>
        </div>
        <div id="deepScanHint" class="hint" style="padding:0 18px 8px; display:none;"></div>
        <div class="terminal module-live-output" id="deepScanLiveOutput" style="display:none; height:140px; margin:0 18px 12px;"></div>
        <div id="hostsTruncatedMsg">${hostsTruncated ? `<div class="hint" style="padding:0 18px 8px;">Showing the first ${MAX_REPORT_ROWS.toLocaleString()} of ${subs.length.toLocaleString()} hosts — export above for the complete list, or narrow with search below.</div>` : ""}</div>
        <div class="table-wrap" style="max-height:460px;">
          <table id="reportHostsTable">
            <thead><tr><th style="width:30px;">✓</th><th style="width:30px;" title="Select for deep scan">🔍</th><th>Subdomain</th><th>IP</th><th>Sources</th><th>HTTP</th><th>Title</th><th>Tech</th><th>Ports</th><th>Confidence</th></tr></thead>
            <tbody id="reportHostsBody">${hostsRows}</tbody>
          </table>
        </div>
      </div>

      <div class="report-tab-content" data-tab-content="ports" style="display:none;">
        ${portScanLines.length ? `
          <div style="padding:10px 18px 4px; border-bottom:1px solid var(--line);">
            <div style="font-size:10px; text-transform:uppercase; letter-spacing:0.5px; color:var(--text-dim); margin-bottom:6px;">Port scan detail — exactly what ran, including any bespoke variant's extra args</div>
            ${portScanLines.map(l => `<div style="font-family:var(--mono); font-size:11.5px; padding:2px 0; color:${l.isCmd ? "var(--cyan)" : "var(--text-dim)"};">${escapeHtml(l.text)}</div>`).join("")}
          </div>
        ` : `<div style="padding:10px 18px; color:var(--text-dim); font-size:11.5px;">no naabu/nmap commands recorded for this scan — port scanning may have been disabled or the tools weren't installed (check Settings/Tools).</div>`}
        <div style="padding:10px 18px; color:var(--text-dim); font-size:11.5px;">every open port found, across every host — one row per port</div>
        <div id="portsTruncatedMsg">${portsTruncated ? `<div class="hint" style="padding:0 18px 8px;">Showing the first ${MAX_REPORT_ROWS.toLocaleString()} of ${ports.length.toLocaleString()} ports — export from the Hosts tab for the complete dataset, or narrow with search below.</div>` : ""}</div>
        <div class="table-wrap" style="max-height:460px;">
          <table id="reportPortsTable">
            <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Source(s)</th><th>Confidence</th></tr></thead>
            <tbody id="reportPortsBody">${portsRows}</tbody>
          </table>
        </div>
      </div>

      <div class="report-tab-content" data-tab-content="endpoints" style="display:none;">
        ${buildEndpointsTab(endpoints)}
      </div>

      <div class="report-tab-content" data-tab-content="osint" style="display:none;">
        ${buildOsintTab(spiderfootFindings)}
      </div>

      <div class="report-tab-content" data-tab-content="intel" style="display:none;">
        <div id="intelTruncatedMsg">${intelTruncated ? `<div class="hint" style="padding:8px 0;">Showing the first ${MAX_REPORT_ROWS.toLocaleString()} of ${intel.length.toLocaleString()} rows — export this scan (JSON/CSV) for the complete dataset, or narrow with search below.</div>` : ""}</div>
        <div class="table-wrap" style="max-height:460px;">
          <table id="reportIntelTable">
            <thead><tr><th>Host</th><th>Source</th><th>Field</th><th>Value</th></tr></thead>
            <tbody id="reportIntelBody">${intelRows}</tbody>
          </table>
        </div>
      </div>

      <div class="report-tab-content" data-tab-content="emails" style="display:none;">
        <div class="table-wrap" style="max-height:460px;">
          <table id="reportEmailsTable">
            <thead><tr><th>Email</th><th>Source</th><th>Accounts</th></tr></thead>
            <tbody id="reportEmailsBody">${emailRows}</tbody>
          </table>
        </div>
      </div>

      <div class="report-tab-content" data-tab-content="screenshots" style="display:none;">
        <div style="padding:10px 18px; color:var(--text-dim); font-size:11.5px;">gowitness screenshots of live hosts (Full mode only) — click one to open full-size</div>
        ${buildScreenshotsGrid(screenshots, scan.id)}
      </div>
    </div>
  `;
}

function buildScreenshotsGrid(screenshots, scanId) {
  if (!screenshots.length) {
    return `<div class="empty" style="padding:40px 18px;">No screenshots for this scan.</div>`;
  }
  return `
    <div class="screenshot-grid">
      ${screenshots.map(s => {
        if (!s.filename) {
          return `
            <div class="screenshot-card screenshot-failed">
              <div class="screenshot-placeholder">✕</div>
              <div class="screenshot-meta">
                <div class="screenshot-host">${escapeHtml(s.host)}</div>
                <div class="screenshot-sub" style="color:var(--red);">${escapeHtml(s.error || "failed")}</div>
              </div>
            </div>
          `;
        }
        const imgUrl = `/api/scans/${scanId}/screenshots/${s.id}/image`;
        // final_url is only worth surfacing when it actually differs
        // from the URL that was screenshotted — gowitness records it
        // regardless, but most of the time it's identical (no redirect
        // happened) and repeating the same URL would just be noise.
        const redirected = s.final_url && s.url && s.final_url !== s.url;
        return `
          <a class="screenshot-card" href="${imgUrl}" target="_blank" rel="noopener">
            <img src="${imgUrl}" loading="lazy" alt="${escapeHtml(s.host)}">
            <div class="screenshot-meta">
              <div class="screenshot-host">${escapeHtml(s.host)}</div>
              <div class="screenshot-sub">${s.status_code || "-"}${s.title ? " · " + escapeHtml(s.title) : ""}</div>
              ${redirected ? `<div class="screenshot-sub" style="color:var(--amber);" title="This target redirected elsewhere before the screenshot was taken">↪ ${escapeHtml(s.final_url)}</div>` : ""}
            </div>
          </a>
        `;
      }).join("")}
    </div>
  `;
}

function switchReportTab(tab) {
  reportActiveTab = tab;
  document.querySelectorAll(".report-tab").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === tab));
  document.querySelectorAll(".report-tab-content").forEach(elc => {
    elc.style.display = elc.dataset.tabContent === tab ? "block" : "none";
  });
  filterReportRows();
}

async function validateFindings(scanId) {
  const btn = el("validateBtn");
  if (btn) { btn.disabled = true; btn.textContent = "Validating…"; }
  try {
    const res = await fetch(`/api/scans/${scanId}/validate`, { method: "POST" });
    const data = await res.json();
    if (data.ok) {
      lastValidateSummary =
        `✅ Hosts: ${data.hosts_confirmed}/${data.hosts_checked} confirmed` +
        (data.hosts_unreachable ? `, ${data.hosts_unreachable} unreachable` : "") +
        ` · Ports: ${data.ports_confirmed}/${data.ports_checked} confirmed open` +
        (data.ports_closed ? `, ${data.ports_closed} possibly closed now` : "");
    } else {
      lastValidateSummary = "Validation failed.";
    }
  } catch (e) {
    lastValidateSummary = "Validation failed — request error.";
  }
  lastValidateSummaryScanId = scanId;
  await loadScanReport(scanId);
}

function jumpToToolResults(toolName, tab, context) {
  if (context === "live") {
    // The live Scan tab doesn't have the report's tab system — it's
    // separate stacked panels instead. Map each report "tab" to whichever
    // live panel actually shows that kind of data (ports show inline in
    // the Hosts & assets table's Ports column, so there's no separate
    // live ports panel to jump to).
    const liveTargets = { hosts: "hostsPanel", ports: "hostsPanel", intel: "intelPanel", emails: "emailsPanel", screenshots: "liveScreenshotsPanel" };
    scrollToPanel(liveTargets[tab] || "hostsPanel");
    return;
  }
  switchReportTab(tab);
  const searchInput = el("reportSearchInput");
  if (searchInput) {
    searchInput.value = toolName;
    filterReportRows();
    searchInput.focus();
  }
}

function filterReportRows() {
  if (!currentReportData) return;
  const term = (el("reportSearchInput").value || "").trim().toLowerCase();
  const { subs, ports, intel, emails, assetsByHost, portsByHost, scan } = currentReportData;

  // Re-renders each affected tab's table body from the FULL dataset on
  // every keystroke, rather than toggling CSS visibility on an
  // already-capped set of rows — this is the actual fix for search
  // previously only reaching whatever the default 500-row cap happened
  // to include. All re-render together regardless of which tab is
  // currently visible; simpler and safer than only updating the active
  // one and needing extra logic to catch up when switching tabs
  // mid-search, and none of these datasets are large enough post-filter
  // for the extra work to matter.
  const hostsResult = renderHostsRows(subs, { assetsByHost, portsByHost, intel, scan }, term);
  el("reportHostsBody").innerHTML = hostsResult.rows;
  el("hostsTruncatedMsg").innerHTML = hostsResult.truncated
    ? `<div class="hint" style="padding:0 18px 8px;">Showing the first ${MAX_REPORT_ROWS.toLocaleString()} of ${hostsResult.matchedCount.toLocaleString()}${term ? " matching" : ""} hosts — export above for the complete list${term ? "" : ", or narrow with search below"}.</div>`
    : "";

  const portsResult = renderPortsRows(ports, { intel }, term);
  el("reportPortsBody").innerHTML = portsResult.rows;
  el("portsTruncatedMsg").innerHTML = portsResult.truncated
    ? `<div class="hint" style="padding:0 18px 8px;">Showing the first ${MAX_REPORT_ROWS.toLocaleString()} of ${portsResult.matchedCount.toLocaleString()}${term ? " matching" : ""} ports — export from the Hosts tab for the complete dataset${term ? "" : ", or narrow with search below"}.</div>`
    : "";

  const intelResult = renderIntelRows(intel, term);
  el("reportIntelBody").innerHTML = intelResult.rows;
  el("intelTruncatedMsg").innerHTML = intelResult.truncated
    ? `<div class="hint" style="padding:8px 0;">Showing the first ${MAX_REPORT_ROWS.toLocaleString()} of ${intelResult.matchedCount.toLocaleString()}${term ? " matching" : ""} rows — export this scan (JSON/CSV) for the complete dataset${term ? "" : ", or narrow with search below"}.</div>`
    : "";

  // Confirmed as a real gap and fixed: this box's own placeholder
  // claimed "emails" as part of its scope, but nothing here ever
  // actually touched the Emails tab until now.
  const emailsResult = renderEmailsRows(emails, term);
  const emailsBodyEl = el("reportEmailsBody");
  if (emailsBodyEl) emailsBodyEl.innerHTML = emailsResult.rows;

  // Vulnerabilities/OSINT/Endpoints each already have their own working
  // filter function and search input rendered in the DOM (just hidden,
  // not absent, when their tab isn't active) — reused directly here
  // rather than reimplementing the same filtering logic a second time.
  // Leaks/Screenshots have no search input of their own at all yet, so
  // there's nothing to sync for those two.
  [
    ["[oninput*='filterVulnRows']", filterVulnRows],
    ["[oninput*='filterOsintRows']", filterOsintRows],
    ["[oninput*='filterEndpointRows']", filterEndpointRows],
  ].forEach(([selector, fn]) => {
    const inputEl = document.querySelector(selector);
    if (inputEl) {
      inputEl.value = term;
      fn(inputEl);
    }
  });

  const resultsByTab = { hosts: hostsResult, ports: portsResult, intel: intelResult, emails: emailsResult };
  const countLabel = el("reportSearchCount");
  const activeResult = resultsByTab[reportActiveTab];
  if (countLabel) {
    // Vulnerabilities/OSINT/Endpoints now filter from this box too (see
    // above), but each already shows its own count in its own summary
    // bar — nothing extra to report here for those. Leaks/Screenshots
    // still have no search at all, so nothing to report there either.
    countLabel.textContent = activeResult
      ? (term ? `${activeResult.matchedCount} / ${activeResult.totalCount} match (this tab)` : `${activeResult.totalCount} rows in this tab`)
      : "";
  }
}


function toggleDeepScanSelection(host, checked) {
  if (checked) {
    selectedDeepScanHosts.add(host);
  } else {
    selectedDeepScanHosts.delete(host);
  }
  const countEl = el("deepScanCount");
  const btnEl = el("deepScanBtn");
  if (countEl) countEl.textContent = selectedDeepScanHosts.size;
  if (btnEl) btnEl.disabled = selectedDeepScanHosts.size === 0;
}

async function runDeepScan(scanId) {
  const hosts = [...selectedDeepScanHosts];
  if (!hosts.length) return;
  const btn = el("deepScanBtn");
  const hint = el("deepScanHint");
  btn.disabled = true;
  const originalLabel = btn.textContent;
  btn.textContent = "Running…";
  hint.style.display = "block";
  hint.style.color = "var(--text-dim)";
  hint.textContent = `Starting deep scan on ${hosts.length} host(s)…`;
  // Same async-background-task + poll-for-completion pattern as the
  // Company module — the endpoint has to return immediately for live
  // progress to be possible at all, so real completion is detected via
  // deep_scan_running on the scan row, not by this fetch() resolving.
  const socket = attachModuleWs(scanId, "deepScanLiveOutput", (percent, stage) => {
    hint.style.color = "var(--text-dim)";
    hint.textContent = `${stage} (${percent}%)…`;
  });
  try {
    const res = await fetch(`/api/scans/${scanId}/deep-scan/run`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hosts }),
    });
    const data = await res.json();
    if (!res.ok) {
      hint.style.color = "var(--red)";
      hint.textContent = data.error || "Deep scan failed to start.";
      return;
    }
    await new Promise((resolve) => {
      const interval = setInterval(async () => {
        const r = await fetch(`/api/scans/${scanId}`);
        const scanData = await r.json();
        if (!scanData.scan || !scanData.scan.deep_scan_running) {
          clearInterval(interval);
          resolve();
        }
      }, 1500);
    });
    hint.style.color = "var(--green)";
    hint.textContent = "Done — see the updated hosts table below.";
    selectedDeepScanHosts = new Set();
    // loadScanReport's very first synchronous action replaces this
    // whole report's DOM with a "Loading…" placeholder — confirmed
    // directly that calling it immediately meant the "Done" message
    // above never actually rendered, just got silently overwritten in
    // the same tick. A brief pause lets the person actually see the
    // confirmation before the refresh happens.
    await new Promise(r => setTimeout(r, 900));
    await loadScanReport(scanId);
  } catch (e) {
    hint.style.color = "var(--red)";
    hint.textContent = "Request failed — check your connection and try again.";
  } finally {
    socket.close();
    if (btn) { btn.textContent = originalLabel; btn.disabled = selectedDeepScanHosts.size === 0; }
  }
}

async function toggleVerify(scanId, subdomain, checkbox) {
  const tr = checkbox.closest("tr");
  const prevChecked = !checkbox.checked;
  try {
    const res = await fetch(`/api/scans/${scanId}/verify`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subdomain, verified: checkbox.checked })
    });
    if (!res.ok) throw new Error("request failed");
    tr.classList.toggle("row-verified", checkbox.checked);
  } catch (e) {
    checkbox.checked = prevChecked;
  }
}

// ---------------------------------------------------------------------------
// Wordlists — a small library of uploaded files, each assignable to at most
// one wordlist-capable tool (amass, dnsx) at a time. Assignment itself
// happens from that tool's entry in the Tools sidebar, not here — this
// section is just the upload/manage library.
// ---------------------------------------------------------------------------
