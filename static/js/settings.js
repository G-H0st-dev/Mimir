// Settings modal, tool configuration (variants/profiles/wordlists/
// intensity), and the per-tool Command modal. Depends on core.js (loaded
// first) for shared state and utilities.

function openSettings() {
  el("settingsOverlay").classList.add("open");
  loadConfig();
}
function closeSettings() {
  el("settingsOverlay").classList.remove("open");
}
function scrollSettingsTo(event, sectionId) {
  event.preventDefault();
  const target = el(sectionId);
  if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
}
el("settingsOverlay").addEventListener("click", (e) => {
  if (e.target.id === "settingsOverlay") closeSettings();
});

el("ctFormat").addEventListener("change", () => {
  el("ctCustomFieldWrap").style.display = el("ctFormat").value === "json:custom" ? "block" : "none";
});

function onShellToggle() {
  const isShell = el("ctShell").checked;
  el("ctHint").style.display = isShell ? "none" : "block";
  el("ctShellExample").style.display = isShell ? "block" : "none";
  el("ctCmd").placeholder = isShell
    ? "e.g. subfinder -d {domain} -silent && assetfinder --subs-only {domain}"
    : "e.g. subfinder -d {domain} -silent -sources crtsh";
}
el("asCategory").addEventListener("change", () => {
  const isSubdomain = el("asCategory").value === "subdomain";
  el("asJsonPathWrap").style.display = isSubdomain ? "block" : "none";
  el("asIntelFieldsWrap").style.display = isSubdomain ? "none" : "block";
});

function renderSettings() {
  if (!configCache) return;

  const shodan = configCache.api_keys.shodan;
  el("shodanStatus").innerHTML = shodan.configured
    ? `<span style="color:var(--green)">configured</span> — key ending ${shodan.masked}`
    : `<span style="color:var(--text-dim)">not configured</span> — Shodan sources are skipped until a key is set`;

  const leakix = configCache.api_keys.leakix;
  el("leakixStatus").innerHTML = leakix.configured
    ? `<span style="color:var(--green)">configured</span> — key ending ${leakix.masked}`
    : `<span style="color:var(--text-dim)">not configured</span> — LeakIX lookups are skipped until a key is set`;

  const wpscan = configCache.api_keys.wpscan;
  el("wpscanStatus").innerHTML = wpscan.configured
    ? `<span style="color:var(--green)">configured</span> — key ending ${wpscan.masked}`
    : `<span style="color:var(--text-dim)">not configured</span> — wpscan is skipped until a key is set, even if WordPress is detected`;

  const hunter = configCache.api_keys.hunter;
  el("hunterStatus").innerHTML = hunter.configured
    ? `<span style="color:var(--green)">configured</span> — key ending ${hunter.masked}`
    : `<span style="color:var(--text-dim)">not configured</span> — Hunter.io email search is skipped until a key is set`;

  const ai = configCache.ai_config;
  if (ai.configured) {
    el("aiBaseUrlInput").value = ai.base_url;
    el("aiModelInput").value = ai.model;
    el("aiConfigStatus").innerHTML =
      `<span style="color:var(--green)">configured</span> — ${escapeHtml(ai.model)} @ ${escapeHtml(ai.base_url)}` +
      (ai.api_key_set ? " (API key set)" : " (no API key — fine for a local Ollama server)");
  } else {
    el("aiBaseUrlInput").value = "";
    el("aiModelInput").value = "";
    el("aiConfigStatus").innerHTML = `<span style="color:var(--text-dim)">not configured</span> — the Company profile's AI analysis section stays hidden until this is set up`;
  }

  el("builtinToolsList").innerHTML = configCache.builtin_tools.map(t => `
    <div class="tool-row">
      <div>
        <div class="tname">${t.name}
          <span class="badge ${t.available ? 'ok' : 'missing'}">${t.available ? 'available' : (t.category === 'enrichment' ? 'no key' : 'not on PATH')}</span>
        </div>
        <div class="tmeta">${t.category} · ${t.modes.join(', ')}</div>
        <div class="tmeta" style="white-space:pre-line; color:var(--cyan); opacity:0.85;">${escapeHtml(t.cmd || '')}</div>
      </div>
      <label class="switch">
        <input type="checkbox" ${t.enabled ? 'checked' : ''} onchange="toggleTool('${t.name}', this.checked)">
        <span class="slider"></span>
      </label>
    </div>
  `).join("");

  el("customToolsList").innerHTML = (configCache.custom_tools || []).map(t => {
    let availBadge;
    if (t.shell) {
      availBadge = `<span class="badge info">shell chain</span>`;
    } else {
      availBadge = `<span class="badge ${t.available ? 'ok' : 'missing'}">${t.available ? 'available' : 'not on PATH'}</span>`;
    }
    return `
    <div class="tool-row">
      <div>
        <div class="tname">${t.name} ${availBadge}</div>
        <div class="tmeta" style="color:var(--cyan); opacity:0.85;">${escapeHtml(t.command_template)}</div>
        <div class="tmeta">${t.output_format}${t.shell ? ' · runs via shell' : ''}</div>
      </div>
      <div style="display:flex; align-items:center; gap:10px;">
        <label class="switch">
          <input type="checkbox" ${t.enabled ? 'checked' : ''} onchange="toggleCustomTool(${t.id}, this.checked)">
          <span class="slider"></span>
        </label>
        <button class="btn-sm danger" onclick="deleteCustomTool(${t.id})">Remove</button>
      </div>
    </div>
  `;
  }).join("") || `<div class="hint">No custom CLI tools added yet.</div>`;

  el("apiSourcesList").innerHTML = (configCache.custom_api_sources || []).map(s => `
    <div class="tool-row">
      <div>
        <div class="tname">${s.name} <span class="badge info">${s.category}</span></div>
        <div class="tmeta">${escapeHtml(s.url_template)}</div>
      </div>
      <div style="display:flex; align-items:center; gap:10px;">
        <label class="switch">
          <input type="checkbox" ${s.enabled ? 'checked' : ''} onchange="toggleApiSource(${s.id}, this.checked)">
          <span class="slider"></span>
        </label>
        <button class="btn-sm danger" onclick="deleteApiSource(${s.id})">Remove</button>
      </div>
    </div>
  `).join("") || `<div class="hint">No custom API resources added yet.</div>`;
}

async function toggleTool(name, enabled) {
  await fetch("/api/config/tool_toggle", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, enabled })
  });
  await loadConfig();
}

async function toggleAllTools(enabled) {
  await fetch("/api/config/tool_toggle_all", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled })
  });
  await loadConfig();
}

async function toggleCustomTool(id, enabled) {
  await fetch(`/api/config/custom_tool/${id}`, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled })
  });
  await loadConfig();
}

async function deleteCustomTool(id) {
  await fetch(`/api/config/custom_tool/${id}`, { method: "DELETE" });
  await loadConfig();
}

async function addCustomTool() {
  const name = el("ctName").value.trim();
  const cmd = el("ctCmd").value.trim();
  const shell = el("ctShell").checked;
  let format = el("ctFormat").value;
  if (format === "json:custom") {
    const field = el("ctCustomField").value.trim();
    if (!field) { el("ctCustomField").focus(); return; }
    format = "json:" + field;
  }
  if (!name || !cmd) return;
  await fetch("/api/config/custom_tool", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, command_template: cmd, output_format: format, shell })
  });
  el("ctName").value = ""; el("ctCmd").value = ""; el("ctCustomField").value = "";
  el("ctShell").checked = false; onShellToggle();
  await loadConfig();
}

async function toggleApiSource(id, enabled) {
  await fetch(`/api/config/api_source/${id}`, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled })
  });
  await loadConfig();
}

async function deleteApiSource(id) {
  await fetch(`/api/config/api_source/${id}`, { method: "DELETE" });
  await loadConfig();
}

async function addApiSource() {
  const name = el("asName").value.trim();
  const category = el("asCategory").value;
  const url_template = el("asUrl").value.trim();
  const json_path = el("asJsonPath").value.trim();
  const intel_fields = el("asIntelFields").value.trim();
  const api_key = el("asApiKey").value.trim();
  if (!name || !url_template) return;
  await fetch("/api/config/api_source", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, category, url_template, json_path, intel_fields, api_key })
  });
  el("asName").value = ""; el("asUrl").value = ""; el("asJsonPath").value = "";
  el("asIntelFields").value = ""; el("asApiKey").value = "";
  await loadConfig();
}

async function saveApiKey(service) {
  const key = el(service + "KeyInput").value.trim();
  await fetch("/api/config/api_key", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ service, key })
  });
  el(service + "KeyInput").value = "";
  await loadConfig();
}

async function saveAiConfig() {
  const base_url = el("aiBaseUrlInput").value.trim();
  const model = el("aiModelInput").value.trim();
  const api_key = el("aiApiKeyInput").value.trim();
  const statusEl = el("aiConfigStatus");
  if (base_url && !model) {
    statusEl.textContent = "A model name is required.";
    statusEl.style.color = "var(--red)";
    return;
  }
  try {
    const res = await fetch("/api/ai/config", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ base_url, model, api_key: api_key || null })
    });
    if (!res.ok) throw new Error("save failed");
    el("aiApiKeyInput").value = "";
    statusEl.textContent = base_url ? "✅ Saved." : "Cleared — AI analysis is now unconfigured.";
    statusEl.style.color = "var(--green)";
    await loadConfig();
  } catch (e) {
    statusEl.textContent = "❌ Couldn't save — try again.";
    statusEl.style.color = "var(--red)";
  }
}

// ---------------------------------------------------------------------------
// Backup & restore — everything already auto-persists to surface.db; this
// is just a way to snapshot/move that state (VACUUM INTO on the backend,
// so it's always a clean, complete file even though the live DB runs in
// WAL mode).
// ---------------------------------------------------------------------------
async function restoreBackup(inputEl) {
  const file = inputEl.files && inputEl.files[0];
  if (!file) return;
  const statusEl = el("backupStatus");

  const sure = confirm(
    `Restore from "${file.name}"?\n\nThis replaces everything currently in the app — every scan, ` +
    `custom tool, variant, and API key — with what's in this file. There's no undo except ` +
    `restoring a different backup.`
  );
  if (!sure) {
    inputEl.value = "";
    return;
  }

  statusEl.textContent = "Restoring…";
  statusEl.style.color = "var(--text-dim)";

  try {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch("/api/backup/restore", { method: "POST", body: formData });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      statusEl.textContent = "❌ " + (data.error || "Restore failed.");
      statusEl.style.color = "var(--red)";
      return;
    }
    statusEl.textContent = "✅ Restored — reloading…";
    statusEl.style.color = "var(--green)";
    setTimeout(() => location.reload(), 1200);
  } catch (e) {
    statusEl.textContent = "❌ Restore failed — request error.";
    statusEl.style.color = "var(--red)";
  } finally {
    inputEl.value = "";
  }
}

async function clearBrowserData() {
  const statusEl = el("clearDataStatus");
  statusEl.textContent = "Clearing…";
  statusEl.style.color = "var(--text-dim)";
  try {
    const res = await fetch("/api/clear-browser-data", { method: "POST" });
    if (!res.ok) {
      statusEl.textContent = "❌ Request failed.";
      statusEl.style.color = "var(--red)";
      return;
    }
    statusEl.textContent = "✅ Cleared — reloading…";
    statusEl.style.color = "var(--green)";
    // location.reload() alone can still serve from memory cache in some
    // browsers; a fresh navigation to the same URL forces an actual
    // network fetch, which combined with Clear-Site-Data on the last
    // response guarantees the next load is genuinely clean.
    setTimeout(() => { window.location.href = window.location.href; }, 800);
  } catch (e) {
    statusEl.textContent = "❌ Request error.";
    statusEl.style.color = "var(--red)";
  }
}

async function resetScanData() {
  const statusEl = el("clearDataStatus");
  const sure = confirm(
    "Reset all scan data?\n\nThis deletes every scan and everything that belongs to one — hosts, " +
    "ports, intel, emails, logs. Your setup (custom tools, bespoke command variants, custom API " +
    "sources, API keys) is left untouched. There's no undo short of restoring a backup."
  );
  if (!sure) return;

  statusEl.textContent = "Resetting…";
  statusEl.style.color = "var(--text-dim)";
  try {
    const res = await fetch("/api/reset-scan-data", { method: "POST" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      statusEl.textContent = "❌ Reset failed.";
      statusEl.style.color = "var(--red)";
      return;
    }
    statusEl.textContent = `✅ Deleted ${data.scans_deleted} scan(s) — reloading…`;
    statusEl.style.color = "var(--green)";
    setTimeout(() => location.reload(), 1000);
  } catch (e) {
    statusEl.textContent = "❌ Request error.";
    statusEl.style.color = "var(--red)";
  }
}

// ---------------------------------------------------------------------------
// Company profile — synthesized on demand from a scan's intel, shown in
// its own persistent tab (see switchView/loadCompanyTab above) rather
// than a modal, so it's a real destination you can navigate back to
// rather than something you have to re-open from a specific scan.
// ---------------------------------------------------------------------------
function renderWordlistsList() {
  if (!configCache) return;
  const el2 = el("wordlistsList");
  if (!el2) return;
  const wordlists = configCache.wordlists || [];
  const assignments = configCache.tool_wordlists || {};
  if (!wordlists.length) {
    el2.innerHTML = `<div class="hint">No wordlists uploaded yet.</div>`;
    return;
  }
  el2.innerHTML = wordlists.map(w => {
    const usedBy = Object.entries(assignments).filter(([, id]) => id === w.id).map(([tool]) => tool);
    return `
      <div class="tool-row">
        <div>
          <div class="tname">${escapeHtml(w.name)}</div>
          <div class="tmeta">${w.line_count.toLocaleString()} lines · ${formatFileSize(w.size_bytes)}${usedBy.length ? ` · assigned to ${usedBy.join(", ")}` : ""}</div>
        </div>
        <button class="btn-sm danger" onclick="deleteWordlist(${w.id})">Remove</button>
      </div>
    `;
  }).join("");
}

async function uploadWordlist(inputEl) {
  const file = inputEl.files && inputEl.files[0];
  if (!file) return;
  const statusEl = el("wordlistUploadStatus");
  statusEl.textContent = "Uploading…";
  statusEl.style.color = "var(--text-dim)";
  try {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch("/api/wordlists", { method: "POST", body: formData });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      statusEl.textContent = "❌ " + (data.error || "Upload failed.");
      statusEl.style.color = "var(--red)";
      return;
    }
    statusEl.textContent = `✅ Uploaded "${data.name}" (${data.line_count.toLocaleString()} lines)`;
    statusEl.style.color = "var(--green)";
    await loadConfig();
  } catch (e) {
    statusEl.textContent = "❌ Request error.";
    statusEl.style.color = "var(--red)";
  } finally {
    inputEl.value = "";
  }
}

// Same upload endpoint as uploadWordlist above, but triggered from
// directly within a tool's own Variants tab — uploads the file, then
// immediately assigns it to that tool via the existing setToolWordlist,
// which itself refreshes config and re-renders this modal showing the
// new wordlist already selected. Skips the round trip through Settings
// entirely, which was the actual point of adding this.
async function uploadWordlistForTool(inputEl, toolName) {
  const file = inputEl.files && inputEl.files[0];
  if (!file) return;
  try {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch("/api/wordlists", { method: "POST", body: formData });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      alert("Upload failed: " + (data.error || "unknown error"));
      return;
    }
    await setToolWordlist(toolName, data.id);
  } catch (e) {
    alert("Upload failed — request error.");
  } finally {
    inputEl.value = "";
  }
}

async function deleteWordlist(id) {
  await fetch(`/api/wordlists/${id}`, { method: "DELETE" });
  await loadConfig();
}

async function setToolWordlist(toolName, wordlistId) {
  await fetch("/api/config/tool_wordlist", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool_name: toolName, wordlist_id: wordlistId ? parseInt(wordlistId, 10) : null }),
  });
  await loadConfig();
}

async function setToolIntensity(toolName, aggressive) {
  await fetch("/api/config/tool_intensity", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool_name: toolName, aggressive }),
  });
  await loadConfig();
}

async function setToolProfile(toolName, profile) {
  await fetch("/api/config/tool_profile", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool_name: toolName, profile }),
  });
  await loadConfig();
}

// ---------------------------------------------------------------------------
// Tools sidebar list + tool command modal (bespoke command variants)
// ---------------------------------------------------------------------------
let currentToolModalName = null;

const TOOL_CATEGORY_LABELS = {
  subdomain: "Subdomain discovery", osint: "OSINT & people", whois: "WHOIS",
  resolution: "DNS resolution", probe: "HTTP probing", ports: "Port scanning",
  screenshots: "Screenshots", fingerprinting: "Technology fingerprinting",
  geo: "Geolocation", company: "Company info", enrichment: "Enrichment",
};
const TOOL_CATEGORY_ORDER = [
  "subdomain", "whois", "resolution", "probe", "ports", "osint", "fingerprinting",
  "screenshots", "geo", "company", "enrichment",
];

function renderToolsList() {
  if (!configCache) return;
  const filterEl = el("toolsFilterInput");
  const filter = (filterEl && filterEl.value || "").trim().toLowerCase();

  const modeToolCount = configCache.builtin_tools.filter(t => t.modes.includes(mode)).length;
  const totalCount = configCache.builtin_tools.length;
  const subtitleEl = el("toolsListSubtitle");
  if (subtitleEl) {
    subtitleEl.textContent = `Showing ${modeToolCount} of ${totalCount} tools — the ones that actually run in ${mode === "full" ? "Full stack" : "Fast"} mode.`;
  }

  const tools = configCache.builtin_tools.filter(t =>
    t.modes.includes(mode) &&
    (!filter || t.name.toLowerCase().includes(filter) || (TOOL_CATEGORY_LABELS[t.category] || t.category).toLowerCase().includes(filter))
  );

  const byCategory = {};
  tools.forEach(t => { (byCategory[t.category] = byCategory[t.category] || []).push(t); });
  const orderedCats = [...TOOL_CATEGORY_ORDER.filter(c => byCategory[c]), ...Object.keys(byCategory).filter(c => !TOOL_CATEGORY_ORDER.includes(c))];

  if (!tools.length) {
    el("toolsList").innerHTML = `<div class="hint" style="padding:6px 0;">No tools match "${escapeHtml(filter)}".</div>`;
  } else {
    el("toolsList").innerHTML = orderedCats.map(cat => `
      <div class="tool-category-label">${escapeHtml(TOOL_CATEGORY_LABELS[cat] || cat)}</div>
      ${byCategory[cat].map(t => {
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
      }).join("")}
    `).join("");
  }

  // Master switch reflects reality rather than tracking its own state:
  // checked only when every tool actually is enabled right now, so it
  // stays correct even if individual tools were toggled one at a time.
  const allEnabled = configCache.builtin_tools.length > 0 && configCache.builtin_tools.every(t => t.enabled);
  const masterInput = el("allToolsSwitch");
  if (masterInput) {
    masterInput.checked = allEnabled;
    el("allToolsSwitchLabel").title = allEnabled ? "Disable every tool" : "Enable every tool";
  }
}

function openToolCommand(toolName) {
  currentToolModalName = toolName;
  toolModalActiveSubTab = "command";
  el("toolCommandOverlay").classList.add("open");
  renderToolCommandModal();
}
function closeToolCommand() {
  el("toolCommandOverlay").classList.remove("open");
  currentToolModalName = null;
}
el("toolCommandOverlay").addEventListener("click", (e) => {
  if (e.target.id === "toolCommandOverlay") closeToolCommand();
});

let toolModalActiveSubTab = "command";

function switchToolModalTab(tab) {
  toolModalActiveSubTab = tab;
  renderToolCommandModal();
}

// Extracted so the same picker can render right on the Command tab
// (so it's visible the moment the tool is opened, no extra click) as
// well as under the Variants tab where it originally lived — same
// dropdown, same upload button, same "here's what changes" copy either
// place it's shown.
function buildWordlistSectionHtml(tool, wordlists, assignedWordlistId, activeWl) {
  // Each wordlist-capable tool behaves differently without one: amass
  // and dnsx run fine either way (a wordlist just adds a bruteforce
  // pass on top of what they'd do anyway), while ffuf and shuffledns
  // have nothing to do at all without one — they're skipped outright.
  // A single hardcoded amass/dnsx-shaped message here previously
  // described ffuf/shuffledns as if they behaved like dnsx (talking
  // about a "bruteforce pass alongside normal resolution", which
  // means nothing for a content-fuzzing tool) — this was probably
  // what looked like the wordlist option being "missing" for ffuf:
  // the picker was there, the explanation just didn't make sense.
  const WORDLIST_COPY = {
    amass: {
      none: "passive mode",
      assigned: "switches from <code>-passive</code> to <code>-brute -w &lt;wordlist&gt;</code> automatically.",
    },
    dnsx: {
      none: "resolution only, no bruteforce pass",
      assigned: "runs an extra <code>dnsx -d {domain} -w &lt;wordlist&gt;</code> bruteforce pass alongside normal resolution.",
    },
    ffuf: {
      none: "skipped — nothing to fuzz without one",
      assigned: "fuzzes each confirmed-live host's paths with this wordlist. Without one assigned, ffuf does not run at all.",
    },
    shuffledns: {
      none: "skipped — nothing to brute-force without one",
      assigned: "brute-forces subdomains with this wordlist via massdns. Without one assigned, shuffledns does not run at all.",
    },
  }[tool.name] || { none: "default behavior", assigned: "runs with this wordlist." };

  let html = `<div class="settings-section-title">Wordlist</div>`;
  const uploadRow = `
    <div class="field full-span" style="margin-bottom:10px; display:flex; align-items:center; gap:8px;">
      <label class="btn-sm" style="cursor:pointer; margin:0;">
        📁 Upload new wordlist
        <input type="file" style="display:none;" onchange="uploadWordlistForTool(this, '${tool.name}')">
      </label>
      <span class="hint" style="margin:0;">Uploads and assigns it to ${escapeHtml(tool.name)} immediately — no need to go to Settings first.</span>
    </div>
  `;
  if (!wordlists.length) {
    html += uploadRow;
    html += `<div class="hint" style="margin-bottom:14px;">No wordlists uploaded yet.</div>`;
  } else {
    const recommendedId = (configCache.wordlist_recommendations || {})[tool.name];
    html += uploadRow;
    html += `
      <div class="field full-span" style="margin-bottom:6px;">
        <select onchange="setToolWordlist('${tool.name}', this.value)">
          <option value="">— none (${WORDLIST_COPY.none}) —</option>
          ${wordlists.map(w => {
            const isRecommended = recommendedId && w.id === recommendedId;
            const label = isRecommended ? `★ ${w.name} — recommended` : w.name;
            return `<option value="${w.id}" ${w.id === assignedWordlistId ? "selected" : ""}>${escapeHtml(label)} (${w.line_count.toLocaleString()} lines)</option>`;
          }).join("")}
        </select>
      </div>
    `;
    html += activeWl ? `
      <div class="hint" style="color:var(--green); margin-bottom:14px;">
        ✓ "${escapeHtml(activeWl.name)}" assigned — the command shown above will run differently next scan:
        ${WORDLIST_COPY.assigned}
      </div>
    ` : `<div class="hint" style="margin-bottom:14px;">No wordlist assigned — ${WORDLIST_COPY.none}.</div>`;
    if (recommendedId && recommendedId !== assignedWordlistId) {
      const recommendedWl = wordlists.find(w => w.id === recommendedId);
      if (recommendedWl) {
        const reason = assignedWordlistId
          ? "marked above, not switched to automatically since something else is already assigned"
          : "marked above — should already be assigned automatically; if it shows as unassigned, a restart may be needed to pick it up";
        html += `
          <div class="hint" style="margin-bottom:14px;">
            ★ Recommended for ${escapeHtml(tool.name)}: "${escapeHtml(recommendedWl.name)}" — ${reason}.
          </div>
        `;
      }
    }
  }
  return html;
}

function renderToolCommandModal() {
  if (!configCache || !currentToolModalName) return;
  const tool = configCache.builtin_tools.find(t => t.name === currentToolModalName);
  if (!tool) return;

  el("toolCommandTitle").textContent = `🔧 ${tool.name}`;

  const variants = (configCache.tool_variants || []).filter(v => v.tool_name === tool.name);
  const activeVariant = variants.find(v => v.active);
  const wordlistCapable = (configCache.wordlist_capable_tools || []).includes(tool.name);
  const assignedWordlistId = (configCache.tool_wordlists || {})[tool.name] || null;
  const wordlists = configCache.wordlists || [];
  const aggressiveCapable = (configCache.aggressive_capable_tools || []).includes(tool.name);
  const isAggressive = !!(configCache.tool_intensity || {})[tool.name];
  const hasProfile = !!(configCache.tool_profiles || {})[tool.name];
  const activeWl = wordlists.find(w => w.id === assignedWordlistId);
  const hasCheatsheet = !!(tool.cheatsheet && tool.cheatsheet.length);

  const tabs = ["command"];
  if (tool.is_cli) tabs.push("variants");
  if (hasCheatsheet) tabs.push("cheatsheet");
  if (!tabs.includes(toolModalActiveSubTab)) toolModalActiveSubTab = "command";
  const tabLabels = { command: "Command", variants: "Variants", cheatsheet: "Cheat sheet" };

  let html = `
    <div class="hint" style="margin-bottom:10px;">
      ${escapeHtml(tool.category)} · modes: ${tool.modes.join(", ")} ·
      ${tool.available === false ? '<span style="color:var(--red)">not available</span>' : '<span style="color:var(--green)">available</span>'}
    </div>
    <div class="tool-modal-tabs">
      ${tabs.map(tb => `<button class="tool-modal-tab ${toolModalActiveSubTab === tb ? "active" : ""}" onclick="switchToolModalTab('${tb}')">${tabLabels[tb]}</button>`).join("")}
    </div>
  `;

  if (toolModalActiveSubTab === "command") {
    const statusRow = (active, onLabel, offLabel, name) =>
      `<div class="tool-run-row"><span style="color:${active ? "var(--green)" : "var(--text-dim)"};">${active ? "✓" : "○"}</span> <span class="tool-run-name">${name}</span> <span class="tool-run-label" style="color:${active ? "var(--green)" : "var(--text-dim)"};">${active ? onLabel : offLabel}</span></div>`;
    html += `
      <div class="settings-section-title" style="margin-top:12px;">Base command</div>
      <div class="commands-list" style="margin-bottom:14px;">${tool.cmd.split("\n").map(l => `<div>${escapeHtml(l)}</div>`).join("")}</div>
      <div class="settings-section-title">What will actually run next scan</div>
      <div class="tool-run-grid" style="margin-top:6px;">
        ${aggressiveCapable ? statusRow(isAggressive, "aggressive (louder/faster)", "normal", "⚡ Scan intensity") : ""}
        ${hasProfile ? (() => {
          const profileDef = configCache.tool_profiles[tool.name];
          const currentValue = (configCache.current_tool_profiles || {})[tool.name] || profileDef.default;
          const currentLabel = (profileDef.options.find(o => o.value === currentValue) || {}).label || currentValue;
          return statusRow(currentValue !== profileDef.default, escapeHtml(currentLabel), escapeHtml(currentLabel), "Profile");
        })() : ""}
        ${tool.is_cli ? statusRow(!!activeVariant, escapeHtml(activeVariant ? activeVariant.label : ""), "none", "Bespoke variant") : ""}
        ${!aggressiveCapable && !hasProfile && !wordlistCapable && !tool.is_cli ? `<div class="hint">This is an HTTP-based source — nothing to customize, it always runs the request shown above.</div>` : ""}
      </div>
      ${tool.is_cli && tabs.includes("variants") ? `<div class="hint" style="margin-top:10px;">Switch to the <b>Variants</b> tab for bespoke command variants.</div>` : ""}
    `;

    // Wordlist picker — shown right here on the Command tab (not buried a
    // click away under Variants) since this is the thing people go
    // looking for immediately after opening a tool. It used to live only
    // under Variants, which for a tool like nmap meant nothing about
    // wordlists showed up anywhere at all — nmap scans by port count
    // (--top-ports), not a wordlist, so it was never going to have this
    // section, but the modal said nothing about *why*, which reads
    // exactly like a missing feature rather than "not applicable here".
    if (wordlistCapable) {
      html += buildWordlistSectionHtml(tool, wordlists, assignedWordlistId, activeWl);
    } else if (tool.is_cli) {
      html += `
        <div class="settings-section-title">Wordlist</div>
        <div class="hint" style="margin-bottom:14px;">
          ${escapeHtml(tool.name)} doesn't take a wordlist — it doesn't do subdomain brute-forcing
          or path fuzzing, so there's nothing here to pick one for. Wordlists only apply to
          <b>amass</b>, <b>dnsx</b>, <b>ffuf</b>, and <b>shuffledns</b> — open one of those instead.
        </div>
      `;
    }
  }

  if (toolModalActiveSubTab === "variants" && tool.is_cli) {
    if (aggressiveCapable) {
      html += `
        <div class="settings-section-title">Scan intensity</div>
        <div class="tool-row" style="margin-bottom:14px;">
          <div>
            <div class="tname">⚡ Aggressive mode</div>
            <div class="tmeta">
              ${tool.name === "nmap"
                ? "Off: <code>-T4 -sV -sC</code> (current default). On: <code>-T5 -A</code> — nmap's own \"aggressive\" flag (OS detection, version, scripts, traceroute) at its fastest, loudest timing."
                : "Off: top 100 ports (current default). On: top 1000 ports at a much higher packet rate — faster and far more visible to any IDS/IPS watching."}
            </div>
          </div>
          <label class="switch">
            <input type="checkbox" ${isAggressive ? "checked" : ""} onchange="setToolIntensity('${tool.name}', this.checked)">
            <span class="slider"></span>
          </label>
        </div>
        ${isAggressive ? `<div class="hint" style="color:var(--amber); margin-bottom:14px;">⚡ Aggressive mode is ON — this tool will run louder and faster than its normal default on the next scan.</div>` : ""}
      `;
    }

    if (hasProfile) {
      const profileDef = configCache.tool_profiles[tool.name];
      const currentValue = (configCache.current_tool_profiles || {})[tool.name] || profileDef.default;
      html += `
        <div class="settings-section-title">Profile</div>
        <div style="margin-bottom:14px;">
          ${profileDef.options.map(opt => `
            <label class="tool-row" style="cursor:pointer; align-items:flex-start; margin-bottom:6px;">
              <input type="radio" name="profile-${tool.name}" value="${escapeHtml(opt.value)}"
                     ${opt.value === currentValue ? "checked" : ""}
                     style="margin-top:3px;"
                     onchange="setToolProfile('${tool.name}', this.value)">
              <div style="margin-left:8px;">
                <div class="tname">${escapeHtml(opt.label)}</div>
                <div class="tmeta">${escapeHtml(opt.description)}</div>
              </div>
            </label>
          `).join("")}
        </div>
      `;
    }

    html += activeVariant ? `
      <div class="hint" style="color:var(--green); margin-bottom:14px;">
        ✓ Active: "${escapeHtml(activeVariant.label)}" adds <code>${escapeHtml(activeVariant.extra_args)}</code>
        (${activeVariant.mode === "both" ? "both modes" : activeVariant.mode + " mode only"})
      </div>
    ` : `
      <div class="hint" style="margin-bottom:14px;">No variant active — the base command runs as-is (plus any wordlist/aggressive-mode change made on the Command tab).</div>
    `;

    html += `<div class="settings-section-title">Your bespoke command variants</div>`;
    html += `<div id="toolVariantsList">${renderVariantsList(variants)}</div>`;

    html += `
      <div class="form-grid" style="margin-top:10px;">
        <div class="field full-span">
          <label>Variant name</label>
          <input id="tvLabel" type="text" placeholder="e.g. Rate limited, Aggressive, Stealthy">
        </div>
        <div class="field full-span">
          <label>Applies to</label>
          <select id="tvMode">
            <option value="both">Both modes</option>
            <option value="fast">Fast only</option>
            <option value="full">Full only</option>
          </select>
        </div>
      </div>
    `;

    if (hasCheatsheet) {
      html += `
        <div class="field full-span" style="margin-top:10px;">
          <label>Common arguments — check to add, uncheck to remove</label>
          <div class="arg-checklist">
            ${tool.cheatsheet.map(pair => `
              <label class="arg-check-row">
                <input type="checkbox" class="arg-checkbox" data-flag="${escapeHtml(pair[0])}" onchange="onArgCheckboxToggle(this)">
                <span class="arg-flag">${escapeHtml(pair[0])}</span>
                <span class="arg-desc">${escapeHtml(pair[1])}</span>
              </label>
            `).join("")}
          </div>
        </div>
      `;
    }

    html += `
      <div class="form-grid" style="margin-top:10px;">
        <div class="field full-span">
          <label>Extra arguments <span style="text-transform:none; letter-spacing:0; color:var(--text-dim);">— composed from checkboxes above, or type your own</span></label>
          <input id="tvArgs" type="text" placeholder="e.g. -rate-limit 5">
        </div>
        <div class="full-span">
          <button class="btn-sm" onclick="addToolVariant()">Add variant</button>
          <div class="hint" id="tvError" style="display:none; color:var(--red); margin-top:8px;"></div>
        </div>
      </div>
      <div class="hint">
        Extra args are appended after the base command — they can't remove or replace anything in it,
        so a variant can't accidentally break how results get parsed. Some checkboxes insert a
        placeholder like <code>N</code> (e.g. <code>-rate-limit N</code>) — swap it for a real value
        before adding the variant. Whichever variant is active runs automatically next time you hit
        Run scan in a matching mode.
      </div>
    `;
  }

  if (toolModalActiveSubTab === "cheatsheet" && hasCheatsheet) {
    html += `
      <div class="settings-section-title" style="margin-top:12px;">Cheat sheet</div>
      <div class="table-wrap" style="max-height:400px;">
        <table class="cheatsheet-table">
          <tbody>
            ${tool.cheatsheet.map(pair => `<tr><td>${escapeHtml(pair[0])}</td><td>${escapeHtml(pair[1])}</td></tr>`).join("")}
          </tbody>
        </table>
      </div>
    `;
  }

  el("toolCommandBody").innerHTML = html;
}


function onArgCheckboxToggle(checkbox) {
  const flag = checkbox.dataset.flag;
  const argsInput = el("tvArgs");
  let current = argsInput.value.trim();
  if (checkbox.checked) {
    if (!current.includes(flag)) {
      current = (current + " " + flag).trim();
    }
  } else {
    current = current.split(flag).join("").replace(/\s+/g, " ").trim();
  }
  argsInput.value = current;
}

function renderVariantsList(variants) {
  if (!variants.length) return `<div class="hint">No custom variants yet — add one below.</div>`;
  return variants.map(v => `
    <div class="tool-row">
      <div>
        <div class="tname">${escapeHtml(v.label)} <span class="badge info">${v.mode}</span></div>
        <div class="tmeta" style="color:var(--cyan);">${escapeHtml(v.extra_args)}</div>
      </div>
      <div style="display:flex; align-items:center; gap:10px;">
        <label class="switch">
          <input type="checkbox" ${v.active ? "checked" : ""} onchange="toggleToolVariantActive(${v.id}, this.checked)">
          <span class="slider"></span>
        </label>
        <button class="btn-sm danger" onclick="deleteToolVariant(${v.id})">Remove</button>
      </div>
    </div>
  `).join("");
}

async function addToolVariant() {
  const label = el("tvLabel").value.trim();
  const modeSel = el("tvMode").value;
  const extra_args = el("tvArgs").value.trim();
  const errEl = el("tvError");
  errEl.style.display = "none";
  if (!label || !extra_args) return;
  const res = await fetch("/api/config/tool_variants", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tool_name: currentToolModalName, mode: modeSel, label, extra_args })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    errEl.textContent = err.error || "Failed to add variant.";
    errEl.style.display = "block";
    return;
  }
  el("tvLabel").value = ""; el("tvArgs").value = "";
  await loadConfig();
}

async function toggleToolVariantActive(variantId, activate) {
  await fetch(`/api/config/tool_variants/${variantId}/${activate ? "activate" : "deactivate"}`, { method: "PUT" });
  await loadConfig();
}

async function deleteToolVariant(variantId) {
  await fetch(`/api/config/tool_variants/${variantId}`, { method: "DELETE" });
  await loadConfig();
}

// ---------------------------------------------------------------------------
// Theme — dark (default) / light, persisted client-side. This is a real
// standalone app served from the user's own machine, not a sandboxed
// Claude Artifact, so localStorage is the right tool here.
// ---------------------------------------------------------------------------
