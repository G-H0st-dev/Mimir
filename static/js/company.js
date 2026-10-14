// Company profile + Vulnerability module trigger UI. Depends on core.js
// (loaded first) for shared state and utilities.

async function loadCompanyView(scanId) {
  // Only the profile body gets replaced here — the Live output panel
  // above it (in index.html's static markup) is a stable element this
  // doesn't touch, so a scan running in the background via
  // attachModuleWs/runCompanyScan keeps streaming into it undisturbed
  // even while someone switches which scan's profile they're looking at.
  el("companyProfileBody").innerHTML = `<div class="empty" style="padding:60px 20px;">Loading…</div>`;
  const res = await fetch(`/api/scans/${scanId}`);
  const data = await res.json();
  if (!data.scan) {
    el("companyProfileBody").innerHTML = `<div class="empty" style="padding:60px 20px;">Scan not found.</div>`;
    return;
  }
  el("companyProfileBody").innerHTML = `<div class="panel" style="padding:18px 20px;">${buildCompanyProfileHtml(data)}</div>`;
  el("companyScanLabel").textContent = `— ${data.scan.domain}`;
  renderAiAnalysisTrigger(scanId);
}

// The AI analysis trigger's enabled/disabled state depends on whether
// the feature is configured at all (see Settings → AI analysis) — a
// dynamic, config-driven state, not a static button, so it's rendered
// into its own placeholder rather than hardcoded in the page markup.
function renderAiAnalysisTrigger(scanId) {
  const target = el("aiAnalysisTrigger");
  if (!target || !configCache) return;
  if (!configCache.ai_config.configured) {
    target.innerHTML = `<div class="hint">AI analysis not configured — see Settings → AI analysis. Entirely optional; everything else works without it.</div>`;
    return;
  }
  target.innerHTML = `
    <button class="btn-sm" id="aiAnalysisRunBtn" style="width:100%;" onclick="runAiAnalysis(${scanId})">Generate AI analysis</button>
    <div class="hint" id="aiAnalysisHint" style="margin-top:6px;">Uses ${escapeHtml(configCache.ai_config.model)} to reason over this scan's own findings — a narrative write-up, not new verified data.</div>
  `;
}

async function runAiAnalysis(scanId) {
  const btn = el("aiAnalysisRunBtn");
  const hint = el("aiAnalysisHint");
  btn.disabled = true;
  const originalLabel = btn.textContent;
  btn.textContent = "Generating… (can take a while, especially on local hardware)";
  hint.style.color = "var(--text-dim)";
  hint.textContent = "Waiting for a response from the model…";
  try {
    const res = await fetch(`/api/scans/${scanId}/ai-analysis/run`, { method: "POST" });
    const result = await res.json();
    if (!res.ok || !result.ok) {
      hint.style.color = "var(--red)";
      hint.textContent = result.error || "Generation failed.";
    } else {
      hint.style.color = "var(--green)";
      hint.textContent = "Done.";
      await loadCompanyView(scanId);
    }
  } catch (e) {
    hint.style.color = "var(--red)";
    hint.textContent = "Request failed — check your connection and try again.";
  } finally {
    if (btn) { btn.textContent = originalLabel; btn.disabled = false; }
  }
}

async function runManualCompanyLookup(scanId) {
  const input = el("companyLookupInput");
  const statusEl = el("companyLookupStatus");
  const name = input.value.trim();
  if (!name) return;

  statusEl.textContent = `Looking up "${name}"…`;
  statusEl.style.color = "var(--text-dim)";
  try {
    const res = await fetch(`/api/scans/${scanId}/company_lookup`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ company_name: name }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      statusEl.textContent = "❌ " + (data.error || "Lookup failed.");
      statusEl.style.color = "var(--red)";
      return;
    }
    // Reload the profile so the (possibly updated) confirmed data shows.
    // If the supplied name's entity didn't validate against this domain,
    // nothing changes — that's the same "don't guess" behavior as the
    // automatic lookup, not a failure of this request specifically.
    await loadCompanyView(scanId);
    const freshStatus = el("companyLookupStatus");
    if (freshStatus) {
      freshStatus.textContent = `Looked up "${name}" — see Company information above if it validated against this domain.`;
      freshStatus.style.color = "var(--green)";
    }
  } catch (e) {
    statusEl.textContent = "❌ Request error.";
    statusEl.style.color = "var(--red)";
  }
}

async function runAddKnownEmails(scanId) {
  const input = el("knownEmailsInput");
  const statusEl = el("knownEmailsStatus");
  const raw = input.value.trim();
  if (!raw) return;
  const emails = raw.split(/[,\s]+/).map(s => s.trim()).filter(Boolean);

  statusEl.textContent = `Checking ${emails.length} email${emails.length === 1 ? "" : "s"}…`;
  statusEl.style.color = "var(--text-dim)";
  try {
    const res = await fetch(`/api/scans/${scanId}/known-emails`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ emails }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      statusEl.textContent = "❌ " + (data.error || "Failed to add emails.");
      statusEl.style.color = "var(--red)";
      return;
    }
    const bits = [`${data.accepted.length} accepted`];
    if (data.rejected && data.rejected.length) {
      bits.push(`${data.rejected.length} rejected (not on this domain): ${data.rejected.join(", ")}`);
    }
    if (data.pattern_label) {
      bits.push(`naming pattern confirmed: ${data.pattern_label}`);
      bits.push(data.guessed && data.guessed.length
        ? `${data.guessed.length} other employee email(s) guessed`
        : `no other employees to apply it to yet`);
    } else if (data.accepted.length) {
      bits.push(`no naming pattern could be confirmed from this against known employees`);
    }
    await loadCompanyView(scanId);
    const freshStatus = el("knownEmailsStatus");
    if (freshStatus) {
      freshStatus.textContent = bits.join(" — ");
      freshStatus.style.color = data.accepted.length ? "var(--green)" : "var(--red)";
    }
    if (data.accepted.length) input.value = "";
  } catch (e) {
    statusEl.textContent = "❌ Request error.";
    statusEl.style.color = "var(--red)";
  }
}

// --- host_intel helpers -----------------------------------------------------
// host_intel rows are generic (host, source, field, value) tuples — these
// three helpers are how the profile/report code pulls specific facts back
// out without every call site re-writing the same find/filter.
function buildCompanyProfileHtml(data) {
  const intel = data.host_intel || [];
  const subs = data.subdomains || [];
  const assets = data.http_assets || [];
  const ports = data.ports || [];
  const emails = data.emails || [];
  const leaks = data.leaks || [];
  let foundAnyIntel = false;

  if (data.scan.status === "running") {
    return `<div class="empty">This scan is still running — intel gathered so far may be incomplete. Close this and check back once it finishes.</div>` +
      buildProfileStats(subs, assets, ports, emails, new Set());
  }

  // whois registrant_org deliberately not displayed on this profile —
  // it's frequently the registrar/reseller/privacy-protection service
  // rather than the actual company (common for domains registered
  // through an ISP on the client's behalf), so showing it risked being
  // read as "the company's organization" when it usually wasn't. Still
  // used on the backend as one of several name-guessing signals in
  // get_company_name_candidates — this only removes the misleading
  // direct display.
  const whoisCountry = intelBy(intel, "whois", "registrant_country");
  const registrar = intelBy(intel, "whois", "registrar");
  const created = intelBy(intel, "whois", "created");

  const hostingOrgs = new Set([...intelSetBy(intel, "ip-geo", "org"), ...intelSetBy(intel, "shodan", "org")]);
  const isps = new Set([...intelSetBy(intel, "ip-geo", "isp"), ...intelSetBy(intel, "shodan", "isp")]);
  const cities = intelSetBy(intel, "ip-geo", "city");
  const countries = new Set([...intelSetBy(intel, "ip-geo", "country"), ...intelSetBy(intel, "shodan", "country_name")]);
  const certIssuers = intelBy(intel, "crtsh", "cert_issuers");
  // Shodan-specific fields with no ip-geo equivalent — captured by
  // shodan_enrich_hosts but never actually surfaced anywhere in this
  // profile until now.
  const asns = intelSetBy(intel, "shodan", "asn");
  const detectedOS = intelSetBy(intel, "shodan", "os");
  // InternetDB (Shodan's free, keyless dataset) and LeakIX both store
  // more than what feeds into the vulnerabilities/leaks tables — CPEs
  // (precise software/version fingerprints), Shodan's own risk/
  // categorization tags (e.g. "self-signed", "cloud", "honeypot"), and
  // LeakIX's exposed-service summaries all had zero dedicated display
  // anywhere, only visible buried in the raw Intel tab, until now.
  const internetdbCpes = new Set(
    intel.filter(i => i.source === "internetdb" && i.field === "cpes")
      .flatMap(i => i.value.split(",").map(v => v.trim()).filter(Boolean))
  );
  const internetdbTags = new Set(
    intel.filter(i => i.source === "internetdb" && i.field === "tags")
      .flatMap(i => i.value.split(",").map(v => v.trim()).filter(Boolean))
  );
  const leakixServices = new Set(
    intel.filter(i => i.source === "leakix" && i.field === "services")
      .flatMap(i => i.value.split(",").map(v => v.trim()).filter(Boolean))
  );
  // Shodan's own reverse-DNS for each scanned IP — this can reveal
  // OTHER hostnames pointing at the same infrastructure that this
  // scan's own subdomain enumeration (subfinder/amass/etc.) never
  // found. Genuinely new attack surface, not just enrichment of
  // something already known, so it gets its own dedicated section
  // below rather than folding into the hosting summary. Filtered
  // against this scan's own discovered hosts — otherwise "other
  // hostnames" would just list ones already sitting in the Hosts tab,
  // which defeats the point of calling them out separately.
  const knownHosts = new Set(subs.map(s => s.subdomain.toLowerCase()));
  const shodanHostnames = new Set(
    intel.filter(i => i.source === "shodan" && i.field === "hostnames")
      .flatMap(i => i.value.split(",").map(h => h.trim().toLowerCase()).filter(Boolean))
      .filter(h => !knownHosts.has(h))
  );

  const social = {};
  ["linkedin", "twitter", "github", "facebook", "instagram", "youtube"].forEach(p => {
    const v = intelBy(intel, "social", p);
    if (v) social[p] = v;
  });
  const siteName = intelBy(intel, "social", "site_name") || intelBy(intel, "social", "page_title");
  const description = intelBy(intel, "social", "description");

  // Additional pages the homepage's own navigation links to (About,
  // Pricing, Privacy, Terms, Contact) — discovered and read the way a
  // human analyst would review a company's public site, not guessed.
  // Only the page's own declared title/description is shown, plus any
  // named compliance framework its Privacy/Terms page directly states
  // (a real, citable textual mention, not an inference about actual
  // compliance posture).
  const PAGE_CATEGORY_LABELS = { about: "About", pricing: "Pricing", privacy: "Privacy", terms: "Terms", contact: "Contact", team: "Team" };
  const additionalPages = Object.keys(PAGE_CATEGORY_LABELS)
    .map(category => {
      const url = intelBy(intel, "social", `page:${category}:url`);
      if (!url) return null;
      return {
        category,
        label: PAGE_CATEGORY_LABELS[category],
        url,
        title: intelBy(intel, "social", `page:${category}:title`),
        description: intelBy(intel, "social", `page:${category}:description`),
        complianceMentions: intelBy(intel, "social", `page:${category}:compliance_mentions`),
      };
    })
    .filter(Boolean);

  // Emails found this way already land in the Emails tab (same table
  // theHarvester/CrossLinked/recon-ng use, source="social-scan") — no
  // separate display needed here for those. Phone numbers and possible
  // staff names don't have an existing home, so they get one below.
  const scrapedPhones = intel
    .filter(i => i.source === "social" && i.field.startsWith("phone:"))
    .map(i => i.value);
  const scrapedStaffNames = intel
    .filter(i => i.source === "social" && i.field.startsWith("possible_staff_name:"))
    .map(i => i.value);

  // Public company record — Wikidata, only ever populated when the
  // entity's own official-website claim matched the scanned domain. See
  // company_lookup() server-side; nothing here is a guess.
  const companyFounded = intelBy(intel, "company", "founded");
  const companyEmployees = intelBy(intel, "company", "employees");
  const companyHQ = intelBy(intel, "company", "headquarters");
  const companyCountry = intelBy(intel, "company", "country");
  const companyIndustry = intelBy(intel, "company", "industry");
  const companyLegalForm = intelBy(intel, "company", "legal_form");
  const companyStreet = intelBy(intel, "company", "street_address");
  const companyWikipedia = intelBy(intel, "company", "wikipedia");
  const companyWriteup = intelBy(intel, "company", "writeup");
  const writeupConfidence = intelBy(intel, "company", "writeup_confidence"); // "confirmed" | "name_matched" | "unverified"
  const writeupSource = intelBy(intel, "company", "writeup_source");
  // Separate from writeupConfidence: the writeup only exists when a
  // Wikipedia extract was available, but the structured facts below
  // (industry, HQ, employees, etc.) can exist without one — this stays
  // set whenever any Wikidata-sourced fact was stored, confirmed or not.
  const wikidataMatchConfidence = intelBy(intel, "company", "wikidata_match_confidence"); // "confirmed" | "name_matched"
  const headquartersLine = companyHQ ? [companyHQ, companyCountry].filter(Boolean).join(", ") : null;

  // Parent organization — only populated when the confirmed entity's own
  // Wikidata record lists an "owned by" or "parent organization" claim.
  // This is the "X is now part of Y" signal a single-entity lookup used
  // to miss entirely — a rebranded/acquired company's old brand often
  // doesn't even have its own current Wikidata entity, but its current
  // owner does, complete with its own headquarters/industry.
  const parentOrg = intelBy(intel, "company", "parent_organization");
  const parentHQ = intelBy(intel, "company", "parent_headquarters");
  const parentCountry = intelBy(intel, "company", "parent_country");
  const parentIndustry = intelBy(intel, "company", "parent_industry");
  const parentWikipedia = intelBy(intel, "company", "parent_wikipedia");
  const parentWriteup = intelBy(intel, "company", "parent_writeup");
  const parentHQLine = parentHQ ? [parentHQ, parentCountry].filter(Boolean).join(", ") : null;

  // TLD variants — other common TLDs of the same base name that were
  // found to actually resolve (e.g. scanning sensepost.com also finding
  // sensepost.co.za live). Real, related infrastructure this app would
  // otherwise never surface, or a lookalike domain worth flagging.
  const tldVariants = intel
    .filter(i => i.source === "company" && i.field.startsWith("tld_variant:"))
    .map(i => i.value);

  // Recent press mentions — each stored as a JSON-encoded value (title/
  // url/source/date), not a plain string like most other intel fields,
  // since a pipe-delimited or similar plain format would break the
  // moment an article title happened to contain that delimiter. Parsed
  // defensively since a malformed row shouldn't take down the whole
  // profile view.
  const newsArticles = intel
    .filter(i => i.source === "news" && i.field.startsWith("article:"))
    .map(i => { try { return JSON.parse(i.value); } catch (e) { return null; } })
    .filter(Boolean)
    .sort((a, b) => (b.date || "").localeCompare(a.date || ""));

  // "Main domain" — real, verifiable signals only: an actual HTTP redirect
  // (httpx followed it), or a canonical/og:url tag the page itself
  // declares. Priority roughly follows how authoritative each signal is.
  const redirectsTo = intelBy(intel, "httpx", "redirects_to");
  const canonicalUrl = intelBy(intel, "social", "canonical_url");
  const ogUrl = intelBy(intel, "social", "og_url");
  let primarySignal = null, primarySource = "";
  if (redirectsTo) { primarySignal = redirectsTo; primarySource = "HTTP redirect"; }
  else if (canonicalUrl) { primarySignal = canonicalUrl; primarySource = "canonical link tag"; }
  else if (ogUrl) { primarySignal = ogUrl; primarySource = "og:url tag"; }

  // Two distinct locations, never conflated: where the server actually
  // sits (hosting, from IP geolocation) vs. the company's real HQ (only
  // shown when confirmed via the public record above).
  const hostingLocation = modeOf(ipGeoLocations(intel)) || (whoisCountry && !headquartersLine ? `${whoisCountry} (registrant)` : null);

  const vulnerabilities = data.vulnerabilities || [];

  const parts = [];

  parts.push(`
    <div class="profile-hero">
      <div class="profile-hero-name">${escapeHtml(siteName || data.scan.domain)}</div>
      ${description ? `<div class="profile-hero-desc">${escapeHtml(description)}</div>` : ""}
      ${(primarySignal || headquartersLine || hostingLocation) ? `
        <div class="profile-hero-facts">
          ${primarySignal ? `<div class="profile-fact">🔗 <b>Main domain:</b> <a href="${escapeHtml(primarySignal)}" target="_blank" rel="noopener">${escapeHtml(extractHost(primarySignal))}</a> <span style="color:var(--text-dim); font-size:10.5px;">via ${primarySource}</span></div>` : ""}
          ${headquartersLine ? `<div class="profile-fact">🏢 <b>Headquarters:</b> ${escapeHtml(headquartersLine)} <span style="color:var(--text-dim); font-size:10.5px;">confirmed public record</span></div>` : ""}
          ${hostingLocation ? `<div class="profile-fact">🖥️ <b>Hosting location:</b> ${escapeHtml(hostingLocation)} <span style="color:var(--text-dim); font-size:10.5px;">${headquartersLine ? "server location — may differ from HQ" : "from server IP; no confirmed company HQ found"}</span></div>` : ""}
        </div>
      ` : ""}
    </div>
  `);

  // Executive summary — deliberately computed, not narrative-generated:
  // every value here traces directly to counted findings already in
  // this profile (vulnerabilities/leaks/data completeness), never
  // inferred business judgment. This is NOT equivalent to an
  // externally-informed risk assessment — it's an honest summary of
  // what this scan itself found, labeled as such.
  {
    const kevCount = vulnerabilities.filter(v => v.is_kev).length;
    const criticalCount = vulnerabilities.filter(v => (v.severity || "").toLowerCase() === "critical").length;
    const highCount = vulnerabilities.filter(v => (v.severity || "").toLowerCase() === "high").length;
    const execEmployeeCount = intel.filter(i => i.source === "crosslinked" && i.field.startsWith("employee:")).length;

    let exposure, exposureColor, exposureDetail;
    // Confirmed as a real bug, not just missing data: checking only
    // vulnerability_scanned_at meant a scan with real findings — including
    // a critical one — could still show "Not yet assessed" here, because
    // Full-mode scans already run nuclei/ffuf as part of the main
    // pipeline, independent of whether the separate Vulnerability module
    // was ever triggered. vulnerabilities.length is the actual signal;
    // the timestamp only tells us whether the *dedicated, revalidated*
    // pass has also happened.
    if (!vulnerabilities.length && !leaks.length && !data.scan.vulnerability_scanned_at) {
      exposure = "Not yet assessed"; exposureColor = "var(--text-dim)";
      exposureDetail = "The Vulnerability module hasn't been run for this scan yet.";
    } else if (kevCount || criticalCount || leaks.length) {
      exposure = "High"; exposureColor = "var(--red)";
      const reasons = [];
      if (kevCount) reasons.push(`${kevCount} confirmed actively-exploited (CISA KEV)`);
      if (criticalCount) reasons.push(`${criticalCount} critical-severity finding(s)`);
      if (leaks.length) reasons.push(`${leaks.length} breach/leak finding(s)`);
      exposureDetail = reasons.join(", ") + ".";
    } else if (highCount) {
      exposure = "Medium"; exposureColor = "var(--amber)";
      exposureDetail = `${highCount} high-severity finding(s); no confirmed-exploited or critical findings.`;
    } else if (vulnerabilities.length) {
      exposure = "Low"; exposureColor = "var(--green)";
      exposureDetail = `${vulnerabilities.length} lower-severity finding(s) only.`;
    } else {
      exposure = "Low"; exposureColor = "var(--green)";
      exposureDetail = "No vulnerabilities or breach exposure found in this scan.";
    }
    // Provenance note — only relevant when findings exist but the
    // dedicated module never ran: these came from the main scan's own
    // nuclei/ffuf pass, not a revalidated, targeted one.
    if (vulnerabilities.length && !data.scan.vulnerability_scanned_at) {
      exposureDetail += " (from the main scan's own findings — the Vulnerability module hasn't done its own revalidated pass yet.)";
    }

    let riskTheme;
    if (leaks.length) riskTheme = "Data exposure";
    else if (kevCount || criticalCount) riskTheme = "Exploitable infrastructure";
    else if (vulnerabilities.length) riskTheme = "Infrastructure hygiene";
    else riskTheme = "None identified";

    let evidenceConfidence, evidenceDetail;
    if (writeupConfidence === "confirmed" && data.scan.company_scanned_at && data.scan.vulnerability_scanned_at) {
      evidenceConfidence = "High";
      evidenceDetail = "Company and Vulnerability modules both run; public-record match confirmed.";
    } else if (data.scan.company_scanned_at || data.scan.vulnerability_scanned_at) {
      evidenceConfidence = "Medium";
      evidenceDetail = "Partial data gathered — see individual sections for what's confirmed vs. inferred.";
    } else {
      evidenceConfidence = "Low";
      evidenceDetail = "Neither the Company nor Vulnerability module has been run for this scan yet.";
    }

    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Executive summary
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— computed from this scan's own findings, not external threat intelligence</span>
        </div>
        <div class="exec-summary-grid">
          <div class="exec-summary-metric">
            <div class="exec-summary-metric-label">Overall exposure</div>
            <div class="exec-summary-metric-value" style="color:${exposureColor};">${exposure}</div>
            <div class="exec-summary-metric-detail">${escapeHtml(exposureDetail)}</div>
          </div>
          <div class="exec-summary-metric">
            <div class="exec-summary-metric-label">Primary risk theme</div>
            <div class="exec-summary-metric-value">${escapeHtml(riskTheme)}</div>
            <div class="exec-summary-metric-detail">Based on which finding type dominates this scan.</div>
          </div>
          <div class="exec-summary-metric">
            <div class="exec-summary-metric-label">Evidence confidence</div>
            <div class="exec-summary-metric-value">${evidenceConfidence}</div>
            <div class="exec-summary-metric-detail">${escapeHtml(evidenceDetail)}</div>
          </div>
          ${execEmployeeCount ? `
          <div class="exec-summary-metric">
            <div class="exec-summary-metric-label">Employees found</div>
            <div class="exec-summary-metric-value">${execEmployeeCount}</div>
            <div class="exec-summary-metric-detail">Via CrossLinked — see Employees below.</div>
          </div>` : ""}
        </div>
      </div>
    `);
  }

  // AI-generated narrative analysis — entirely optional, only present
  // if explicitly generated via the button in the sidebar. Visually
  // distinct on purpose (dashed border, explicit banner) so it can
  // never be mistaken for the rest of this profile's sourced, verified
  // findings — this is reasoning *about* that data, not new fact.
  {
    const aiNarrative = intelBy(intel, "ai_analysis", "narrative");
    if (aiNarrative) {
      foundAnyIntel = true;
      const aiModel = intelBy(intel, "ai_analysis", "model");
      const aiGeneratedAt = intelBy(intel, "ai_analysis", "generated_at");
      parts.push(`
        <div class="profile-section" style="border-style:dashed; border-color:var(--amber);">
          <div class="profile-section-title" style="color:var(--amber);">
            🤖 AI-generated analysis
          </div>
          <div class="hint" style="margin-bottom:10px;">
            Generated by ${escapeHtml(aiModel || "an LLM")}${aiGeneratedAt ? ` on ${escapeHtml(aiGeneratedAt.split("T")[0])}` : ""} —
            reasoning about this scan's own findings above, not independently verified data.
            Treat it as a starting point for your own judgment, not a source to cite.
          </div>
          <div style="white-space:pre-wrap; font-size:12.5px; line-height:1.6;">${escapeHtml(aiNarrative)}</div>
        </div>
      `);
    }
  }

  // Breach/leak exposure — deliberately placed right after the hero,
  // ahead of everything else. This module already runs LeakIX and
  // XposedOrNot as part of the same trigger that builds the rest of
  // this profile, but the results previously never reached this view at
  // all — only the separate, unrelated Leaks report tab. "Has this
  // organization been breached" is about as direct a risk signal as a
  // company profile can carry, so it doesn't belong buried at the
  // bottom or missing entirely.
  if (leaks.length) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section" style="border-color:var(--red);">
        <div class="profile-section-title" style="color:var(--red);">
          ⚠️ Breach / leak exposure
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— ${leaks.length} finding(s) via LeakIX / XposedOrNot</span>
        </div>
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
    `);
  }

  parts.push(buildProfileStats(subs, assets, ports, emails, countries));

  // A domain often doesn't match the company's actual registered name —
  // a rebrand, a product-specific domain, a domain under a corporate
  // parent, and so on. This lets you supply the real name directly
  // rather than relying only on the auto-detected guess (WHOIS org /
  // scraped site name / domain label). It still goes through the exact
  // same official-website validation as the automatic lookup — a name
  // match alone is never enough, so this can't be used to make the
  // profile show a company that isn't actually confirmed to run this
  // domain.
  parts.push(`
    <div class="profile-section">
      <div class="profile-section-title">Look up a different company name</div>
      <div class="hint" style="margin-bottom:8px;">
        If the auto-detected name above is wrong or missing, enter the real company name — it's
        still validated against this domain's official website before anything is shown as confirmed.
      </div>
      <div style="display:flex; gap:8px;">
        <input type="text" id="companyLookupInput" placeholder="e.g. Acme Corporation" style="flex:1;"
               onkeydown="if(event.key==='Enter') runManualCompanyLookup(${data.scan.id})">
        <button class="btn-sm" onclick="runManualCompanyLookup(${data.scan.id})">Look up</button>
      </div>
      <div class="hint" id="companyLookupStatus" style="margin-top:8px;"></div>
    </div>
  `);

  // Feeding in real, already-known emails has two distinct payoffs: they
  // get saved to the Emails tab like any other source, and — if one
  // matches a CrossLinked-found employee's name closely enough — they
  // confirm the org's actual naming convention, which then gets applied
  // to every other employee found with no known address (unverified
  // guesses, clearly tagged, never shown as confirmed).
  parts.push(`
    <div class="profile-section">
      <div class="profile-section-title">Known email address(es)</div>
      <div class="hint" style="margin-bottom:8px;">
        Already have one or two real emails for this org (from a past engagement, a contact)?
        Add them here — they're saved to the Emails tab, and if one matches a naming pattern
        against an employee CrossLinked already found (e.g. jane.doe@ matching "Jane Doe"), that
        pattern gets applied to every other employee found here too, producing unverified guessed
        addresses for the rest.
      </div>
      <div style="display:flex; gap:8px;">
        <input type="text" id="knownEmailsInput" placeholder="jane.doe@company.com, john.smith@company.com"
               style="flex:1;" onkeydown="if(event.key==='Enter') runAddKnownEmails(${data.scan.id})">
        <button class="btn-sm" onclick="runAddKnownEmails(${data.scan.id})">Add &amp; enrich</button>
      </div>
      <div class="hint" id="knownEmailsStatus" style="margin-top:8px;"></div>
    </div>
  `);

  // The write-up itself — prose, not a fact table, so it goes first among
  // the detail sections. Confidence is shown explicitly rather than
  // silently treating a confirmed (Wikidata official-website match),
  // name-matched (Wikidata by name only, domain not confirmed — e.g. a
  // subsidiary whose parent's Wikidata entry lists a different flagship
  // domain), and unverified (plain web search) write-up the same way.
  if (companyWriteup) {
    foundAnyIntel = true;
    const writeupBadge = {
      confirmed: { color: "var(--green)", text: "— from the confirmed Wikipedia article" },
      name_matched: { color: "var(--amber)", text: "— from Wikipedia, matched by company name only — domain not confirmed" },
      from_own_site: { color: "var(--amber)", text: "— from the company's own About page, not an independent source" },
      unverified: { color: "var(--amber)", text: "— from a web search, name match only, not verified against the domain" },
    }[writeupConfidence] || { color: "var(--amber)", text: "— from a web search, name match only, not verified against the domain" };
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Company write-up
          <span style="text-transform:none; letter-spacing:0; font-size:10px; color:${writeupBadge.color};">
            ${writeupBadge.text}
          </span>
        </div>
        <div class="profile-writeup">${escapeHtml(companyWriteup)}</div>
        ${writeupSource ? `<div class="hint" style="margin-top:8px;"><a href="${escapeHtml(writeupSource)}" target="_blank" rel="noopener">Source ↗</a></div>` : ""}
      </div>
    `);
  }

  const hasCompanyInfo = companyFounded || companyEmployees || headquartersLine || companyIndustry || companyLegalForm || companyStreet || companyWikipedia;
  if (hasCompanyInfo) {
    foundAnyIntel = true;
    const infoBadge = {
      confirmed: { color: "var(--text-dim)", text: "— public record, confirmed by matching official website" },
      name_matched: { color: "var(--amber)", text: "— public record, matched by company name only — domain not confirmed" },
    }[wikidataMatchConfidence] || { color: "var(--text-dim)", text: "— public record" };
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">Company information <span style="color:${infoBadge.color}; text-transform:none; letter-spacing:0; font-size:10px;">${infoBadge.text}</span></div>
        ${companyFounded ? row("Founded", companyFounded) : ""}
        ${companyEmployees ? row("Employees (est.)", companyEmployees) : ""}
        ${headquartersLine ? row("Headquarters", headquartersLine) : ""}
        ${companyStreet ? row("Street address", companyStreet) : ""}
        ${companyIndustry ? row("Industry", companyIndustry) : ""}
        ${companyLegalForm ? row("Legal form", companyLegalForm) : ""}
        ${companyWikipedia ? `<div class="profile-row"><span>Wikipedia</span><span><a href="${escapeHtml(companyWikipedia)}" target="_blank" rel="noopener">Source ↗</a></span></div>` : ""}
      </div>
    `);
  }

  if (additionalPages.length) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Pages reviewed
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— the company's own site, read directly, not inferred</span>
        </div>
        ${additionalPages.map(p => `
          <div class="profile-row" style="align-items:flex-start;">
            <span style="flex-shrink:0; width:70px;">${escapeHtml(p.label)}</span>
            <span style="text-align:left; flex:1;">
              <a href="${escapeHtml(p.url)}" target="_blank" rel="noopener">${escapeHtml(p.title || p.url)}</a>
              ${p.description ? `<div style="color:var(--text-dim); font-size:11px; margin-top:2px;">${escapeHtml(p.description)}</div>` : ""}
              ${p.complianceMentions ? `<div style="color:var(--amber); font-size:11px; margin-top:2px;">Mentions: ${escapeHtml(p.complianceMentions)}</div>` : ""}
            </span>
          </div>
        `).join("")}
      </div>
    `);
  }

  if (scrapedPhones.length || scrapedStaffNames.length) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Contacts found on site
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— scraped directly from the pages above, not a third-party source</span>
        </div>
        ${scrapedPhones.length ? `
          <div class="profile-row" style="align-items:flex-start;">
            <span style="flex-shrink:0; width:70px;">Phone</span>
            <span style="text-align:left; flex:1;">${scrapedPhones.map(p => escapeHtml(p)).join(", ")}</span>
          </div>
        ` : ""}
        ${scrapedStaffNames.length ? `
          <div class="profile-row" style="align-items:flex-start;">
            <span style="flex-shrink:0; width:70px;">Possible staff</span>
            <span style="text-align:left; flex:1;">
              ${scrapedStaffNames.map(n => escapeHtml(n)).join(", ")}
              <div style="color:var(--amber); font-size:10.5px; margin-top:4px;">
                Heuristic, not verified — a capitalized name-shaped phrase found near a job-title word on the page. Expect some false positives (and some real staff missed); treat as a starting point, not a confirmed staff list.
              </div>
            </span>
          </div>
        ` : ""}
      </div>
    `);
  }

  if (parentOrg) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Parent organization
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— this entity's own public record lists it as owned by / part of another organization</span>
        </div>
        ${row("Name", parentOrg)}
        ${parentHQLine ? row("Headquarters", parentHQLine) : ""}
        ${parentIndustry ? row("Industry", parentIndustry) : ""}
        ${parentWikipedia ? `<div class="profile-row"><span>Wikipedia</span><span><a href="${escapeHtml(parentWikipedia)}" target="_blank" rel="noopener">Source ↗</a></span></div>` : ""}
        ${parentWriteup ? `<div class="profile-writeup" style="margin-top:8px;">${escapeHtml(parentWriteup)}</div>` : ""}
      </div>
    `);
  }

  if (newsArticles.length) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Recent press mentions
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— last ~3 months, via GDELT — an acquisition, funding round, incident, or leadership change may show up here before it shows up anywhere else in this profile</span>
        </div>
        ${newsArticles.map(a => `
          <div class="profile-row" style="align-items:flex-start;">
            <span style="color:var(--text-dim); flex-shrink:0; width:80px;">${escapeHtml(a.date || "")}</span>
            <span style="text-align:left; flex:1;">
              <a href="${escapeHtml(a.url)}" target="_blank" rel="noopener">${escapeHtml(a.title)}</a>
              ${a.source ? `<span style="color:var(--text-dim); font-size:11px;"> — ${escapeHtml(a.source)}</span>` : ""}
              ${a.country ? `<span style="color:var(--text-dim); font-size:11px;"> (${escapeHtml(a.country)})</span>` : ""}
            </span>
          </div>
        `).join("")}
      </div>
    `);
  }

  if (tldVariants.length) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Other TLDs of this domain that resolve
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— related infrastructure, or a lookalike worth checking</span>
        </div>
        ${tldVariants.map(v => `
          <div class="profile-row"><span>${escapeHtml(v)}</span><span><a href="https://${escapeHtml(v)}" target="_blank" rel="noopener">Visit ↗</a></span></div>
        `).join("")}
      </div>
    `);
  }

  if (whoisCountry || registrar || created) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">Registrant (WHOIS)</div>
        ${whoisCountry ? row("Country", whoisCountry) : ""}
        ${registrar ? row("Registrar", registrar) : ""}
        ${created ? row("Registered", created) : ""}
      </div>
    `);
  }

  if (hostingOrgs.size || isps.size || cities.size || countries.size || certIssuers || asns.size || detectedOS.size || internetdbTags.size || internetdbCpes.size || leakixServices.size) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">Hosting / infrastructure</div>
        ${hostingOrgs.size ? row("Org(s)", [...hostingOrgs].join(", ")) : ""}
        ${isps.size ? row("ISP(s)", [...isps].join(", ")) : ""}
        ${asns.size ? row("ASN(s)", [...asns].join(", ")) : ""}
        ${cities.size ? row("Location(s)", [...cities].join(", ")) : ""}
        ${countries.size ? row("Countries", [...countries].join(", ")) : ""}
        ${detectedOS.size ? row("Detected OS", [...detectedOS].join(", ")) : ""}
        ${certIssuers ? row("Cert issuer(s)", certIssuers) : ""}
        ${internetdbTags.size ? row("Shodan tags", [...internetdbTags].join(", ")) : ""}
        ${internetdbCpes.size ? row("Software fingerprints (CPEs)", [...internetdbCpes].join(", ")) : ""}
        ${leakixServices.size ? row("Exposed services (LeakIX)", [...leakixServices].join(", ")) : ""}
      </div>
    `);
  }

  if (shodanHostnames.size) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Other hostnames on this infrastructure
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">— via Shodan's own reverse-DNS, may include hosts this scan's own enumeration didn't find</span>
        </div>
        ${row("Hostname(s)", [...shodanHostnames].sort().join(", "))}
      </div>
    `);
  }

  const whatwebSummary = buildWhatwebSummary(intel);
  if (whatwebSummary) {
    foundAnyIntel = true;
    parts.push(whatwebSummary);
  }

  const socialKeys = Object.keys(social);
  if (socialKeys.length) {
    foundAnyIntel = true;
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">Social presence</div>
        ${socialKeys.map(k => `
          <div class="profile-row">
            <span style="text-transform:capitalize">${k}</span>
            <span><a href="${escapeHtml(social[k])}" target="_blank" rel="noopener">${escapeHtml(social[k])}</a></span>
          </div>
        `).join("")}
      </div>
    `);
  }

  // Employees — CrossLinked's own findings, stored one host_intel row per
  // person (field "employee:<name>", value is their title or "—" if none
  // was found). Capped display here too, matching the storage-side cap,
  // so a company with hundreds of hits doesn't make this section
  // unreadable — the full set is still in the raw Intel tab either way.
  const employeeRows = intel
    .filter(i => i.source === "crosslinked" && i.field.startsWith("employee:"))
    .map(i => {
      const name = i.field.slice("employee:".length);
      const urlRow = intel.find(x => x.source === "crosslinked" && x.field === `employee_url:${name}`);
      return { name, title: i.value, url: urlRow ? urlRow.value : null };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
  if (employeeRows.length) {
    foundAnyIntel = true;
    const shown = employeeRows.slice(0, 100);
    parts.push(`
      <div class="profile-section">
        <div class="profile-section-title">
          Employees found
          <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">
            — ${employeeRows.length} via CrossLinked (Google/Bing search)${employeeRows.length > shown.length ? `, showing first ${shown.length}` : ""}
          </span>
        </div>
        <div class="employee-list">
          ${shown.map(e => `
            <div class="employee-row">
              <span class="employee-name">${escapeHtml(e.name)}</span>
              ${e.title && e.title !== "—" ? `<span class="employee-title">${escapeHtml(e.title)}</span>` : ""}
              ${e.url ? `<a href="${escapeHtml(e.url)}" target="_blank" rel="noopener" class="employee-title" style="color:var(--accent);">LinkedIn ↗</a>` : ""}
              <button class="btn-sm" data-identity="${escapeHtml(e.name)}" style="margin-top:4px; align-self:flex-start;" onclick="runUserScanner(${data.scan.id}, 'username', this.dataset.identity, this, this.nextElementSibling)">🔎 Check accounts</button>
              <div class="user-scanner-result" style="display:none; margin-top:4px; font-size:11px;"></div>
            </div>
          `).join("")}
        </div>
      </div>
    `);
  }

  // A "Vulnerability findings" summary used to live here, duplicating
  // (and, with no live findings to point to during review, functionally
  // masking) what the dedicated Vulnerability tab shows — removed at
  // Greg's request so the Company page sticks to company/OSINT intel and
  // the Vulnerability tab is the one place vuln findings are shown.

  if (!foundAnyIntel) {
    parts.push(`<div class="empty">No WHOIS, hosting, company-record, social, employee, or breach intel was gathered for this scan. Try enabling more OSINT sources (whois, ip-geo, social-scan, company-lookup, crosslinked, LeakIX, XposedOrNot) in Settings, or re-run in Full Stack mode.</div>`);
  }

  return parts.join("");
}

// Groups whatweb's per-host findings into a prevalence summary: for each
// distinct technology, what fraction of whatweb-scanned hosts actually
// run it. Percentage is of *hosts*, not raw finding count — whatweb's
// plugins are a mix of real technologies (Nginx, WordPress) and header/
// cookie observations (HttpOnly, Country), so "hosts running this" is a
// more meaningful denominator than "share of all findings" would be.
// Mirrors app.py's _strip_version_suffix/tech_kb_lookup exactly — kept in
// sync deliberately rather than fetched per-lookup, so expanding a
// technology's detail is instant with no network round-trip. The
// knowledge base itself (configCache.tech_knowledge_base) is static and
// loaded once with the rest of /api/config.
function buildWhatwebSummary(intel) {
  const rows = intel.filter(i => i.source === "whatweb");
  if (!rows.length) return "";

  const byTech = {};
  const hostsSeen = new Set();
  rows.forEach(i => {
    const techName = i.field.replace(/^tech:/, "");
    const prefix = techName + ": ";
    const detail = i.value.startsWith(prefix) ? i.value.slice(prefix.length) : (i.value === techName ? "" : i.value);
    (byTech[techName] = byTech[techName] || []).push({ host: i.host, detail });
    hostsSeen.add(i.host);
  });

  const totalHosts = hostsSeen.size;
  const entries = Object.entries(byTech).map(([name, occurrences]) => {
    const distinctHosts = new Set(occurrences.map(o => o.host)).size;
    const pct = totalHosts > 0 ? Math.round((distinctHosts / totalHosts) * 100) : 0;
    return { name, occurrences, distinctHosts, pct, kb: techKbLookup(name) };
  }).sort((a, b) => b.pct - a.pct || b.distinctHosts - a.distinctHosts || a.name.localeCompare(b.name));

  return `
    <div class="profile-section">
      <div class="profile-section-title">
        Technology stack (whatweb)
        <span style="color:var(--text-dim); text-transform:none; letter-spacing:0; font-size:10px;">
          — ${totalHosts} host${totalHosts === 1 ? "" : "s"} fingerprinted · click a technology to see what it is and what to check
        </span>
      </div>
      <div class="whatweb-tech-list">
        ${entries.map((t, idx) => `
          <div class="whatweb-tech-row" onclick="toggleWhatwebTechDetail(this)">
            <div class="whatweb-tech-bar-wrap">
              <span class="whatweb-tech-name">${escapeHtml(t.name)}${t.kb ? `<span class="tech-kb-badge">${escapeHtml(t.kb.category)}</span>` : ""}</span>
              <span class="whatweb-tech-pct" title="Percentage of fingerprinted hosts running this technology — not a detection-confidence score">on ${t.pct}% of hosts <span style="color:var(--text-dim);">(${t.distinctHosts}/${totalHosts})</span></span>
            </div>
            <div class="whatweb-tech-bar"><div class="whatweb-tech-bar-fill" style="width:${t.pct}%;"></div></div>
            <div class="whatweb-tech-detail" style="display:none;" onclick="event.stopPropagation();">
              ${t.kb ? `
                <div class="tech-kb-panel">
                  <div class="tech-kb-row"><span class="tech-kb-icon">ℹ️</span><span>${escapeHtml(t.kb.description)}</span></div>
                  <div class="tech-kb-row tech-kb-security"><span class="tech-kb-icon">⚠️</span><span>${escapeHtml(t.kb.security_notes)}</span></div>
                </div>
              ` : `
                <div class="tech-kb-panel tech-kb-panel-empty">No specific guidance in this app's knowledge base for "${escapeHtml(t.name)}" yet — that's just a gap in the reference list, not a signal either way.</div>
              `}
              <div class="whatweb-tech-detail-hosts-label">Found on</div>
              ${t.occurrences.map(o => `
                <div class="whatweb-tech-detail-row">
                  <span class="whatweb-tech-detail-host">${escapeHtml(o.host)}</span>
                  <span class="whatweb-tech-detail-value">${escapeHtml(o.detail || "detected")}</span>
                </div>
              `).join("")}
            </div>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

function switchToCompanyView(scanId) {
  switchView("company");
  loadCompanyTab(scanId);
}

// Enables/disables a tab's "Run ... scan" button based on whether the
// currently-selected scan has actually finished — running/stopped/failed
// scans have nothing stable to revalidate against yet (or ever, in the
// failed/stopped case), so the button stays disabled with an explanation
// rather than letting someone trigger a follow-up scan against a scan
// that's still in flux.
function updateRunButtonState(btnId, hintId, scanId) {
  const scan = scansCache.find(s => String(s.id) === String(scanId));
  const btn = el(btnId);
  const hint = el(hintId);
  if (!scan) {
    btn.disabled = true;
    hint.textContent = "";
    return;
  }
  if (scan.status === "completed") {
    btn.disabled = false;
    hint.textContent = "";
    hint.style.color = "var(--text-dim)";
  } else {
    btn.disabled = true;
    hint.style.color = "var(--amber)";
    hint.textContent = scan.status === "running"
      ? "Scan is still running — the button enables once it finishes."
      : `Scan ${scan.status} — nothing completed to run against.`;
  }
}

async function loadCompanyTab(preselectScanId) {
  // Always refreshed, not reused from a cache that might be stale —
  // confirmed directly as a real bug: scansCache only got (re-)fetched
  // here when it was currently empty, so once populated once this
  // session, a newly completed scan from the Scan tab would never show
  // up in this picker no matter how many times this tab was revisited.
  // A GET here is cheap; showing the wrong list of scans isn't worth
  // saving it.
  const res = await fetch("/api/scans");
  scansCache = await res.json();
  const picker = el("companyScanPicker");
  const previousValue = picker.value;
  picker.innerHTML = scansCache.map(s =>
    `<option value="${s.id}">${escapeHtml(s.domain)} — #${s.id} (${new Date(s.started_at).toLocaleDateString()})</option>`
  ).join("");
  if (!scansCache.length) {
    el("companyProfileBody").innerHTML = `<div class="empty" style="padding:60px 20px;">No scans yet — run one from the Scan tab first.</div>`;
    return;
  }
  const target = preselectScanId || previousValue || scansCache[0].id;
  picker.value = target;
  updateRunButtonState("companyRunBtn", "companyRunHint", target);
  await loadCompanyView(target);
}

async function runCompanyScan() {
  const scanId = el("companyScanPicker").value;
  const btn = el("companyRunBtn");
  const hint = el("companyRunHint");
  btn.disabled = true;
  const originalLabel = btn.textContent;
  btn.textContent = "Running…";
  hint.style.color = "var(--text-dim)";
  hint.textContent = "Starting…";
  // The endpoint kicks off a background task and returns immediately —
  // it has to, for a live progress bar to be possible at all, rather
  // than blocking this request for however long the whole run takes.
  // Confirmed directly: the old code here read live_assets_used etc.
  // straight off that immediate response, which doesn't carry them —
  // those only ever existed inside the background task's own (discarded)
  // return value — so it always showed "undefined" and reloaded the
  // profile before any real work had happened. Real completion has to
  // be detected by polling the scan's own company_scan_running flag.
  const socket = attachModuleWs(scanId, "companyLiveOutput", (percent, stage) => {
    hint.style.color = "var(--text-dim)";
    hint.textContent = `${stage} (${percent}%)…`;
  });
  try {
    const res = await fetch(`/api/scans/${scanId}/company/run`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) {
      hint.style.color = "var(--red)";
      hint.textContent = data.error || "Company scan failed to start.";
      return;
    }
    await new Promise((resolve) => {
      const interval = setInterval(async () => {
        const r = await fetch(`/api/scans/${scanId}`);
        const scanData = await r.json();
        if (!scanData.scan || !scanData.scan.company_scan_running) {
          clearInterval(interval);
          resolve();
        }
      }, 1500);
    });
    hint.style.color = "var(--green)";
    hint.textContent = "Done — see the updated profile below.";
    await loadCompanyView(scanId);
  } catch (e) {
    hint.style.color = "var(--red)";
    hint.textContent = "Request failed — check your connection and try again.";
  } finally {
    socket.close();
    btn.textContent = originalLabel;
    btn.disabled = false;
  }
}

async function loadVulnerabilityTab(preselectScanId) {
  // Same fix, same reasoning as loadCompanyTab above — always refresh,
  // never reuse a cache that could be stale.
  const res = await fetch("/api/scans");
  scansCache = await res.json();
  const picker = el("vulnScanPicker");
  const previousValue = picker.value;
  picker.innerHTML = scansCache.map(s =>
    `<option value="${s.id}">${escapeHtml(s.domain)} — #${s.id} (${new Date(s.started_at).toLocaleDateString()})</option>`
  ).join("");
  if (!scansCache.length) {
    el("vulnProfileBody").innerHTML = `<div class="empty" style="padding:60px 20px;">No scans yet — run one from the Scan tab first.</div>`;
    return;
  }
  const target = preselectScanId || previousValue || scansCache[0].id;
  picker.value = target;
  updateRunButtonState("vulnRunBtn", "vulnRunHint", target);
  await loadVulnerabilityView(target);
}

async function loadVulnerabilityView(scanId) {
  // Same stable-terminal-panel reasoning as loadCompanyView above — this
  // only ever replaces the findings body, never the Live output panel.
  el("vulnProfileBody").innerHTML = `<div class="empty" style="padding:60px 20px;">Loading…</div>`;
  const res = await fetch(`/api/scans/${scanId}`);
  const data = await res.json();
  if (!data.scan) {
    el("vulnProfileBody").innerHTML = `<div class="empty" style="padding:60px 20px;">Scan not found.</div>`;
    return;
  }
  // buildVulnerabilitiesTab(vulnerabilities, scan) needs BOTH arguments —
  // it reads scan.vulnerability_scanned_at once there's at least one
  // finding to show. This call was passing only the first argument, so
  // `scan` was undefined inside it; the early-return path for zero
  // findings never touches `scan` (so an empty result looked fine), but
  // the moment a real scan actually had findings, this threw a
  // TypeError reading `.vulnerability_scanned_at` off undefined — right
  // when there was something to show, not before. That's exactly what
  // left this tab stuck on "Loading…" for any scan with real findings
  // (silently; nothing here catches the error). Confirmed by comparing
  // against report.js's own call to the same function, which always
  // passes both.
  el("vulnProfileBody").innerHTML = `<div class="panel" style="padding:18px 20px;">${buildVulnerabilitiesTab(data.vulnerabilities || [], data.scan)}</div>`;
  el("vulnScanLabel").textContent = `— ${data.scan.domain}`;
}

async function runVulnerabilityScan() {
  const scanId = el("vulnScanPicker").value;
  const btn = el("vulnRunBtn");
  const hint = el("vulnRunHint");
  btn.disabled = true;
  const originalLabel = btn.textContent;
  btn.textContent = "Running…";
  hint.style.color = "var(--text-dim)";
  hint.textContent = "Revalidating live assets, then running nuclei and ffuf against what's confirmed live…";
  const socket = attachModuleWs(scanId, "vulnLiveOutput");
  try {
    const res = await fetch(`/api/scans/${scanId}/vulnerability/run`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) {
      hint.style.color = "var(--red)";
      hint.textContent = data.error || "Vulnerability scan failed.";
    } else if (data.urls_targeted === 0) {
      hint.style.color = "var(--amber)";
      hint.textContent = "No confirmed-live web assets after revalidation — nothing to scan.";
    } else {
      hint.style.color = "var(--green)";
      hint.textContent = `Done — ${data.urls_targeted} URL(s) scanned, ${data.nuclei_findings} nuclei finding(s), ${data.ffuf_findings} ffuf finding(s).`;
      await loadVulnerabilityView(scanId);
    }
  } catch (e) {
    hint.style.color = "var(--red)";
    hint.textContent = "Request failed — check your connection and try again.";
  } finally {
    socket.close();
    btn.textContent = originalLabel;
    btn.disabled = false;
  }
}



