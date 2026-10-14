/*
 * Tutorial walkthrough — a manually-triggered, button-started coachmark
 * tour (never auto-shown) that points at real elements across all four
 * views and explains what they're for. No page-dimming overlay: each
 * step glows the actual target element (.tutorial-highlight, defined in
 * index.html) and a small fixed card (#tutorialCard) carries the
 * explanation + Back/Next in the same screen position throughout, so it
 * never covers the thing it's pointing at.
 *
 * Deliberately explanation-only — it never fills in the domain field,
 * flips a mode tab, or clicks Run/scan buttons on the person's behalf.
 * Triggering an actual scan or tool run is a real, consequential action
 * (hits the network, costs API quota, writes to the DB); a tutorial
 * should never do that without the person actually choosing to.
 */

const TUTORIAL_STEPS = [
  {
    title: "Welcome",
    body: "Mimir enumerates a domain's attack surface — subdomains, live hosts, ports, OSINT — " +
      "plus two independent manual modules for company intel and vulnerability scanning. This " +
      "walkthrough points at each part of the UI and explains what it does. Click Next to begin, " +
      "or ✕ anytime to exit.",
  },
  {
    view: "scan", target: "#domainInput",
    title: "1. Target domain",
    body: "Start here — type the domain you're assessing (e.g. example.com). A leading '*.' on a " +
      "wildcard-style domain is silently stripped ('*.example.com' becomes 'example.com'); " +
      "'example.*' is rejected outright, since no tool here understands a literal TLD wildcard.",
  },
  {
    view: "scan", target: "#tldCheckBtn",
    title: "Optional: check other TLDs first",
    body: "Before scanning, this checks whether the same name resolves under ~100 other common " +
      "TLDs (.co.za, .org, .io, etc.) — useful for spotting a company's other regional or " +
      "product domains up front.",
  },
  {
    view: "scan", target: "#subdomainCheckBtn",
    title: "Optional: check common subdomains",
    body: "Same idea, the front of the domain instead — a quick DNS-only check against ~100 " +
      "curated prefixes (admin, vpn, staging, mail, api...) across 6 categories, before running " +
      "a full scan.",
  },
  {
    view: "scan", target: ".tabs",
    title: "2. Fast vs Full Stack",
    body: "FAST is passive and quick — subfinder, crt.sh, Shodan, WHOIS, DNS, HTTP probing, a " +
      "quick top-100 nmap scan, IP geolocation, a homepage social scan. FULL STACK adds amass, " +
      "assetfinder, theHarvester, naabu, a deeper nmap scan (top 1000 ports + version detection), " +
      "and Shodan host enrichment. Full takes longer but finds more.",
  },
  {
    view: "scan", target: "#toolsList",
    title: "Every tool, visible and adjustable",
    body: "Everything the selected mode actually runs is listed here. Click any tool's name for " +
      "its exact command and a cheat sheet, or to add your own variant (extra arguments) or " +
      "toggle it off entirely for that mode.",
  },
  {
    view: "scan", target: "#runBtn",
    title: "3. Run the scan",
    body: "Kicks it off. Live output streams into the terminal panel below as each tool runs, " +
      "with a progress bar and a running explanation of why each step is happening.",
  },
  {
    view: "scan", target: "#history",
    title: "Scan history",
    body: "Every scan you've run is kept here — click one to revisit it without starting over.",
  },
  {
    view: "scans", target: "#scansList",
    title: "4. The Scans tab — full results",
    body: "Once a scan finishes, open it here for the full report: Hosts, Ports, Intel, Emails, " +
      "Endpoints, Screenshots and more, each searchable. You can also re-validate live " +
      "reachability on demand, or compare two scans side by side.",
  },
  {
    view: "company", target: "#companyRunBtn",
    title: "5. Company module (manual)",
    body: "A separate module, triggered by hand per scan — it never runs automatically. Run " +
      "company scan revalidates live hosts first, then runs the social/homepage scan, a " +
      "Wikidata company-record lookup, CrossLinked employee search, Hunter.io email discovery " +
      "(if you've set an API key), TLD-variant discovery, Shodan enrichment, and an XposedOrNot " +
      "breach check.",
  },
  {
    view: "company", target: "#companyProfileBody",
    title: "Enrichment, once you have real data",
    body: "Once employees or emails are found, two manual enrichment tools show up here: a 🔎 " +
      "Check accounts button per person/email (runs user-scanner against third-party platforms), " +
      "and a Known email address(es) field — feed in one or two real emails you already have, and " +
      "if one matches a found employee's name, the same naming pattern gets applied to guess " +
      "addresses for everyone else found (clearly tagged, never shown as confirmed).",
  },
  {
    view: "vulnerability", target: "#vulnRunBtn",
    title: "6. Vulnerability module (manual)",
    body: "Also independent and manual. Run vulnerability scan revalidates web assets first, " +
      "then runs nuclei and ffuf against exactly what's confirmed live right now, wpscan if " +
      "WordPress was detected (needs an API key), and dalfox against any parameterized URLs " +
      "gau/katana already found.",
  },
  {
    target: "#settingsBtn",
    title: "Settings",
    body: "Enable/disable tools, set per-tool command variants and Profile pickers (SpiderFoot, " +
      "nuclei, user-scanner breadth), add API keys (Shodan, LeakIX, WPScan, Hunter.io), manage " +
      "wordlists, add your own CLI tools or API sources, and back up or reset stored data.",
  },
  {
    title: "That's the workflow",
    body: "Domain → Fast/Full scan → review in the Scans tab → optionally run the Company and/or " +
      "Vulnerability modules once you have confirmed-live data. Re-open this walkthrough anytime " +
      "from the ❓ Tutorial button. Click Finish to exit.",
  },
];

let tutorialStepIndex = 0;
let tutorialHighlightedEl = null;

function clearTutorialHighlight() {
  if (tutorialHighlightedEl) {
    tutorialHighlightedEl.classList.remove("tutorial-highlight");
    tutorialHighlightedEl = null;
  }
}

function renderTutorialStep() {
  const step = TUTORIAL_STEPS[tutorialStepIndex];
  if (!step) return;

  if (step.view) switchView(step.view);

  clearTutorialHighlight();
  if (step.target) {
    const targetEl = document.querySelector(step.target);
    if (targetEl) {
      targetEl.classList.add("tutorial-highlight");
      tutorialHighlightedEl = targetEl;
      targetEl.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }

  el("tutorialCardTitle").textContent = step.title;
  el("tutorialCardBody").textContent = step.body;
  el("tutorialStepCount").textContent = `${tutorialStepIndex + 1} / ${TUTORIAL_STEPS.length}`;
  el("tutorialBackBtn").disabled = tutorialStepIndex === 0;
  el("tutorialNextBtn").textContent = tutorialStepIndex === TUTORIAL_STEPS.length - 1 ? "Finish" : "Next →";
}

function startTutorial() {
  tutorialStepIndex = 0;
  el("tutorialCard").classList.add("open");
  renderTutorialStep();
}

function nextTutorialStep() {
  if (tutorialStepIndex >= TUTORIAL_STEPS.length - 1) {
    exitTutorial();
    return;
  }
  tutorialStepIndex++;
  renderTutorialStep();
}

function prevTutorialStep() {
  if (tutorialStepIndex === 0) return;
  tutorialStepIndex--;
  renderTutorialStep();
}

function exitTutorial() {
  clearTutorialHighlight();
  el("tutorialCard").classList.remove("open");
  tutorialStepIndex = 0;
}
