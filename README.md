# MIMIR // — local attack-surface + OSINT enumeration

Mimir orchestrates real recon, OSINT and vulnerability tools on your own Kali box, streams their output live, and stores everything in a local SQLite database with JSON/CSV/Markdown export. Everything runs on your machine; the only traffic it generates goes to the domain you scan and to the upstream APIs of the sources you enable (Shodan, LeakIX, Wikidata, WPScan, Hunter.io and similar).

Two interfaces share one engine and one database (`surface.db`):

| | Browser UI | Terminal UI (TUI) |
|---|---|---|
| Start | `python3 app.py` → http://127.0.0.1:8787 | `python3 -m tui` |
| Needs a server | Yes (binds to localhost only) | No |
| Scan, Scans/History, Company, Vulnerability, Settings | Yes | Yes |
| Interactive tutorial, 🌐 TLD check, 🔎 subdomain-prefix check | Yes | No |
| 🔎 Check accounts (user-scanner), known-emails enrichment | Yes | No |
| Scan comparison, bulk export/delete, deep scan | Yes | No |

A scan started in one interface shows up live in the other. Run both, or just one.

---

## 1. Install

Run as your normal user, **not with `sudo`**. The script asks for your password only for the steps that need it (apt installs, naabu's raw-socket capability), and refuses to run as root, because a root install puts every tool under root's home and then forces `sudo` to run the app.

```bash
cd surface
chmod +x install.sh
./install.sh
```

It skips anything already installed and is safe to re-run. It installs:

- **Go tools:** subfinder, dnsx, httpx, naabu, assetfinder, gowitness, gau, nuclei, katana, shuffledns, dalfox
- **apt:** amass, whois, dnsutils (dig), nmap, whatweb, ffuf, wpscan, massdns, spiderfoot, recon-ng, theHarvester
- **pip:** crosslinked, user-scanner
- **recon-ng marketplace modules:** hackertarget, bing_domain_web, whois_pocs (keyless; add more in `RECON_NG_MODULES` in `app.py`)
- **Wordlists:** SecLists and n0kovo_subdomains, auto-registered in the app's wordlist picker
- **naabu capability:** `setcap` so SYN scans work without root
- **Python dependencies** from `requirements.txt` (FastAPI, uvicorn, pydantic, python-multipart, and **Textual** for the TUI)

It finishes with a status table and exits non-zero only if a Fast-mode essential (subfinder, dnsx, httpx) is missing. Everything else is optional and is skipped with a warning at scan time if absent.

```bash
./install.sh --check-only     # report what's missing, install nothing
./install.sh --dry-run        # print every command, change nothing
./install.sh -y               # non-interactive, assume yes
./install.sh --skip-apt       # skip apt-get installs
./install.sh --no-naabu-cap   # skip the setcap step
```

Go tools land in `~/go/bin`. The app adds that to its own PATH at startup, so you don't need a new shell.

**Go installs fail with "Network is unreachable"?** On VMs this is usually a configured-but-unrouted IPv6 path. `install.sh` detects the signature and switches Go to the `goproxy.cn` mirror (checksum verification stays on). Setting `net.ipv6.conf.all.disable_ipv6=1` also helps in some cases.

---

## 2. Run it

**Browser:**

```bash
python3 app.py            # then open http://127.0.0.1:8787
```

Built for a desktop browser. The main views stack into one column below ~900px, so it is usable on a phone but not polished for one.

**Terminal:**

```bash
python3 -m tui
```

Five tabs (**Scan**, **Scan History**, **Company**, **Vulnerability**, **Settings**): `Tab`/`Shift+Tab` or the mouse to switch, `Ctrl+R` to refresh, `q` to quit. The TUI calls `app.py`'s functions directly (via `tui/bridge.py`), so it has the same pipeline, modules, settings and backup/restore as the browser app. With no browser to download to, exports and backups are written to disk (`exports/` next to the app) and the path is shown when done. To follow a scan started elsewhere, use **Watch live** on Scan History.

**Privileges:** neither interface needs `sudo`. Tools run with whatever privileges you start Mimir with. Only nmap's aggressive `-A` mode (OS detection) needs root; everything else works unprivileged, and naabu uses the capability granted at install.

---

## 3. Using it

New to Mimir? Click **❓ Tutorial** in the browser header for a 14-step walkthrough that highlights each part of the UI. It explains only and never runs anything for you.

### Scan
Enter a domain, choose **Fast** or **Full stack**, and hit **Run scan**. Output streams live, with a "why this ran" note per tool, **Skip step** and **Stop scan** controls, and results filling in as they're found.

- **Fast:** subfinder, crt.sh, Shodan and InternetDB, LeakIX (key), WHOIS, DNS, HTTP probing, nmap (top 100), IP geolocation.
- **Full:** Fast plus amass, assetfinder, shuffledns (needs a wordlist), theHarvester, recon-ng, SpiderFoot, naabu, nmap (top 1000, `-sV -sC`), whatweb, gau, katana, gowitness screenshots and Shodan host enrichment.
- A leading `*.` is stripped (`*.example.com` → `example.com`). `example.*` is rejected, because no tool understands a TLD wildcard.
- *(Browser)* **🌐 Check other TLDs** DNS-checks 100 TLDs by region and can start a scan for any that resolve. **🔎 Check common subdomains** DNS-checks 100 prefixes (admin, vpn, staging, mail, api and more) before you commit to a full scan.

### Scans / Scan History
Every past scan, searchable, with export (JSON, CSV, Markdown report). The browser adds bulk actions, two-scan **Compare**, and a full report: attack-surface summary plus Vulnerabilities, Leaks, Hosts, Ports, Endpoints, OSINT, Intel, Emails and Screenshots tabs. Large tables render the first 500 rows by default, search reaches the complete dataset, and exports are always uncapped. A **deep scan** (browser) brute-forces second-level subdomains under hosts you select.

### Company (manual, per scan)
Not part of Fast or Full. Pick a finished scan and hit **Run company scan**. It revalidates what's live, then runs: homepage/social scan, Wikidata company record (with parent org), CrossLinked employee search, Hunter.io emails (needs a key), TLD-variant discovery, Shodan enrichment, XposedOrNot breach check, and recent press (GDELT). You can supply the real company name if the auto-detected one is wrong.

*Browser-only enrichment:*
- **🔎 Check accounts** on any employee or email runs `user-scanner` against third-party platforms for that one identity. The **Core** profile checks about 20 major platforms and is fast. **Full breadth** checks every module, which is slow and loud. Choose it under Settings → Tools → user-scanner.
- **Known email address(es):** paste real emails you already have. They're saved to the Emails tab, and if one matches a found employee's name, the inferred naming pattern is applied to the other employees to produce guessed addresses. Guesses are tagged `pattern-guess` and shown as unverified.

### Vulnerability (manual, per scan)
Revalidates, then runs nuclei and ffuf against confirmed-live URLs, wpscan (WordPress, needs a key), dalfox against parameterized URLs, an AXFR zone-transfer check, an SPF/DMARC check, JS secret scanning, and a cloud-bucket check. CVE findings are enriched with CISA KEV and EPSS. Findings can be triaged (Open, False Positive, Reported, Risk Accepted, Fixed) with notes.

### Settings (⚙)
- **API keys:** Shodan, LeakIX, WPScan, Hunter.io. All optional; a source is skipped if its key isn't set.
- **Built-in tools:** enable or disable each tool, add command **variants** (extra arguments appended, never substituted), and use **Profile** pickers where they exist (SpiderFoot, nuclei, user-scanner). A per-tool aggressive toggle exists for nmap, naabu and whatweb.
- **Wordlists:** upload your own, or use the ones the installer fetched. A wordlist must be assigned for ffuf and shuffledns to run.
- **Custom CLI tools / custom API sources:** add your own subdomain or enrichment sources.
- **AI analysis (optional, off by default):** an LLM summary of a scan's own findings via any OpenAI-compatible endpoint, such as a local Ollama. It is labeled unverified.
- **Backup / restore** of `surface.db`, plus clearing the browser cache or resetting scan data.

---

## 4. Data

Everything lives in `surface.db` in the app directory; back it up by copying that file. Screenshots are stored in `screenshots/`, and full gau/katana/dalfox/JS-scan outputs go to `scan_outputs/<id>_<domain>/`. Nothing leaves your machine except traffic to the scan target and each enabled source's API. API keys are stored in the database, so keep `surface.db` out of version control.

## 5. Layout

```
app.py, core.py, company.py, vulnerability.py, ai_analysis.py   backend + engine
static/                    browser UI (no build step): index.html + js/{core,company,report,settings,tutorial}.js
tui/                       Textual terminal UI (bridge.py calls app.py directly)
install.sh                 installer / status checker
wordlists/, scan_docs/     wordlists and generated scan docs
```

## 6. Tools (38)

subfinder, amass, assetfinder, shuffledns, crt.sh, dnsx, httpx, naabu, nmap, whatweb, gowitness, gau, katana, whois, dig (AXFR), ip-geo, Shodan InternetDB, Shodan, LeakIX, theHarvester, recon-ng, SpiderFoot, CrossLinked, Hunter.io, user-scanner, social/homepage scan, Wikidata company lookup, XposedOrNot, GDELT press mentions, nuclei, ffuf, wpscan, dalfox, JS secret scanning, cloud bucket enumeration, SPF/DMARC check, CISA KEV, EPSS.

Only Shodan, LeakIX, WPScan and Hunter.io need an API key. This tool wraps the work of many open-source projects; credit belongs to their authors.

Only scan systems you own or are authorized to test.
