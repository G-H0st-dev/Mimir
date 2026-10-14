"""
MIMIR // — local attack-surface + OSINT enumeration app.

Orchestrates recon tools installed on the host (Kali) as subprocesses, plus
API-based sources (Shodan, crt.sh, ip-api.com, Wikidata, and any custom API
resource you register), streams live output to the browser over a
websocket, and persists results to a local SQLite database.

FILE MAP (in order):
  - Config/constants: BUILTIN_TOOLS registry (name, category, modes, base
    command, cheat sheet), DB schema + migrations, small config-table
    helpers (custom tools, custom API sources, tool variants, API keys).
  - ConnectionManager / log_line: per-scan websocket fan-out + the SQLite-
    backed log that's replayed to late-joining clients.
  - run_stream / run_stream_shell: subprocess execution with live streaming
    and process-group-aware kill-on-cancel (see "Stage cancellation" below).
  - Parsers: turn each tool's raw stdout into structured rows.
  - OSINT source functions: crt.sh, WHOIS, theHarvester, ip-geo, social
    homepage scrape, Shodan, and the Wikidata company lookup — each is a
    standalone async function the pipeline calls as one stage.
  - Live validation: check_dns_now / check_tcp_port_now / check_http_now +
    the two score_*_confidence() functions used by POST .../validate.
  - Stage cancellation + progress: ScanStopped, run_stage(), ProgressTracker
    — this is what makes "skip this step" / "stop the scan" / the progress
    bar all work without each pipeline stage needing to know about any of it.
  - run_pipeline(): builds an exact, ordered list of stages for this
    specific scan (varies by mode + which tools/sources are enabled), then
    runs them. This is the actual scan orchestration.
  - FastAPI app + endpoints: scan lifecycle (start/skip/stop/verify/
    validate), config CRUD (tools, custom tools, custom API sources, tool
    variants, API keys), and export (JSON/CSV/Markdown report).

Everything about the toolset is configurable at runtime from the Settings
panel and the Tools sidebar: built-in tools can be disabled or given
bespoke command variants, custom CLI tools and custom API resources can be
added, and API keys are stored locally.

Run with:  python3 app.py
Then open: http://127.0.0.1:8787
"""

import asyncio
import csv
import io
import zipfile
import json
import os
import re
import xml.etree.ElementTree as ET
import shlex
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# core.py holds the shared infrastructure every tool module (including
# this one) needs: DB connection/schema, subprocess execution with live
# log streaming, generic HTTP fetch helpers, and per-tool config helpers
# (variants, wordlists, aggressive mode, API keys). Split out specifically
# so tool modules can depend on it without a circular import back to this
# file, since this file is the orchestrator that imports FROM tool
# modules (see the `company` import below).
from core import (
    AGGRESSIVE_CAPABLE_TOOLS,
    BASE_DIR,
    DB_PATH,
    DOCS_DIR,
    RESOLVERS_FILE,
    SCREENSHOTS_DIR,
    STATIC_DIR,
    STREAM_READ_LIMIT,
    TOOL_PROFILES,
    WORDLISTS_DIR,
    WORDLIST_CAPABLE_TOOLS,
    ConnectionManager,
    add_emails,
    apply_variant,
    build_custom_cmd,
    check_dns_now,
    build_custom_shell_cmd,
    filter_emails_to_domain,
    find_binary,
    get_active_variant,
    get_active_wordlist,
    get_ai_config,
    get_tool_profile,
    get_api_key,
    get_confirmed_live_urls,
    get_custom_api_sources,
    get_custom_tools,
    get_db,
    get_tool_settings_map,
    get_tool_variants,
    http_get_json,
    http_get_json_headers,
    init_db,
    is_aggressive,
    is_enabled,
    get_wordlist_recommendations,
    register_bootstrap_wordlists,
    log_line,
    manager,
    mask_key,
    now_iso,
    run_quiet,
    run_stream,
    run_stream_shell,
    sanitize_filename_part,
    set_ai_config,
    set_tool_profile,
    set_api_key,
    store_intel,
    upsert_port,
    write_full_output_file,
)

# company.py: everything about the organization behind a scanned domain —
# social presence, the public company record, employee enumeration
# (CrossLinked), and breach/leak exposure (LeakIX + XposedOrNot). Kept
# separate from the rest of the tool modules since it's the one category
# that's about the *organization* rather than its infrastructure.
from company import (
    apply_known_emails,
    company_lookup,
    crosslinked_run_multi,
    discover_subdomain_prefixes,
    discover_tld_variants,
    discover_tld_variants_global,
    get_company_name_candidates,
    hunter_lookup,
    news_lookup,
    shodan_dns_domain,
    shodan_enrich_hosts,
    social_scan,
    user_scanner_lookup,
    xposedornot_lookup,
)

# vulnerability.py: nuclei and ffuf, run as a deliberate follow-up against
# a scan's currently confirmed-live assets rather than baked into one
# monolithic pass — see core.get_confirmed_live_urls().
from vulnerability import (
    check_cisa_kev,
    check_cloud_buckets,
    check_dns_zone_transfer,
    check_email_auth,
    check_epss_scores,
    dalfox_run,
    ffuf_run,
    nuclei_run,
    secrets_scan_js,
    wpscan_run,
)

# ai_analysis.py: an entirely optional narrative layer on top of a
# scan's own already-collected data. Never called automatically from
# any pipeline step — only from its own dedicated endpoints below.
from ai_analysis import check_ai_configured, generate_ai_analysis


def _is_accessible_dir(path_str: str) -> bool:
    """Path.is_dir() raises PermissionError (not just returning False) when
    the *parent* directory blocks traversal — e.g. a non-root user
    checking anything under /root, which is exactly the "/root/go/bin"
    fallback candidate below when this app runs as a regular user rather
    than via sudo. That's a completely normal, expected case here, not an
    error worth crashing over — this treats "can't even check, no
    permission" the same as "doesn't exist"."""
    try:
        return Path(path_str).is_dir()
    except OSError:
        return False


def _extend_path_for_common_tool_locations() -> list[str]:
    """install.sh (and most manual install guides) put Go-installed tools
    like subfinder/httpx/naabu in ~/go/bin — but it only adds that to
    PATH for *future* shell sessions (appended to .bashrc/.zshrc). If this
    app gets started in the same terminal right after installing
    something, or via a launcher that doesn't source shell rc files at
    all (cron, systemd, an IDE's run button, etc.), those tools genuinely
    aren't on this process's PATH no matter how they're looked up.

    This extends the *current process's* PATH at startup to include the
    well-known locations, so every tool lookup in the app — not just
    httpx's wrong-binary disambiguation — benefits without anyone needing
    to restart their terminal. Runs once at import time, synchronously,
    before anything else in the app does a single PATH-dependent lookup.
    Returns whichever directories actually got added, for the startup log.
    """
    homes = [Path.home()]

    # Under `sudo`, $HOME (and therefore Path.home()) usually resolves to
    # root's home instead of the real user's — unless the environment was
    # explicitly preserved with `-E`/`sudo -H`. install.sh, and most Go
    # tool installs, happen as the actual logged-in user, not root, so if
    # this app gets started with `sudo python3 app.py`, checking only
    # Path.home() misses exactly where the tools actually are. SUDO_USER
    # is what sudo sets to the original username — look their real home
    # directory up directly rather than trusting $HOME.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            homes.append(Path(pwd.getpwnam(sudo_user).pw_dir))
        except (KeyError, ImportError, OSError):
            pass

    candidates = []
    for home in homes:
        candidates.append(str(home / "go" / "bin"))       # default GOPATH/bin
        candidates.append(str(home / ".local" / "bin"))   # common `pip install --user` location
    candidates.append("/usr/local/go/bin")
    candidates.append("/root/go/bin")

    gopath_env = os.environ.get("GOPATH")
    if gopath_env:
        candidates.append(str(Path(gopath_env) / "bin"))
    else:
        go_bin = shutil.which("go")
        if go_bin:
            try:
                result = subprocess.run(
                    [go_bin, "env", "GOPATH"], capture_output=True, text=True, timeout=5
                )
                gopath = result.stdout.strip()
                if gopath:
                    candidates.append(str(Path(gopath) / "bin"))
            except Exception:
                pass

    # Last-resort safety net, in case HOME resolution is still wrong for
    # some other reason: this is a local, single-user recon tool (not a
    # shared multi-tenant server), so directly checking every /home/*/go/bin
    # is a reasonable trade-off against yet another "installed but not
    # found" report. Each entry is checked individually — one other
    # user's home directory blocking access (normal, e.g. mode 700)
    # shouldn't stop the rest of /home from being checked.
    try:
        for entry in Path("/home").iterdir():
            if _is_accessible_dir(str(entry)):
                candidates.append(str(entry / "go" / "bin"))
    except OSError:
        pass

    current_dirs = os.environ.get("PATH", "").split(os.pathsep)
    seen = set(current_dirs)
    added = []
    for d in candidates:
        if d and d not in seen and _is_accessible_dir(d):
            added.append(d)
            seen.add(d)
    if added:
        os.environ["PATH"] = os.pathsep.join(added + current_dirs)
    return added


_added_path_dirs = _extend_path_for_common_tool_locations()
if _added_path_dirs:
    print(f"[MIMIR //] found tools outside this session's PATH — added: {', '.join(_added_path_dirs)}")

HARVESTER_BINARIES = ["theHarvester", "theharvester"]
# Passive, no-API-key-required theHarvester sources. "-b all" is intentionally
# avoided since many of its sources are paid/keyed and just fail or throttle.
#
# Confirmed directly against theHarvester's own source list: crtsh/otx/
# hackertarget/rapiddns/urlscan are all subdomain/DNS/threat-intel
# sources — none of them actually search for email addresses at all.
# "threatminer" — previously in this list — was worse than just
# unhelpful: it isn't a real theHarvester source name at all (checked
# against theHarvester's own get_supportedengines() source list; its
# data is folded into OTX these days anyway, via threatcrowd's API,
# which OTX absorbed). Passing an unrecognized name doesn't error the
# whole run, but that source prints "[!] Invalid source." and
# contributes nothing — one of seven configured sources doing
# literally nothing, every single scan, silently.
#
# theHarvester's actual email-finding capability comes from
# search-engine-scrape sources (baidu, duckduckgo, yahoo — all free,
# no key) and a couple of leak/breach-adjacent ones (hudsonrock:
# infostealer-malware credential dumps; gitlab: commit author emails
# from public GitLab repos under the org). All five added here.
# Deliberately not adding google/bing, which theHarvester also
# supports: those get CAPTCHA-blocked on automated scraping far more
# aggressively than baidu/duckduckgo/yahoo (the same failure mode
# already noted for CrossLinked's Google/Bing dependency below), so
# they'd mostly just add failed requests, not real results. hunter.io
# (by far the best-quality email source that exists) needs a paid API
# key theHarvester would have to be separately configured with outside
# this app — better suited to this app's own custom API source
# mechanism (Settings → API sources) than baking a key into theHarvester's
# own config file, if you want to add it.
HARVESTER_SOURCES = "crtsh,otx,hackertarget,rapiddns,urlscan,baidu,duckduckgo,yahoo,hudsonrock,gitlab"

# ---------------------------------------------------------------------------
# Built-in tool/source definitions. category drives where in the pipeline a
# source runs; modes says which scan modes it applies to by default. All of
# this can be overridden per-tool via the tool_settings table.
# ---------------------------------------------------------------------------
BUILTIN_TOOLS = [
    {"name": "subfinder", "category": "subdomain", "modes": ["fast", "full"], "is_cli": True,
     "cmd": "subfinder -d {domain} -silent",
     "cheatsheet": [
         ("-all", "use every source, not just the fast ones — slower, more thorough"),
         ("-sources s1,s2", "restrict to specific sources, e.g. crtsh,virustotal"),
         ("-rate-limit N", "cap requests/sec — helps avoid being throttled/blocked"),
         ("-timeout N", "per-request timeout in seconds (default 30)"),
         ("-max-time N", "hard cap on total run time, in minutes"),
     ]},
    {"name": "crtsh", "category": "subdomain", "modes": ["fast", "full"], "is_cli": False,
     "cmd": "GET https://crt.sh/?q=%25.{domain}&output=json"},
    {"name": "amass", "category": "subdomain", "modes": ["full"], "is_cli": True,
     "cmd": "amass enum -passive -d {domain} -silent",
     "cheatsheet": [
         ("-passive", "OSINT-only, no direct contact with the target — this app always keeps this on"),
         ("-timeout N", "hard cap on total run time, in minutes"),
         ("-src", "annotate each result with which data source found it"),
         ("-nolocaldb", "skip amass's local graph database — faster for a one-off run"),
     ]},
    {"name": "assetfinder", "category": "subdomain", "modes": ["full"], "is_cli": True,
     "cmd": "assetfinder --subs-only {domain}",
     "cheatsheet": [
         ("--subs-only", "only print actual subdomains — this app always keeps this on"),
         ("(no other flags)", "assetfinder is intentionally minimal; there's little else to tune"),
     ]},
    {"name": "theharvester", "category": "osint", "modes": ["full"], "is_cli": True,
     "cmd": f"theHarvester -d {{domain}} -b {HARVESTER_SOURCES}",
     "cheatsheet": [
         ("-b s1,s2", "comma list of sources — this app defaults to free/no-key ones; adding keyed sources (e.g. securitytrails) will just fail silently without a configured key"),
         ("-l N", "limit results returned per source"),
         ("-b all", "every source theHarvester supports — mostly redundant with keyed sources that won't work here"),
     ]},
    {"name": "crosslinked", "category": "osint", "modes": ["independent"], "is_cli": True,
     "cmd": "crosslinked -f '{first} {last}' -o <scan-temp-dir>/names <company name> "
            "(company name best-guessed from WHOIS org / site name / domain label)",
     "cheatsheet": [
         ("-f FORMAT", "naming pattern, e.g. '{first}.{last}@domain.com' — output shaped like an email gets stored as emails, otherwise as employee names"),
         ("-t N", "max timeout per search in seconds (default 15)"),
         ("-j N", "jitter between requests, for scraping evasion (default 1)"),
         ("--search google,bing", "which search engines to scrape (default both)"),
         ("--proxy IP:PORT", "route requests through a single proxy"),
         ("--proxy-file FILE", "rotate through multiple proxies from a file"),
     ]},
    {"name": "hunter", "category": "osint", "modes": ["independent"], "is_cli": False,
     "cmd": "GET https://api.hunter.io/v2/domain-search?domain={domain}&api_key=...  (real, found emails — "
            "not guessed from a pattern — plus the detected naming convention; needs a free API key, "
            "50 lookups/month on Hunter's free tier)"},
    {"name": "user-scanner", "category": "osint", "modes": ["independent"], "is_cli": True,
     "cmd": "user-scanner -u|-e <name or email already found> -m <module list> -f json -o <tmpfile>  "
            "(checks ONE already-discovered person against third-party platforms for registered "
            "accounts; triggered manually per person from the Company profile, not run automatically)",
     "cheatsheet": [
         ("Profile: Core platforms", "~20 recognizable major platforms (GitHub, LinkedIn, X, etc.) — fast, low noise"),
         ("Profile: Full breadth", "every module (2,500+ username / 200+ email) — slow, loud, picks up rate-limits/CAPTCHAs"),
     ]},
    {"name": "whois", "category": "whois", "modes": ["fast", "full"], "is_cli": True,
     "cmd": "whois {domain}",
     "cheatsheet": [
         ("-h server", "query a specific WHOIS server instead of the default referral chain"),
         ("-H", "hide legal disclaimers some registries prepend to the output"),
     ]},
    {"name": "dnsx", "category": "resolution", "modes": ["fast", "full"], "is_cli": True,
     "cmd": "dnsx -silent -json -a -l <discovered-hosts-file>",
     "cheatsheet": [
         ("-a", "resolve A (IPv4) records — this app always keeps this on"),
         ("-aaaa", "also resolve AAAA (IPv6) records"),
         ("-cname", "also resolve and follow CNAME chains"),
         ("-resp-only", "only output hosts that actually resolved"),
         ("-threads N", "concurrency — raise for speed, lower if you're rate-limited"),
     ]},
    {"name": "httpx", "category": "probe", "modes": ["fast", "full"], "is_cli": True,
     "cmd": "httpx -silent -json -title -tech-detect -status-code -fr -l <discovered-hosts-file>",
     "cheatsheet": [
         ("-fr", "follow redirects — this app always keeps this on (used for main-domain detection)"),
         ("-screenshot", "capture a screenshot per host — needs a headless Chrome install"),
         ("-threads N", "concurrency — raise for speed, lower if you're getting timeouts"),
         ("-timeout N", "per-request timeout in seconds"),
         ("-mc 200,301,302", "only report specific status codes"),
     ]},
    {"name": "naabu", "category": "ports", "modes": ["full"], "is_cli": True,
     "cmd": "naabu -silent -json -top-ports 100 -l <discovered-hosts-file>",
     "cheatsheet": [
         ("-top-ports N", "scan N most common ports — this app defaults to 100"),
         ("-p 1-65535", "full port range — thorough but much slower"),
         ("-rate N", "packets/sec — lower if you're worried about tripping IDS/rate limits"),
     ]},
    {"name": "nmap", "category": "ports", "modes": ["fast", "full"], "is_cli": True,
     "cmd": "fast: nmap -Pn -T4 -F --open -iL <resolved-ips-file> -oX -\n"
            "full: nmap -Pn -T4 --top-ports 1000 -sV -sC --open -iL <resolved-ips-file> -oX -",
     "cheatsheet": [
         ("-Pn", "skip host discovery (treat all as online) — this app always keeps this on"),
         ("-sV", "version detection — already on in Full mode"),
         ("-sC", "nmap's default *safe* NSE scripts — already on in Full mode, output stored per-port/host"),
         ("--script vuln", "run vulnerability-detection scripts — more intrusive, use with authorization"),
         ("-A", "aggressive: OS detection + version + scripts + traceroute — thorough but slow and noisy"),
         ("-T0..-T5", "timing template — higher is faster but noisier, lower is stealthier but slower"),
     ]},
    {"name": "ip-geo", "category": "geo", "modes": ["fast", "full"], "is_cli": False,
     "cmd": "GET http://ip-api.com/json/{ip}?fields=... (per resolved IP)"},
    {"name": "social-scan", "category": "company", "modes": ["independent"], "is_cli": False,
     "cmd": "GET <live homepage URL>  (scraped for social links + title/meta)"},
    {"name": "company-lookup", "category": "company", "modes": ["independent"], "is_cli": False,
     "cmd": "GET wikidata.org (search + entity fetch) — only accepted if the "
            "entity's own official-website claim matches {domain}"},
    {"name": "gowitness", "category": "screenshots", "modes": ["full"], "is_cli": True,
     "cmd": "gowitness scan file -f <live-http-assets-file> --screenshot-path <scan-screenshot-dir> "
            "--write-jsonl --write-jsonl-file <results.jsonl> --threads 4 --timeout 20",
     "cheatsheet": [
         ("--threads N", "concurrency — this app defaults to 4, low since each thread runs its own headless Chrome tab"),
         ("--timeout N", "per-target timeout in seconds (this app defaults to 20)"),
         ("--screenshot-fullpage", "capture the entire page, not just the visible viewport"),
         ("--screenshot-format png", "PNG instead of the default JPEG — larger files, lossless"),
         ("--chrome-proxy proto://host:port", "route Chrome's traffic through a proxy"),
         ("--save-content", "also save raw response bodies to the configured writers — can get large fast"),
     ]},
    {"name": "whatweb", "category": "fingerprinting", "modes": ["full"], "is_cli": True,
     "cmd": "whatweb -i <live-http-assets-file> --log-json=<results.json> -a 1 --no-errors",
     "cheatsheet": [
         ("-a 1", "stealthy (default) — one HTTP request per target, follows redirects"),
         ("-a 3", "aggressive — makes extra requests when a level-1 plugin already matched, digging deeper"),
         ("-a 4", "heavy — full aggressive tests on every target regardless of level-1 matches; noisy, thorough"),
         ("-v", "verbose — includes plugin descriptions in the output"),
         ("--wait N", "seconds to wait between requests — useful for rate-limited/large target lists"),
         ("-p PLUGINS", "only run specific plugins (comma-separated) instead of all ~1800"),
     ]},
    {"name": "shodan", "category": "enrichment", "modes": ["fast", "full"], "is_cli": False,
     "cmd": "GET https://api.shodan.io/dns/domain/{domain}?key=...\n"
            "GET https://api.shodan.io/shodan/host/{ip}?key=...  (per resolved IP)"},
    {"name": "internetdb", "category": "enrichment", "modes": ["fast", "full"], "is_cli": False,
     "cmd": "GET https://internetdb.shodan.io/{ip}  (per resolved IP — free, no key)"},
    {"name": "leakix", "category": "enrichment", "modes": ["fast", "full"], "is_cli": False,
     "cmd": "GET https://leakix.net/host/{ip}  (per resolved IP, api-key header)"},
    {"name": "xposedornot", "category": "enrichment", "modes": ["independent"], "is_cli": False,
     "cmd": "GET https://api.xposedornot.com/v1/check-email/{email}  (per harvested email — free, no key)"},
    {"name": "news", "category": "company", "modes": ["independent"], "is_cli": False,
     "cmd": "GET https://api.gdeltproject.org/api/v2/doc/doc?query=\"{company_name}\"&mode=artlist"
            "&maxrecords=15&sort=DateDesc&timespan=3m&format=json  (free, no key — GDELT DOC 2.0 API)"},
    {"name": "gau", "category": "discovery", "modes": ["full"], "is_cli": True,
     "cmd": "gau {domain}  (historical URLs from Wayback Machine, Common Crawl, OTX)",
     "cheatsheet": [
         ("--blacklist ext,ext", "skip URLs ending in given extensions, e.g. png,jpg,gif,svg,css"),
         ("--from YYYYMM", "only URLs archived on/after this month"),
         ("--to YYYYMM", "only URLs archived on/before this month"),
         ("--providers wayback,commoncrawl,otx,urlscan", "choose which archive sources to query"),
         ("--threads N", "concurrency"),
     ]},
    {"name": "ffuf", "category": "fuzzing", "modes": ["independent"], "is_cli": True,
     "cmd": "ffuf -w <wordlist>:FUZZ -u <live-http-asset-url>/FUZZ -mc 200,204,301,302,307,401,403 "
            "-of json -o <results.json> -s  (one run per live host — needs a wordlist assigned to run at all)",
     "cheatsheet": [
         ("-mc 200,301,403", "match only these status codes — this app's default excludes plain 404s"),
         ("-fs N", "filter out responses of exactly N bytes — useful for a noisy custom 404 page"),
         ("-recursion", "recurse into discovered directories automatically"),
         ("-t N", "concurrent threads (default 40)"),
         ("-rate N", "cap requests/sec — gentler on rate-limited targets"),
     ]},
    {"name": "nuclei", "category": "vulnerability", "modes": ["independent"], "is_cli": True,
     "cmd": "nuclei -update-templates -silent  (runs first, every time)\n"
            "nuclei -l <live-http-assets-file> -tags cve,exposure,exposures,misconfig,misconfiguration,"
            "default-login,takeover -severity critical,high,medium,low -jsonl -o <results.jsonl> -silent",
     "cheatsheet": [
         ("-severity critical,high", "narrow back down to just these — the default here deliberately includes low too"),
         ("-tags cve,exposure", "only run templates carrying these tags"),
         ("-exclude-tags dos,fuzz", "skip templates tagged as risky/disruptive"),
         ("-rate-limit N", "cap requests/sec (default 150) — lower for sensitive targets"),
         ("-etags intrusive", "exclude intrusive/potentially-disruptive checks"),
     ]},
    {"name": "wpscan", "category": "vulnerability", "modes": ["independent"], "is_cli": True,
     "cmd": "wpscan --url <first WordPress host found> --enumerate vp,vt --api-token <key> "
            "--format json -o <results.json> --no-banner --random-user-agent\n"
            "(only runs if whatweb detected WordPress, and only against one host, to protect the free "
            "API's 25 requests/day quota)",
     "cheatsheet": [
         ("--enumerate p", "all installed plugins, not just already-known-vulnerable ones — costs more API requests"),
         ("--enumerate u", "enumerate usernames too — separate from vulnerability data, no API cost"),
         ("--api-token TOKEN", "required for actual vulnerability data — set once in Settings → API keys instead"),
         ("--plugins-detection aggressive", "more thorough plugin detection at the cost of more requests to the target"),
     ]},
    {"name": "dalfox", "category": "vulnerability", "modes": ["independent"], "is_cli": True,
     "cmd": "dalfox file <parameterized-urls-file> --silence --format json -o <results.json>\n"
            "(targets URLs gau/katana already found containing a '?' — capped to the first 50)",
     "cheatsheet": [
         ("--skip-bav", "skip basic another vulnerability (SQLi/SSTI/CRLF) checks dalfox also does alongside XSS"),
         ("--waf-evasion", "attempt basic WAF-evasion payload variants — slower, more requests"),
         ("--only-poc", "only report confirmed, verified findings — drops the unconfirmed 'possible' ones"),
         ("-w N", "concurrent workers (default varies) — lower for sensitive/rate-limited targets"),
     ]},
    {"name": "cisa-kev", "category": "vulnerability", "modes": ["independent"], "is_cli": False,
     "cmd": "GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            "  (free, no key — cross-references every CVE-bearing finding against confirmed active exploitation)"},
    {"name": "epss", "category": "vulnerability", "modes": ["independent"], "is_cli": False,
     "cmd": "GET https://api.first.org/data/v1/epss?cve=<comma-separated CVEs>"
            "  (free, no key — FIRST.org's 30-day exploitation-probability model)"},
    {"name": "axfr", "category": "vulnerability", "modes": ["independent"], "is_cli": True,
     "cmd": "dig +short NS <domain>, then dig @<nameserver> axfr <domain> +time=10 for each"
            "  (free, no key — checks whether any nameserver allows an unauthenticated zone transfer)"},
    {"name": "email-auth", "category": "vulnerability", "modes": ["independent"], "is_cli": True,
     "cmd": "dig +short TXT <domain>, dig +short TXT _dmarc.<domain>"
            "  (free, no key — checks for missing/weak SPF and DMARC records)"},
    {"name": "secrets", "category": "vulnerability", "modes": ["independent"], "is_cli": False,
     "cmd": "GET each .js file gau/katana already found, scanned locally against a curated regex set"
            "  (AWS/GitHub/Stripe/Slack key formats, private key headers, JWTs — capped to the first 40 files)"},
    {"name": "buckets", "category": "vulnerability", "modes": ["independent"], "is_cli": False,
     "cmd": "GET https://<name><suffix>.s3.amazonaws.com/, https://storage.googleapis.com/<name><suffix>"
            "  (free, no key — checks common S3/GCS bucket name permutations; Azure gets a weaker DNS-only check)"},
    {"name": "katana", "category": "discovery", "modes": ["full"], "is_cli": True,
     "cmd": "katana -u <live-http-asset-url> -jsonl -o <results.jsonl> -silent  (one run per live host)",
     "cheatsheet": [
         ("-d N", "max crawl depth (default 3)"),
         ("-jc", "also parse/crawl endpoints referenced from JS files"),
         ("-kf all", "also check known files: robots.txt, sitemap.xml, etc."),
         ("-ct N", "max crawl duration in seconds — bounds a slow/large site"),
         ("-hl", "headless mode (real Chrome) — finds JS-rendered links a plain fetch would miss"),
     ]},
    {"name": "shuffledns", "category": "subdomain", "modes": ["full"], "is_cli": True,
     "cmd": "shuffledns -d {domain} -w <wordlist> -r <resolvers> -mode bruteforce -silent "
            "(needs a wordlist assigned to run at all — see the Wordlist section below)",
     "cheatsheet": [
         ("-t N", "concurrent massdns resolves (default 10000 — this app uses a gentler default)"),
         ("-mode resolve", "resolve an existing host list instead of brute-forcing (this app uses dnsx for that already)"),
         ("-o file", "write matched subdomains to a file"),
     ]},
    {"name": "spiderfoot", "category": "osint", "modes": ["full"], "is_cli": True,
     "cmd": "spiderfoot -s {domain} -u passive -max-threads 20 -o json  (SpiderFoot's own curated "
            "passive-only module profile; -max-threads raised from SpiderFoot's own default of 3 — "
            "confirmed against its source, that default is a real bottleneck for this kind of "
            "many-independent-API-calls workload, not a deliberate safety limit)",
     "cheatsheet": [
         ("-max-threads N", "modules run concurrently — default here is 20 (SpiderFoot's own default is 3); "
                             "higher finishes faster but raises the risk of hitting free-tier third-party rate limits"),
         ("-x -t type1,type2", "strict mode — selectable as the 'Strict (fastest)' profile below. Only runs "
                                "modules that query the domain directly (no chained/multi-hop modules), for a "
                                "fixed, curated set of event types. Faster than passive, but narrower — a real "
                                "trade, not a free win"),
         ("-u footprint", "a broader profile — includes some active/intrusive modules, not just passive"),
         ("-u all", "every module SpiderFoot has — very slow, heavy overlap with tools this app already runs"),
         ("-m mod1,mod2", "run specific modules by name instead of a profile — see spiderfoot -M for the current list"),
     ]},
    {"name": "recon-ng", "category": "osint", "modes": ["full"], "is_cli": True,
     "cmd": "recon-cli -w <workspace> -m recon/domains-hosts/hackertarget -o SOURCE={domain} -x\n"
            "recon-cli -w <workspace> -m recon/domains-hosts/bing_domain_web -o SOURCE={domain} -x\n"
            "recon-cli -w <workspace> -m recon/domains-contacts/whois_pocs -o SOURCE={domain} -x\n"
            "(three keyless modules by default — see README for why, and how to add more)",
     "cheatsheet": [
         ("-m recon/domains-hosts/*", "browse `marketplace search domains-hosts` inside recon-ng for more host-discovery modules"),
         ("-m recon/domains-contacts/*", "contact/people-focused modules — many need an API key configured in recon-ng's own keystore"),
         ("keys add <name> <value>", "run inside recon-ng itself to add API keys for modules that need one — separate from this app's Settings"),
     ]},
]


# ---------------------------------------------------------------------------
# Technology knowledge base — plain-English context for what a detected
# technology actually is, plus general security notes (common
# misconfiguration classes, historically-relevant vulnerability
# categories) for people who don't recognize every name whatweb/httpx
# turn up. Deliberately NOT a live CVE feed keyed to exact versions —
# that goes stale immediately and would need constant upkeep against a
# database this app has no way to stay current with. This is closer to
# "what should I go check" than "here is a live vulnerability scan" —
# nuclei (already integrated) is the actual live vulnerability-scanning
# tool; this is context to help interpret what nuclei, whatweb, and the
# ports table are actually showing.
#
# Keyed by lowercase technology name. Lookup (see tech_kb_lookup) strips
# version numbers and tries common aliases before giving up, since the
# exact string whatweb reports (e.g. "Nginx", "nginx", "WordPress") isn't
# always the same casing/form as what a human would type.
# ---------------------------------------------------------------------------
TECH_KNOWLEDGE_BASE = {
    # --- Web servers ---
    "nginx": {
        "category": "Web server",
        "description": "A widely-used web server and reverse proxy, often placed in front of application servers for performance and load balancing.",
        "security_notes": "Check the version against known CVEs for that specific release. Misconfigured reverse-proxy rules (path normalization, header handling) are a more common real-world issue than the server itself — look for exposed internal paths, missing rate limiting, and default server blocks left enabled.",
    },
    "apache": {
        "category": "Web server",
        "description": "The Apache HTTP Server, one of the most widely deployed web servers, often paired with PHP via mod_php.",
        "security_notes": "Older Apache versions have a long CVE history (path traversal, request smuggling). Check for enabled but unnecessary modules (mod_status, mod_info exposed publicly), directory listing left on, and default/example pages still present.",
    },
    "iis": {
        "category": "Web server",
        "description": "Microsoft's Internet Information Services web server, typically indicating a Windows Server backend.",
        "security_notes": "Check for outdated versions with known RCEs (e.g. historical ones like CVE-2017-7269). Look for verbose error pages leaking stack traces/file paths, and WebDAV enabled unnecessarily.",
    },
    "litespeed": {
        "category": "Web server",
        "description": "A high-performance web server, commonly used as a drop-in Apache replacement, especially on shared hosting.",
        "security_notes": "Check the version against published CVEs. Often paired with cPanel hosting — worth checking for other cPanel-related exposure.",
    },
    "openresty": {
        "category": "Web server",
        "description": "Nginx bundled with the Lua scripting engine, used to build custom request-handling logic directly into the web server.",
        "security_notes": "Custom Lua logic is application-specific and can't be assessed generically — treat it as custom application code needing its own review, not just \"nginx.\"",
    },
    "caddy": {
        "category": "Web server",
        "description": "A modern web server known for automatic HTTPS certificate management.",
        "security_notes": "Generally has secure defaults out of the box. Check for exposed admin API (default port 2019) if present.",
    },
    "cloudflare": {
        "category": "CDN / WAF",
        "description": "A CDN and reverse proxy that sits in front of the real origin server, providing caching, DDoS protection, and a web application firewall.",
        "security_notes": "The IP/host you're scanning may just be Cloudflare's edge, not the real origin — a raw port scan against it can be misleading (Cloudflare filters most scan traffic while still serving HTTP/S normally, which can look like 'nothing open' even on a live site). Finding the real origin IP (DNS history, subdomain misconfigurations bypassing the proxy) is often the actual next step, not scanning the CDN edge itself.",
    },
    "akamai": {
        "category": "CDN / WAF",
        "description": "A large CDN and edge security platform, similar in role to Cloudflare.",
        "security_notes": "Same consideration as Cloudflare — you're likely looking at edge infrastructure, not the origin. A scan finding little here doesn't mean the real origin is equally locked down.",
    },
    "fastly": {
        "category": "CDN / WAF",
        "description": "A CDN and edge platform, similar in role to Cloudflare/Akamai.",
        "security_notes": "Same origin-vs-edge consideration as other CDNs — treat scan results against the CDN's own IPs cautiously.",
    },
    "sucuri": {
        "category": "CDN / WAF",
        "description": "A CDN with an integrated web application firewall, commonly used to protect WordPress sites specifically.",
        "security_notes": "Its presence suggests the origin has (or had) a reason to want WAF protection — worth checking whether it's actively blocking your own probes, which can produce misleadingly clean results.",
    },
    "varnish": {
        "category": "Caching",
        "description": "An HTTP reverse-proxy cache, often placed between a CDN/load balancer and the actual application server.",
        "security_notes": "Misconfigured cache rules can lead to cache poisoning or accidentally caching pages containing session/auth data — worth checking Vary headers and what's actually being cached.",
    },

    # --- CMSs ---
    "wordpress": {
        "category": "CMS",
        "description": "The most widely deployed content management system on the web — a large share of all websites run on it.",
        "security_notes": "Check the specific version and installed plugins/themes against known CVEs (plugins are the far more common vulnerability source than WordPress core itself). Look for /wp-admin/ and /wp-login.php exposure, XML-RPC left enabled (a common brute-force/amplification vector), and whether user enumeration is possible via /?author=1.",
    },
    "drupal": {
        "category": "CMS",
        "description": "An open-source CMS, common in government, education, and enterprise sites.",
        "security_notes": "Has had several severe, widely-exploited core vulnerabilities historically (the 'Drupalgeddon' family) — version is very important to check here specifically, more so than with most CMSs.",
    },
    "joomla": {
        "category": "CMS",
        "description": "An open-source CMS, popular for small-to-medium business sites.",
        "security_notes": "Check version and installed extensions against known CVEs. The administrator login path and configuration.php backup files left accessible are common findings.",
    },
    "magento": {
        "category": "E-commerce CMS",
        "description": "An e-commerce platform, common for online stores, known for handling payment data directly.",
        "security_notes": "A frequent target for skimming/Magecart-style attacks. Version and patch level matter a lot here given the payment-data exposure if compromised.",
    },
    "typo3": {
        "category": "CMS",
        "description": "An open-source enterprise CMS, common in Europe especially.",
        "security_notes": "Check version against known CVEs; the backend login path (/typo3/) is a common enumeration target.",
    },
    "ghost": {
        "category": "CMS",
        "description": "A Node.js-based CMS focused on publishing/blogging.",
        "security_notes": "Check the admin panel path (/ghost/) exposure and version against known CVEs.",
    },
    "shopify": {
        "category": "E-commerce platform",
        "description": "A fully-hosted e-commerce platform — the underlying infrastructure is managed by Shopify, not the site owner.",
        "security_notes": "Core platform security is Shopify's responsibility; focus shifts to the store's own custom app/theme code and third-party app integrations instead.",
    },
    "woocommerce": {
        "category": "E-commerce plugin",
        "description": "A WordPress plugin that turns a WordPress site into an online store.",
        "security_notes": "Inherits all WordPress considerations, plus its own plugin-specific CVE history — check the exact version.",
    },
    "prestashop": {
        "category": "E-commerce CMS",
        "description": "An open-source e-commerce platform, common in Europe especially.",
        "security_notes": "Check version and installed modules against known CVEs — the admin login path is often left at a predictable default.",
    },

    # --- Languages / frameworks ---
    "php": {
        "category": "Server-side language",
        "description": "A widely-used server-side scripting language, underlying WordPress, Drupal, and much of the older web.",
        "security_notes": "Many older PHP versions are end-of-life with no security patches — check whether the version shown still receives updates. Exposed phpinfo() pages are a common, high-value information leak worth checking for.",
    },
    "asp.net": {
        "category": "Server-side framework",
        "description": "Microsoft's web application framework, typically indicating a Windows/IIS backend.",
        "security_notes": "Check for verbose error pages (custom errors disabled) leaking stack traces, and ViewState not using MAC validation (can enable deserialization attacks in older configurations).",
    },
    "django": {
        "category": "Server-side framework",
        "description": "A Python web framework with a strong emphasis on secure defaults.",
        "security_notes": "Check specifically whether DEBUG mode has been left enabled in production — this is the single most common and most severe Django misconfiguration, and it leaks source code, settings, and stack traces directly.",
    },
    "laravel": {
        "category": "Server-side framework",
        "description": "A popular PHP web framework.",
        "security_notes": "Check whether APP_DEBUG is left enabled (leaks stack traces and environment variables including secrets) and whether the .env file is accidentally web-accessible.",
    },
    "ruby on rails": {
        "category": "Server-side framework",
        "description": "A Ruby web framework.",
        "security_notes": "Check the version against known CVEs — Rails has had several notable deserialization/RCE vulnerabilities historically. Verbose error pages in production are also worth checking for.",
    },
    "express": {
        "category": "Server-side framework",
        "description": "A minimal Node.js web framework — very common as the backend for JavaScript-heavy sites and APIs.",
        "security_notes": "Express itself is minimal by design, so security depends heavily on which middleware is used — check for missing security headers (helmet.js not used), verbose stack traces, and permissive CORS configuration.",
    },
    "next.js": {
        "category": "Frontend framework",
        "description": "A React-based framework for server-rendered and statically-generated sites.",
        "security_notes": "Check for accidentally-exposed API routes and server-side environment variables leaking into client-side bundles (a common Next.js-specific misconfiguration).",
    },
    "flask": {
        "category": "Server-side framework",
        "description": "A lightweight Python web framework.",
        "security_notes": "Check specifically whether debug mode is enabled in production — like Django, this is a severe, common misconfiguration that leaks an interactive debugger and source code.",
    },

    # --- JS libraries / frontend ---
    "jquery": {
        "category": "JavaScript library",
        "description": "A widely-used JavaScript library for DOM manipulation — extremely common, though declining in modern development.",
        "security_notes": "Versions before 3.5.0 have known XSS vulnerabilities in their HTML-parsing functions. Worth checking the exact version against jQuery's own security advisories.",
    },
    "react": {
        "category": "JavaScript framework",
        "description": "A JavaScript library for building user interfaces, maintained by Meta.",
        "security_notes": "React itself auto-escapes output by default, so XSS usually comes from dangerouslySetInnerHTML misuse rather than the framework — not something detectable from the outside, but worth knowing if source is available.",
    },
    "angular": {
        "category": "JavaScript framework",
        "description": "A full JavaScript framework maintained by Google, common in enterprise applications.",
        "security_notes": "Check the version — AngularJS (1.x, now end-of-life) has known sandbox-escape/XSS issues distinct from the modern Angular (2+) rewrite.",
    },
    "vue.js": {
        "category": "JavaScript framework",
        "description": "A progressive JavaScript framework for building user interfaces.",
        "security_notes": "Generally has safe defaults; issues usually come from v-html misuse (rendering unescaped content) rather than the framework itself.",
    },
    "bootstrap": {
        "category": "CSS framework",
        "description": "A widely-used CSS/JS framework for responsive design — purely presentational, not a security-relevant technology on its own.",
        "security_notes": "No direct security implications; mainly useful as a hint about the site's general tech stack age/style.",
    },

    # --- Analytics / marketing ---
    "google analytics": {
        "category": "Analytics",
        "description": "Google's web analytics/tracking service.",
        "security_notes": "Not a security concern directly, though it's a data-privacy consideration (GDPR/POPIA relevance) worth noting in a company profile.",
    },
    "google tag manager": {
        "category": "Analytics / tag management",
        "description": "A Google service for deploying tracking/marketing scripts without editing site code directly.",
        "security_notes": "Whoever has access to the GTM container can inject arbitrary JavaScript into the site — worth understanding who has that access as part of a supply-chain risk assessment.",
    },

    # --- Security-relevant header findings (whatweb reports these as their own 'plugins') ---
    "httponly": {
        "category": "Security header (cookie flag)",
        "description": "Indicates at least one cookie is marked HttpOnly, preventing client-side JavaScript from reading it.",
        "security_notes": "This is a good sign, not a finding to remediate — its presence reduces the impact of any XSS that does occur. Its *absence* on session cookies specifically would be the thing worth flagging.",
    },
    "strict-transport-security": {
        "category": "Security header (HSTS)",
        "description": "Indicates the HTTP Strict-Transport-Security header is present, telling browsers to only ever connect over HTTPS.",
        "security_notes": "Good practice — its presence protects against SSL-stripping downgrade attacks. Worth checking the max-age value and whether includeSubDomains is set for full coverage.",
    },
    "uncommonheaders": {
        "category": "Observation",
        "description": "whatweb flags response headers it doesn't recognize as standard — often custom, internal, or debug headers.",
        "security_notes": "Worth reviewing manually — these sometimes leak internal hostnames, framework/version details, or debug information not intended to be public.",
    },
    "x-powered-by": {
        "category": "Information disclosure",
        "description": "A header some frameworks (PHP, ASP.NET, Express) add automatically, announcing the underlying technology and often its version.",
        "security_notes": "Not a vulnerability itself, but unnecessary information disclosure — makes targeted attacks easier by removing guesswork. Straightforward to remove/suppress and generally worth doing.",
    },
    "cookies": {
        "category": "Observation",
        "description": "Indicates the site sets one or more cookies.",
        "security_notes": "Worth checking whether session/auth cookies specifically have Secure, HttpOnly, and SameSite attributes set — this plugin alone doesn't tell you which, just that cookies exist.",
    },
}


# ---------------------------------------------------------------------------
# Port/service knowledge base — plain-English context for common ports,
# same philosophy as the technology one above: general "what to check"
# guidance rather than a live CVE feed. Keyed by port number as a string.
# ---------------------------------------------------------------------------
PORT_KNOWLEDGE_BASE = {
    "21": {"service": "FTP", "description": "File Transfer Protocol — an old protocol for file transfer.",
           "security_notes": "Plain FTP transmits credentials in cleartext. Check whether anonymous login is allowed and whether FTPS/SFTP is available as an alternative."},
    "22": {"service": "SSH", "description": "Secure Shell — encrypted remote administration access.",
           "security_notes": "Check for password authentication still being allowed (key-only is stronger), and whether it's exposed to the whole internet vs. restricted by IP/VPN."},
    "23": {"service": "Telnet", "description": "An old remote-administration protocol with no encryption at all.",
           "security_notes": "Credentials and all traffic are sent in cleartext. Finding this open at all on an internet-facing host is a significant finding worth flagging directly — migration to SSH is the standard fix."},
    "25": {"service": "SMTP", "description": "Simple Mail Transfer Protocol — mail server communication.",
           "security_notes": "Check for open relay configuration (allows anyone to send mail through it, a spam/abuse risk) and whether STARTTLS is supported."},
    "53": {"service": "DNS", "description": "Domain Name System — resolves hostnames to IPs.",
           "security_notes": "Check whether this is a recursive resolver open to the whole internet (can be abused for DNS amplification DDoS attacks) vs. authoritative-only."},
    "80": {"service": "HTTP", "description": "Unencrypted web traffic.",
           "security_notes": "Check whether it properly redirects to HTTPS (443) rather than serving content unencrypted, and if a redirect exists, whether it's a permanent (301) redirect."},
    "110": {"service": "POP3", "description": "An older email retrieval protocol.",
            "security_notes": "Check whether this is plain POP3 (cleartext credentials) or POP3S (995, encrypted) — plain POP3 exposed externally is a credential-interception risk."},
    "111": {"service": "RPCbind", "description": "Unix RPC port mapper, often associated with NFS.",
            "security_notes": "Frequently a sign of NFS being present — check port 2049 too. RPC services exposed to the internet are a common source of information disclosure and, historically, RCE."},
    "135": {"service": "MSRPC", "description": "Microsoft RPC endpoint mapper, a Windows service.",
            "security_notes": "Exposed to the internet, this has historically been a significant attack surface (e.g. Blaster worm). Should generally not be internet-facing at all."},
    "139": {"service": "NetBIOS", "description": "An older Windows file-sharing protocol, predecessor to modern SMB.",
            "security_notes": "Should not be exposed to the internet — has a long history of information disclosure and exploitation. Check for null session access."},
    "143": {"service": "IMAP", "description": "Internet Message Access Protocol — email retrieval.",
            "security_notes": "Check whether this is plain IMAP (cleartext) or IMAPS (993, encrypted) — plain IMAP exposed externally risks credential interception."},
    "389": {"service": "LDAP", "description": "Lightweight Directory Access Protocol — often Active Directory or another directory service.",
            "security_notes": "Check whether anonymous binds are allowed (can leak directory structure/usernames) and whether this should be internet-facing at all — usually shouldn't be."},
    "443": {"service": "HTTPS", "description": "Encrypted web traffic — the standard secure web port.",
            "security_notes": "Check the certificate's validity/expiry, the TLS version supported (older than TLS 1.2 is a finding), and cipher suite strength."},
    "445": {"service": "SMB", "description": "Server Message Block — modern Windows file sharing.",
            "security_notes": "Should essentially never be exposed to the internet directly — this port is associated with some of the most severe worms/ransomware in history (WannaCry/EternalBlue exploited SMBv1 specifically). Check the SMB version and whether SMBv1 is still enabled."},
    "465": {"service": "SMTPS", "description": "Encrypted SMTP (mail submission over implicit TLS).",
            "security_notes": "Generally fine if properly configured — check certificate validity and that authentication is required."},
    "587": {"service": "SMTP submission", "description": "The standard port for authenticated mail submission (as opposed to server-to-server SMTP on 25).",
            "security_notes": "Check that STARTTLS is enforced and that authentication is actually required, not optional."},
    "993": {"service": "IMAPS", "description": "Encrypted IMAP.",
            "security_notes": "Generally fine if properly configured — check certificate validity and TLS version."},
    "995": {"service": "POP3S", "description": "Encrypted POP3.",
            "security_notes": "Generally fine if properly configured — check certificate validity and TLS version."},
    "1433": {"service": "MSSQL", "description": "Microsoft SQL Server's default port.",
             "security_notes": "A database port exposed directly to the internet is almost always a significant finding — check whether this is actually necessary, and if so, that strong authentication (not default 'sa' credentials) and IP restriction are in place."},
    "1521": {"service": "Oracle DB", "description": "Oracle database's default listener port.",
             "security_notes": "Same consideration as other exposed databases — internet exposure is a significant finding on its own. Check for default TNS listener misconfigurations."},
    "2049": {"service": "NFS", "description": "Network File System — Unix/Linux file sharing.",
             "security_notes": "Check export permissions (who's allowed to mount) — misconfigured NFS exports are a classic source of unauthorized file access."},
    "2375": {"service": "Docker (unencrypted)", "description": "The Docker daemon's unencrypted remote API port.",
             "security_notes": "Exposing this without TLS is equivalent to giving root access to the host — anyone who can reach this port can run arbitrary containers with host access. Should never be exposed without mutual TLS auth, and ideally not at all."},
    "2376": {"service": "Docker (TLS)", "description": "The Docker daemon's TLS-encrypted remote API port.",
             "security_notes": "Better than 2375, but still check that client certificate authentication is actually enforced, not just that TLS is available."},
    "3306": {"service": "MySQL", "description": "MySQL/MariaDB database's default port.",
             "security_notes": "Internet-facing database ports are almost always a significant finding — check whether external access is actually needed, and if so, verify strong authentication and IP restriction."},
    "3389": {"service": "RDP", "description": "Remote Desktop Protocol — Windows remote access.",
             "security_notes": "A very common ransomware entry point via credential stuffing/brute force. Check that Network Level Authentication (NLA) is enforced and consider whether it should be reachable from the internet at all vs. behind a VPN."},
    "5432": {"service": "PostgreSQL", "description": "PostgreSQL database's default port.",
             "security_notes": "Internet-facing database ports are almost always a significant finding — check pg_hba.conf-style access restrictions and authentication strength."},
    "5900": {"service": "VNC", "description": "Virtual Network Computing — remote desktop access.",
             "security_notes": "VNC historically has weak default authentication (and sometimes none at all). Finding this open to the internet is a significant finding worth flagging directly."},
    "5984": {"service": "CouchDB", "description": "Apache CouchDB's default HTTP API port.",
             "security_notes": "Older CouchDB versions have well-known unauthenticated-admin-access misconfigurations. Check whether authentication is actually required for admin endpoints."},
    "6379": {"service": "Redis", "description": "Redis in-memory data store's default port.",
             "security_notes": "Redis has no authentication by default in many configurations — an exposed, unauthenticated Redis instance allows full read/write access to whatever data it holds, and has historically been used for remote code execution via config manipulation. Check whether AUTH is configured."},
    "8080": {"service": "HTTP (alt)", "description": "A common alternate HTTP port, often used for admin panels, dev servers, or app servers running behind a reverse proxy.",
             "security_notes": "Worth checking what's actually running here specifically — alternate ports are sometimes used to 'hide' admin interfaces that have weaker access controls than the main site."},
    "8443": {"service": "HTTPS (alt)", "description": "A common alternate HTTPS port, similar use cases to 8080.",
             "security_notes": "Same consideration as 8080 — check what's actually running and whether it has appropriate access controls."},
    "9000": {"service": "PHP-FPM / misc", "description": "Commonly PHP-FPM's FastCGI port, though also used by various other admin/dev tools.",
             "security_notes": "PHP-FPM exposed directly to the internet (rather than only to the local web server) is a significant misconfiguration that can lead to source code disclosure or code execution."},
    "9200": {"service": "Elasticsearch", "description": "Elasticsearch's default HTTP API port.",
             "security_notes": "Elasticsearch has no authentication by default in many configurations — an exposed instance allows anyone to read/write/delete the entire index. This has been one of the most common causes of major data breaches from misconfigured cloud infrastructure. Check for authentication and internet exposure directly."},
    "11211": {"service": "Memcached", "description": "Memcached's default port, an in-memory caching service.",
              "security_notes": "Has no authentication in most deployments and has been widely abused for massive DDoS amplification attacks when exposed to the internet over UDP. Should not be internet-facing."},
    "27017": {"service": "MongoDB", "description": "MongoDB's default port.",
              "security_notes": "MongoDB historically shipped with no authentication enabled by default, leading to widespread exposure/ransom incidents. Check whether authentication is required and whether this needs to be internet-facing at all."},
}


def _strip_version_suffix(name: str) -> str:
    """'Nginx 1.18.0' -> 'nginx', 'Microsoft-IIS/10.0' -> 'microsoft-iis',
    'WordPress' -> 'wordpress' — technology names from whatweb/nuclei
    come in several different formats (space-separated, slash-separated
    server-banner style) with a version number appended that a plain KB
    lookup needs stripped first, regardless of which format it's in."""
    name = name.strip().lower()
    # Slash-separated banner style, e.g. "microsoft-iis/10.0" -> "microsoft-iis"
    name = re.split(r"/\d", name)[0]
    # Space-separated, e.g. "nginx 1.18.0" -> "nginx" — keeps names that
    # are legitimately alphanumeric throughout, e.g. "ruby on rails"
    match = re.match(r"^([a-z][a-z0-9.\s\-]*?)\s+\d", name)
    if match:
        name = match.group(1)
    return name.strip().rstrip("/-")



TECH_KB_ALIASES = {
    "httpd": "apache", "apache httpd": "apache", "apache2": "apache",
    "microsoft-iis": "iis", "microsoft iis": "iis",
    "wp": "wordpress",
    "reactjs": "react", "react.js": "react",
    "vue": "vue.js", "vuejs": "vue.js",
    "angularjs": "angular",
    "gtm": "google tag manager",
    "ga": "google analytics", "google-analytics": "google analytics",
    "rails": "ruby on rails", "ror": "ruby on rails",
    "expressjs": "express", "express.js": "express",
    "nextjs": "next.js",
    "cf": "cloudflare",
}


def tech_kb_lookup(name: str) -> Optional[dict]:
    key = _strip_version_suffix(name)
    key = TECH_KB_ALIASES.get(key, key)
    return TECH_KNOWLEDGE_BASE.get(key)





def get_json_path(obj, path: str):
    """Traverse a dotted path through nested dicts. Returns None if any hop
    isn't a dict (arrays mid-path aren't supported — see get_json_path list
    handling in extract helpers below for the one place that needs it)."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


# ---------------------------------------------------------------------------
# Parsers — CLI tool output
# ---------------------------------------------------------------------------
def parse_plain_hostnames(lines: list[str], domain: str) -> set[str]:
    out = set()
    for raw in lines:
        token = raw.strip().split()[0] if raw.strip() else ""
        token = token.strip(".").lower()
        if token and domain in token:
            out.add(token)
    return out


def parse_json_field_hostnames(lines: list[str], field_path: str, domain: str) -> set[str]:
    out = set()
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        val = get_json_path(obj, field_path)
        if isinstance(val, str):
            v = val.strip().lower().strip(".")
            if v and domain in v:
                out.add(v)
    return out


def parse_dnsx_json(lines: list[str]) -> dict[str, list[str]]:
    """Every A record dnsx found per host — not just the first. Multiple
    A records are extremely common for anything behind a CDN or load
    balancer, and only ever capturing the first one (as this used to do)
    meant only that single edge/backend IP ever got port-scanned — even
    though a live HTTP request (httpx does its own separate DNS
    resolution at connection time) can easily land on a different IP
    from the same pool. That mismatch was a real, confirmed cause of
    nmap turning up nothing for a host httpx had just confirmed live
    seconds earlier: not a scanning failure, just the wrong IP being
    scanned. See _dnsx() below for how this is used.
    """
    out = {}
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("input")
        ips = obj.get("a") or obj.get("A") or []
        if host and ips:
            out[host.lower()] = ips
    return out


def parse_httpx_json(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        tech = obj.get("tech") or obj.get("technologies") or []
        out.append(
            {
                "subdomain": (obj.get("input") or obj.get("host") or "").lower(),
                "url": obj.get("url", ""),
                # With -fr (follow redirects), "url" reflects the final
                "final_url": obj.get("final_url") or obj.get("url", ""),
                "status_code": obj.get("status_code") or obj.get("status-code"),
                "title": obj.get("title", ""),
                "tech": ", ".join(tech) if isinstance(tech, list) else str(tech),
                "server": obj.get("webserver") or obj.get("server", ""),
                "ip": obj.get("host_ip") or obj.get("ip", ""),
            }
        )
    return out


def parse_naabu_json(lines: list[str]) -> list[tuple[str, int]]:
    out = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host") or obj.get("ip")
        port = obj.get("port")
        if host and port:
            try:
                out.append((host.lower(), int(port)))
            except (TypeError, ValueError):
                continue
    return out


def looks_like_wrong_binary(lines: list[str]) -> bool:
    """Detects the tell-tale sign that a *different* program with the same
    binary name got invoked instead of the recon tool meant — most
    commonly Python's `httpx[cli]` HTTP client package shadowing
    ProjectDiscovery's httpx recon tool (identical binary name, completely
    different tool). Click (the CLI framework several Python packages use)
    has a very recognizable error format that ProjectDiscovery's Go tools
    never produce, which is what this checks for."""
    joined = "\n".join(lines)
    return "No such option" in joined or ("Usage:" in joined and "[OPTIONS]" in joined)


_RESOLVED_BINARY_CACHE: dict[str, Optional[str]] = {}


async def find_working_binary(name: str, version_flag: str, scan_id: Optional[int] = None) -> Optional[str]:
    """`shutil.which()` only ever returns the *first* match on PATH — if
    that one happens to be the wrong program (see looks_like_wrong_binary
    above), every other same-named binary further down PATH is invisible
    to it. This instead checks every `name` found across every PATH
    directory (the same set `which -a` would show), running each with
    `version_flag` until one responds without the Click-style error
    signature, and uses that one. If several exist and the first one on
    PATH turns out to be the wrong program, this silently picks a working
    one instead — no PATH surgery required from the user, though a log
    line explains what happened so it's not a mystery.

    Re-checks well-known install locations (see
    _extend_path_for_common_tool_locations) on every call rather than
    only once at process startup — a tool can genuinely get installed
    *while this app is still running* (mid-troubleshooting, right after
    install.sh finishes in another terminal), and the very next scan
    should be able to find it without needing a restart.

    Only a *successful* resolution gets cached. A failed one (nothing on
    PATH responded correctly) deliberately does not get cached — caching
    that would mean a tool installed after the first failed attempt could
    never be picked up again for the life of the process, which is
    exactly the bug this fixes: install.sh finishing *after* this app
    already tried and failed to find a working httpx used to mean the
    fix wouldn't take effect until a full app restart.
    """
    if name in _RESOLVED_BINARY_CACHE:
        return _RESOLVED_BINARY_CACHE[name]

    newly_added = _extend_path_for_common_tool_locations()
    if newly_added and scan_id is not None:
        await log_line(
            scan_id, f"[{name}] found tools outside this session's PATH — added: {', '.join(newly_added)}", "meta"
        )

    candidates: list[str] = []
    seen_dirs: set[str] = set()
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory or directory in seen_dirs:
            continue
        seen_dirs.add(directory)
        candidate = Path(directory) / name
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                candidates.append(str(candidate))
        except OSError:
            continue

    working: Optional[str] = None
    for candidate in candidates:
        try:
            proc = await asyncio.create_subprocess_exec(
                candidate, version_flag,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            )
            raw = await asyncio.wait_for(proc.stdout.read(), timeout=5)
            await proc.wait()
            if not looks_like_wrong_binary(raw.decode(errors="replace").splitlines()):
                working = candidate
                break
        except Exception:
            continue

    if working is not None:
        if scan_id is not None and len(candidates) > 1:
            skipped = [c for c in candidates if c != working]
            if skipped:
                await log_line(
                    scan_id,
                    f"[{name}] multiple '{name}' found on PATH — using {working} "
                    f"(skipped {', '.join(skipped)}, which didn't respond like the real tool)",
                    "meta",
                )
        _RESOLVED_BINARY_CACHE[name] = working
        return working

    # Nothing passed the probe. Fall back to whatever's first on PATH (or
    # None) so the normal "not found"/error-explaining paths still have
    # something concrete to report — but deliberately don't cache this,
    # so the next call tries again from scratch instead of being stuck.
    return candidates[0] if candidates else shutil.which(name)


def parse_nmap_xml(xml_text: str) -> dict:
    """Parses nmap's -oX XML output. Used instead of -oG (greppable)
    specifically because greppable format has no way to represent NSE
    script output or OS detection results at all — that's a hard
    limitation of the format itself, not a parsing choice. -sC/-A were
    already being passed (and costing real scan time to run) with their
    output structurally impossible to capture under the old format, so
    switching to XML was necessary, not just an enhancement.

    Returns {
        "hits": [(ip, port, service_string), ...],  # same shape the old
            greppable parser returned, so callers didn't need to change,
        "scripts": {ip: [{"port": int|None, "script_id": str, "output": str}, ...]},
            # port is None for host-level scripts (some smb-*/dns-*
            # scripts run once per host, not per port)
        "os_guesses": {ip: "OS name (NN% confidence)"},
    }
    Malformed XML (a killed/crashed nmap process, an empty stream) is
    handled the same way a missing results file is handled elsewhere in
    this app — logged and treated as "nothing found", not a crash.
    """
    hits: list[tuple[str, int, str]] = []
    scripts: dict[str, list[dict]] = {}
    os_guesses: dict[str, str] = {}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {"hits": hits, "scripts": scripts, "os_guesses": os_guesses}

    MAX_SCRIPT_OUTPUT = 2000  # a verbose script (e.g. a vuln-check) shouldn't produce an oversized host_intel row

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        # Prefer the ipv4 address specifically rather than relying on
        # ElementTree's attribute-predicate XPath support, which varies
        # across versions — iterating plainly is safer and just as fast
        # at this scale (a handful of <address> elements per host).
        ip = None
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr")
                break
        if not ip:
            first_addr = host_el.find("address")
            ip = first_addr.get("addr") if first_addr is not None else None
        if not ip:
            continue

        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            for script_el in hostscript_el.findall("script"):
                sid, output = script_el.get("id"), script_el.get("output")
                if sid and output:
                    scripts.setdefault(ip, []).append(
                        {"port": None, "script_id": sid, "output": output.strip()[:MAX_SCRIPT_OUTPUT]}
                    )

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                try:
                    port_num = int(port_el.get("portid"))
                except (TypeError, ValueError):
                    continue

                service_name = ""
                service_el = port_el.find("service")
                if service_el is not None:
                    parts = [service_el.get("name") or "", service_el.get("product") or "", service_el.get("version") or ""]
                    service_name = " ".join(p for p in parts if p).strip()

                hits.append((ip, port_num, service_name))

                for script_el in port_el.findall("script"):
                    sid, output = script_el.get("id"), script_el.get("output")
                    if sid and output:
                        scripts.setdefault(ip, []).append(
                            {"port": port_num, "script_id": sid, "output": output.strip()[:MAX_SCRIPT_OUTPUT]}
                        )

        os_el = host_el.find("os")
        if os_el is not None:
            osmatch_el = os_el.find("osmatch")
            if osmatch_el is not None and osmatch_el.get("name"):
                accuracy = osmatch_el.get("accuracy")
                os_guesses[ip] = f"{osmatch_el.get('name')} ({accuracy}% confidence)" if accuracy else osmatch_el.get("name")

    return {"hits": hits, "scripts": scripts, "os_guesses": os_guesses}


# ---------------------------------------------------------------------------
# OSINT sources
# ---------------------------------------------------------------------------
async def crtsh_lookup(scan_id: int, domain: str) -> set[str]:
    """Certificate Transparency search via crt.sh — free, no key. Also pulls
    issuer org strings as a loose signal of hosting/CDN provider.

    crt.sh is a free community service that's frequently overloaded —
    502/503/504 are common under load, and they're usually transient, so
    those specifically get a couple of quick retries before giving up.
    Anything else (a real 4xx, a connection failure, etc.) fails straight
    away rather than wasting time retrying something that won't change."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    await log_line(
        scan_id,
        "[why] crt.sh: searches public certificate transparency logs for any TLS "
        "certificate ever issued covering this domain — surfaces subdomains that "
        "were only ever exposed briefly, or that no DNS-brute-force wordlist would guess.",
        "why",
    )
    await log_line(scan_id, "$ crt.sh certificate transparency lookup", "cmd")
    names = set()
    issuers = set()
    data = None
    for attempt in range(3):
        try:
            data = await http_get_json(url, timeout=30)
            break
        except urllib.error.HTTPError as e:
            if e.code in (502, 503, 504) and attempt < 2:
                await log_line(scan_id, f"[crt.sh] HTTP {e.code} (server likely overloaded) — retrying in 4s...", "warn")
                await asyncio.sleep(4)
                continue
            await log_line(scan_id, f"[error] crt.sh lookup failed: HTTP {e.code}", "error")
            return names
        except Exception as e:
            await log_line(scan_id, f"[error] crt.sh lookup failed: {e}", "error")
            return names

    if data is None:
        return names
    try:
        entries = data[:3000] if isinstance(data, list) else []
        for entry in entries:
            nv = entry.get("name_value", "") or ""
            for n in nv.split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n and domain in n:
                    names.add(n)
            iss = entry.get("issuer_name", "") or ""
            m = re.search(r"O=([^,]+)", iss)
            if m:
                issuers.add(m.group(1).strip())
        if issuers:
            conn = get_db()
            store_intel(conn, scan_id, domain, "crtsh", "cert_issuers", ", ".join(sorted(issuers)))
            conn.commit()
            conn.close()
        await log_line(scan_id, f"[done] crt.sh — {len(names)} names from {len(entries)} certs", "meta")
    except Exception as e:
        await log_line(scan_id, f"[error] crt.sh lookup failed: {e}", "error")
    return names


WHOIS_KEY_MAP = {
    "registrant organization": "registrant_org",
    "registrant org": "registrant_org",
    "registrant country": "registrant_country",
    "registrar": "registrar",
}
WHOIS_DATE_KEYS = {
    "creation date": "created",
    "created on": "created",
    "domain registration date": "created",
    "registry expiry date": "expires",
    "expiration date": "expires",
    "expiry date": "expires",
    "registrar registration expiration date": "expires",
    "updated date": "updated",
    "last updated on": "updated",
    "domain last updated date": "updated",
}

# Some TLDs aren't reliably resolved by the standard whois client's own
# IANA-referral-following logic — when it can't cleanly parse a referral
# line, it falls back to guessing "whois.nic.<tld>", which is wrong for
# TLDs where the registry runs whois under a different name. Google's
# registry (Charleston Road Registry) is the most common case in practice:
# .app/.dev/.page all actually use whois.nic.google, not whois.nic.app/
# whois.nic.dev/whois.nic.page, so the guess fails outright with a DNS
# lookup error on a whois server that doesn't exist.
WHOIS_SERVER_OVERRIDES = {
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "page": "whois.nic.google",
}


async def whois_lookup(scan_id: int, domain: str, mode: str = "fast"):
    """Best-effort WHOIS parse — field names vary a fair bit by TLD/registrar,
    so this captures the common ones and leaves the rest out rather than
    guessing wrong."""
    cmd = apply_variant(["whois", domain], "whois", mode)
    lines = await run_stream(scan_id, cmd, "whois")

    tld = domain.rsplit(".", 1)[-1].lower()
    failed_lookup = not lines or any(
        ("getaddrinfo" in l and ("not known" in l.lower() or "failure" in l.lower()))
        or "no whois server is known for" in l.lower()
        for l in lines
    )
    if tld in WHOIS_SERVER_OVERRIDES and failed_lookup:
        override = WHOIS_SERVER_OVERRIDES[tld]
        await log_line(
            scan_id,
            f"[whois] .{tld} isn't reliably found by this whois client's own referral logic — retrying against {override} directly",
            "meta",
        )
        lines = await run_stream(scan_id, ["whois", "-h", override, domain], "whois (retry)")

    if not lines:
        return
    fields: dict[str, str] = {}
    name_servers = set()
    statuses = set()
    for line in lines:
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9 /\-.]*):\s*(.+?)\s*$", line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        if not val or "redacted" in val.lower():
            continue
        if key == "name server":
            name_servers.add(val.lower())
        elif key == "domain status":
            statuses.add(val.split()[0] if val else val)
        elif key in WHOIS_KEY_MAP:
            fields.setdefault(WHOIS_KEY_MAP[key], val)
        elif key in WHOIS_DATE_KEYS:
            fields.setdefault(WHOIS_DATE_KEYS[key], val)

    conn = get_db()
    for k, v in fields.items():
        store_intel(conn, scan_id, domain, "whois", k, v)
    if name_servers:
        store_intel(conn, scan_id, domain, "whois", "name_servers", ", ".join(sorted(name_servers)))
    if statuses:
        store_intel(conn, scan_id, domain, "whois", "status", ", ".join(sorted(statuses)))
    conn.commit()
    conn.close()
    await log_line(scan_id, f"[whois] parsed {len(fields)} fields, {len(name_servers)} name servers", "meta")


async def theharvester_run(scan_id: int, domain: str, mode: str = "full") -> tuple[set[str], set[str]]:
    binary = find_binary(HARVESTER_BINARIES)
    if not binary:
        await log_line(scan_id, "[skip] theHarvester not found on PATH — skipping theharvester", "warn")
        return set(), set()
    cmd = apply_variant([binary, "-d", domain, "-b", HARVESTER_SOURCES], "theharvester", mode)
    lines = await run_stream(scan_id, cmd, "theharvester")
    hostnames: set[str] = set()
    emails: set[str] = set()
    host_re = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+" + re.escape(domain), re.IGNORECASE)
    email_re = re.compile(r"[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+")
    for line in lines:
        for m in host_re.findall(line):
            h = m.strip(".").lower()
            if domain in h:
                hostnames.add(h)
        for m in email_re.findall(line):
            emails.add(m.strip().lower())
    # theHarvester's own output can legitimately include emails found on
    # third-party pages that merely mention this domain (a directory
    # listing, a news article, a WHOIS/registrar record) — confirmed
    # directly as a real source of off-domain noise, the same class of
    # problem as the site-scraping filter in social_scan. Restricting to
    # genuinely @ this domain here is what theHarvester's own hostname
    # extraction two lines up already does; the email side never had the
    # same restriction until now.
    kept_emails = filter_emails_to_domain(emails, domain)
    discarded = len(emails) - len(kept_emails)
    if discarded:
        await log_line(scan_id, f"[theharvester] discarded {discarded} email(s) not @ {domain}", "meta")
    return hostnames, kept_emails


async def ip_geo_lookup(scan_id: int, ips: list[str]):
    """Free geolocation/org lookup via ip-api.com — no key, ~45 req/min limit
    on the free tier, so this throttles itself between calls. Opens a fresh
    DB connection per IP rather than holding one across the whole loop —
    the loop spans network calls and deliberate throttle sleeps, and a
    connection held open across that many awaits was blocking other writers
    (e.g. the live log stream) with 'database is locked' errors."""
    if not ips:
        return
    await log_line(scan_id, f"[+] ip-api.com geolocation for {len(ips)} unique IPs", "meta")
    for i, ip in enumerate(ips):
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon"
        )
        try:
            data = await http_get_json(url, timeout=10)
            if data.get("status") == "success":
                conn = get_db()
                try:
                    for f in ("country", "countryCode", "regionName", "city", "isp", "org", "as"):
                        val = data.get(f)
                        if val:
                            store_intel(conn, scan_id, ip, "ip-geo", f, val)
                    lat, lon = data.get("lat"), data.get("lon")
                    if lat is not None and lon is not None:
                        store_intel(conn, scan_id, ip, "ip-geo", "coordinates", f"{lat}, {lon}")
                    conn.commit()
                finally:
                    conn.close()
                await log_line(
                    scan_id,
                    f"[ip-geo] {ip}: {data.get('city', '-')}, {data.get('country', '-')} ({data.get('org', '-')})",
                    "out",
                )
            else:
                await log_line(scan_id, f"[ip-geo] {ip}: {data.get('message', 'lookup failed')}", "warn")
        except Exception as e:
            await log_line(scan_id, f"[ip-geo] {ip}: failed — {e}", "warn")
        if i < len(ips) - 1:
            await asyncio.sleep(1.5)


async def internetdb_lookup(scan_id: int, ips: list[str]):
    """Shodan's InternetDB — a free, unauthenticated lookup returning open
    ports, hostnames, CPEs, tags, and known CVEs for an IP, refreshed
    weekly. No key, no account — a genuinely free complement to this
    app's optional full Shodan API integration below, which needs a paid
    membership for its search/host endpoints. Response schema (ip, ports,
    hostnames, cpes, vulns, tags) confirmed directly against Shodan's own
    API documentation rather than assumed."""
    if not ips:
        return
    await log_line(scan_id, f"[+] Shodan InternetDB lookup for {len(ips)} unique IPs (free, no key)", "meta")
    for i, ip in enumerate(ips):
        url = f"https://internetdb.shodan.io/{ip}"
        try:
            data = await http_get_json(url, timeout=10)
            conn = get_db()
            try:
                ports = sorted(data.get("ports") or [])
                if ports:
                    store_intel(conn, scan_id, ip, "internetdb", "ports", ", ".join(str(p) for p in ports))
                hostnames = data.get("hostnames") or []
                if hostnames:
                    store_intel(conn, scan_id, ip, "internetdb", "hostnames", ", ".join(hostnames))
                cpes = data.get("cpes") or []
                if cpes:
                    store_intel(conn, scan_id, ip, "internetdb", "cpes", ", ".join(cpes))
                vulns = sorted(data.get("vulns") or [])
                if vulns:
                    store_intel(conn, scan_id, ip, "internetdb", "vulns", ", ".join(vulns))
                    # This is the fix for a real gap found during an audit
                    # of this app: these CVE IDs were previously ONLY
                    # stored as a comma-joined text string above — never
                    # surfaced as an actual vulnerability finding, so they
                    # were invisible from the Vulnerability tab entirely,
                    # even though InternetDB is free, keyless, and runs by
                    # default. Treated as "high" severity by default —
                    # InternetDB only reports CVEs it has actually matched
                    # against the service's own fingerprint, so this is a
                    # confirmed signature match, not a guess — though it's
                    # a fingerprint match, not a verified live exploit, so
                    # the detail field says so explicitly rather than
                    # overstate the confidence. matched_at links straight
                    # to the NVD entry so a person can immediately see
                    # what the CVE actually is.
                    for cve in vulns:
                        conn.execute(
                            "INSERT INTO vulnerabilities (scan_id, host, source, template_id, name, severity, "
                            "matched_at, is_takeover, detail) VALUES (?, ?, 'internetdb', ?, ?, 'high', ?, 0, ?)",
                            (
                                scan_id, ip, cve, f"Known vulnerable service ({cve})",
                                f"https://nvd.nist.gov/vuln/detail/{cve}",
                                "Flagged by Shodan InternetDB — the service's fingerprint matches a known-"
                                "vulnerable version. This is a signature match, not a verified live exploit; "
                                "confirm manually before treating it as certain.",
                            ),
                        )
                tags = data.get("tags") or []
                if tags:
                    store_intel(conn, scan_id, ip, "internetdb", "tags", ", ".join(tags))
                conn.commit()
            finally:
                conn.close()
            await log_line(scan_id, f"[internetdb] {ip}: {len(ports)} port(s), {len(vulns)} known CVE(s)", "out")
        except urllib.error.HTTPError as e:
            # InternetDB returns 404 for an IP it simply has nothing on —
            # not an error condition, just "no data", so this stays at
            # 'out' level rather than 'warn' to avoid flagging normal
            # non-findings as if something went wrong.
            if e.code == 404:
                await log_line(scan_id, f"[internetdb] {ip}: no data available", "out")
            else:
                await log_line(scan_id, f"[internetdb] {ip}: HTTP {e.code}", "warn")
        except Exception as e:
            await log_line(scan_id, f"[internetdb] {ip}: failed — {e}", "warn")
        if i < len(ips) - 1:
            await asyncio.sleep(0.3)


async def leakix_lookup(scan_id: int, ips: list[str], api_key: str):
    """LeakIX — free for researchers, but does require a free account and
    API key (unlike InternetDB above), sent via the api-key header. Hits
    the per-host endpoint for each resolved IP; response shape confirmed
    directly from LeakIX's own API docs: {"Services": [...], "Leaks":
    [...]}, both possibly null if nothing was found for that host."""
    if not ips:
        return
    await log_line(scan_id, f"[+] LeakIX host lookup for {len(ips)} unique IPs", "meta")
    for i, ip in enumerate(ips):
        url = f"https://leakix.net/host/{ip}"
        try:
            data = await http_get_json_headers(url, {"api-key": api_key, "Accept": "application/json"}, timeout=15)
            services = data.get("Services") or data.get("services") or []
            leaks = data.get("Leaks") or data.get("leaks") or []
            if not services and not leaks:
                await log_line(scan_id, f"[leakix] {ip}: nothing indexed", "out")
                continue
            conn = get_db()
            try:
                if services:
                    summaries = []
                    for svc in services[:20]:
                        port = svc.get("port")
                        software = (svc.get("software") or {}).get("name") or ""
                        summaries.append(f"{port}/{software}".strip("/"))
                    store_intel(conn, scan_id, ip, "leakix", "services", ", ".join(s for s in summaries if s))
                if leaks:
                    # LeakIX's exact per-leak schema beyond 'plugin' isn't
                    # fully pinned down without live access to test
                    # against, so several reasonable detail fields are
                    # tried before falling back to a compact dump of
                    # whatever the object actually contains — the goal is
                    # to never silently lose a real finding just because
                    # a specific field-name guess was wrong.
                    for leak in leaks:
                        if not isinstance(leak, dict):
                            continue
                        leak_type = leak.get("plugin") or "unknown"
                        detail = (
                            leak.get("summary") or leak.get("description") or leak.get("dataset")
                            or leak.get("data")
                            or ", ".join(f"{k}={v}" for k, v in leak.items() if k != "plugin" and v)
                            or "leak detected, no further detail available"
                        )
                        conn.execute(
                            "INSERT INTO leaks (scan_id, host, source, leak_type, detail) VALUES (?, ?, 'leakix', ?, ?)",
                            (scan_id, ip, leak_type, str(detail)[:500]),
                        )
                conn.commit()
            finally:
                conn.close()
            await log_line(scan_id, f"[leakix] {ip}: {len(services)} service(s), {len(leaks)} leak(s) indexed", "out")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                await log_line(scan_id, f"[leakix] {ip}: nothing indexed", "out")
            elif e.code in (401, 403):
                await log_line(scan_id, f"[leakix] {ip}: authentication failed — check the API key in Settings", "warn")
            else:
                await log_line(scan_id, f"[leakix] {ip}: HTTP {e.code}", "warn")
        except Exception as e:
            await log_line(scan_id, f"[leakix] {ip}: failed — {e}", "warn")
        if i < len(ips) - 1:
            await asyncio.sleep(0.5)


    return people, emails_found


# ---------------------------------------------------------------------------
# gowitness (github.com/sensepost/gowitness) — Chrome-headless website
# screenshots, run against this scan's live HTTP assets. Full-mode only,
# since launching a real browser per target is comparatively slow.
#
# Like crosslinked, this writes to files (a JSONL results file + one image
# per target) rather than to stdout. Screenshot filenames from gowitness's
# own output are only ever trusted after confirming they resolve to a real
# file *inside* this scan's screenshot directory — never used to build a
# path from user/tool input directly — since they get served back over
# HTTP later (see /api/scans/{id}/screenshots/{screenshot_id}/image).
# ---------------------------------------------------------------------------
def _safe_dir_join(base: Path, filename: str) -> Optional[Path]:
    """Resolves `filename` under `base` and returns it only if the result
    is genuinely still inside `base` (blocks '../' escapes) and exists."""
    if not filename:
        return None
    try:
        resolved = (base / filename).resolve()
        base_resolved = base.resolve()
    except OSError:
        return None
    if resolved != base_resolved and base_resolved not in resolved.parents:
        return None
    return resolved if resolved.is_file() else None


def _gw_field(obj: dict, *names):
    """gowitness's JSON field casing isn't fully pinned down across
    versions in the public docs available — this tries the documented
    PascalCase names first (confirmed from the project's own API/wiki
    examples) and falls back to lowercase/snake_case variants, so parsing
    doesn't silently break either way."""
    for n in names:
        if n in obj and obj[n] not in (None, ""):
            return obj[n]
    return None


def parse_gowitness_jsonl(lines: list[str]) -> list[dict]:
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = _gw_field(obj, "URL", "url")
        if not url:
            continue
        out.append({
            "url": url,
            "final_url": _gw_field(obj, "FinalURL", "final_url") or url,
            "status_code": _gw_field(obj, "ResponseCode", "response_code", "status_code"),
            "title": _gw_field(obj, "Title", "title") or "",
            "filename": _gw_field(obj, "Filename", "filename") or "",
            "failed": bool(_gw_field(obj, "Failed", "failed") or False),
            "error": _gw_field(obj, "Error", "error", "Failed") or "",
        })
    return out


def _find_screenshot_file(shot_dir: Path, url: str, claimed: set) -> str:
    """gowitness's exact JSONL filename field wasn't fully verifiable
    without a live headless-Chrome environment to test against (not
    available in development), and a real-world run showed the field-name
    guess was wrong — gowitness's own log confirmed `have-screenshot=true`
    for every target while this app reported 0 captured. Rather than
    depend on getting that field name exactly right, this falls back to
    matching an actual file gowitness wrote to `shot_dir` (ground truth)
    against the target URL's own hostname, so a field-naming mismatch
    can't silently report zero screenshots that genuinely exist on disk.
    """
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except Exception:
        host = ""
    slug_parts = [p for p in re.split(r"[^a-z0-9]+", (host or url).lower()) if len(p) > 2]
    try:
        candidates = sorted(
            f.name for f in shot_dir.iterdir()
            if f.is_file() and f.suffix.lower() in (".jpeg", ".jpg", ".png") and f.name not in claimed
        )
    except OSError:
        return ""
    if not candidates:
        return ""
    # Prefer a file matching every slug part of the hostname (e.g. "www",
    # "sensepost", "com" all appearing) — strict enough to avoid mismatches
    # between similarly-named hosts.
    for fname in candidates:
        fname_lower = fname.lower()
        if slug_parts and all(part in fname_lower for part in slug_parts):
            return fname
    # Loosen to the most distinctive single part (the longest one, usually
    # the actual domain label rather than "www"/"com").
    if slug_parts:
        best_part = max(slug_parts, key=len)
        for fname in candidates:
            if best_part in fname.lower():
                return fname
    return ""


async def gowitness_run(scan_id: int, domain: str, mode: str, urls: list[str]) -> int:
    """Returns the number of screenshots actually captured. Screenshots are
    kept permanently under SCREENSHOTS_DIR/scan_<id>/ (not cleaned up like
    the working temp dir) — they're a genuinely useful artifact worth
    keeping alongside the rest of a scan's results, not scratch space."""
    binary = shutil.which("gowitness")
    if not binary:
        await log_line(scan_id, "[skip] gowitness not found on PATH — skipping gowitness", "warn")
        return 0
    if not urls:
        await log_line(scan_id, "[gowitness] no live HTTP assets to screenshot", "warn")
        return 0

    shot_dir = SCREENSHOTS_DIR / f"scan_{scan_id}"
    shot_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = BASE_DIR / f".scan_{scan_id}_gowitness"
    tmp_dir.mkdir(exist_ok=True)
    urls_file = tmp_dir / "urls.txt"
    urls_file.write_text("\n".join(urls))
    jsonl_path = tmp_dir / "results.jsonl"

    cmd = apply_variant(
        [
            binary, "scan", "file", "-f", str(urls_file),
            "--screenshot-path", str(shot_dir),
            "--write-jsonl", "--write-jsonl-file", str(jsonl_path),
            "--threads", "4", "--timeout", "20",
        ],
        "gowitness", mode,
    )
    await log_line(scan_id, f"[gowitness] screenshotting {len(urls)} live host(s)...", "meta")
    count = 0
    try:
        await run_stream(scan_id, cmd, "gowitness", cwd=tmp_dir)

        if not jsonl_path.exists():
            await log_line(
                scan_id,
                "[gowitness] no results file was produced — this usually means the run failed before "
                "screenshotting anything (check the [out] lines above; a missing/broken Chrome install "
                "is the most common cause — gowitness needs one available, whether system Chrome or "
                "the one it can auto-download)",
                "warn",
            )
            return 0

        raw_jsonl = jsonl_path.read_text(encoding="utf-8", errors="replace")
        results = parse_gowitness_jsonl(raw_jsonl.splitlines())
        conn = get_db()
        claimed_files: set = set()
        fallback_used = 0
        for r in results:
            try:
                host = urllib.parse.urlsplit(r["url"]).hostname or r["url"]
            except Exception:
                host = r["url"]
            filename = r["filename"] if _safe_dir_join(shot_dir, r["filename"]) else ""
            if not filename:
                # The JSONL's own filename field didn't resolve to a real
                # file — fall back to matching one directly from disk
                # rather than reporting this as "no screenshot" when one
                # may well exist.
                fallback_name = _find_screenshot_file(shot_dir, r["url"], claimed_files)
                if fallback_name:
                    filename = fallback_name
                    fallback_used += 1
            if filename:
                claimed_files.add(filename)
            conn.execute(
                "INSERT INTO screenshots (scan_id, host, url, final_url, status_code, title, filename, failed, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, host, r["url"], r["final_url"], r["status_code"], r["title"], filename, int(r["failed"]), r["error"]),
            )
            if filename:
                count += 1
        conn.commit()
        conn.close()

        if fallback_used:
            await log_line(
                scan_id,
                f"[gowitness] matched {fallback_used} screenshot(s) by filename on disk rather than the "
                f"JSONL's own filename field — that field may not be named what this app expected; "
                f"results are still correct, this is just how they were found",
                "meta",
            )
        if count == 0 and results:
            # Nothing resolved even with the fallback — dump a sample of
            # the raw JSONL so the actual field names are visible in the
            # scan log instead of needing another round of guessing.
            sample = raw_jsonl[:600]
            await log_line(
                scan_id,
                f"[gowitness] 0 of {len(results)} results resolved to an actual file — raw JSONL sample "
                f"for diagnosis: {sample}",
                "warn",
            )
        await log_line(
            scan_id,
            f"[+] gowitness: {count} screenshot(s) captured of {len(results)} target(s) attempted",
            "meta",
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    return count


# ---------------------------------------------------------------------------
# WhatWeb (github.com/urbanadventurer/WhatWeb) — technology fingerprinting,
# run as its own dedicated pass rather than relying only on httpx's
# lightweight built-in -tech-detect. Full-mode only, since this app
# defaults it to a thorough pass across every live host.
#
# Chosen over both the commercial Wappalyzer API (paid, requires an
# account) and webanalyze (a Wappalyzer *port* that depends on Wappalyzer's
# own technologies.json, which Wappalyzer stopped publishing — that's
# exactly what broke webanalyze's -update step). WhatWeb has its own
# ~1800-plugin database bundled directly into the package via apt — no
# external definitions file to go stale or disappear.
#
# Like gowitness/crosslinked, --log-json writes to a file, not stdout, so
# this needs the same temp-dir-and-read-back pattern. The exact schema
# (a JSON array of {target, http_status, plugins: {name: {string/version/
# module: [...]}}}) was confirmed against a real sample output rather than
# assumed, including two known WhatWeb quirks defended against here: a
# stray trailing empty object in the array (WhatWeb issue #289), and
# malformed output if given an empty input file (issue #288) — this app
# never calls it with an empty host list, but the parser tolerates
# malformed JSON gracefully either way rather than crashing.
# ---------------------------------------------------------------------------
def parse_whatweb_json(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []

    out = []
    for entry in data:
        if not isinstance(entry, dict) or "target" not in entry:
            continue  # skips the known trailing {} bug (issue #289)
        target = entry.get("target", "")
        plugins = entry.get("plugins", {})
        if not isinstance(plugins, dict):
            continue
        findings = []
        for plugin_name, plugin_data in plugins.items():
            detail = ""
            if isinstance(plugin_data, dict):
                for key in ("version", "string", "module"):
                    val = plugin_data.get(key)
                    if val:
                        detail = ", ".join(str(v) for v in val) if isinstance(val, list) else str(val)
                        break
            findings.append({"name": plugin_name, "detail": detail})
        out.append({"target": target, "findings": findings})
    return out


async def whatweb_run(scan_id: int, domain: str, mode: str, urls: list[str]) -> int:
    """Returns the number of (host, technology) findings stored."""
    binary = shutil.which("whatweb")
    if not binary:
        await log_line(scan_id, "[skip] whatweb not found on PATH — skipping whatweb", "warn")
        return 0
    if not urls:
        await log_line(scan_id, "[whatweb] no live HTTP assets to fingerprint", "warn")
        return 0

    tmp_dir = BASE_DIR / f".scan_{scan_id}_whatweb"
    tmp_dir.mkdir(exist_ok=True)
    hosts_file = tmp_dir / "hosts.txt"
    hosts_file.write_text("\n".join(urls))
    results_file = tmp_dir / "results.json"

    try:
        aggression = "3" if is_aggressive("whatweb") else "1"
        cmd = apply_variant(
            [binary, "-i", str(hosts_file), f"--log-json={results_file}", "-a", aggression, "--no-errors"],
            "whatweb", mode,
        )
        await log_line(
            scan_id,
            f"[whatweb] fingerprinting {len(urls)} live host(s) (aggression {aggression})...",
            "meta",
        )
        await run_stream(scan_id, cmd, "whatweb")

        if not results_file.exists():
            await log_line(
                scan_id,
                "[whatweb] no results file was produced — check the [out] lines above for the actual error",
                "warn",
            )
            return 0

        results = parse_whatweb_json(results_file.read_text(encoding="utf-8", errors="replace"))
        conn = get_db()
        count = 0
        for r in results:
            try:
                host = urllib.parse.urlsplit(r["target"]).hostname or r["target"]
            except Exception:
                host = r["target"] or domain
            for f in r["findings"]:
                label = f"{f['name']}: {f['detail']}" if f["detail"] else f["name"]
                store_intel(conn, scan_id, host, "whatweb", f"tech:{f['name']}", label)
                count += 1
        conn.commit()
        conn.close()
        await log_line(scan_id, f"[+] whatweb: {count} technology finding(s) across {len(urls)} host(s)", "meta")
        return count
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# gau (github.com/lc/gau) — historical URL discovery via the Wayback
# Machine, Common Crawl, and AlienVault OTX. Runs against the root domain
# rather than per-host, matching gau's own design: it queries archive
# services domain-wide, not host-by-host, so there's nothing to gain by
# looping per discovered subdomain the way gowitness/whatweb do.
#
# A note on naming: gau shares its name with an oh-my-zsh git-plugin
# alias ('gau' -> 'git add --update') — a real, documented conflict, but
# one that can't actually reach this app. Shell aliases only exist
# inside an interactive shell session; this app spawns the binary
# directly via asyncio subprocess (no shell, no rc-file sourcing), the
# same resolution path shutil.which() uses. That's a fundamentally
# different situation from httpx's collision, where a *different
# program* was genuinely installed under the same PATH-resolvable name
# and would be found (and run) regardless of how it was invoked.
# ---------------------------------------------------------------------------
async def gau_run(scan_id: int, domain: str, mode: str) -> int:
    binary = shutil.which("gau")
    if not binary:
        await log_line(scan_id, "[skip] gau not found on PATH — skipping gau", "warn")
        return 0

    cmd = apply_variant([binary, domain], "gau", mode)
    await log_line(scan_id, f"[gau] pulling historical URLs for {domain} (Wayback/CommonCrawl/OTX)...", "meta")
    # quiet=True — confirmed directly (from a real scan's output) that a
    # long-lived domain can return tens of thousands of legitimately valid
    # URLs here, every one of which was getting streamed to the live log
    # individually even though only the first MAX_STORED ever actually
    # gets kept below. Every line is still captured for parsing — nothing
    # about what gets found or stored changes — this only stops echoing
    # each one to scan_logs/the live terminal before that capping happens.
    lines = await run_stream(scan_id, cmd, "gau", quiet=True)

    urls = [l.strip() for l in lines if l.strip().startswith(("http://", "https://"))]
    if not urls:
        await log_line(scan_id, "[gau] no historical URLs found", "warn")
        return 0

    # The database only ever keeps the first MAX_STORED (below) to avoid
    # ballooning the report tabs — but the complete list gau actually
    # found is still real, valid data worth having on hand, so the full,
    # uncapped set gets written to this scan's own output folder
    # regardless of the storage cap.
    try:
        out_path = write_full_output_file(scan_id, domain, "gau_full.txt", urls)
        await log_line(scan_id, f"[gau] full list of {len(urls)} URL(s) written to {out_path.name} in this scan's output folder", "meta")
    except Exception as e:
        await log_line(scan_id, f"[gau] couldn't write full output file: {e}", "warn")

    # A long-lived or large domain can return many thousands of archived
    # URLs — capped here so one gau run can't balloon the database, while
    # still reporting the true total found in the log.
    MAX_STORED = 300
    stored_urls = urls[:MAX_STORED]

    conn = get_db()
    for i, u in enumerate(stored_urls):
        try:
            host = urllib.parse.urlsplit(u).hostname or domain
        except Exception:
            host = domain
        store_intel(conn, scan_id, host, "gau", f"historical_url:{i}", u)
    conn.commit()
    conn.close()

    note = f" (stored the first {MAX_STORED}; {len(urls) - MAX_STORED} more not stored)" if len(urls) > MAX_STORED else ""
    await log_line(scan_id, f"[+] gau: {len(urls)} historical URL(s) found{note}", "meta")
    return len(stored_urls)




# ---------------------------------------------------------------------------
# katana (github.com/projectdiscovery/katana) — a proper crawler. httpx
# only ever looks at each host's root URL; katana follows links from
# there, surfacing deeper pages and endpoints that gowitness/whatweb/
# nuclei would otherwise never see (they only get pointed at whatever
# httpx already found). Runs against all live hosts in one invocation via
# -list, unlike ffuf which genuinely needs one process per host.
#
# Build note: katana needs CGO_ENABLED=1 at install time (not a plain
# go install) and a newer minimum Go version than this app's other Go
# tools — see install.sh, which handles both explicitly rather than
# reusing the generic install helper.
# ---------------------------------------------------------------------------
def parse_katana_jsonl(lines: list[str]) -> list[str]:
    urls = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        url = obj.get("endpoint") or obj.get("url") or obj.get("URL")
        if not url:
            req = obj.get("request") or {}
            if isinstance(req, dict):
                url = req.get("endpoint") or req.get("url")
        if url:
            urls.append(url)
    return urls


async def katana_run(scan_id: int, domain: str, mode: str, urls: list[str]) -> int:
    binary = shutil.which("katana")
    if not binary:
        await log_line(scan_id, "[skip] katana not found on PATH — skipping katana", "warn")
        return 0
    if not urls:
        await log_line(scan_id, "[katana] no live HTTP assets to crawl", "warn")
        return 0

    tmp_dir = BASE_DIR / f".scan_{scan_id}_katana"
    tmp_dir.mkdir(exist_ok=True)
    hosts_file = tmp_dir / "hosts.txt"
    hosts_file.write_text("\n".join(urls))
    results_file = tmp_dir / "results.jsonl"

    try:
        cmd = apply_variant(
            [binary, "-list", str(hosts_file), "-d", "2", "-jsonl", "-o", str(results_file), "-silent"],
            "katana", mode,
        )
        await log_line(scan_id, f"[katana] crawling {len(urls)} live host(s) (depth 2)...", "meta")
        # run_quiet, not run_stream — katana's raw JSONL output includes
        # the full raw HTTP response body (complete page HTML, inline
        # scripts, everything) for every crawled URL by default, and this
        # app's own parsing only ever needs the endpoint URL from each
        # line. Streaming that verbatim to the live log was confirmed
        # directly (from a real scan's output) to produce individual log
        # entries running into hundreds of KB each, repeated for every
        # crawled page — a serious performance problem a line-count cap
        # alone doesn't address, since it's the size of individual lines
        # that's the issue here, not how many of them there are. Results
        # are read from the -o file afterward regardless, so nothing
        # about parsing changes — only what gets streamed live.
        await run_quiet(scan_id, cmd, "katana")

        if not results_file.exists():
            await log_line(scan_id, "[katana] no results file was produced — the crawl may have failed to find anything", "warn")
            return 0

        found_urls = parse_katana_jsonl(results_file.read_text(encoding="utf-8", errors="replace").splitlines())
        # De-dupe and cap, same reasoning as gau — a deep crawl of a large
        # site can surface thousands of URLs.
        unique_urls = list(dict.fromkeys(found_urls))

        try:
            out_path = write_full_output_file(scan_id, domain, "katana_full.txt", unique_urls)
            await log_line(scan_id, f"[katana] full list of {len(unique_urls)} URL(s) written to {out_path.name} in this scan's output folder", "meta")
        except Exception as e:
            await log_line(scan_id, f"[katana] couldn't write full output file: {e}", "warn")

        MAX_STORED = 300
        stored = unique_urls[:MAX_STORED]

        conn = get_db()
        for i, u in enumerate(stored):
            try:
                host = urllib.parse.urlsplit(u).hostname or domain
            except Exception:
                host = domain
            store_intel(conn, scan_id, host, "katana", f"crawled_url:{i}", u)
        conn.commit()
        conn.close()

        note = (
            f" (stored the first {MAX_STORED}; {len(unique_urls) - MAX_STORED} more not stored)"
            if len(unique_urls) > MAX_STORED else ""
        )
        await log_line(scan_id, f"[+] katana: {len(unique_urls)} unique URL(s) crawled{note}", "meta")
        return len(stored)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# shuffledns (github.com/projectdiscovery/shuffledns) — a massdns wrapper
# for high-speed wordlist-based subdomain brute-forcing, faster at scale
# than amass's or dnsx's own wordlist modes. Like ffuf, genuinely useless
# without a wordlist, so skipped outright rather than run with some
# default no-op behavior if none is assigned.
#
# Three real setup requirements worth knowing, each handled explicitly
# here rather than assumed to just work:
#   1. massdns must be present, and — this is shuffledns' own design, not
#      a choice made here — auto-detected ONLY at /usr/bin/massdns or
#      /usr/local/bin/massdns specifically. Anywhere else on PATH and
#      shuffledns simply won't find it. install.sh apt-installs massdns,
#      which lands at /usr/bin/massdns and satisfies this automatically.
#   2. shuffledns needs a resolvers file it doesn't ship with. This app
#      generates one once (a short list of well-known public resolvers)
#      rather than requiring the person to supply their own.
#   3. There's a documented history of `go install` failing outright for
#      shuffledns specifically on Kali (unrelated to this app — a
#      long-standing upstream/environment issue). install.sh still
#      attempts it as the current official method, but the fallback
#      compile-from-source steps are called out in this app's README in
#      case that history repeats.
# ---------------------------------------------------------------------------
DEFAULT_RESOLVERS = [
    "8.8.8.8", "8.8.4.4",           # Google
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
]


async def shuffledns_run(scan_id: int, domain: str, mode: str) -> set[str]:
    """Returns the set of newly-discovered subdomains, same contract as
    the other subdomain-discovery sources feeding into add_subs()."""
    binary = shutil.which("shuffledns")
    if not binary:
        await log_line(scan_id, "[skip] shuffledns not found on PATH — skipping shuffledns", "warn")
        return set()
    wordlist = get_active_wordlist("shuffledns")
    if not wordlist:
        await log_line(
            scan_id,
            "[shuffledns] no wordlist assigned — shuffledns has nothing to brute-force without one; "
            "assign one under Settings → Wordlists, then pick it for shuffledns from its entry in the Tools sidebar",
            "warn",
        )
        return set()
    if not (Path("/usr/bin/massdns").is_file() or Path("/usr/local/bin/massdns").is_file()):
        await log_line(
            scan_id,
            "[shuffledns] massdns not found at /usr/bin/massdns or /usr/local/bin/massdns — shuffledns "
            "only auto-detects it at those exact paths (its own design). Install massdns "
            "(install.sh does this automatically) and re-run",
            "warn",
        )
        return set()

    if not RESOLVERS_FILE.is_file():
        RESOLVERS_FILE.write_text("\n".join(DEFAULT_RESOLVERS) + "\n")

    tmp_dir = BASE_DIR / f".scan_{scan_id}_shuffledns"
    tmp_dir.mkdir(exist_ok=True)
    output_file = tmp_dir / "found.txt"

    try:
        cmd = apply_variant(
            [
                binary, "-d", domain, "-w", wordlist["path"], "-r", str(RESOLVERS_FILE),
                "-mode", "bruteforce", "-t", "2000", "-o", str(output_file), "-silent",
            ],
            "shuffledns", mode,
        )
        await log_line(scan_id, f"[shuffledns] brute-forcing subdomains with wordlist '{wordlist['name']}'...", "meta")
        await run_stream(scan_id, cmd, "shuffledns")

        if not output_file.exists():
            await log_line(scan_id, "[shuffledns] no output file was produced — check the [out] lines above", "warn")
            return set()

        found = {
            l.strip().lower() for l in output_file.read_text(encoding="utf-8", errors="replace").splitlines()
            if l.strip()
        }
        await log_line(scan_id, f"[+] shuffledns: {len(found)} subdomain(s) found", "meta")
        return found
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# SpiderFoot (github.com/smicallef/spiderfoot) — a 200+ module OSINT
# automation framework, not a single-purpose tool. Uses SpiderFoot's own
# `-u passive` profile rather than a hand-picked list of individual
# module names: SpiderFoot's own maintainers keep that profile in sync
# with whatever modules currently exist, which is more robust than this
# app guessing specific sfp_* module names that could be renamed or
# removed between versions — a real risk, since some of SpiderFoot's own
# modules literally shell out to nmap/whatweb, which aren't things this
# app needs SpiderFoot to also do. Passive mode naturally avoids that
# overlap, since none of the active/tool-shelling modules run in it.
#
# SpiderFoot's own modules (Shodan, VirusTotal, HaveIBeenPwned, etc.) take
# their API keys from SpiderFoot's own config, not this app's Settings —
# a deliberate choice not to try to bridge the two, documented in the
# README rather than silently assumed to just work.
#
# The exact JSON field names weren't fully pinned down without a live
# install to test against, so parsing tries several reasonable key-name
# variants per field rather than assuming one, and tolerates either a
# single JSON array or JSON-lines.
# ---------------------------------------------------------------------------
HOSTNAME_LIKE_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")

# Event types requested by the "strict" tool profile (-x -t <types>) — see
# TOOL_PROFILES["spiderfoot"]. -x rebuilds SpiderFoot's module list from
# scratch using only modules that directly consume the target AND produce
# one of these event types, which is what makes it fast (no chained,
# multi-hop modules) but also means picking the wrong type names here
# would silently produce a near-empty scan rather than an error. Verified
# against SpiderFoot's own event-type table (spiderfoot/db.py) rather than
# guessed. Curated to the categories this app actually stores/surfaces
# elsewhere (host_intel/leaks/vulnerabilities), not every event type
# SpiderFoot defines.
SPIDERFOOT_STRICT_EVENT_TYPES = [
    "INTERNET_NAME", "EMAILADDR", "IP_ADDRESS", "IPV6_ADDRESS",
    "SSL_CERTIFICATE_ISSUED", "WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY",
    "TCP_PORT_OPEN", "CLOUD_STORAGE_BUCKET",
    "PASSWORD_COMPROMISED", "EMAILADDR_COMPROMISED", "HASH_COMPROMISED",
    "VULNERABILITY_CVE_CRITICAL", "VULNERABILITY_CVE_HIGH",
]


def parse_spiderfoot_output(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    raw: list[dict] = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            raw = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict):
            raw = [data]
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # A line can be a single finding (dict) or a whole array of
            # them (SpiderFoot's own internal logging can interleave with
            # its JSON output, so a batch of findings sometimes lands on
            # its own line rather than the whole stream being one clean
            # JSON document) — both are handled, not just the dict case,
            # since silently dropping the array case meant real findings
            # went missing whenever this fallback path was needed at all.
            if isinstance(obj, dict):
                raw.append(obj)
            elif isinstance(obj, list):
                raw.extend(r for r in obj if isinstance(r, dict))

    out = []
    for r in raw:
        event_type = r.get("type") or r.get("eventType") or r.get("event_type") or "finding"
        value = r.get("data") or r.get("value") or r.get("eventData") or ""
        module = r.get("module") or r.get("source") or ""
        host_field = r.get("host") or r.get("sourceEntity") or ""
        if not value:
            continue
        value_str = str(value)
        # Most SpiderFoot findings (INTERNET_NAME especially) are a bare
        # hostname, not a full URL — urlsplit() only extracts .hostname
        # when a scheme is present, so a plain "api.example.com" needs
        # its own check rather than relying on urlsplit alone.
        try:
            host = urllib.parse.urlsplit(value_str).hostname or ""
        except Exception:
            host = ""
        if not host and HOSTNAME_LIKE_RE.match(value_str):
            host = value_str
        if not host:
            host = host_field
        out.append({"event_type": str(event_type), "value": value_str, "module": str(module), "host": host})
    return out


async def spiderfoot_run(scan_id: int, domain: str, mode: str) -> int:
    binary = shutil.which("spiderfoot")
    if not binary:
        await log_line(scan_id, "[skip] spiderfoot not found on PATH — skipping spiderfoot", "warn")
        return 0

    profile = get_tool_profile("spiderfoot", TOOL_PROFILES["spiderfoot"]["default"])
    # -max-threads controls how many of SpiderFoot's 200+ modules run
    # concurrently — confirmed directly against SpiderFoot's own source
    # (sf.py), its default is only 3. For a workload that's almost
    # entirely independent, I/O-bound HTTP calls to third-party sources,
    # 3-at-a-time is a real, significant bottleneck, not a deliberate
    # safety limit. Raised once already from 3 to 10; raised again here to
    # 20 after the same reasoning held up on reflection — SpiderFoot's own
    # passive module set queries free-tier/no-key third-party APIs almost
    # exclusively, and at 10-wide this is still consistently the single
    # longest step in a full-mode scan. 20 is still well short of
    # SpiderFoot's own modcount (so it's not "run everything at once"),
    # and no rate-limit errors specific to this step have shown up in
    # testing at this width, but if a particular source's free tier does
    # start getting flagged, dialing -max-threads back down is the first
    # thing to try before assuming something else broke.
    if profile == "strict":
        # -x rebuilds SpiderFoot's own module list from scratch using only
        # modules that directly consume the target domain and produce one
        # of the requested -t event types — no -u, and -x is documented as
        # incompatible with -m (confirmed against sf.py), so this is a
        # genuinely different command shape, not just a different -u value.
        types_arg = ",".join(SPIDERFOOT_STRICT_EVENT_TYPES)
        cmd = apply_variant(
            [binary, "-s", domain, "-x", "-t", types_arg, "-max-threads", "20", "-o", "json"],
            "spiderfoot", mode,
        )
        await log_line(
            scan_id,
            f"[spiderfoot] running strict mode against {domain} — only modules that query the domain "
            f"directly, for {len(SPIDERFOOT_STRICT_EVENT_TYPES)} curated event type(s) (20 modules "
            f"concurrently). Faster than passive mode, but skips chained/multi-hop modules.",
            "meta",
        )
    else:
        cmd = apply_variant([binary, "-s", domain, "-u", profile, "-max-threads", "20", "-o", "json"], "spiderfoot", mode)
        await log_line(
            scan_id,
            f"[spiderfoot] running its '{profile}' module profile against {domain} (20 modules concurrently) — "
            f"this can still take a while, it queries many independent sources",
            "meta",
        )
    # quiet=True — confirmed directly (from a real scan's output) that
    # SpiderFoot's own internal logging (every single HTTP fetch attempt,
    # at INFO level: "Fetching (GET): https://...") vastly outnumbers its
    # actual JSON findings, which is all parse_spiderfoot_output below
    # ever looks for. Tens of thousands of lines of SpiderFoot's own
    # internal chatter were streaming to the live log for zero benefit —
    # none of it is a finding, all of it gets discarded by the parser
    # either way. Every line is still captured, nothing about what gets
    # found changes.
    lines = await run_stream(scan_id, cmd, "spiderfoot", quiet=True)

    findings = parse_spiderfoot_output("\n".join(lines))
    if not findings:
        await log_line(scan_id, "[spiderfoot] no results parsed from its output — nothing to show for this pass", "warn")
        return 0

    conn = get_db()
    count = 0
    leak_keywords = ("leak", "paste", "breach", "darkweb", "compromis")
    for i, f in enumerate(findings):
        host = f["host"] or domain
        label = f["value"] + (f" (via {f['module']})" if f["module"] else "")
        store_intel(conn, scan_id, host, "spiderfoot", f"{f['event_type']}:{i}", label)
        # SpiderFoot's exact event-type names for leak/breach/paste-site
        # findings aren't fully pinned down without live access to test
        # against, so this checks for the general keyword rather than an
        # exact type name — deliberately loose, since missing a real leak
        # finding here is worse than an occasional over-inclusive match.
        if any(kw in f["event_type"].lower() for kw in leak_keywords):
            conn.execute(
                "INSERT INTO leaks (scan_id, host, source, leak_type, detail) VALUES (?, ?, 'spiderfoot', ?, ?)",
                (scan_id, host, f["event_type"], f["value"][:500]),
            )
        count += 1
    conn.commit()
    conn.close()
    await log_line(scan_id, f"[+] spiderfoot: {count} finding(s)", "meta")
    return count


# ---------------------------------------------------------------------------
# recon-ng (recon-ng.org) — a modular OSINT framework with workspaces and
# a marketplace of installable modules, run here via recon-cli (its
# non-interactive sibling built for exactly this, confirmed exact flags
# from its own -h output: -w workspace, -m module, -o key=value, -x run).
#
# Defaults to three modules, deliberately chosen because none of them
# need an API key — recon-ng modules fail *silently* when a required key
# isn't configured (in recon-ng's own keys.db, not this app's Settings),
# which would otherwise look identical to "ran, found nothing" with no
# way to tell the difference. More modules can be added the same way
# (marketplace install, then add to the list this app runs) — see README.
#
# recon-cli doesn't print clean structured output to parse directly, so
# each run is followed by `-C "show hosts"` / `-C "show contacts"`,
# pattern-matching hostnames and emails out of whatever text comes back
# rather than depending on an exact table format or an assumed database
# file location — more robust against version differences in either.
# ---------------------------------------------------------------------------
RECON_NG_MODULES = [
    "recon/domains-hosts/hackertarget",
    "recon/domains-hosts/bing_domain_web",
    "recon/domains-contacts/whois_pocs",
]

RECON_NG_HOSTNAME_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
RECON_NG_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


async def recon_ng_run(scan_id: int, domain: str, mode: str) -> tuple[set[str], set[str]]:
    """Returns (hostnames, emails) found. Both feed into this scan's
    normal discovery pools the same way any other source's findings do."""
    binary = shutil.which("recon-cli")
    if not binary:
        await log_line(scan_id, "[skip] recon-cli not found on PATH — skipping recon-ng", "warn")
        return set(), set()

    workspace = f"mimir_scan_{scan_id}"
    for module in RECON_NG_MODULES:
        cmd = [binary, "-w", workspace, "-m", module, "-o", f"SOURCE={domain}", "-x"]
        cmd = apply_variant(cmd, "recon-ng", mode)
        await log_line(scan_id, f"[recon-ng] running {module}...", "meta")
        await run_stream(scan_id, cmd, f"recon-ng ({module})")

    hosts_lines = await run_stream(scan_id, [binary, "-w", workspace, "-C", "show hosts"], "recon-ng (show hosts)")
    contacts_lines = await run_stream(
        scan_id, [binary, "-w", workspace, "-C", "show contacts"], "recon-ng (show contacts)"
    )

    hostnames: set[str] = set()
    for line in hosts_lines:
        for m in RECON_NG_HOSTNAME_RE.findall(line):
            h = m.lower().rstrip(".")
            if h.endswith(domain.lower()) or domain.lower().endswith(h):
                hostnames.add(h)

    emails_raw: set[str] = set()
    for line in contacts_lines + hosts_lines:
        for m in RECON_NG_EMAIL_RE.findall(line):
            emails_raw.add(m.lower())
    # Same reasoning as theHarvester's fix above — recon-ng's own
    # hostname extraction two lines up already restricts to this
    # domain; the email side never had the same restriction until now.
    emails = filter_emails_to_domain(emails_raw, domain)
    discarded = len(emails_raw) - len(emails)

    await log_line(
        scan_id,
        f"[+] recon-ng: {len(hostnames)} host(s), {len(emails)} email(s) found across {len(RECON_NG_MODULES)} module(s)"
        + (f" ({discarded} other email(s) discarded — not @ {domain})" if discarded else ""),
        "meta",
    )
    return hostnames, emails


# ---------------------------------------------------------------------------
# Live validation — re-checks findings right now (DNS/HTTP/TCP) and scores
# a confidence rating, rather than trusting a scan's results forever.
# ---------------------------------------------------------------------------

async def check_tcp_port_now(host: str, port: int, timeout: float = 4) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


def _check_http_now_sync(url: str, timeout: float) -> dict:
    """Returns {"ok": bool, "status_code": int|None} — not just whether
    it responded, but what it actually returned right now, so validation
    can refresh the asset's own record (e.g. 200 -> 403 since the
    original scan) rather than only using this to score the host."""
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "surface-recon/1.0"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return {"ok": True, "status_code": resp.getcode()}
    except urllib.error.HTTPError as e:
        return {"ok": True, "status_code": e.code}  # server responded at all, even if non-2xx — still "up"
    except Exception:
        return {"ok": False, "status_code": None}


async def check_http_now(url: str, timeout: float = 6) -> dict:
    if not url:
        return {"ok": False, "status_code": None}
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _check_http_now_sync(url, timeout))


def score_asset_confidence(had_original_status: bool, http_ok: bool) -> tuple[int, str]:
    """Mirrors score_host_confidence's shape but for a single web asset
    specifically — what matters here isn't "is the host real" (that's the
    host-level score's job), it's "does this exact URL actually respond
    right now," since that's the precise thing a follow-up vulnerability
    scan needs to know before targeting it."""
    if http_ok:
        return 90, "confirmed"
    if had_original_status:
        return 10, "unreachable"  # used to respond, doesn't now
    return 25, "unconfirmed"  # never had a status to begin with


def score_host_confidence(sources_count: int, dns_ok: bool, had_http: bool, http_ok: bool) -> tuple[int, str]:
    """DNS resolving *right now* is the dominant signal — it's live,
    first-hand evidence the host is real, stronger than how many passive
    tools happened to report it during the original scan. Sources count
    and HTTP reachability are bonuses on top of that, not prerequisites
    for reaching "confirmed" — a host with no web server on it (mail,
    internal admin panel, etc.) is still a perfectly real, confirmed host
    if it resolves, and shouldn't be capped at "unconfirmed" just because
    there's nothing running on port 80/443."""
    if not dns_ok:
        return 15, "unreachable"
    score = 70  # baseline: it resolves right now
    score += min(sources_count * 5, 15)  # up to +15 for multiple tools agreeing
    if had_http:
        score += 15 if http_ok else -15  # bonus if still live; penalty if it used to respond and doesn't now
    score = max(0, min(score, 100))
    if score >= 70:
        return score, "confirmed"
    if score >= 45:
        return score, "likely valid"
    return score, "unconfirmed"


def score_port_confidence(sources_count: int, still_open: bool) -> tuple[int, str]:
    score = min(sources_count * 25, 50)
    if still_open:
        return min(score + 45, 100), "confirmed open"
    return min(score, 20), "possibly closed now"


# ---------------------------------------------------------------------------
# Generic custom API resources
# ---------------------------------------------------------------------------
def extract_hostnames_from_json(data, json_path: str, domain: str) -> set[str]:
    """json_path points at a list of hostname strings, or 'list.path|subfield'
    when the list contains objects and the hostname is one of their fields."""
    if "|" in json_path:
        list_path, subfield = json_path.split("|", 1)
    else:
        list_path, subfield = json_path, None
    lst = get_json_path(data, list_path) if list_path else data
    out = set()
    if isinstance(lst, list):
        for item in lst:
            val = get_json_path(item, subfield) if subfield and isinstance(item, dict) else item
            if isinstance(val, str):
                v = val.strip().lower().strip(".")
                if v and domain in v:
                    out.add(v)
    return out


def fill_template(template: str, domain: str, ip: Optional[str], api_key: Optional[str]) -> str:
    out = template.replace("{domain}", urllib.parse.quote(domain))
    if ip:
        out = out.replace("{ip}", ip)
    out = out.replace("{api_key}", urllib.parse.quote(api_key) if api_key else "")
    return out


async def run_custom_api_subdomain_source(scan_id: int, src: dict, domain: str) -> set[str]:
    url = fill_template(src["url_template"], domain, None, src.get("api_key"))
    await log_line(scan_id, f"$ GET {url.split('?')[0]}  (custom: {src['name']})", "cmd")
    try:
        data = await http_get_json(url, timeout=25)
        names = extract_hostnames_from_json(data, src.get("json_path") or "", domain)
        await log_line(scan_id, f"[done] {src['name']} — {len(names)} hostnames", "meta")
        return names
    except Exception as e:
        await log_line(scan_id, f"[error] {src['name']} failed: {e}", "error")
        return set()


async def run_custom_api_enrich_source(scan_id: int, src: dict, domain: str, ips: list[str]):
    """Fresh connection per target rather than one held across the loop —
    same reasoning as ip_geo_lookup/shodan_enrich_hosts: this loop spans
    network calls and throttle sleeps, and a connection held open across
    all of it was blocking other writers with 'database is locked'."""
    fields = [f.strip() for f in (src.get("intel_fields") or "").split(",") if f.strip()]
    per_ip = "{ip}" in src["url_template"]
    targets = ips if per_ip else [domain]
    if not targets:
        return
    for i, t in enumerate(targets):
        url = fill_template(src["url_template"], domain, t if per_ip else None, src.get("api_key"))
        await log_line(scan_id, f"$ GET {url.split('?')[0]}  (custom: {src['name']})", "cmd")
        try:
            data = await http_get_json(url, timeout=25)
            conn = get_db()
            try:
                hit = 0
                for f in fields:
                    val = get_json_path(data, f)
                    if isinstance(val, list):
                        val = ", ".join(str(v) for v in val)
                    if isinstance(val, (dict,)):
                        continue
                    if val not in (None, ""):
                        store_intel(conn, scan_id, t, src["name"], f.split(".")[-1], val)
                        hit += 1
                conn.commit()
            finally:
                conn.close()
            await log_line(scan_id, f"[{src['name']}] {t}: {hit}/{len(fields)} fields found", "out")
        except Exception as e:
            await log_line(scan_id, f"[{src['name']}] {t}: failed — {e}", "warn")
        if i < len(targets) - 1:
            await asyncio.sleep(0.5)


# ---------------------------------------------------------------------------
# Stage cancellation (skip current step / stop whole scan) + progress
# ---------------------------------------------------------------------------
# Each running scan's *current* stage is tracked as a real asyncio Task so it
# can be cancelled on demand. "Skip" just cancels that task — run_stage()
# catches the cancellation, logs it, and returns None, and the pipeline
# carries on to the next stage exactly as if this one had returned no
# results. "Stop" sets a flag first, so the same cancellation is instead
# turned into a ScanStopped exception that unwinds the whole pipeline.
RUNNING_STAGE_TASKS: dict[int, asyncio.Task] = {}
STOP_REQUESTED: dict[int, bool] = {}


class ScanStopped(Exception):
    """Raised to unwind run_pipeline when the user clicks Stop."""
    pass


async def run_stage(scan_id: int, coro):
    if STOP_REQUESTED.get(scan_id):
        coro.close()
        raise ScanStopped()
    task = asyncio.create_task(coro)
    RUNNING_STAGE_TASKS[scan_id] = task
    try:
        return await task
    except asyncio.CancelledError:
        if STOP_REQUESTED.get(scan_id):
            raise ScanStopped()
        await log_line(scan_id, "[!] step skipped by user — moving to the next one", "warn")
        return None
    finally:
        if RUNNING_STAGE_TASKS.get(scan_id) is task:
            del RUNNING_STAGE_TASKS[scan_id]


class ProgressTracker:
    """Tracks (done/total stages, current stage label) for a running scan,
    persists it to the scans row, and broadcasts it live over the websocket
    so a reconnecting/polling client picks up exactly where things are.

    `kind` selects which pair of columns gets updated — "scan" (the
    default, main pipeline) writes progress_percent/progress_stage;
    "company"/"vulnerability" write their own dedicated
    {kind}_progress_percent/{kind}_progress_stage columns instead. These
    two modules run independently and often much later than the
    original scan, so they need their own progress state entirely —
    reusing the main scan's columns would overwrite its completed 100%
    state with "Company scan 20% running" the moment someone triggers
    it, which has nothing to do with the original scan's own progress.

    `kind` is always one of a small, fixed set of literal strings passed
    by this app's own code, never derived from a request — the f-string
    column names below are safe for that reason, the same reasoning
    already applied elsewhere in this app for similar internally-fixed
    dynamic SQL fragments.
    """

    def __init__(self, scan_id: int, total: int, kind: str = "scan"):
        self.scan_id = scan_id
        self.total = max(total, 1)
        self.done = 0
        self.label = ""
        self.kind = kind
        self.percent_col = "progress_percent" if kind == "scan" else f"{kind}_progress_percent"
        self.stage_col = "progress_stage" if kind == "scan" else f"{kind}_progress_stage"

    async def start(self, label: str):
        self.label = label
        await self._push()

    async def advance(self):
        self.done = min(self.done + 1, self.total)
        await self._push()

    async def finish(self, label: str = "Complete"):
        self.done = self.total
        self.label = label
        await self._push()

    async def _push(self):
        percent = int(round(self.done / self.total * 100))
        conn = get_db()
        conn.execute(
            f"UPDATE scans SET {self.percent_col} = ?, {self.stage_col} = ? WHERE id = ?",
            (percent, self.label, self.scan_id),
        )
        conn.commit()
        conn.close()
        await manager.broadcast(
            self.scan_id,
            {"type": f"{self.kind}_progress", "percent": percent, "stage": self.label, "done": self.done, "total": self.total},
        )


async def run_named_stage(progress: ProgressTracker, scan_id: int, label: str, coro):
    await progress.start(label)
    await run_stage(scan_id, coro)
    await progress.advance()


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------
async def run_pipeline(scan_id: int, domain: str, mode: str):
    """The actual scan. Two phases:

    1. Build phase (no I/O): construct closures for every stage that will
       run — which ones depend entirely on `mode` plus what's enabled in
       Settings (tool_settings / custom_tools / custom_api_sources) and
       whether a Shodan key is set. Nothing executes yet, so the total
       stage count is exact before the first log line goes out.
    2. Execute phase: run each stage in order via run_named_stage(), which
       reports progress and makes the stage cancellable (skip/stop).

    Bespoke command variants (apply_variant) are resolved per-stage at
    execution time, not at build time, since they only affect the argv
    passed to run_stream — the stage list's shape doesn't change.

    `subs`/`resolved`/`assets` are mutated in place by the stage closures
    below rather than returned, since later stages (resolution, probing,
    enrichment) need whatever earlier stages found. `nonlocal` marks the
    few spots where a closure reassigns the name itself rather than
    mutating the object it points to.
    """
    conn = get_db()
    subs: dict[str, set[str]] = {}
    resolved: dict[str, str] = {}
    # Every A record per host, not just the "primary" one in `resolved`
    # above — used specifically for nmap/naabu's scan target list, so a
    # host behind a CDN/load-balancer gets ALL its backend IPs scanned,
    # not just whichever one dnsx happened to list first.
    host_all_ips: dict[str, list[str]] = {}
    assets: list[dict] = []
    tmp_hosts: Optional[Path] = None

    def add_subs(names: set[str], source: str):
        for n in names:
            subs.setdefault(n, set()).add(source)

    settings_map = get_tool_settings_map()

    def enabled(name: str, default: bool = True) -> bool:
        return is_enabled(name, settings_map, default)

    shodan_key = get_api_key("shodan")
    leakix_key = get_api_key("leakix")
    custom_tools = get_custom_tools(enabled_only=True)
    custom_api_subdomain_sources = get_custom_api_sources(enabled_only=True, category="subdomain")
    custom_api_enrich_sources = get_custom_api_sources(enabled_only=True, category="enrich")

    await log_line(scan_id, f"=== starting {mode} scan for {domain} ===", "meta")

    # =====================================================================
    # Build the ordered list of discovery stages that will actually run,
    # so the progress bar's total is exact rather than estimated, and so
    # every stage is individually skippable via run_stage().
    # =====================================================================
    discovery_steps: list[tuple[str, "asyncio.coroutines"]] = []  # (label, coro-factory)

    if enabled("subfinder", True):
        async def _subfinder():
            cmd = apply_variant(["subfinder", "-d", domain, "-silent"], "subfinder", mode)
            lines = await run_stream(scan_id, cmd, "subfinder")
            add_subs(parse_plain_hostnames(lines, domain), "subfinder")
        discovery_steps.append(("Subdomain discovery: subfinder", _subfinder))

    if mode == "full":
        if enabled("amass", True):
            async def _amass():
                wordlist = get_active_wordlist("amass")
                if wordlist:
                    # Wordlist present: this fundamentally changes what
                    # amass does, not just adds a flag — passive mode
                    # can't use a wordlist at all, so switching to -brute
                    # is required, not optional, once one's assigned.
                    base = ["amass", "enum", "-brute", "-w", wordlist["path"], "-d", domain, "-silent"]
                    await log_line(
                        scan_id,
                        f"[amass] wordlist '{wordlist['name']}' assigned — switching from passive to "
                        f"active brute-force mode",
                        "meta",
                    )
                    source_label = "amass-brute"
                else:
                    base = ["amass", "enum", "-passive", "-d", domain, "-silent"]
                    source_label = "amass"
                cmd = apply_variant(base, "amass", mode)
                lines = await run_stream(scan_id, cmd, "amass")
                add_subs(parse_plain_hostnames(lines, domain), source_label)
            discovery_steps.append(("Subdomain discovery: amass", _amass))

        if enabled("assetfinder", True):
            async def _assetfinder():
                cmd = apply_variant(["assetfinder", "--subs-only", domain], "assetfinder", mode)
                lines = await run_stream(scan_id, cmd, "assetfinder")
                add_subs(parse_plain_hostnames(lines, domain), "assetfinder")
            discovery_steps.append(("Subdomain discovery: assetfinder", _assetfinder))

        if enabled("theharvester", True):
            async def _theharvester():
                hostnames, emails = await theharvester_run(scan_id, domain, mode)
                add_subs(hostnames, "theharvester")
                if emails:
                    c = get_db()
                    add_emails(c, scan_id, emails, "theharvester")
                    c.commit()
                    c.close()
                    await log_line(scan_id, f"[theharvester] {len(emails)} emails found", "meta")
            discovery_steps.append(("theHarvester (emails + hosts)", _theharvester))

        if enabled("dnsx", True):
            dnsx_wordlist = get_active_wordlist("dnsx")
            if dnsx_wordlist:
                async def _dnsx_bruteforce():
                    cmd = ["dnsx", "-d", domain, "-w", dnsx_wordlist["path"], "-silent", "-json"]
                    cmd = apply_variant(cmd, "dnsx", mode)
                    await log_line(
                        scan_id,
                        f"[dnsx] bruteforcing subdomains with wordlist '{dnsx_wordlist['name']}'...",
                        "meta",
                    )
                    lines = await run_stream(scan_id, cmd, "dnsx (bruteforce)")
                    found = parse_dnsx_json(lines)
                    add_subs(set(found.keys()), "dnsx-bruteforce")
                    await log_line(scan_id, f"[+] dnsx bruteforce: {len(found)} host(s) found", "meta")
                discovery_steps.append(("dnsx wordlist bruteforce", _dnsx_bruteforce))

        if enabled("shuffledns", True):
            async def _shuffledns():
                found = await shuffledns_run(scan_id, domain, mode)
                add_subs(found, "shuffledns")
            discovery_steps.append(("shuffledns wordlist bruteforce", _shuffledns))

        if enabled("recon-ng", True):
            async def _recon_ng():
                hostnames, found_emails = await recon_ng_run(scan_id, domain, mode)
                add_subs(hostnames, "recon-ng")
                if found_emails:
                    c = get_db()
                    add_emails(c, scan_id, found_emails, "recon-ng")
                    c.commit()
                    c.close()
            discovery_steps.append(("recon-ng: keyless host + contact modules", _recon_ng))

    for ct in custom_tools:
        def _make_custom_step(ct=ct):
            async def _fn():
                label = f"custom:{ct['name']}"
                if ct.get("shell"):
                    cmd_str = build_custom_shell_cmd(ct["command_template"], domain)
                    if not cmd_str.strip():
                        return
                    lines = await run_stream_shell(scan_id, cmd_str, label)
                else:
                    cmd = build_custom_cmd(ct["command_template"], domain)
                    if not cmd:
                        return
                    lines = await run_stream(scan_id, cmd, label)
                out_fmt = ct.get("output_format") or "plain"
                if out_fmt.startswith("json:"):
                    found = parse_json_field_hostnames(lines, out_fmt.split(":", 1)[1], domain)
                else:
                    found = parse_plain_hostnames(lines, domain)
                add_subs(found, ct["name"])
            return _fn
        discovery_steps.append((f"Custom tool: {ct['name']}", _make_custom_step()))

    if enabled("crtsh", True):
        async def _crtsh():
            add_subs(await crtsh_lookup(scan_id, domain), "crtsh")
        discovery_steps.append(("Certificate transparency: crt.sh", _crtsh))

    for src in custom_api_subdomain_sources:
        def _make_api_sub_step(src=src):
            async def _fn():
                add_subs(await run_custom_api_subdomain_source(scan_id, src, domain), src["name"])
            return _fn
        discovery_steps.append((f"Custom API source: {src['name']}", _make_api_sub_step()))

    if shodan_key and enabled("shodan", True):
        async def _shodan_dns():
            add_subs(await shodan_dns_domain(scan_id, domain, shodan_key), "shodan")
        discovery_steps.append(("Shodan: passive subdomains", _shodan_dns))

    if enabled("whois", True):
        async def _whois():
            await whois_lookup(scan_id, domain, mode)
        discovery_steps.append(("WHOIS lookup", _whois))

    # =====================================================================
    # Resolution / probing stages (each optional based on tool_settings)
    # =====================================================================
    run_dnsx = enabled("dnsx", True)
    run_httpx = enabled("httpx", True)
    run_naabu = mode == "full" and enabled("naabu", True)
    run_nmap = enabled("nmap", True)

    async def _dnsx():
        nonlocal resolved, host_all_ips
        cmd = apply_variant(["dnsx", "-silent", "-json", "-a", "-l", str(tmp_hosts)], "dnsx", mode)
        dnsx_lines = await run_stream(scan_id, cmd, "dnsx")
        host_all_ips = parse_dnsx_json(dnsx_lines)
        resolved = {host: ips[0] for host, ips in host_all_ips.items() if ips}


    async def _httpx():
        nonlocal assets
        # Proactively resolve the *real* ProjectDiscovery httpx even if a
        # same-named Python httpx[cli] HTTP client shadows it earlier on
        # PATH — see find_working_binary(). Falls back to the plain name
        # if nothing resolves, so the reactive check below still catches
        # and explains it if this somehow finds nothing usable either.
        httpx_bin = await find_working_binary("httpx", "-version", scan_id) or "httpx"
        cmd = apply_variant(
            [httpx_bin, "-silent", "-json", "-title", "-tech-detect", "-status-code", "-fr", "-l", str(tmp_hosts)],
            "httpx", mode,
        )
        httpx_lines = await run_stream(scan_id, cmd, "httpx")

        # Belt and suspenders: if resolution above somehow still picked
        # the wrong one (e.g. only the Python tool exists anywhere on
        # PATH), this explains clearly what went wrong rather than
        # leaving a cryptic Click parser error with no context.
        if looks_like_wrong_binary(httpx_lines):
            await log_line(
                scan_id,
                "[httpx] this looks like a DIFFERENT program also called 'httpx' — most likely the "
                "Python httpx[cli] HTTP client, not ProjectDiscovery's recon tool (same binary name, "
                "different tool), and no working ProjectDiscovery httpx was found anywhere on PATH. "
                "Install it with `go install github.com/projectdiscovery/httpx/cmd/httpx@latest`.",
                "error",
            )
            return

        assets = parse_httpx_json(httpx_lines)
        for a in assets:
            conn.execute(
                "INSERT INTO http_assets (scan_id, subdomain, url, status_code, title, tech, server, ip) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, a["subdomain"], a["url"], a["status_code"], a["title"], a["tech"], a["server"], a["ip"]),
            )
        conn.commit()
        await log_line(scan_id, f"[+] {len(assets)} live HTTP assets found", "meta")

        # If the root domain's homepage redirects to a different hostname
        # entirely (bare domain -> www, or off to a whole different brand
        # domain), that's real, verifiable evidence of what the "main" site
        # actually is — not a guess, just following what the server itself
        # told us. -fr above makes httpx follow the redirect chain.
        root_asset = next((a for a in assets if a["subdomain"] == domain), None)
        if root_asset and root_asset.get("final_url"):
            try:
                final_host = (urllib.parse.urlsplit(root_asset["final_url"]).hostname or "").lower()
            except Exception:
                final_host = ""
            if final_host and final_host != domain:
                store_intel(conn, scan_id, domain, "httpx", "redirects_to", root_asset["final_url"])
                conn.commit()
                await log_line(scan_id, f"[+] {domain} redirects to {final_host} — likely the main site", "meta")

    async def _naabu():
        if not shutil.which("naabu"):
            await run_stream(scan_id, ["naabu"], "naabu")  # logs the standard "not found" skip message
            return
        host_count = len(tmp_hosts.read_text().splitlines()) if tmp_hosts.exists() else 0
        aggressive = is_aggressive("naabu")
        if aggressive:
            top_ports, rate = "1000", "5000"
            desc = "top 1000 ports, rate 5000/s (aggressive mode)"
        else:
            top_ports, rate = "100", None
            desc = "top 100 ports"
        await log_line(scan_id, f"[naabu] scanning {desc} across {host_count} host(s)...", "meta")
        naabu_cmd = ["naabu", "-silent", "-json", "-top-ports", top_ports, "-l", str(tmp_hosts)]
        if rate:
            naabu_cmd += ["-rate", rate]
        cmd = apply_variant(naabu_cmd, "naabu", mode)
        naabu_lines = await run_stream(scan_id, cmd, "naabu")
        port_hits = parse_naabu_json(naabu_lines)
        for host, port in port_hits:
            upsert_port(conn, scan_id, host, port, "naabu")
        conn.commit()
        hosts_with_hits = len({h for h, p in port_hits})
        await log_line(
            scan_id,
            f"[+] naabu: {len(port_hits)} open port(s) found across {hosts_with_hits}/{host_count} host(s) "
            f"({desc}, {host_count - hosts_with_hits} host(s) had none open)",
            "meta",
        )

    async def _nmap():
        if not shutil.which("nmap"):
            await run_stream(scan_id, ["nmap"], "nmap")  # logs the standard "not found" skip message
            return
        # Every resolved A record, not just each host's "primary" one —
        # a host behind a CDN/load-balancer can have several backend
        # IPs, and only ever scanning the first one dnsx listed was a
        # real, confirmed cause of nmap finding nothing on a host httpx
        # had just confirmed live: httpx does its own DNS resolution at
        # connection time and can land on a different IP from the same
        # pool than the single one this used to scan.
        ips = sorted({ip for host_ips in host_all_ips.values() for ip in host_ips})
        if not ips:
            await log_line(scan_id, "[nmap] no resolved IPs to scan", "warn")
            return
        tmp_ips = BASE_DIR / f".scan_{scan_id}_ips.txt"
        tmp_ips.write_text("\n".join(ips))
        try:
            aggressive = is_aggressive("nmap")
            if mode == "full":
                if aggressive:
                    # nmap's own literal -A ("aggressive") flag: OS
                    # detection, version detection, script scanning, and
                    # traceroute, all in one — already implies -sV -sC so
                    # those aren't also passed separately. -T5 ("insane")
                    # trades accuracy/stealth for raw speed.
                    cmd = [
                        "nmap", "-Pn", "-T5", "-A", "--top-ports", "1000", "--open",
                        "-iL", str(tmp_ips), "-oX", "-",
                    ]
                    label = "nmap (full, AGGRESSIVE: -A -T5)"
                    port_desc = "top 1000 ports, OS detection + version + scripts + traceroute (-A), fastest timing (-T5)"
                else:
                    # Deeper pass: wider port range, version detection, and
                    # nmap's default (safe) NSE script set — the "scripting"
                    # part of the ask. -Pn means hosts that don't answer ping
                    # are still scanned rather than skipped as "down".
                    cmd = [
                        "nmap", "-Pn", "-T4", "--top-ports", "1000", "-sV", "-sC", "--open",
                        "-iL", str(tmp_ips), "-oX", "-",
                    ]
                    label = "nmap (full: top 1000 ports, version + scripts)"
                    port_desc = "top 1000 ports, with version detection (-sV) and default scripts (-sC)"
            else:
                if aggressive:
                    cmd = ["nmap", "-Pn", "-T5", "-F", "--open", "-iL", str(tmp_ips), "-oX", "-"]
                    label = "nmap (fast, aggressive timing: -T5)"
                    port_desc = "top 100 ports, fastest timing (-T5)"
                else:
                    # Quick pass: top 100 ports, no version/script overhead, but
                    # still -Pn so ping-blocking hosts aren't skipped.
                    cmd = ["nmap", "-Pn", "-T4", "-F", "--open", "-iL", str(tmp_ips), "-oX", "-"]
                    label = "nmap (fast: top 100 ports)"
                    port_desc = "top 100 ports"
            cmd = apply_variant(cmd, "nmap", mode)
            await log_line(scan_id, f"[nmap] scanning {port_desc} across {len(ips)} unique resolved IP(s)...", "meta")
            nmap_lines = await run_stream(scan_id, cmd, label)
            # -oX (XML) instead of -oG (greppable) — greppable format has
            # no way to represent NSE script output or OS detection
            # results at all, by nmap's own design. -sC/-A were already
            # being requested (and costing real scan time to run) with
            # their output structurally impossible to capture under the
            # old format, so this switch was necessary, not just an
            # enhancement. run_stream returns individual lines; nmap's
            # own XML output has internal newlines regardless, so
            # rejoining them reconstructs the exact same document.
            parsed = parse_nmap_xml("\n".join(nmap_lines))
            hits = parsed["hits"]

            # A host with more than one A record can have its open ports
            # land on any of them, not just the "primary" one that gets
            # its own row in the Hosts table. Rather than storing each
            # such finding twice (once by IP, once by hostname — which
            # would inflate the Ports count and look like duplicate
            # findings), a secondary IP's findings are attributed
            # directly to the owning hostname instead of the raw IP,
            # since that raw secondary IP has no row of its own to
            # cross-reference against anyway. Primary IPs are unaffected
            # — those already match the Hosts table's existing IP-based
            # lookup and keep working exactly as before.
            secondary_ip_owner: dict[str, str] = {}
            for host, host_ips in host_all_ips.items():
                for extra_ip in host_ips[1:]:
                    secondary_ip_owner.setdefault(extra_ip, host)

            for ip, port, service in hits:
                target = secondary_ip_owner.get(ip, ip)
                upsert_port(conn, scan_id, target, port, "nmap", service or None)

            # NSE script output and OS detection — the actual new data
            # this format switch unlocks. Same host/secondary-IP
            # attribution as the port hits above, stored as host_intel
            # since neither has a dedicated table of its own (script
            # findings are free-form text, not the kind of thing that
            # benefits from its own schema the way ports/vulnerabilities
            # do).
            script_count = 0
            for ip, entries in parsed["scripts"].items():
                target = secondary_ip_owner.get(ip, ip)
                for entry in entries:
                    port_part = str(entry["port"]) if entry["port"] is not None else "host"
                    field = f"script:{port_part}:{entry['script_id']}"
                    store_intel(conn, scan_id, target, "nmap", field, entry["output"])
                    script_count += 1
            for ip, os_name in parsed["os_guesses"].items():
                target = secondary_ip_owner.get(ip, ip)
                store_intel(conn, scan_id, target, "nmap", "os_guess", os_name)

            conn.commit()
            hosts_with_hits = len({ip for ip, p, s in hits})
            await log_line(
                scan_id,
                f"[+] nmap: {len(hits)} open port(s) found across {hosts_with_hits}/{len(ips)} IP(s) "
                f"({port_desc}, {len(ips) - hosts_with_hits} IP(s) had none open)"
                + (f"; {script_count} script finding(s), {len(parsed['os_guesses'])} OS guess(es)" if (script_count or parsed["os_guesses"]) else ""),
                "meta",
            )
        finally:
            tmp_ips.unlink(missing_ok=True)

    # =====================================================================
    # Enrichment stages — closures read `resolved`/`assets` at call time,
    # so it's safe to build this list before those are populated.
    # =====================================================================
    enrich_steps: list[tuple[str, "asyncio.coroutines"]] = []

    if enabled("ip-geo", True):
        async def _ip_geo():
            await ip_geo_lookup(scan_id, sorted(set(resolved.values())))
        enrich_steps.append(("IP geolocation (ip-api.com)", _ip_geo))

    for src in custom_api_enrich_sources:
        def _make_api_enrich_step(src=src):
            async def _fn():
                await run_custom_api_enrich_source(scan_id, src, domain, sorted(set(resolved.values())))
            return _fn
        enrich_steps.append((f"Custom API source: {src['name']}", _make_api_enrich_step()))

    if enabled("internetdb", True):
        async def _internetdb():
            ips = sorted(set(resolved.values()))
            if ips:
                await internetdb_lookup(scan_id, ips)
            else:
                await log_line(scan_id, "[internetdb] no resolved IPs to look up", "warn")
        enrich_steps.append(("Shodan InternetDB: free host lookup", _internetdb))

    if leakix_key and enabled("leakix", True):
        async def _leakix():
            ips = sorted(set(resolved.values()))
            if ips:
                await leakix_lookup(scan_id, ips, leakix_key)
            else:
                await log_line(scan_id, "[leakix] no resolved IPs to look up", "warn")
        enrich_steps.append(("LeakIX: exposed-service lookup", _leakix))

    # social-scan, shodan host enrichment, company-lookup, crosslinked, and
    # xposedornot no longer run automatically here — they've moved to the
    # independent Company module (see run_company_scan / the Company tab's
    # "Run company scan" button), which is a deliberate, separately-
    # triggered action rather than something that happens just because a
    # scan happened to run in Full mode. See run_company_scan for where
    # this logic now lives.

    if mode == "full" and enabled("gowitness", True):
        async def _gowitness():
            # `assets` was populated by _httpx() earlier in this same
            # pipeline run (enrichment steps execute after HTTP probing —
            # see the stage order below), so it's already available here.
            urls = sorted({a["url"] for a in assets if a["url"]})
            await gowitness_run(scan_id, domain, mode, urls)
        enrich_steps.append(("gowitness: screenshotting live hosts", _gowitness))

    if mode == "full" and enabled("whatweb", True):
        async def _whatweb():
            urls = sorted({a["url"] for a in assets if a["url"]})
            await whatweb_run(scan_id, domain, mode, urls)
        enrich_steps.append(("whatweb: technology fingerprinting", _whatweb))

    if mode == "full" and enabled("katana", True):
        async def _katana():
            urls = sorted({a["url"] for a in assets if a["url"]})
            await katana_run(scan_id, domain, mode, urls)
        enrich_steps.append(("katana: crawling live hosts for deeper endpoints", _katana))

    if mode == "full" and enabled("gau", True):
        async def _gau():
            await gau_run(scan_id, domain, mode)
        enrich_steps.append(("gau: historical URL discovery", _gau))

    # nuclei, ffuf, wpscan, and dalfox no longer run automatically here —
    # they've moved to the independent Vulnerability module (see
    # run_vulnerability_scan / the Vulnerability tab's "Run vulnerability
    # scan" button), a deliberate, separately-triggered action against
    # whatever this scan's enumeration (including gau/katana above) has
    # found, rather than something baked into every Full-mode scan.

    if mode == "full" and enabled("spiderfoot", True):
        async def _spiderfoot():
            await spiderfoot_run(scan_id, domain, mode)
        enrich_steps.append(("SpiderFoot: passive OSINT modules", _spiderfoot))

    # =====================================================================
    # Total is exact — everything above only *defines* stages, nothing has
    # run yet — so the progress bar is accurate from the very first update.
    # =====================================================================
    total_stages = (
        len(discovery_steps)
        + (1 if run_dnsx else 0)
        + (1 if run_httpx else 0)
        + (1 if run_naabu else 0)
        + (1 if run_nmap else 0)
        + len(enrich_steps)
    )
    progress = ProgressTracker(scan_id, total_stages)

    try:
        # --- Discovery ---------------------------------------------------
        for label, fn in discovery_steps:
            await run_named_stage(progress, scan_id, label, fn())

        subs.setdefault(domain, set()).add("root")
        if not subs:
            await log_line(scan_id, "[warn] no subdomains discovered — stopping here", "warn")
            await progress.finish("No hosts found")
            finalize_scan(scan_id, "completed")
            return

        await log_line(scan_id, f"[+] {len(subs)} unique candidate hosts before resolution", "meta")
        tmp_hosts = BASE_DIR / f".scan_{scan_id}_hosts.txt"
        tmp_hosts.write_text("\n".join(sorted(subs.keys())))

        # --- Resolution ----------------------------------------------------
        if run_dnsx:
            await run_named_stage(progress, scan_id, "DNS resolution", _dnsx())

        for host, sources in subs.items():
            conn.execute(
                "INSERT INTO subdomains (scan_id, subdomain, sources, ip) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(scan_id, subdomain) DO UPDATE SET sources=excluded.sources, ip=excluded.ip",
                (scan_id, host, ",".join(sorted(sources)), resolved.get(host)),
            )
        conn.commit()

        # --- HTTP probing ----------------------------------------------------
        if run_httpx:
            await run_named_stage(progress, scan_id, "HTTP probing: httpx", _httpx())

        # --- Port scan (full stack only) --------------------------------------
        if run_naabu:
            await run_named_stage(progress, scan_id, "Port scan: naabu (top 100)", _naabu())

        # --- Port scan: nmap (both modes — fast pass or deep scripted pass) ----
        if run_nmap:
            nmap_label = "Port scan: nmap (deep)" if mode == "full" else "Port scan: nmap (quick)"
            await run_named_stage(progress, scan_id, nmap_label, _nmap())

        # --- Enrichment ----------------------------------------------------
        for label, fn in enrich_steps:
            await run_named_stage(progress, scan_id, label, fn())

    finally:
        if tmp_hosts is not None:
            tmp_hosts.unlink(missing_ok=True)

    await progress.finish("Complete")
    await log_line(scan_id, "=== scan complete ===", "meta")
    finalize_scan(scan_id, "completed")


def finalize_scan(scan_id: int, status: str):
    conn = get_db()
    conn.execute(
        "UPDATE scans SET status = ?, completed_at = ? WHERE id = ?",
        (status, now_iso(), scan_id),
    )
    conn.commit()
    conn.close()


def build_scan_docs_text(scan_id: int) -> tuple[str, str]:
    """Builds the holistic per-scan text capture: every line of text
    output generated during the scan (the full live log, exactly as
    streamed to the terminal — not just commands, not just a summary),
    followed by a complete results dump. Returns (filename, content);
    doesn't touch disk itself, see write_scan_docs_file() for that.
    """
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        raise ValueError(f"scan {scan_id} not found")
    logs = conn.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
    subs = conn.execute("SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain", (scan_id,)).fetchall()
    assets = conn.execute("SELECT * FROM http_assets WHERE scan_id = ? ORDER BY subdomain", (scan_id,)).fetchall()
    ports = conn.execute("SELECT * FROM ports WHERE scan_id = ? ORDER BY host, port", (scan_id,)).fetchall()
    intel = conn.execute("SELECT * FROM host_intel WHERE scan_id = ? ORDER BY host, source, field", (scan_id,)).fetchall()
    emails = conn.execute("SELECT * FROM emails WHERE scan_id = ? ORDER BY email", (scan_id,)).fetchall()
    conn.close()

    mode_label = "Full" if scan["mode"] == "full" else "Fast"
    filename = f"{sanitize_filename_part(scan['domain'])}_Docs_Scan{scan_id}_{mode_label}.txt"

    assets_by_host = {a["subdomain"]: a for a in assets}
    ports_by_host: dict[str, list[str]] = {}
    for p in ports:
        ports_by_host.setdefault(p["host"], []).append(f"{p['port']}/{p['source']}")

    bar = "=" * 78
    out: list[str] = []
    out += [bar, "MIMIR // scan documentation", bar]
    out += [
        f"Domain:      {scan['domain']}",
        f"Scan #:      {scan_id}",
        f"Mode:        {mode_label}",
        f"Status:      {scan['status']}",
        f"Started:     {scan['started_at']}",
        f"Completed:   {scan['completed_at'] or 'n/a'}",
        f"Generated:   {now_iso()}",
        "",
        "This file is a complete, holistic record of one scan run: every line of",
        "text output generated during the scan (the full live log, exactly as it",
        "streamed to the terminal) followed by a complete results dump. It's",
        "written automatically once the scan finishes, and refreshed with the",
        "latest data (e.g. after Validate findings) any time it's re-downloaded.",
        "",
    ]

    out += [bar, "FULL LOG — every text output generated during this scan", bar]
    for l in logs:
        out.append(f"[{l['ts']}] [{l['level']}] {l['line']}")
    out.append("")

    out += [bar, "SUMMARY", bar]
    out += [
        f"Hosts discovered:   {len(subs)}",
        f"Live HTTP assets:   {len(assets)}",
        f"Open ports:         {len(ports)}",
        f"Emails harvested:   {len(emails)}",
        f"Intel facts:        {len(intel)}",
        "",
    ]

    out += [bar, "HOSTS & ASSETS", bar]
    for s in subs:
        a = assets_by_host.get(s["subdomain"])
        http_status = a["status_code"] if a else "-"
        title = a["title"] if a and a["title"] else "-"
        prt = ", ".join(ports_by_host.get(s["subdomain"], []) or ports_by_host.get(s["ip"] or "", [])) or "-"
        conf = f"{s['confidence']}% {s['validation_status']}" if s["confidence"] is not None else "not validated"
        out.append(
            f"- {s['subdomain']}  ip={s['ip'] or '-'}  sources={s['sources']}  "
            f"http={http_status}  title={title}  ports={prt}  confidence={conf}"
        )
    out.append("")

    if ports:
        out += [bar, "OPEN PORTS", bar]
        for p in ports:
            conf = f"{p['confidence']}% {p['validation_status']}" if p["confidence"] is not None else "not validated"
            out.append(f"- {p['host']}:{p['port']}  source={p['source']}  service={p['service'] or '-'}  confidence={conf}")
        out.append("")

    if intel:
        out += [bar, "OSINT & ENRICHMENT INTEL", bar]
        for i in intel:
            out.append(f"- [{i['host']}] {i['source']}.{i['field']}: {i['value']}")
        out.append("")

    if emails:
        out += [bar, "EMAILS HARVESTED", bar]
        for e in emails:
            out.append(f"- {e['email']} (via {e['source']})")
        out.append("")

    return filename, "\n".join(out)


def write_scan_docs_file(scan_id: int) -> Path:
    filename, content = build_scan_docs_text(scan_id)
    DOCS_DIR.mkdir(exist_ok=True)
    path = DOCS_DIR / filename
    path.write_text(content, encoding="utf-8")
    return path


async def run_pipeline_safe(scan_id: int, domain: str, mode: str):
    try:
        await run_pipeline(scan_id, domain, mode)
    except ScanStopped:
        await log_line(scan_id, "=== scan stopped by user ===", "warn")
        finalize_scan(scan_id, "stopped")
    except Exception as e:
        await log_line(scan_id, f"[fatal] pipeline crashed: {e}", "error")
        finalize_scan(scan_id, "failed")
    finally:
        STOP_REQUESTED.pop(scan_id, None)
        RUNNING_STAGE_TASKS.pop(scan_id, None)
    # One holistic .txt file per scan, written regardless of how it ended
    # (completed/stopped/failed) — a permanent record on disk independent
    # of the database.
    try:
        docs_path = write_scan_docs_file(scan_id)
        await log_line(scan_id, f"[+] scan documentation written: {docs_path.name}", "meta")
    except Exception as e:
        await log_line(scan_id, f"[warn] couldn't write scan documentation file: {e}", "warn")
    await manager.broadcast(scan_id, {"type": "scan_finished"})


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="MIMIR //", lifespan=lifespan)


@app.middleware("http")
async def no_cache_middleware(request, call_next):
    """This is a local, single-user recon tool, not a public site — there's
    no upside to letting the browser cache anything, and real downside:
    the frontend (index.html) has been updated many times over this app's
    development, and a browser holding onto a stale cached copy is
    exactly what makes it look like fixes/features "aren't there" even
    though the file on disk is current. Every response, including the
    static frontend itself, tells the browser not to cache it at all."""
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


class ScanRequest(BaseModel):
    domain: str
    mode: str = "fast"
    company_name: Optional[str] = None


class CustomToolIn(BaseModel):
    name: str
    command_template: str
    output_format: str = "plain"
    shell: bool = False


class ApiKeyIn(BaseModel):
    service: str
    key: str = ""


class ApiSourceIn(BaseModel):
    name: str
    category: str = "enrich"  # "subdomain" | "enrich"
    url_template: str
    json_path: str = ""
    intel_fields: str = ""
    api_key: str = ""


@app.get("/api/config")
async def get_config():
    settings_map = get_tool_settings_map()
    builtin_tools = []
    for b in BUILTIN_TOOLS:
        if b["name"] == "shodan":
            available = bool(get_api_key("shodan"))
        elif b["name"] == "leakix":
            available = bool(get_api_key("leakix"))
        elif b["name"] == "hunter":
            available = bool(get_api_key("hunter"))
        elif b["name"] in ("crtsh", "ip-geo", "social-scan", "company-lookup", "internetdb"):
            available = True
        elif b["name"] == "theharvester":
            available = bool(find_binary(HARVESTER_BINARIES))
        elif b["name"] == "httpx":
            # Not just "is *something* called httpx on PATH" — is a
            # *working* ProjectDiscovery httpx findable, even if a
            # same-named Python HTTP client shadows it. See
            # find_working_binary(); same resolution the pipeline itself
            # uses, so this pill won't lie about what a scan will actually do.
            available = bool(await find_working_binary("httpx", "-version"))
        else:
            available = bool(shutil.which(b["name"]))
        builtin_tools.append({**b, "available": available, "enabled": is_enabled(b["name"], settings_map, True)})

    custom = get_custom_tools()
    for c in custom:
        if c.get("shell"):
            # Chained/piped commands can't be reduced to a single binary check
            c["available"] = None
        else:
            try:
                first_bin = build_custom_cmd(c["command_template"], "example.com")[0]
                c["available"] = bool(shutil.which(first_bin))
            except Exception:
                c["available"] = False

    api_sources = get_custom_api_sources()
    for s in api_sources:
        s["api_key_masked"] = mask_key(s.get("api_key"))
        s.pop("api_key", None)  # never return the raw key to the client

    shodan_key = get_api_key("shodan")
    leakix_key = get_api_key("leakix")
    wpscan_key = get_api_key("wpscan")
    hunter_key = get_api_key("hunter")
    conn2 = get_db()
    intensity_rows = conn2.execute("SELECT tool_name, aggressive FROM tool_intensity").fetchall()
    profile_rows = conn2.execute("SELECT tool_name, profile FROM tool_profiles").fetchall()
    conn2.close()
    current_profiles = {name: TOOL_PROFILES[name]["default"] for name in TOOL_PROFILES}
    current_profiles.update({r["tool_name"]: r["profile"] for r in profile_rows if r["tool_name"] in TOOL_PROFILES})
    return {
        "builtin_tools": builtin_tools,
        "custom_tools": custom,
        "custom_api_sources": api_sources,
        "tool_variants": get_tool_variants(),
        "wordlists": get_wordlists(),
        "wordlist_recommendations": get_wordlist_recommendations(),
        "ai_config": (lambda c: {
            "configured": c is not None,
            "base_url": c["base_url"] if c else None,
            "model": c["model"] if c else None,
            "api_key_set": bool(c["api_key"]) if c else False,
        })(get_ai_config()),
        "tool_wordlists": get_tool_wordlist_assignments(),
        "wordlist_capable_tools": sorted(WORDLIST_CAPABLE_TOOLS),
        "tool_intensity": {r["tool_name"]: bool(r["aggressive"]) for r in intensity_rows},
        "aggressive_capable_tools": sorted(AGGRESSIVE_CAPABLE_TOOLS),
        "tool_profiles": TOOL_PROFILES,
        "current_tool_profiles": current_profiles,
        "api_keys": {
            "shodan": {"configured": bool(shodan_key), "masked": mask_key(shodan_key)},
            "leakix": {"configured": bool(leakix_key), "masked": mask_key(leakix_key)},
            "wpscan": {"configured": bool(wpscan_key), "masked": mask_key(wpscan_key)},
            "hunter": {"configured": bool(hunter_key), "masked": mask_key(hunter_key)},
        },
        "tech_knowledge_base": TECH_KNOWLEDGE_BASE,
        "tech_kb_aliases": TECH_KB_ALIASES,
        "port_knowledge_base": PORT_KNOWLEDGE_BASE,
    }


@app.post("/api/config/tool_toggle")
async def toggle_tool(payload: dict):
    name = payload.get("name")
    enabled_val = bool(payload.get("enabled", True))
    if not name:
        return JSONResponse({"error": "name required"}, status_code=400)
    conn = get_db()
    conn.execute(
        "INSERT INTO tool_settings (name, enabled) VALUES (?, ?) "
        "ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled",
        (name, int(enabled_val)),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/config/tool_toggle_all")
async def toggle_all_tools(payload: dict):
    """Bulk on/off for every built-in tool at once — one transaction
    rather than the frontend firing 15 separate toggle requests."""
    enabled_val = bool(payload.get("enabled", True))
    conn = get_db()
    for tool in BUILTIN_TOOLS:
        conn.execute(
            "INSERT INTO tool_settings (name, enabled) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET enabled = excluded.enabled",
            (tool["name"], int(enabled_val)),
        )
    conn.commit()
    conn.close()
    return {"ok": True, "enabled": enabled_val, "count": len(BUILTIN_TOOLS)}


@app.post("/api/config/custom_tool")
async def add_custom_tool(t: CustomToolIn):
    name = t.name.strip()
    template = t.command_template.strip()
    if not name or not template:
        return JSONResponse({"error": "name and command_template are required"}, status_code=400)
    conn = get_db()
    conn.execute(
        "INSERT INTO custom_tools (name, command_template, output_format, shell, enabled, created_at) "
        "VALUES (?, ?, ?, ?, 1, ?)",
        (name, template, t.output_format.strip() or "plain", int(t.shell), now_iso()),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.put("/api/config/custom_tool/{tool_id}")
async def update_custom_tool(tool_id: int, payload: dict):
    conn = get_db()
    if "enabled" in payload:
        conn.execute("UPDATE custom_tools SET enabled = ? WHERE id = ?", (int(bool(payload["enabled"])), tool_id))
        conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/config/custom_tool/{tool_id}")
async def delete_custom_tool(tool_id: int):
    conn = get_db()
    conn.execute("DELETE FROM custom_tools WHERE id = ?", (tool_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/config/api_source")
async def add_api_source(s: ApiSourceIn):
    name = s.name.strip()
    url_template = s.url_template.strip()
    if not name or not url_template:
        return JSONResponse({"error": "name and url_template are required"}, status_code=400)
    category = s.category if s.category in ("subdomain", "enrich") else "enrich"
    conn = get_db()
    conn.execute(
        "INSERT INTO custom_api_sources (name, category, url_template, json_path, intel_fields, api_key, enabled, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        (name, category, url_template, s.json_path.strip(), s.intel_fields.strip(), s.api_key.strip(), now_iso()),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.put("/api/config/api_source/{source_id}")
async def update_api_source(source_id: int, payload: dict):
    conn = get_db()
    if "enabled" in payload:
        conn.execute(
            "UPDATE custom_api_sources SET enabled = ? WHERE id = ?", (int(bool(payload["enabled"])), source_id)
        )
        conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/config/api_source/{source_id}")
async def delete_api_source(source_id: int):
    conn = get_db()
    conn.execute("DELETE FROM custom_api_sources WHERE id = ?", (source_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


def get_wordlists() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM wordlists ORDER BY uploaded_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_tool_wordlist_assignments() -> dict[str, int]:
    conn = get_db()
    rows = conn.execute("SELECT tool_name, wordlist_id FROM tool_wordlists").fetchall()
    conn.close()
    return {r["tool_name"]: r["wordlist_id"] for r in rows if r["wordlist_id"] is not None}


@app.post("/api/wordlists")
async def upload_wordlist(file: UploadFile = File(...)):
    """Stores an uploaded wordlist under WORDLISTS_DIR with a collision-safe
    filename (id prefix), and records line/size metadata so the UI can
    show something useful without re-reading the file every time."""
    content = await file.read()
    if not content.strip():
        return JSONResponse({"error": "that file is empty"}, status_code=400)

    WORDLISTS_DIR.mkdir(exist_ok=True)
    name = (file.filename or "wordlist.txt").strip()
    safe_name = sanitize_filename_part(name) or "wordlist.txt"

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO wordlists (name, filename, line_count, size_bytes, uploaded_at) VALUES (?, '', ?, ?, ?)",
        (name, 0, len(content), now_iso()),
    )
    wordlist_id = cur.lastrowid
    stored_filename = f"{wordlist_id}_{safe_name}"
    (WORDLISTS_DIR / stored_filename).write_bytes(content)

    line_count = sum(1 for line in content.decode("utf-8", errors="replace").splitlines() if line.strip())
    conn.execute(
        "UPDATE wordlists SET filename = ?, line_count = ? WHERE id = ?",
        (stored_filename, line_count, wordlist_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "id": wordlist_id, "name": name, "line_count": line_count, "size_bytes": len(content)}


@app.delete("/api/wordlists/{wordlist_id}")
async def delete_wordlist(wordlist_id: int):
    conn = get_db()
    row = conn.execute("SELECT filename FROM wordlists WHERE id = ?", (wordlist_id,)).fetchone()
    if row:
        (WORDLISTS_DIR / row["filename"]).unlink(missing_ok=True)
    conn.execute("DELETE FROM wordlists WHERE id = ?", (wordlist_id,))  # ON DELETE SET NULL clears tool_wordlists refs
    conn.commit()
    conn.close()
    return {"ok": True}


class ToolWordlistIn(BaseModel):
    tool_name: str
    wordlist_id: Optional[int] = None


@app.put("/api/config/tool_wordlist")
async def set_tool_wordlist(payload: ToolWordlistIn):
    if payload.tool_name not in WORDLIST_CAPABLE_TOOLS:
        return JSONResponse(
            {"error": f"'{payload.tool_name}' doesn't take a wordlist — only {', '.join(sorted(WORDLIST_CAPABLE_TOOLS))} do"},
            status_code=400,
        )
    conn = get_db()
    if payload.wordlist_id is None:
        conn.execute("DELETE FROM tool_wordlists WHERE tool_name = ?", (payload.tool_name,))
    else:
        exists = conn.execute("SELECT 1 FROM wordlists WHERE id = ?", (payload.wordlist_id,)).fetchone()
        if not exists:
            conn.close()
            return JSONResponse({"error": "wordlist not found"}, status_code=404)
        conn.execute(
            "INSERT INTO tool_wordlists (tool_name, wordlist_id) VALUES (?, ?) "
            "ON CONFLICT(tool_name) DO UPDATE SET wordlist_id = excluded.wordlist_id",
            (payload.tool_name, payload.wordlist_id),
        )
    conn.commit()
    conn.close()
    return {"ok": True}


class ToolIntensityIn(BaseModel):
    tool_name: str
    aggressive: bool


@app.put("/api/config/tool_intensity")
async def set_tool_intensity(payload: ToolIntensityIn):
    if payload.tool_name not in AGGRESSIVE_CAPABLE_TOOLS:
        return JSONResponse(
            {"error": f"'{payload.tool_name}' doesn't have an aggressive-mode toggle — only {', '.join(sorted(AGGRESSIVE_CAPABLE_TOOLS))} do"},
            status_code=400,
        )
    conn = get_db()
    conn.execute(
        "INSERT INTO tool_intensity (tool_name, aggressive) VALUES (?, ?) "
        "ON CONFLICT(tool_name) DO UPDATE SET aggressive = excluded.aggressive",
        (payload.tool_name, int(payload.aggressive)),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


class ToolProfileIn(BaseModel):
    tool_name: str
    profile: str


@app.put("/api/config/tool_profile")
async def set_tool_profile_endpoint(payload: ToolProfileIn):
    if payload.tool_name not in TOOL_PROFILES:
        return JSONResponse(
            {"error": f"'{payload.tool_name}' doesn't have configurable profiles — only {', '.join(sorted(TOOL_PROFILES))} do"},
            status_code=400,
        )
    valid_values = {opt["value"] for opt in TOOL_PROFILES[payload.tool_name]["options"]}
    if payload.profile not in valid_values:
        return JSONResponse({"error": f"'{payload.profile}' isn't a valid profile for {payload.tool_name}"}, status_code=400)
    set_tool_profile(payload.tool_name, payload.profile)
    return {"ok": True}


class CompanyLookupIn(BaseModel):
    company_name: str


@app.post("/api/scans/{scan_id}/company_lookup")
async def manual_company_lookup(scan_id: int, payload: CompanyLookupIn):
    """Lets you supply the real company name directly rather than relying
    on the auto-detected guess (WHOIS org / scraped site name / domain
    label) — genuinely useful since a domain often doesn't match the
    company's actual registered name (a rebrand, a product-specific
    domain, a domain under a corporate parent, etc.). The supplied name
    goes first in the candidate list, so it's tried before the
    auto-detected ones — but it still goes through the same
    official-website verification as always (see company_lookup): a name
    match alone is never enough, the confirmed Wikidata entity's own
    website has to actually match this scan's domain, or nothing gets
    shown as confirmed. That's what "validate" means here — cross-checked
    against the domain, not just accepted at face value.
    """
    conn = get_db()
    scan = conn.execute("SELECT domain FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        return JSONResponse({"error": "scan not found"}, status_code=404)

    name = payload.company_name.strip()
    if not name:
        return JSONResponse({"error": "company_name required"}, status_code=400)

    domain = scan["domain"]
    candidates = [name] + get_company_name_candidates(scan_id, domain)
    await log_line(scan_id, f"[company] manual lookup requested for '{name}'", "meta")
    await company_lookup(scan_id, domain, candidates, user_supplied_name=name)
    return {"ok": True}


class KnownEmailsIn(BaseModel):
    emails: list[str]


@app.post("/api/scans/{scan_id}/known-emails")
async def add_known_emails(scan_id: int, payload: KnownEmailsIn):
    """Lets you feed in one or more real emails you already have for the
    org from somewhere else (a past engagement, a client contact). They
    get saved to this scan's Emails tab (after the same off-domain
    filtering every other email source goes through — a known TLD
    variant of this domain still counts as "on domain"), and if one
    matches a CrossLinked-found employee's name closely enough to reveal
    the org's actual naming convention, that convention gets applied to
    every *other* CrossLinked employee with no known address — producing
    unverified guesses, clearly tagged as such (source="pattern-guess"),
    never shown as confirmed. See apply_known_emails in company.py for
    the actual matching/guessing logic.
    """
    conn = get_db()
    scan = conn.execute("SELECT domain FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return JSONResponse({"error": "scan not found"}, status_code=404)
    variant_rows = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id = ? AND source = 'company' AND field LIKE 'tld_variant:%'",
        (scan_id,),
    ).fetchall()
    conn.close()

    if not payload.emails:
        return JSONResponse({"error": "at least one email required"}, status_code=400)

    domain = scan["domain"]
    extra_domains = {r["value"] for r in variant_rows if r["value"]}
    result = await apply_known_emails(scan_id, domain, payload.emails, extra_domains=extra_domains or None)
    return {"ok": True, **result}


@app.post("/api/reset-scan-data")
async def reset_scan_data():
    """Wipes every scan and everything that belongs to one (subdomains,
    ports, HTTP assets, intel, emails, logs) — but deliberately leaves
    your setup alone (custom tools, bespoke command variants, custom API
    sources, API keys, tool on/off state). This is for "start with a
    clean slate of results" without having to redo any configuration.
    Deleting from `scans` cascades to every child table automatically
    (see the schema's ON DELETE CASCADE + PRAGMA foreign_keys=ON), so one
    statement is enough — this is not the same thing as clearing browser
    cache (see /api/clear-browser-data), it's this app's own stored data.
    """
    conn = get_db()
    scan_count = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return {"ok": True, "scans_deleted": scan_count}


@app.post("/api/config/api_key")
async def save_api_key(k: ApiKeyIn):
    service = k.service.strip().lower()
    if not service:
        return JSONResponse({"error": "service required"}, status_code=400)
    set_api_key(service, k.key.strip())
    return {"ok": True, "configured": bool(k.key.strip())}


@app.post("/api/clear-browser-data")
async def clear_browser_data():
    """The no-cache middleware above stops *future* caching, but doesn't
    retroactively purge whatever the browser already cached before this
    app was updated. Clear-Site-Data is the standards-based way a site
    can tell the browser to actually wipe its cache/storage for that
    site specifically — this is the "make the browser forget everything
    it has about this page" button. Works over plain HTTP here because
    browsers treat http://localhost and http://127.0.0.1 as secure
    contexts for this purpose, same as HTTPS.
    """
    return JSONResponse(
        {"ok": True, "message": "Told the browser to clear its cache and storage for this site."},
        headers={"Clear-Site-Data": '"cache", "storage"'},
    )


REQUIRED_BACKUP_TABLES = {"scans", "subdomains", "tool_variants", "custom_tools", "api_keys"}


@app.get("/api/backup/download")
async def download_backup():
    """A clean, consistent snapshot of the *entire* app state — every
    scan, every log, every custom tool/variant/API source/key — as a
    single portable SQLite file. This file already is the persistent
    state (surface.db, next to app.py, survives restarts on its own); this
    endpoint just hands you a safe-to-copy snapshot of it on demand, e.g.
    before wiping a machine or to move everything to a new install.

    Uses VACUUM INTO rather than just copying surface.db directly, since
    the live file is in WAL mode — a plain file copy could catch it
    mid-write or miss data still sitting in the -wal sidecar file.
    VACUUM INTO always produces one complete, self-contained file.
    """
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
    os.close(tmp_fd)
    tmp_path_obj = Path(tmp_path)
    tmp_path_obj.unlink()  # VACUUM INTO requires the target not exist yet
    try:
        conn = get_db()
        conn.execute("VACUUM INTO ?", (str(tmp_path_obj),))
        conn.close()
        data = tmp_path_obj.read_bytes()
    finally:
        tmp_path_obj.unlink(missing_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"surface_backup_{timestamp}.db"
    buf = io.BytesIO(data)
    return StreamingResponse(
        buf, media_type="application/x-sqlite3",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/backup/restore")
async def restore_backup(file: UploadFile = File(...)):
    """Replaces the running app's entire state with an uploaded backup
    file. Validated first (must actually open as SQLite and have the
    tables this app expects) so a wrong/corrupt upload can't brick the
    install. Existing WAL sidecar files for the current DB are removed as
    part of the swap so nothing tries to replay old WAL frames against
    the newly-restored file.
    """
    content = await file.read()
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
    os.close(tmp_fd)
    tmp_path_obj = Path(tmp_path)
    try:
        tmp_path_obj.write_bytes(content)
        try:
            test_conn = sqlite3.connect(tmp_path)
            tables = {r[0] for r in test_conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            test_conn.close()
        except sqlite3.DatabaseError:
            return JSONResponse({"error": "that file isn't a valid SQLite database"}, status_code=400)
        missing = REQUIRED_BACKUP_TABLES - tables
        if missing:
            return JSONResponse(
                {"error": f"doesn't look like a MIMIR // backup — missing tables: {', '.join(sorted(missing))}"},
                status_code=400,
            )
        for suffix in ("-shm", "-wal"):
            sidecar = Path(str(DB_PATH) + suffix)
            sidecar.unlink(missing_ok=True)
        shutil.copyfile(tmp_path, DB_PATH)
        return {"ok": True, "message": "Backup restored — reload the page to see it."}
    finally:
        tmp_path_obj.unlink(missing_ok=True)


class ToolVariantIn(BaseModel):
    tool_name: str
    mode: str = "both"  # "fast" | "full" | "both"
    label: str
    extra_args: str = ""


CLI_TOOL_NAMES = {t["name"] for t in BUILTIN_TOOLS if t.get("is_cli")}


@app.post("/api/config/tool_variants")
async def add_tool_variant(v: ToolVariantIn):
    tool_name = v.tool_name.strip()
    label = v.label.strip()
    if tool_name not in CLI_TOOL_NAMES:
        return JSONResponse({"error": f"'{tool_name}' isn't a CLI tool that supports command variants"}, status_code=400)
    if not label:
        return JSONResponse({"error": "label is required"}, status_code=400)
    mode = v.mode if v.mode in ("fast", "full", "both") else "both"
    # Validate the extra args are at least shell-tokenizable, so a bad
    # variant doesn't silently break the tool the next time it's used.
    try:
        shlex.split(v.extra_args)
    except ValueError as e:
        return JSONResponse({"error": f"couldn't parse extra args: {e}"}, status_code=400)
    conn = get_db()
    conn.execute(
        "INSERT INTO tool_variants (tool_name, mode, label, extra_args, active, created_at) VALUES (?, ?, ?, ?, 0, ?)",
        (tool_name, mode, label, v.extra_args.strip(), now_iso()),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.put("/api/config/tool_variants/{variant_id}/activate")
async def activate_tool_variant(variant_id: int):
    conn = get_db()
    row = conn.execute("SELECT tool_name, mode FROM tool_variants WHERE id = ?", (variant_id,)).fetchone()
    if not row:
        conn.close()
        return JSONResponse({"error": "not found"}, status_code=404)
    # Only one active variant per tool at a time — activating this one
    # deactivates every other variant for the same tool (regardless of
    # mode), so there's never ambiguity about what "the" active command is.
    conn.execute("UPDATE tool_variants SET active = 0 WHERE tool_name = ?", (row["tool_name"],))
    conn.execute("UPDATE tool_variants SET active = 1 WHERE id = ?", (variant_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.put("/api/config/tool_variants/{variant_id}/deactivate")
async def deactivate_tool_variant(variant_id: int):
    conn = get_db()
    conn.execute("UPDATE tool_variants SET active = 0 WHERE id = ?", (variant_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/config/tool_variants/{variant_id}")
async def delete_tool_variant(variant_id: int):
    conn = get_db()
    conn.execute("DELETE FROM tool_variants WHERE id = ?", (variant_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


DOMAIN_BAD_CHARS = re.compile(r"""[;&|`$(){}<>"'\\\s]""")


class TldCheckRequest(BaseModel):
    domain: str


@app.post("/api/domain-variants/check")
async def check_domain_variants(req: TldCheckRequest):
    """Existence-check across a broad, global, continent-grouped set of
    TLDs for a base name, so someone can scan a whole org across
    .com/.co.za/.com.au/.app/etc. from one input instead of typing each
    one in by hand and running separate scans blind. Uses company.py's
    discover_tld_variants_global/TLD_CONTINENT_GROUPS rather than keeping
    a second, possibly drifting copy of the TLD list here — this is a
    deliberately bigger, slower-to-check list than the one the automatic
    Company-scan flow uses internally (see company_lookup/social_scan),
    since this is a manual, DNS-only, user-triggered check with no page
    fetching, so a far larger candidate set is cheap here in a way it
    wouldn't be there.

    Accepts either a bare name ("acme") or a full domain ("acme.com") —
    the wildcard-style input people reach for instinctively ("acme.*",
    "*.acme.com") isn't real domain syntax and no tool downstream
    understands it, so this is the actual answer to that: a bare name
    checked against every candidate TLD, or a full domain checked against
    every *other* candidate TLD plus itself.
    """
    raw = req.domain.strip().lower().lstrip("*.").rstrip("/").replace("https://", "").replace("http://", "")
    raw = raw.split("/")[0].rstrip(".*")
    if not raw or DOMAIN_BAD_CHARS.search(raw):
        return JSONResponse({"error": "invalid domain"}, status_code=400)

    has_dot = "." in raw
    if has_dot:
        original_resolves, variants = await asyncio.gather(
            check_dns_now(raw), discover_tld_variants_global(raw),
        )
        results = [{"domain": raw, "tld": None, "continent": None, "resolves": original_resolves, "is_original": True}]
    else:
        variants = await discover_tld_variants_global(raw)
        results = []
    results += [{**v, "is_original": False} for v in variants]

    return {"base": raw, "results": results}


@app.post("/api/subdomain-prefixes/check")
async def check_subdomain_prefixes(req: TldCheckRequest):
    """The "front side" counterpart to /api/domain-variants/check — same
    manual, DNS-only, user-triggered shape, but checking curated
    subdomain prefixes (admin, vpn, staging, mail, api, etc.) against the
    entered domain instead of checking suffixes against the entered
    label. Doesn't replace the real subdomain enumeration the normal
    scan pipeline already does (subfinder/amass/crt.sh and friends) —
    this is for the quick, no-scan-required peek at the specific
    prefixes a pentester would think to check by hand before committing
    to a full scan. Reuses company.py's discover_subdomain_prefixes.
    """
    raw = req.domain.strip().lower().lstrip("*.").rstrip("/").replace("https://", "").replace("http://", "")
    raw = raw.split("/")[0].rstrip(".*")
    if not raw or DOMAIN_BAD_CHARS.search(raw) or "." not in raw:
        return JSONResponse({"error": "invalid domain"}, status_code=400)

    results = await discover_subdomain_prefixes(raw)
    return {"base": raw, "results": results}


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    mode = "full" if req.mode == "full" else "fast"
    domain = req.domain.strip().lower().lstrip("*.").rstrip("/")
    domain = domain.replace("https://", "").replace("http://", "")

    if "*" in domain:
        return JSONResponse(
            {"error": "wildcards like 'example.*' aren't valid domain syntax and no tool here understands "
                      "them — use the 🌐 Check other TLDs option next to the domain field instead, it checks "
                      "common TLD variants (.com/.co.za/.org/etc.) for you"},
            status_code=400,
        )

    if not domain or DOMAIN_BAD_CHARS.search(domain):
        return JSONResponse({"error": "invalid domain"}, status_code=400)

    company_name = (req.company_name or "").strip() or None

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO scans (domain, mode, status, started_at, company_name) VALUES (?, ?, 'running', ?, ?)",
        (domain, mode, now_iso(), company_name),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    asyncio.create_task(run_pipeline_safe(scan_id, domain, mode))
    return {"scan_id": scan_id, "domain": domain, "mode": mode}


@app.post("/api/scans/{scan_id}/skip")
async def skip_current_step(scan_id: int):
    """Kills whatever command/lookup is currently running for this scan.
    The pipeline treats that as an empty result for this one step and
    moves straight on to the next — nothing else is affected."""
    task = RUNNING_STAGE_TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()
        return {"ok": True, "skipped": True}
    return JSONResponse({"ok": False, "message": "no step currently running for this scan"}, status_code=409)


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: int):
    """Stops the whole scan: kills whatever's currently running and
    prevents any further stages from starting. Whatever was already
    written to the database (subdomains, assets, intel found so far)
    is kept."""
    conn = get_db()
    row = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    if row["status"] != "running":
        return JSONResponse({"ok": False, "message": "scan is not running"}, status_code=409)

    STOP_REQUESTED[scan_id] = True
    task = RUNNING_STAGE_TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()
    return {"ok": True, "stopping": True}


@app.get("/api/scans")
async def list_scans():
    conn = get_db()
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        return JSONResponse({"error": "not found"}, status_code=404)
    subs = conn.execute("SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain", (scan_id,)).fetchall()
    assets = conn.execute("SELECT * FROM http_assets WHERE scan_id = ? ORDER BY subdomain", (scan_id,)).fetchall()
    ports = conn.execute("SELECT * FROM ports WHERE scan_id = ? ORDER BY host, port", (scan_id,)).fetchall()
    intel = conn.execute(
        "SELECT * FROM host_intel WHERE scan_id = ? ORDER BY host, source, field", (scan_id,)
    ).fetchall()
    emails = conn.execute("SELECT * FROM emails WHERE scan_id = ? ORDER BY email", (scan_id,)).fetchall()
    logs = conn.execute("SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY id", (scan_id,)).fetchall()
    screenshots = conn.execute(
        "SELECT * FROM screenshots WHERE scan_id = ? ORDER BY host", (scan_id,)
    ).fetchall()
    # Takeover findings sort first regardless of severity — a dangling
    # record someone else can claim right now deserves more prominence
    # than severity alone would give it, then ordered by how urgent the
    # severity label itself is.
    vulnerabilities = conn.execute(
        """SELECT * FROM vulnerabilities WHERE scan_id = ?
           ORDER BY is_takeover DESC, is_kev DESC,
             CASE severity
               WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
               WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5
             END, host""",
        (scan_id,),
    ).fetchall()
    leaks = conn.execute("SELECT * FROM leaks WHERE scan_id = ? ORDER BY host, leak_type", (scan_id,)).fetchall()
    conn.close()
    return {
        "scan": dict(scan),
        "subdomains": [dict(r) for r in subs],
        "http_assets": [dict(r) for r in assets],
        "ports": [dict(r) for r in ports],
        "host_intel": [dict(r) for r in intel],
        "emails": [dict(r) for r in emails],
        "logs": [dict(r) for r in logs],
        "screenshots": [dict(r) for r in screenshots],
        "vulnerabilities": [dict(r) for r in vulnerabilities],
        "leaks": [dict(r) for r in leaks],
    }


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    conn = get_db()
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


class BulkScanIdsIn(BaseModel):
    scan_ids: list[int]


@app.post("/api/scans/bulk-delete")
async def bulk_delete_scans(payload: BulkScanIdsIn):
    if not payload.scan_ids:
        return JSONResponse({"error": "no scan_ids provided"}, status_code=400)
    conn = get_db()
    placeholders = ",".join("?" for _ in payload.scan_ids)
    cur = conn.execute(f"DELETE FROM scans WHERE id IN ({placeholders})", payload.scan_ids)
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return {"ok": True, "deleted": deleted}


@app.post("/api/scans/bulk-export")
async def bulk_export_scans(payload: BulkScanIdsIn):
    """One JSON file per scan (the most complete single-file export format
    already used for the single-scan export), zipped together."""
    if not payload.scan_ids:
        return JSONResponse({"error": "no scan_ids provided"}, status_code=400)

    buf = io.BytesIO()
    included = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for scan_id in payload.scan_ids:
            scan, subs, assets, ports, intel, emails, vulns, leaks = _fetch_scan_bundle(scan_id)
            if not scan:
                continue
            payload_data = {
                "scan": dict(scan),
                "subdomains": [dict(r) for r in subs],
                "http_assets": [dict(r) for r in assets],
                "ports": [dict(r) for r in ports],
                "host_intel": [dict(r) for r in intel],
                "emails": [dict(r) for r in emails],
                "vulnerabilities": [dict(r) for r in vulns],
                "leaks": [dict(r) for r in leaks],
            }
            safe_domain = sanitize_filename_part(scan["domain"])
            zf.writestr(f"{safe_domain}_scan{scan_id}.json", json.dumps(payload_data, indent=2))
            included += 1

    if included == 0:
        return JSONResponse({"error": "none of the given scan_ids exist"}, status_code=404)

    buf.seek(0)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"mimir_scans_export_{timestamp}.zip"
    return StreamingResponse(
        buf, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class VerifyIn(BaseModel):
    subdomain: str
    verified: bool


@app.put("/api/scans/{scan_id}/verify")
async def verify_subdomain(scan_id: int, v: VerifyIn):
    conn = get_db()
    cur = conn.execute(
        "UPDATE subdomains SET verified = ? WHERE scan_id = ? AND subdomain = ?",
        (int(v.verified), scan_id, v.subdomain),
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return JSONResponse({"error": "subdomain not found on this scan"}, status_code=404)
    return {"ok": True, "subdomain": v.subdomain, "verified": v.verified}


async def run_validation(scan_id: int) -> Optional[dict]:
    """Live re-check: does each host still resolve, is each web asset URL
    still actually responding, and is each reported port still open,
    right now? Produces a 0-100 confidence score per finding rather than
    trusting the original scan forever — and, critically, this is also
    the thing anything downstream (a triggered vulnerability or company
    scan) relies on to know which URLs are actually worth targeting, via
    get_confirmed_live_urls(). Returns None if the scan doesn't exist.

    Each http_assets row gets checked directly and exactly once — not
    just a single representative check per host — with that same result
    reused for the host's own confidence score, so a host with two asset
    rows (http and https, say) doesn't trigger duplicate requests to the
    same origin. Runs everything concurrently (capped) so even a scan
    with dozens of hosts finishes in a few seconds.

    This is a plain function, not the HTTP endpoint itself (see
    validate_scan below) — so a triggered vulnerability/company scan can
    call it directly rather than making an HTTP request back to its own
    server, which FastAPI doesn't support cleanly.
    """
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return None
    subs = conn.execute("SELECT * FROM subdomains WHERE scan_id = ?", (scan_id,)).fetchall()
    ports = conn.execute("SELECT * FROM ports WHERE scan_id = ?", (scan_id,)).fetchall()
    assets = conn.execute("SELECT * FROM http_assets WHERE scan_id = ?", (scan_id,)).fetchall()
    conn.close()

    sem = asyncio.Semaphore(20)

    async def validate_asset_row(a):
        async with sem:
            had_original_status = bool(a["status_code"])
            result = await check_http_now(a["url"]) if a["url"] else {"ok": False, "status_code": None}
            score, status = score_asset_confidence(had_original_status, result["ok"])
            return {
                "id": a["id"], "subdomain": a["subdomain"], "ok": result["ok"],
                "status_code": result["status_code"], "score": score, "status": status,
            }

    async def validate_host(s, asset_result):
        async with sem:
            host = s["subdomain"]
            dns_ok = await check_dns_now(host)
            had_http = asset_result is not None
            http_ok = bool(asset_result and asset_result["ok"])
            sources_count = len([x for x in (s["sources"] or "").split(",") if x])
            score, status = score_host_confidence(sources_count, dns_ok, had_http, http_ok)
            return s["subdomain"], score, status

    async def validate_port_row(p):
        async with sem:
            sources_count = len([x for x in (p["source"] or "").split(",") if x])
            still_open = await check_tcp_port_now(p["host"], p["port"])
            score, status = score_port_confidence(sources_count, still_open)
            return p["id"], score, status

    asset_results = await asyncio.gather(*[validate_asset_row(a) for a in assets]) if assets else []
    # First asset per host stands in for the host-level "did it have/still
    # have a web asset" signal — a host with several asset rows only needs
    # one of them to be reachable for the host itself to be considered live.
    asset_result_by_host: dict[str, dict] = {}
    for r in asset_results:
        if r["subdomain"] not in asset_result_by_host or r["ok"]:
            asset_result_by_host[r["subdomain"]] = r

    host_results = await asyncio.gather(
        *[validate_host(s, asset_result_by_host.get(s["subdomain"])) for s in subs]
    ) if subs else []
    port_results = await asyncio.gather(*[validate_port_row(p) for p in ports]) if ports else []

    now = now_iso()
    conn = get_db()
    for host, score, status in host_results:
        conn.execute(
            "UPDATE subdomains SET confidence = ?, validation_status = ?, validated_at = ? WHERE scan_id = ? AND subdomain = ?",
            (score, status, now, scan_id, host),
        )
    for p in port_results:
        port_id, score, status = p
        conn.execute(
            "UPDATE ports SET confidence = ?, validation_status = ?, validated_at = ? WHERE id = ?",
            (score, status, now, port_id),
        )
    for a in asset_results:
        # Refreshes status_code too, not just the validation columns —
        # otherwise a page that changed from 200 to 403 since the
        # original scan would keep showing the stale 200 forever, even
        # right after "validating" it.
        conn.execute(
            "UPDATE http_assets SET status_code = ?, confidence = ?, validation_status = ?, validated_at = ? "
            "WHERE id = ?",
            (a["status_code"], a["score"], a["status"], now, a["id"]),
        )
    conn.commit()
    conn.close()

    host_confirmed = sum(1 for _, _, st in host_results if st == "confirmed")
    host_unreachable = sum(1 for _, _, st in host_results if st == "unreachable")
    port_confirmed = sum(1 for _, _, st in port_results if st == "confirmed open")
    port_closed = sum(1 for _, _, st in port_results if st == "possibly closed now")
    assets_confirmed = sum(1 for a in asset_results if a["status"] == "confirmed")
    assets_unreachable = sum(1 for a in asset_results if a["status"] == "unreachable")

    return {
        "ok": True,
        "validated_at": now,
        "hosts_checked": len(host_results),
        "hosts_confirmed": host_confirmed,
        "hosts_unreachable": host_unreachable,
        "ports_checked": len(port_results),
        "ports_confirmed": port_confirmed,
        "ports_closed": port_closed,
        "assets_checked": len(asset_results),
        "assets_confirmed": assets_confirmed,
        "assets_unreachable": assets_unreachable,
    }


@app.post("/api/scans/{scan_id}/validate")
async def validate_scan(scan_id: int):
    result = await run_validation(scan_id)
    if result is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return result


@app.post("/api/scans/{scan_id}/vulnerability/run")
async def run_vulnerability_scan(scan_id: int):
    """The Vulnerability tab's trigger button. Always revalidates first
    — never trusts whatever http_assets happened to say at original scan
    time — then runs nuclei, ffuf, wpscan (if WordPress was detected),
    dalfox (against any parameterized URLs already found), a DNS zone
    transfer check, JS file secret scanning, and cloud storage bucket
    enumeration, using the freshly-confirmed live data. Available
    regardless of which mode the original scan ran in; a fast scan just
    means there's more DNS/HTTP validation work to do here before
    there's anything to target.
    """
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        return JSONResponse({"error": "not found"}, status_code=404)
    if scan["status"] == "running":
        return JSONResponse({"error": "scan is still running — wait for it to finish first"}, status_code=409)

    await log_line(scan_id, "=== vulnerability scan triggered: revalidating live assets first ===", "meta")
    validation = await run_validation(scan_id)
    urls = get_confirmed_live_urls(scan_id)

    conn = get_db()
    conn.execute("UPDATE scans SET vulnerability_scanned_at = ? WHERE id = ?", (now_iso(), scan_id))
    conn.commit()
    conn.close()

    # nuclei/ffuf need confirmed-live URLs specifically, but wpscan
    # (WordPress detection) and dalfox (parameterized URLs from gau/
    # katana) have entirely different, independent data requirements —
    # each already guards itself internally when it has nothing to work
    # with. Previously, an empty confirmed-live URL set returned early
    # and skipped wpscan/dalfox too, even in cases where they'd have had
    # something real to check — found this directly while testing the
    # decoupled trigger, not assumed. Now every tool gets a genuine
    # chance to run regardless of what the others need.
    nuclei_count = ffuf_count = 0
    if urls:
        await log_line(scan_id, f"[vulnerability] targeting {len(urls)} confirmed-live URL(s)", "meta")
        nuclei_count = await nuclei_run(scan_id, scan["domain"], "full", urls)
        ffuf_count = await ffuf_run(scan_id, scan["domain"], "full", urls)
    else:
        await log_line(
            scan_id,
            "[vulnerability] no confirmed-live web assets after revalidation — nuclei/ffuf have nothing "
            "to target, but wpscan/dalfox have their own independent data requirements and still get a "
            "chance to run below",
            "warn",
        )

    wpscan_count = await wpscan_run(scan_id, scan["domain"], "full")
    dalfox_count = await dalfox_run(scan_id, scan["domain"], "full")

    # These three have entirely independent data requirements of their
    # own (DNS lookups, JS files gau/katana already found, HTTP checks
    # against guessed bucket names) — none depend on confirmed-live URLs
    # existing, same reasoning as wpscan/dalfox above.
    axfr_count = await check_dns_zone_transfer(scan_id, scan["domain"])
    email_auth_count = await check_email_auth(scan_id, scan["domain"])
    secrets_count = await secrets_scan_js(scan_id, scan["domain"])
    name_candidates = get_company_name_candidates(scan_id, scan["domain"])
    bucket_count = await check_cloud_buckets(scan_id, scan["domain"], name_candidates)

    # Prioritization enrichment — runs against every CVE-bearing finding
    # currently on this scan, not just ones from this specific run, since
    # KEV/EPSS data itself changes over time (KEV grows, EPSS scores get
    # recalculated) and re-checking on every deliberate trigger keeps it
    # current, matching how revalidation already works elsewhere in this
    # module.
    kev_count = await check_cisa_kev(scan_id)
    epss_count = await check_epss_scores(scan_id)

    await log_line(scan_id, "=== vulnerability scan complete ===", "meta")
    return {
        "ok": True,
        "validation": validation,
        "urls_targeted": len(urls),
        "nuclei_findings": nuclei_count,
        "ffuf_findings": ffuf_count,
        "wpscan_findings": wpscan_count,
        "dalfox_findings": dalfox_count,
        "axfr_findings": axfr_count,
        "email_auth_findings": email_auth_count,
        "secrets_findings": secrets_count,
        "bucket_findings": bucket_count,
        "kev_confirmed": kev_count,
        "epss_scored": epss_count,
    }


async def _run_company_scan_task(scan_id: int, progress: ProgressTracker):
    """The actual work — pulled out of the endpoint so it can run as a
    background task (needed for a live progress bar: the endpoint has to
    return immediately, well before this finishes, rather than block the
    HTTP request for the whole duration the way this used to work)."""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    domain = scan["domain"]

    await log_line(scan_id, "=== company scan triggered: revalidating first ===", "meta")
    await progress.start("Revalidating live assets")
    validation = await run_validation(scan_id)
    await progress.advance()

    conn = get_db()
    live_assets = [
        dict(r) for r in conn.execute(
            "SELECT * FROM http_assets WHERE scan_id = ? AND validation_status = 'confirmed'", (scan_id,)
        ).fetchall()
    ]
    resolved_ips = sorted({
        r["ip"] for r in conn.execute(
            "SELECT DISTINCT ip FROM subdomains WHERE scan_id = ? AND ip IS NOT NULL AND validation_status = 'confirmed'",
            (scan_id,),
        ).fetchall()
    })
    harvested_emails = {r["email"] for r in conn.execute("SELECT email FROM emails WHERE scan_id = ?", (scan_id,))}
    conn.close()

    # Discovered once here and shared with both social_scan (scrapes
    # each variant's homepage for extra contacts/social links) and
    # company_lookup (uses them to confirm a Wikidata match) — avoids
    # doing the same DNS checks and "found N variant(s)" log line twice,
    # and means the email-harvesting side actually benefits from this
    # feature too, not just the Wikidata-matching side it originally
    # only fed.
    tld_variants = await discover_tld_variants(domain)
    if tld_variants:
        conn = get_db()
        for i, variant in enumerate(tld_variants):
            store_intel(conn, scan_id, domain, "company", f"tld_variant:{i}", variant)
        conn.commit()
        conn.close()
        await log_line(
            scan_id,
            f"[company] found {len(tld_variants)} other TLD variant(s) of this domain that resolve: "
            f"{', '.join(tld_variants)} — will also check these for contacts/company info",
            "meta",
        )

    await progress.start("Social / homepage scan")
    await social_scan(scan_id, domain, live_assets, tld_variants=tld_variants)
    await progress.advance()

    await progress.start("Company record lookup (Wikidata)")
    candidates = get_company_name_candidates(scan_id, domain)
    await company_lookup(scan_id, domain, candidates, user_supplied_name=scan["company_name"], tld_variants=tld_variants)
    await progress.advance()

    await progress.start("Employee search (CrossLinked)")
    company_name = next((c for c in candidates if c and c.strip()), domain)
    employees_found, _ = await crosslinked_run_multi(scan_id, domain, "full", company_name)
    await progress.advance()

    await progress.start("Email search (Hunter.io)")
    hunter_key = get_api_key("hunter")
    if hunter_key:
        await hunter_lookup(scan_id, domain, hunter_key)
    await progress.advance()

    await progress.start("Shodan host enrichment")
    shodan_key = get_api_key("shodan")
    if shodan_key and resolved_ips:
        await shodan_enrich_hosts(scan_id, resolved_ips, shodan_key)
    elif shodan_key:
        await log_line(scan_id, "[shodan] no confirmed-live resolved IPs to enrich", "warn")
    await progress.advance()

    await progress.start("Breach check (XposedOrNot)")
    if harvested_emails:
        await xposedornot_lookup(scan_id, harvested_emails)
    await progress.advance()

    await progress.start("Recent press mentions (GDELT)")
    # News under both the primary name and any parent org found — a
    # rebranded/acquired company's recent coverage is often reported
    # under whichever name is current, not necessarily the one this
    # scan started from. Same reasoning already used for crosslinked's
    # multi-name search.
    conn = get_db()
    parent_row = conn.execute(
        "SELECT value FROM host_intel WHERE scan_id=? AND source='company' AND field='parent_organization'",
        (scan_id,),
    ).fetchone()
    conn.close()
    names_for_news = [company_name]
    parent_name = parent_row["value"] if parent_row else None
    if parent_name and parent_name.strip().lower() != company_name.strip().lower():
        names_for_news.append(parent_name)
    for name in names_for_news:
        await news_lookup(scan_id, domain, name)
    await progress.advance()

    conn = get_db()
    conn.execute("UPDATE scans SET company_scanned_at = ? WHERE id = ?", (now_iso(), scan_id))
    conn.commit()
    conn.close()

    await progress.finish("Complete")
    await log_line(scan_id, "=== company scan complete ===", "meta")
    return {
        "ok": True,
        "validation": validation,
        "live_assets_used": len(live_assets),
        "resolved_ips_used": len(resolved_ips),
        "employees_found": employees_found,
        "emails_checked": len(harvested_emails),
    }


async def _run_deep_scan_task(scan_id: int, target_hosts: list[str], progress: ProgressTracker):
    """Recursive/second-level subdomain brute-forcing — treats each
    already-discovered host as a new base domain and brute-forces
    against *that*, the way a real second pass would (finding
    dev.api.company.com, which brute-forcing company.com alone would
    never surface, only possible once api.company.com is already
    known). Reuses shuffledns_run directly, called once per target host
    — sequentially, not concurrently, since shuffledns_run's own temp
    directory is keyed only by scan_id and two concurrent calls for the
    same scan would collide over it.
    """
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    mode = scan["mode"] if scan else "full"

    all_found: set[str] = set()
    for host in target_hosts:
        await progress.start(f"Brute-forcing {host}")
        found = await shuffledns_run(scan_id, host, mode)
        all_found.update(found)
        await progress.advance()

    conn = get_db()
    existing = {row["subdomain"] for row in conn.execute("SELECT subdomain FROM subdomains WHERE scan_id = ?", (scan_id,)).fetchall()}
    conn.close()
    # Only genuinely new discoveries matter here — shuffledns_run itself
    # doesn't know what this scan already has on file, since it's the
    # same function used for the original, root-domain brute-force too.
    new_hosts = all_found - existing

    if not new_hosts:
        await log_line(scan_id, "[deep-scan] no new subdomains found beyond what's already known", "meta")
        await progress.finish("No new hosts found")
        return

    await progress.start(f"Resolving {len(new_hosts)} newly found host(s)")
    tmp_hosts = BASE_DIR / f".scan_{scan_id}_deepscan_hosts.txt"
    resolved_count = 0
    asset_count = 0
    try:
        tmp_hosts.write_text("\n".join(sorted(new_hosts)))

        cmd = apply_variant(["dnsx", "-silent", "-json", "-a", "-l", str(tmp_hosts)], "dnsx", mode)
        dnsx_lines = await run_stream(scan_id, cmd, "dnsx (deep-scan)")
        host_ips = parse_dnsx_json(dnsx_lines)
        resolved = {h: ips[0] for h, ips in host_ips.items() if ips}
        resolved_count = len(resolved)

        conn = get_db()
        for host in new_hosts:
            conn.execute(
                "INSERT INTO subdomains (scan_id, subdomain, sources, ip) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(scan_id, subdomain) DO UPDATE SET sources=excluded.sources, ip=excluded.ip",
                (scan_id, host, "deep-scan", resolved.get(host)),
            )
        conn.commit()
        conn.close()
        await log_line(scan_id, f"[+] deep-scan: {len(new_hosts)} new subdomain(s) added, {resolved_count} resolved", "meta")
        await progress.advance()

        await progress.start("HTTP probing new hosts")
        httpx_bin = await find_working_binary("httpx", "-version", scan_id) or "httpx"
        cmd2 = apply_variant(
            [httpx_bin, "-silent", "-json", "-title", "-tech-detect", "-status-code", "-fr", "-l", str(tmp_hosts)],
            "httpx", mode,
        )
        httpx_lines = await run_stream(scan_id, cmd2, "httpx (deep-scan)")
        if not looks_like_wrong_binary(httpx_lines):
            assets = parse_httpx_json(httpx_lines)
            asset_count = len(assets)
            conn = get_db()
            for a in assets:
                # Delete-then-insert rather than relying on a unique
                # constraint — http_assets has none, and this feature
                # being run more than once against the same host
                # shouldn't accumulate duplicate rows for it.
                conn.execute("DELETE FROM http_assets WHERE scan_id = ? AND subdomain = ?", (scan_id, a["subdomain"]))
                conn.execute(
                    "INSERT INTO http_assets (scan_id, subdomain, url, status_code, title, tech, server, ip) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, a["subdomain"], a["url"], a["status_code"], a["title"], a["tech"], a["server"], a["ip"]),
                )
            conn.commit()
            conn.close()
            await log_line(scan_id, f"[+] deep-scan: {asset_count} live HTTP asset(s) found among new hosts", "meta")
        await progress.advance()
    finally:
        tmp_hosts.unlink(missing_ok=True)

    await progress.finish(f"{len(new_hosts)} new host(s) found")


async def _run_deep_scan_task_safe(scan_id: int, target_hosts: list[str]):
    progress = ProgressTracker(scan_id, len(target_hosts) + 2, kind="deep_scan")
    try:
        await _run_deep_scan_task(scan_id, target_hosts, progress)
    except Exception as e:
        await log_line(scan_id, f"[fatal] deep scan crashed: {e}", "error")
        await progress.finish("Failed")
    finally:
        conn = get_db()
        conn.execute("UPDATE scans SET deep_scan_running = 0 WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()


class DeepScanIn(BaseModel):
    hosts: list[str]


@app.post("/api/scans/{scan_id}/deep-scan/run")
async def run_deep_scan(scan_id: int, payload: DeepScanIn):
    """Triggered from the Scans page report view, never the main Scan
    view — recursive subdomain brute-forcing against already-discovered
    hosts, each treated as a new base domain to dig deeper from. Runs as
    a background task for the same reason Company/Vulnerability do — see
    deep_scan_progress_percent/deep_scan_progress_stage/
    deep_scan_running on the scan row.
    """
    hosts = [h.strip().lower() for h in payload.hosts if h.strip()]
    if not hosts:
        return JSONResponse({"error": "no hosts specified"}, status_code=400)
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return JSONResponse({"error": "not found"}, status_code=404)
    if scan["status"] == "running":
        conn.close()
        return JSONResponse({"error": "scan is still running — wait for it to finish first"}, status_code=409)
    if scan["deep_scan_running"]:
        conn.close()
        return JSONResponse({"error": "a deep scan is already running for this scan"}, status_code=409)
    if not shutil.which("shuffledns"):
        conn.close()
        return JSONResponse({"error": "shuffledns isn't installed — this feature needs it, see Settings/Tools"}, status_code=400)
    if not get_active_wordlist("shuffledns"):
        conn.close()
        return JSONResponse(
            {"error": "no wordlist assigned to shuffledns — assign one under Settings → Wordlists first"},
            status_code=400,
        )
    known = {row["subdomain"] for row in conn.execute("SELECT subdomain FROM subdomains WHERE scan_id = ?", (scan_id,)).fetchall()}
    unknown_hosts = [h for h in hosts if h not in known]
    if unknown_hosts:
        conn.close()
        return JSONResponse({"error": f"not part of this scan's discovered hosts: {', '.join(unknown_hosts[:5])}"}, status_code=400)
    conn.execute("UPDATE scans SET deep_scan_running = 1 WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

    asyncio.create_task(_run_deep_scan_task_safe(scan_id, hosts))
    return {"ok": True, "started": True}


async def _run_company_scan_task_safe(scan_id: int):
    progress = ProgressTracker(scan_id, 7, kind="company")
    try:
        await _run_company_scan_task(scan_id, progress)
    except Exception as e:
        await log_line(scan_id, f"[fatal] company scan crashed: {e}", "error")
        await progress.finish("Failed")
    finally:
        conn = get_db()
        conn.execute("UPDATE scans SET company_scan_running = 0 WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()


@app.post("/api/scans/{scan_id}/company/run")
async def run_company_scan(scan_id: int):
    """The Company tab's trigger button. Runs as a background task (not
    blocking this request) so the frontend can poll for live progress —
    see company_progress_percent/company_progress_stage on the scan row,
    and company_scan_running for when to stop polling and refresh the
    results view. Revalidates first (same reasoning as vulnerability
    scanning — an org's homepage or resolved IPs may have changed since
    the original scan), then re-runs every company-intelligence source
    against the refreshed picture.
    """
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return JSONResponse({"error": "not found"}, status_code=404)
    if scan["status"] == "running":
        conn.close()
        return JSONResponse({"error": "scan is still running — wait for it to finish first"}, status_code=409)
    if scan["company_scan_running"]:
        conn.close()
        return JSONResponse({"error": "a company scan is already running for this scan"}, status_code=409)
    conn.execute("UPDATE scans SET company_scan_running = 1 WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

    asyncio.create_task(_run_company_scan_task_safe(scan_id))
    return {"ok": True, "started": True}


class UserScannerRequest(BaseModel):
    identity_type: str  # "username" | "email"
    identity_value: str


@app.post("/api/scans/{scan_id}/user-scanner")
async def run_user_scanner(scan_id: int, req: UserScannerRequest):
    """Manual, per-person trigger for user-scanner (github.com/kaifcodec/
    user-scanner) — called from a button next to one specific employee
    name (CrossLinked) or email (Emails tab) already on the Company
    profile, never automatically. See user_scanner_lookup's own
    docstring in company.py for why this stays opt-in rather than
    joining the automatic Company-scan pipeline: it's hundreds to
    thousands of individual active requests against third-party sites
    for one identity, a meaningfully louder technique than anything else
    this app runs on its own. Blocking (not a background task) — results
    come back in the response, and the existing live-output panel
    already streams the underlying command's output as it runs, the same
    way any other run_stream-based tool's output does.
    """
    identity_type = req.identity_type.strip().lower()
    identity_value = req.identity_value.strip()
    if identity_type not in ("username", "email"):
        return JSONResponse({"error": "identity_type must be 'username' or 'email'"}, status_code=400)
    if not identity_value or len(identity_value) > 320:
        return JSONResponse({"error": "missing or implausibly long identity value"}, status_code=400)

    conn = get_db()
    scan = conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        return JSONResponse({"error": "not found"}, status_code=404)

    hits = await user_scanner_lookup(scan_id, identity_type, identity_value)
    return {
        "ok": True,
        "identity_type": identity_type,
        "identity_value": identity_value,
        "hits": [
            {"site_name": h.get("site_name"), "url": h.get("url"), "status": h.get("status")}
            for h in hits
        ],
    }


def _fetch_scan_bundle(scan_id: int):
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    subs = conn.execute("SELECT * FROM subdomains WHERE scan_id = ? ORDER BY subdomain", (scan_id,)).fetchall()
    assets = conn.execute("SELECT * FROM http_assets WHERE scan_id = ? ORDER BY subdomain", (scan_id,)).fetchall()
    ports = conn.execute("SELECT * FROM ports WHERE scan_id = ? ORDER BY host, port", (scan_id,)).fetchall()
    intel = conn.execute(
        "SELECT * FROM host_intel WHERE scan_id = ? ORDER BY host, source, field", (scan_id,)
    ).fetchall()
    emails = conn.execute("SELECT * FROM emails WHERE scan_id = ? ORDER BY email", (scan_id,)).fetchall()
    vulnerabilities = conn.execute(
        """SELECT * FROM vulnerabilities WHERE scan_id = ?
           ORDER BY is_takeover DESC, is_kev DESC,
             CASE severity
               WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
               WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5
             END, host""",
        (scan_id,),
    ).fetchall()
    leaks = conn.execute("SELECT * FROM leaks WHERE scan_id = ? ORDER BY host, leak_type", (scan_id,)).fetchall()
    conn.close()
    return scan, subs, assets, ports, intel, emails, vulnerabilities, leaks


TRIAGE_STATUSES = {"open", "false_positive", "reported", "risk_accepted", "fixed"}


class AiConfigIn(BaseModel):
    base_url: str
    api_key: Optional[str] = None
    model: str


@app.get("/api/ai/status")
async def get_ai_status():
    """Whether the optional AI analysis feature is configured — never
    whether it's actually reachable right now (that would mean pinging
    an external/local endpoint on every page load). A real connection
    problem surfaces when generation is actually attempted instead."""
    config = get_ai_config()
    if not config:
        return {"configured": False}
    return {
        "configured": True,
        "base_url": config["base_url"],
        "model": config["model"],
        "api_key_set": bool(config["api_key"]),
    }


@app.post("/api/ai/config")
async def save_ai_config(payload: AiConfigIn):
    """Saves the AI analysis config, or clears it entirely if base_url
    is empty — reverting to the default, unconfigured state where this
    whole feature is simply unavailable and everything else in the app
    is completely unaffected."""
    set_ai_config(payload.base_url.strip(), payload.api_key.strip() if payload.api_key else None, payload.model.strip())
    return {"ok": True}


@app.post("/api/scans/{scan_id}/ai-analysis/run")
async def run_ai_analysis(scan_id: int):
    """Gathers this scan's own already-collected, verified findings and
    asks the configured model to reason about them — see
    ai_analysis.build_analysis_prompt for exactly what does and doesn't
    go into that prompt. Returns a clear, graceful error (never a 500)
    if the feature simply isn't configured."""
    if not check_ai_configured():
        return JSONResponse({"ok": False, "error": "AI analysis isn't configured — see Settings."}, status_code=400)

    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return JSONResponse({"error": "scan not found"}, status_code=404)

    subs = conn.execute("SELECT * FROM subdomains WHERE scan_id=?", (scan_id,)).fetchall()
    assets = conn.execute("SELECT * FROM http_assets WHERE scan_id=?", (scan_id,)).fetchall()
    ports = conn.execute("SELECT * FROM ports WHERE scan_id=?", (scan_id,)).fetchall()
    intel = conn.execute("SELECT * FROM host_intel WHERE scan_id=?", (scan_id,)).fetchall()
    vulnerabilities = conn.execute("SELECT * FROM vulnerabilities WHERE scan_id=?", (scan_id,)).fetchall()
    leaks = conn.execute("SELECT * FROM leaks WHERE scan_id=?", (scan_id,)).fetchall()
    conn.close()

    def intel_val(source, field):
        for i in intel:
            if i["source"] == source and i["field"] == field:
                return i["value"]
        return None

    pages_reviewed = sorted({
        i["field"].split(":")[1] for i in intel
        if i["source"] == "social" and i["field"].startswith("page:") and i["field"].endswith(":url")
    })
    compliance_mentions = ", ".join(sorted({
        m.strip() for i in intel if i["source"] == "social" and i["field"].endswith(":compliance_mentions")
        for m in i["value"].split(",")
    })) or None
    tech_stack = ", ".join(sorted({
        i["field"].replace("tech:", "") for i in intel if i["source"] == "whatweb" and i["field"].startswith("tech:")
    })) or None
    employee_count = len({i["field"] for i in intel if i["source"] == "crosslinked" and i["field"].startswith("employee:")})

    vuln_summary = None
    if vulnerabilities:
        crit = sum(1 for v in vulnerabilities if (v["severity"] or "").lower() == "critical")
        kev = sum(1 for v in vulnerabilities if v["is_kev"])
        parts = [f"{len(vulnerabilities)} total"]
        if crit:
            parts.append(f"{crit} critical")
        if kev:
            parts.append(f"{kev} confirmed actively-exploited (CISA KEV)")
        vuln_summary = ", ".join(parts)

    scan_data = {
        "domain": scan["domain"],
        "industry": intel_val("company", "industry"),
        "employee_count": employee_count or None,
        "pages_reviewed": pages_reviewed or None,
        "compliance_mentions": compliance_mentions,
        "host_count": len(subs),
        "live_asset_count": sum(1 for a in assets if a["status_code"]),
        "port_count": len(ports),
        "vulnerability_summary": vuln_summary,
        "leak_summary": f"{len(leaks)} finding(s)" if leaks else None,
        "tech_stack": tech_stack,
    }

    result = await generate_ai_analysis(scan_id, scan_data)
    if not result["ok"]:
        return JSONResponse(result, status_code=502)
    return result


class TriageUpdateIn(BaseModel):
    triage_status: str
    triage_note: Optional[str] = None


@app.post("/api/vulnerabilities/{finding_id}/triage")
async def update_vulnerability_triage(finding_id: int, payload: TriageUpdateIn):
    """Findings triage — tracks what's actually been done with a finding
    (confirmed false positive, reported to the client, risk accepted,
    fixed), not just what was found. A flat findings list can't
    distinguish "12 open criticals" from "12 criticals, all already
    triaged" on its own, and for a real engagement that distinction is
    the whole point of coming back to a scan's results more than once.
    """
    if payload.triage_status not in TRIAGE_STATUSES:
        return JSONResponse({"error": f"invalid status — must be one of {sorted(TRIAGE_STATUSES)}"}, status_code=400)
    conn = get_db()
    row = conn.execute("SELECT id FROM vulnerabilities WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        conn.close()
        return JSONResponse({"error": "finding not found"}, status_code=404)
    conn.execute(
        "UPDATE vulnerabilities SET triage_status = ?, triage_note = ? WHERE id = ?",
        (payload.triage_status, payload.triage_note, finding_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/leaks/{finding_id}/triage")
async def update_leak_triage(finding_id: int, payload: TriageUpdateIn):
    if payload.triage_status not in TRIAGE_STATUSES:
        return JSONResponse({"error": f"invalid status — must be one of {sorted(TRIAGE_STATUSES)}"}, status_code=400)
    conn = get_db()
    row = conn.execute("SELECT id FROM leaks WHERE id = ?", (finding_id,)).fetchone()
    if not row:
        conn.close()
        return JSONResponse({"error": "finding not found"}, status_code=404)
    conn.execute(
        "UPDATE leaks SET triage_status = ?, triage_note = ? WHERE id = ?",
        (payload.triage_status, payload.triage_note, finding_id),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/scans/{scan_id}/export/json")
async def export_json(scan_id: int):
    scan, subs, assets, ports, intel, emails, vulns, leaks = _fetch_scan_bundle(scan_id)
    if not scan:
        return JSONResponse({"error": "not found"}, status_code=404)
    payload = {
        "scan": dict(scan),
        "subdomains": [dict(r) for r in subs],
        "http_assets": [dict(r) for r in assets],
        "ports": [dict(r) for r in ports],
        "host_intel": [dict(r) for r in intel],
        "emails": [dict(r) for r in emails],
        "vulnerabilities": [dict(r) for r in vulns],
        "leaks": [dict(r) for r in leaks],
    }
    buf = io.BytesIO(json.dumps(payload, indent=2).encode())
    filename = f"surface_{scan['domain']}_{scan_id}.json"
    return StreamingResponse(
        buf, media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scans/{scan_id}/export/csv")
async def export_csv(scan_id: int):
    scan, subs, assets, ports, intel, emails, vulns, leaks = _fetch_scan_bundle(scan_id)
    if not scan:
        return JSONResponse({"error": "not found"}, status_code=404)

    ports_by_host: dict[str, list[str]] = {}
    for p in ports:
        ports_by_host.setdefault(p["host"], []).append(f"{p['port']}({p['source']})")
    assets_by_host = {a["subdomain"]: a for a in assets}
    org_by_host: dict[str, str] = {}
    for i in intel:
        if i["field"] == "org":
            org_by_host[i["host"]] = i["value"]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["subdomain", "ip", "sources", "http_status", "title", "tech", "server", "open_ports", "org", "verified"])
    for s in subs:
        a = assets_by_host.get(s["subdomain"], {})
        writer.writerow(
            [
                s["subdomain"], s["ip"] or "", s["sources"],
                a.get("status_code", "") if a else "",
                a.get("title", "") if a else "",
                a.get("tech", "") if a else "",
                a.get("server", "") if a else "",
                ";".join(ports_by_host.get(s["subdomain"], []) or ports_by_host.get(s["ip"] or "", [])),
                org_by_host.get(s["ip"] or "", org_by_host.get(s["subdomain"], "")),
                "yes" if s["verified"] else "",
            ]
        )
    out = io.BytesIO(buf.getvalue().encode())
    filename = f"surface_{scan['domain']}_{scan_id}.csv"
    return StreamingResponse(
        out, media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def build_report_markdown(scan_id: int) -> Optional[str]:
    """Builds the Markdown recon report for a scan. Factored out of
    export_report so the TUI's bridge layer can get the exact same report
    text without wrestling with a StreamingResponse's internals — both the
    web route and tui/bridge.py's get_report() call this directly. Returns
    None if the scan doesn't exist."""
    scan, subs, assets, ports, intel, emails, vulns, leaks = _fetch_scan_bundle(scan_id)
    if not scan:
        return None

    ports_by_host: dict[str, list[str]] = {}
    for p in ports:
        ports_by_host.setdefault(p["host"], []).append(f"{p['port']}/{p['source']}")
    assets_by_host = {a["subdomain"]: a for a in assets}
    intel_by_host: dict[str, list] = {}
    for i in intel:
        intel_by_host.setdefault(i["host"], []).append(i)

    takeover_count = sum(1 for v in vulns if v["is_takeover"])
    md = [
        f"# MIMIR // recon report — {scan['domain']}",
        "",
        f"- Mode: **{scan['mode']}**",
        f"- Started: {scan['started_at']}",
        f"- Completed: {scan['completed_at'] or 'n/a'}",
        f"- Status: {scan['status']}",
        f"- Total hosts discovered: {len(subs)}",
        f"- Live HTTP assets: {len(assets)}",
        f"- Hosts/IPs with open ports: {len(ports_by_host)}",
        f"- Vulnerabilities found: {len(vulns)}" + (f" (**{takeover_count} possible subdomain takeover**)" if takeover_count else ""),
        f"- Leak/exposure findings: {len(leaks)}",
        f"- Emails harvested: {len(emails)}",
        "",
    ]

    if vulns:
        md += ["## Vulnerabilities", "", "Sorted by urgency — possible subdomain takeovers first, then by severity.", "",
               "| Host | Severity | Finding | Matched at |", "|---|---|---|---|"]
        for v in vulns:
            sev_label = f"**TAKEOVER / {v['severity']}**" if v["is_takeover"] else v["severity"]
            md.append(f"| {v['host']} | {sev_label} | {v['name']} | {v['matched_at'] or '-'} |")
        md.append("")

    if leaks:
        md += ["## Leaks / exposed data", "", "| Host | Type | Detail |", "|---|---|---|"]
        for l in leaks:
            md.append(f"| {l['host']} | {l['leak_type'] or 'unknown'} | {l['detail']} |")
        md.append("")

    md += [
        "## Hosts",
        "",
        "| Subdomain | IP | Sources | HTTP | Title | Tech | Ports |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in subs:
        a = assets_by_host.get(s["subdomain"])
        http_status = a["status_code"] if a else "-"
        title = (a["title"][:40] if a and a["title"] else "-")
        tech = (a["tech"][:40] if a and a["tech"] else "-")
        prt = ", ".join(ports_by_host.get(s["subdomain"], []) or ports_by_host.get(s["ip"] or "", [])) or "-"
        md.append(f"| {s['subdomain']} | {s['ip'] or '-'} | {s['sources']} | {http_status} | {title} | {tech} | {prt} |")

    if intel_by_host:
        md += ["", "## OSINT / enrichment intel", ""]
        for host, rows in intel_by_host.items():
            md.append(f"**{host}**")
            for r in rows:
                md.append(f"- {r['source']}.{r['field']}: {r['value']}")
            md.append("")

    if emails:
        md += ["## Emails harvested", ""]
        for e in emails:
            md.append(f"- {e['email']} (via {e['source']})")

    return "\n".join(md)


@app.get("/api/scans/{scan_id}/export/report")
async def export_report(scan_id: int):
    report = build_report_markdown(scan_id)
    if report is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    conn = get_db()
    scan = conn.execute("SELECT domain FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    buf = io.BytesIO(report.encode())
    filename = f"surface_{scan['domain']}_{scan_id}_report.md"
    return StreamingResponse(
        buf, media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scans/{scan_id}/screenshots")
async def list_screenshots(scan_id: int):
    conn = get_db()
    rows = conn.execute(
        "SELECT id, host, url, final_url, status_code, title, filename, failed, error "
        "FROM screenshots WHERE scan_id = ? ORDER BY host",
        (scan_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/scans/{scan_id}/screenshots/{screenshot_id}/image")
async def get_screenshot_image(scan_id: int, screenshot_id: int):
    """The filename served here always comes from our own database, never
    directly from the URL — see _safe_dir_join, applied both when this
    was first stored (gowitness_run) and again here as defense in depth."""
    conn = get_db()
    row = conn.execute(
        "SELECT filename FROM screenshots WHERE id = ? AND scan_id = ?", (screenshot_id, scan_id)
    ).fetchone()
    conn.close()
    if not row or not row["filename"]:
        return JSONResponse({"error": "not found"}, status_code=404)
    shot_dir = SCREENSHOTS_DIR / f"scan_{scan_id}"
    path = _safe_dir_join(shot_dir, row["filename"])
    if not path:
        return JSONResponse({"error": "screenshot file missing on disk"}, status_code=404)
    return FileResponse(path)


@app.get("/api/scans/{scan_id}/export/docs")
async def export_docs(scan_id: int):
    """The holistic per-scan .txt file. Regenerated fresh on every request
    rather than just re-serving whatever was written when the scan
    finished, so a re-download after running Validate findings (or
    checking a few hosts) reflects that — it's always the latest state,
    not a snapshot frozen at scan-completion time."""
    conn = get_db()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        return JSONResponse({"error": "not found"}, status_code=404)
    try:
        filename, content = build_scan_docs_text(scan_id)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    buf = io.BytesIO(content.encode())
    return StreamingResponse(
        buf, media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.websocket("/ws/{scan_id}")
async def ws_endpoint(ws: WebSocket, scan_id: int):
    await manager.connect(scan_id, ws)
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT line, level FROM scan_logs WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        conn.close()
        for r in rows:
            await ws.send_json({"type": "log", "line": r["line"], "level": r["level"]})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, ws)


if not STATIC_DIR.exists():
    print(
        f"\n[MIMIR //] error: expected a 'static' folder next to app.py at:\n"
        f"  {STATIC_DIR}\n"
        f"This folder should contain index.html. If you downloaded the files "
        f"individually rather than as a folder, create it and move index.html "
        f"in:\n"
        f"  mkdir -p {STATIC_DIR}\n"
        f"  mv index.html {STATIC_DIR}/\n",
        file=__import__("sys").stderr,
    )
    raise SystemExit(1)
elif not (STATIC_DIR / "index.html").exists():
    print(
        f"\n[MIMIR //] error: '{STATIC_DIR}' exists but has no index.html in it.\n"
        f"Move the app's index.html into that folder, then re-run.\n",
        file=__import__("sys").stderr,
    )
    raise SystemExit(1)

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    init_db()
    n = register_bootstrap_wordlists()
    if n:
        print(f"Registered {n} bootstrap wordlist(s) found on this system (SecLists/n0kovo_subdomains).")
    uvicorn.run(app, host="127.0.0.1", port=8787)
