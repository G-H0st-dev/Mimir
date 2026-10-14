"""
core.py — shared infrastructure for MIMIR //: SQLite connection/schema,
subprocess execution with live log streaming, generic HTTP fetch helpers,
and the small per-tool config helpers (variants, wordlists, aggressive
mode, API keys) that every tool module needs.

This exists specifically so tool modules (company.py, and future splits
of the rest of app.py) can import these primitives without creating a
circular import with app.py itself — app.py is the orchestrator that
imports FROM tool modules, so nothing tool modules need can live in
app.py.
"""

import asyncio
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import WebSocket

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "surface.db"
STATIC_DIR = BASE_DIR / "static"
DOCS_DIR = BASE_DIR / "scan_docs"  # per-scan holistic text dumps, see write_scan_docs_file()
WORDLISTS_DIR = BASE_DIR / "wordlists"  # uploaded wordlist files, see /api/wordlists
SCREENSHOTS_DIR = BASE_DIR / "screenshots"  # gowitness output, one subfolder per scan
SCAN_OUTPUTS_DIR = BASE_DIR / "scan_outputs"  # full, uncapped tool output — see get_scan_output_dir
RESOLVERS_FILE = BASE_DIR / "resolvers.txt"  # generated once for shuffledns, see shuffledns_run()

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def find_binary(names: list[str]) -> Optional[str]:
    for n in names:
        if shutil.which(n):
            return n
    return None


# ---------------------------------------------------------------------------
# Per-scan output folder — some tools (gau, katana, dalfox, JS secret
# scanning) only store/test a capped subset of what they actually find,
# to avoid the DOM/performance issues an unbounded dataset caused
# elsewhere in this app (see the report-tab rendering caps). The
# complete list is still genuinely useful for manual review, so it's
# written to disk here instead of just being discarded.
# ---------------------------------------------------------------------------
def sanitize_filename_part(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s or "")


def get_scan_output_dir(scan_id: int, domain: str) -> Path:
    """Created lazily on first write, not at scan-start specifically —
    this works correctly regardless of which tool happens to write to
    it first, including Company/Vulnerability modules run long after
    the original scan, on scans that predate this feature entirely."""
    safe_domain = sanitize_filename_part(domain)
    folder = SCAN_OUTPUTS_DIR / f"{scan_id}_{safe_domain}"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def write_full_output_file(scan_id: int, domain: str, filename: str, items: list[str]) -> Path:
    """One item per line. Overwrites on every call, so a re-run of the
    same tool against the same scan replaces the previous file rather
    than accumulating duplicates or stale data alongside it."""
    folder = get_scan_output_dir(scan_id, domain)
    path = folder / filename
    path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
def get_db():
    # timeout=30: how long sqlite3 will retry internally before raising
    # "database is locked", instead of the 5s default. WAL mode lets readers
    # and writers coexist much more gracefully than the default journal mode,
    # which matters given how many small writes (per log line, per enrichment
    # hit) this app makes concurrently with the UI polling for scan status.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    """Creates the schema on first run. Data model, roughly:
      scans            one row per scan run (domain, mode, status, progress)
      subdomains       discovered hosts for a scan, with a comma-joined
                        `sources` list, resolved `ip`, manual `verified`
                        flag, and confidence/status from live validation
      http_assets      one row per live HTTP(S) response httpx got back
      ports            open ports; `source` accumulates as a comma list
                        when multiple tools agree on the same host:port
                        (see upsert_port); also carries validation fields
      host_intel       generic key/value OSINT facts: (host, source,
                        field, value) — this is what whois/ip-geo/social/
                        company/shodan/crt.sh/custom-API-enrich all write
                        into, so the UI can render them uniformly without
                        each source needing its own table
      emails           harvested addresses, deduped per (scan, email, source)
      scan_logs        the live-output terminal log, replayed to clients
                        that connect to the websocket after a scan started
      api_keys / custom_tools / custom_api_sources / tool_settings /
      tool_variants    all runtime configuration (see the get_*/set_*
                        helpers just below), separate from any one scan's
                        results so it persists across runs
    """
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'running',
            started_at TEXT NOT NULL,
            completed_at TEXT,
            company_name TEXT
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            subdomain TEXT NOT NULL,
            sources TEXT NOT NULL DEFAULT '',
            ip TEXT,
            UNIQUE(scan_id, subdomain)
        );

        CREATE TABLE IF NOT EXISTS http_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            subdomain TEXT,
            url TEXT,
            status_code INTEGER,
            title TEXT,
            tech TEXT,
            server TEXT,
            ip TEXT
        );

        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            service TEXT,
            UNIQUE(scan_id, host, port)
        );

        CREATE TABLE IF NOT EXISTS host_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host TEXT NOT NULL,
            source TEXT NOT NULL,
            field TEXT NOT NULL,
            value TEXT,
            UNIQUE(scan_id, host, source, field)
        );

        CREATE TABLE IF NOT EXISTS emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            email TEXT NOT NULL,
            source TEXT NOT NULL,
            UNIQUE(scan_id, email, source)
        );

        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            line TEXT NOT NULL,
            level TEXT NOT NULL DEFAULT 'info',
            ts TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            service TEXT PRIMARY KEY,
            key TEXT NOT NULL,
            updated_at TEXT
        );

        -- Single-row config for the optional AI analysis feature. Any
        -- OpenAI-compatible chat-completions endpoint works here —
        -- Ollama running locally, Groq, OpenRouter, or anything else
        -- that speaks the same request/response shape — since the base
        -- URL, key, and model are just configuration, not hardcoded to
        -- one provider. Entirely optional: every other feature in this
        -- app works identically whether or not this table has a row.
        CREATE TABLE IF NOT EXISTS ai_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            base_url TEXT NOT NULL,
            api_key TEXT,
            model TEXT NOT NULL,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS custom_tools (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            command_template TEXT NOT NULL,
            output_format TEXT NOT NULL DEFAULT 'plain',
            shell INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS custom_api_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT 'enrich',
            url_template TEXT NOT NULL,
            json_path TEXT,
            intel_fields TEXT,
            api_key TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS tool_settings (
            name TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS tool_variants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tool_name TEXT NOT NULL,
            mode TEXT NOT NULL DEFAULT 'both',
            label TEXT NOT NULL,
            extra_args TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 0,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS wordlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            filename TEXT NOT NULL,
            line_count INTEGER,
            size_bytes INTEGER,
            uploaded_at TEXT
        );

        CREATE TABLE IF NOT EXISTS tool_wordlists (
            tool_name TEXT PRIMARY KEY,
            wordlist_id INTEGER REFERENCES wordlists(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS tool_intensity (
            tool_name TEXT PRIMARY KEY,
            aggressive INTEGER NOT NULL DEFAULT 0
        );

        -- For tools with more than a binary aggressive/not choice —
        -- SpiderFoot's passive/footprint/investigate/all use-case
        -- profiles, nuclei's template-tag breadth, and similar. A
        -- separate table rather than extending tool_intensity so the
        -- existing boolean semantics for nmap/naabu/whatweb are never
        -- touched by this.
        CREATE TABLE IF NOT EXISTS tool_profiles (
            tool_name TEXT PRIMARY KEY,
            profile TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS screenshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host TEXT NOT NULL,
            url TEXT,
            final_url TEXT,
            status_code INTEGER,
            title TEXT,
            filename TEXT,
            failed INTEGER NOT NULL DEFAULT 0,
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host TEXT NOT NULL,
            source TEXT NOT NULL,
            template_id TEXT,
            name TEXT NOT NULL,
            severity TEXT NOT NULL,
            matched_at TEXT,
            is_takeover INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS leaks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            host TEXT NOT NULL,
            source TEXT NOT NULL,
            leak_type TEXT,
            detail TEXT NOT NULL
        );
        """
    )
    conn.commit()

    # Migration for DBs created before the 'shell' column existed on custom_tools
    try:
        conn.execute("ALTER TABLE custom_tools ADD COLUMN shell INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # column already exists

    # Migration for DBs created before progress tracking existed on scans
    for stmt in (
        "ALTER TABLE scans ADD COLUMN progress_percent INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN progress_stage TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE subdomains ADD COLUMN verified INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE subdomains ADD COLUMN confidence INTEGER",
        "ALTER TABLE subdomains ADD COLUMN validation_status TEXT",
        "ALTER TABLE subdomains ADD COLUMN validated_at TEXT",
        "ALTER TABLE ports ADD COLUMN confidence INTEGER",
        "ALTER TABLE ports ADD COLUMN validation_status TEXT",
        "ALTER TABLE ports ADD COLUMN validated_at TEXT",
        "ALTER TABLE scans ADD COLUMN company_name TEXT",
        # http_assets never got the same validation tracking subdomains/
        # ports did — meaning there was no way to know "this URL was just
        # reconfirmed live" versus "this is whatever it was at original
        # scan time." That gap matters a lot once something (a triggered
        # vulnerability scan, for instance) needs to know the CURRENT set
        # of live URLs rather than trusting the original scan forever.
        "ALTER TABLE http_assets ADD COLUMN confidence INTEGER",
        "ALTER TABLE http_assets ADD COLUMN validation_status TEXT",
        "ALTER TABLE http_assets ADD COLUMN validated_at TEXT",
        # Richer, tool-specific context that doesn't fit the fixed columns
        # above — WPScan's CVE references and fixed-in version, Dalfox's
        # actual injected payload/evidence. NULL for nuclei findings,
        # which don't have much worth adding beyond what's already
        # captured.
        "ALTER TABLE vulnerabilities ADD COLUMN detail TEXT",
        # Company and Vulnerability no longer run automatically as part
        # of a scan — they're deliberately triggered, independent
        # modules now (see /api/scans/{id}/company/run and .../
        # vulnerability/run). These track WHETHER and WHEN each has
        # actually been run for a given scan, which the Attack Surface
        # Summary needs to know explicitly: "0 vulnerabilities found"
        # and "vulnerability scan never run" are very different
        # statements, and conflating them would make a scan look safer
        # than it's actually been checked to be.
        "ALTER TABLE scans ADD COLUMN company_scanned_at TEXT",
        "ALTER TABLE scans ADD COLUMN vulnerability_scanned_at TEXT",
        # Company and Vulnerability progress tracking — separate columns
        # from the main scan's own progress_percent/progress_stage,
        # deliberately, since these two modules run independently and
        # much later than the original scan; reusing the same columns
        # would overwrite the original scan's own completed-100% state
        # with "Company scan 20% running" the moment someone triggers it,
        # which has nothing to do with the original scan's own progress.
        # The *_running flag is what a client polls to know when to stop
        # polling and refresh the results view — there's no scan-wide
        # "status" column for these the way the main scan has one.
        "ALTER TABLE scans ADD COLUMN company_progress_percent INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN company_progress_stage TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE scans ADD COLUMN company_scan_running INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN vulnerability_progress_percent INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN vulnerability_progress_stage TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE scans ADD COLUMN vulnerability_scan_running INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN deep_scan_progress_percent INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scans ADD COLUMN deep_scan_progress_stage TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE scans ADD COLUMN deep_scan_running INTEGER NOT NULL DEFAULT 0",
        # Prioritization data for CVE-bearing findings — is this CVE
        # confirmed under active exploitation right now (CISA KEV), and
        # what's the modeled probability it gets exploited in the next
        # 30 days (FIRST.org EPSS)? Both NULL/0 until the vulnerability
        # scan's enrichment step actually runs (see check_cisa_kev /
        # check_epss_scores in vulnerability.py) — most findings won't
        # have a CVE at all (nuclei's exposure/misconfig templates,
        # every dalfox XSS finding), so these stay unset for those.
        "ALTER TABLE vulnerabilities ADD COLUMN epss_score REAL",
        "ALTER TABLE vulnerabilities ADD COLUMN is_kev INTEGER NOT NULL DEFAULT 0",
        # Findings triage — tracks what's actually been done with a
        # finding, not just what was found. "0 open findings" and "12
        # findings, all triaged as false positives" are very different
        # states that a flat findings list can't distinguish on its own.
        "ALTER TABLE vulnerabilities ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'open'",
        "ALTER TABLE vulnerabilities ADD COLUMN triage_note TEXT",
        "ALTER TABLE leaks ADD COLUMN triage_status TEXT NOT NULL DEFAULT 'open'",
        "ALTER TABLE leaks ADD COLUMN triage_note TEXT",
    ):
        try:
            conn.execute(stmt)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.close()


# ---------------------------------------------------------------------------
# Config helpers — tool enable/disable, custom tools, custom API sources, keys
# ---------------------------------------------------------------------------
def get_tool_settings_map() -> dict[str, bool]:
    conn = get_db()
    rows = conn.execute("SELECT name, enabled FROM tool_settings").fetchall()
    conn.close()
    return {r["name"]: bool(r["enabled"]) for r in rows}


def is_enabled(name: str, settings_map: dict[str, bool], default: bool = True) -> bool:
    return settings_map.get(name, default)


def get_custom_tools(enabled_only: bool = False) -> list[dict]:
    conn = get_db()
    q = "SELECT * FROM custom_tools" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY id"
    rows = conn.execute(q).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_custom_api_sources(enabled_only: bool = False, category: Optional[str] = None) -> list[dict]:
    conn = get_db()
    q = "SELECT * FROM custom_api_sources WHERE 1=1"
    params = []
    if enabled_only:
        q += " AND enabled = 1"
    if category:
        q += " AND category = ?"
        params.append(category)
    q += " ORDER BY id"
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_tool_variants(tool_name: Optional[str] = None) -> list[dict]:
    conn = get_db()
    q = "SELECT * FROM tool_variants"
    params = []
    if tool_name:
        q += " WHERE tool_name = ?"
        params.append(tool_name)
    q += " ORDER BY created_at"
    rows = conn.execute(q, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_active_variant(tool_name: str, mode: str) -> Optional[dict]:
    """A variant scoped to this exact mode wins over a 'both'-scoped one if
    somehow both are marked active at once (shouldn't normally happen, since
    activation deactivates same-tool siblings, but this keeps it well-defined)."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM tool_variants WHERE tool_name = ? AND active = 1 AND (mode = ? OR mode = 'both') "
        "ORDER BY (mode = ?) DESC LIMIT 1",
        (tool_name, mode, mode),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def apply_variant(base_cmd: list[str], tool_name: str, mode: str) -> list[str]:
    """Appends a user's saved extra args to a built-in tool's base command,
    if they have an active variant for this tool+mode. Never replaces or
    removes the base command's own flags — those are what our parsers rely
    on, so customization is additive only."""
    variant = get_active_variant(tool_name, mode)
    if not variant or not variant.get("extra_args", "").strip():
        return base_cmd
    try:
        extra = shlex.split(variant["extra_args"])
    except ValueError:
        return base_cmd
    return base_cmd + extra


# ---------------------------------------------------------------------------
# Wordlists — unlike tool variants (which only ever append extra args), a
# wordlist can change a tool's fundamental mode of operation: amass with a
# wordlist switches from passive to active brute-force, for example. That's
# why this is deliberately a separate, simpler system (one wordlist per
# tool at most, not multiple named variants) rather than folded into
# tool_variants — the two are conceptually different kinds of "extra".
#
# amass (-brute -w) and dnsx (-w, targeted bruteforce) treat a wordlist as
# optional — they run fine without one, just differently. ffuf and
# shuffledns are different: a wordlist isn't an enhancement for them, it's
# the entire input. Both are skipped outright with no wordlist assigned
# rather than run in some no-op default state, since there's no sane
# "ffuf with nothing to fuzz" behavior. subfinder is deliberately NOT
# included here — its current release dropped bruteforce support
# entirely (older forks had -b/-w, but the actively maintained
# ProjectDiscovery version doesn't anymore), so adding a wordlist option
# for it would silently do nothing.
# ---------------------------------------------------------------------------
WORDLIST_CAPABLE_TOOLS = {"amass", "dnsx", "ffuf", "shuffledns"}


def get_active_wordlist(tool_name: str) -> Optional[dict]:
    """Returns {id, name, filename, path} for the wordlist currently
    assigned to a tool, or None if none is assigned or the file has gone
    missing from disk since it was uploaded."""
    conn = get_db()
    row = conn.execute(
        "SELECT w.* FROM tool_wordlists tw JOIN wordlists w ON w.id = tw.wordlist_id WHERE tw.tool_name = ?",
        (tool_name,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    path = WORDLISTS_DIR / row["filename"]
    if not path.is_file():
        return None
    result = dict(row)
    result["path"] = str(path)
    return result


# ---------------------------------------------------------------------------
# Bootstrap wordlists — auto-registers whatever install.sh actually fetched
# (SecLists via apt, n0kovo_subdomains via git clone) so they show up in
# the wordlist picker without needing a manual upload through the UI
# first. Symlinked into WORDLISTS_DIR rather than copied, so a
# multi-hundred-MB wordlist collection doesn't get duplicated on disk and
# stays current if the source updates later (e.g. an apt upgrade of the
# seclists package). Safe to call on every startup — anything already
# registered (matched by name) or whose source file isn't actually
# present is skipped, so this does nothing on a system that doesn't have
# these tools installed, rather than erroring.
# ---------------------------------------------------------------------------
BOOTSTRAP_WORDLISTS = [
    # (name, source_path, recommended_for) — recommended_for lists which
    # wordlist-capable tools this specific entry is the "best default"
    # for. Used both to auto-assign a sensible default per tool (see
    # register_bootstrap_wordlists) and to tell the frontend which option
    # to highlight in a tool's wordlist dropdown (see
    # get_wordlist_recommendations) — one list, one source of truth for
    # both, rather than duplicating the mapping in two places.
    ("SecLists: common.txt (ffuf — quick first pass)",
     Path("/usr/share/seclists/Discovery/Web-Content/common.txt"), []),
    ("SecLists: raft-medium-directories.txt (ffuf — recommended default)",
     Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"), ["ffuf"]),
    ("SecLists: raft-large-files.txt (ffuf — sensitive file hunting, pair with -e)",
     Path("/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt"), []),
    # n0kovo_subdomains — "tiny" is the recommended default now, not
    # "medium". A real report from actually using this: dnsx (and
    # amass/shuffledns) auto-assigned to "medium" (500,000 lines) made a
    # bruteforce pass genuinely slow — 500k DNS lookups is a lot of
    # volume regardless of how fast the tool itself is per-lookup.
    # "tiny" is still a real, curated subdomain wordlist (n0kovo's own
    # highest-value tier, not an arbitrary truncation), just dramatically
    # smaller — a much more reasonable thing to run by default, with
    # medium/large/huge available as deliberate, slower opt-ins for
    # someone who wants more thorough coverage on a specific engagement.
    ("n0kovo_subdomains — tiny (amass/dnsx/shuffledns — recommended default, fast)",
     BASE_DIR / "wordlists-src" / "n0kovo_subdomains" / "n0kovo_subdomains_tiny.txt",
     ["amass", "dnsx", "shuffledns"]),
    ("n0kovo_subdomains — small (amass/dnsx/shuffledns — a bit more coverage, still quick)",
     BASE_DIR / "wordlists-src" / "n0kovo_subdomains" / "n0kovo_subdomains_small.txt", []),
    ("n0kovo_subdomains — medium (amass/dnsx/shuffledns — thorough, noticeably slower)",
     BASE_DIR / "wordlists-src" / "n0kovo_subdomains" / "n0kovo_subdomains_medium.txt", []),
    ("n0kovo_subdomains — large (amass/dnsx/shuffledns — very thorough, slow)",
     BASE_DIR / "wordlists-src" / "n0kovo_subdomains" / "n0kovo_subdomains_large.txt", []),
]


def register_bootstrap_wordlists() -> int:
    conn = get_db()
    existing_names = {row["name"] for row in conn.execute("SELECT name FROM wordlists").fetchall()}
    WORDLISTS_DIR.mkdir(exist_ok=True)
    registered = 0
    for name, source_path, _recommended_for in BOOTSTRAP_WORDLISTS:
        if name in existing_names or not source_path.is_file():
            continue
        try:
            with open(source_path, encoding="utf-8", errors="replace") as f:
                line_count = sum(1 for line in f if line.strip())
        except Exception:
            continue
        size_bytes = source_path.stat().st_size
        cur = conn.execute(
            "INSERT INTO wordlists (name, filename, line_count, size_bytes, uploaded_at) VALUES (?, '', ?, ?, ?)",
            (name, line_count, size_bytes, now_iso()),
        )
        wordlist_id = cur.lastrowid
        link_filename = f"{wordlist_id}_bootstrap.txt"
        link_path = WORDLISTS_DIR / link_filename
        try:
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink()
            link_path.symlink_to(source_path)
        except Exception:
            conn.execute("DELETE FROM wordlists WHERE id = ?", (wordlist_id,))
            continue
        conn.execute("UPDATE wordlists SET filename = ? WHERE id = ?", (link_filename, wordlist_id))
        registered += 1
    conn.commit()

    # Auto-assign each tool's recommended default — but ONLY where that
    # tool has no assignment at all yet, so this never overwrites a
    # deliberate choice someone already made (including "none", which a
    # person may have picked on purpose for amass/dnsx to keep them in
    # their lighter, non-bruteforce mode). Runs after every registration
    # pass, including on normal restarts, so a tool that's still
    # unassigned picks up a sensible default the moment its recommended
    # wordlist becomes available — not just on a truly first-ever run.
    already_assigned = {row["tool_name"] for row in conn.execute("SELECT tool_name FROM tool_wordlists").fetchall()}
    name_to_id = {row["name"]: row["id"] for row in conn.execute("SELECT id, name FROM wordlists").fetchall()}
    for name, _source_path, recommended_for in BOOTSTRAP_WORDLISTS:
        wordlist_id = name_to_id.get(name)
        if wordlist_id is None:
            continue
        for tool_name in recommended_for:
            if tool_name in already_assigned:
                continue
            conn.execute(
                "INSERT INTO tool_wordlists (tool_name, wordlist_id) VALUES (?, ?) "
                "ON CONFLICT(tool_name) DO NOTHING",
                (tool_name, wordlist_id),
            )
            already_assigned.add(tool_name)
    conn.commit()
    conn.close()
    return registered


def get_wordlist_recommendations() -> dict[str, int]:
    """{tool_name: wordlist_id} for whichever bootstrap wordlist is the
    recommended default for that tool — only included if that specific
    wordlist has actually been registered (e.g. omits ffuf's entry
    entirely if SecLists was never installed, rather than pointing at a
    wordlist that doesn't exist). Used by the frontend to highlight the
    recommended option in a tool's wordlist dropdown; the auto-assignment
    in register_bootstrap_wordlists uses the exact same source data, so
    "recommended" and "what gets auto-assigned" can never drift apart."""
    conn = get_db()
    name_to_id = {row["name"]: row["id"] for row in conn.execute("SELECT id, name FROM wordlists").fetchall()}
    conn.close()
    result: dict[str, int] = {}
    for name, _source_path, recommended_for in BOOTSTRAP_WORDLISTS:
        wordlist_id = name_to_id.get(name)
        if wordlist_id is None:
            continue
        for tool_name in recommended_for:
            result[tool_name] = wordlist_id
    return result


# ---------------------------------------------------------------------------
# Aggressive mode — a simple per-tool on/off toggle for tools that have a
# genuine, well-documented stealth-vs-loud dimension in their own flags:
# nmap's timing templates (-T0..-T5) and its own literal -A "aggressive"
# flag, naabu's scan rate/port coverage, and whatweb's own aggression
# levels (1 stealthy .. 4 heavy — this app maps the toggle to 1 vs 3). Off
# (the default, unchanged from this app's existing behavior) keeps the
# current moderate defaults; on swaps in faster timing and broader/louder
# scanning.
#
# Deliberately NOT extended to every tool — subfinder/amass/dnsx/httpx
# don't have a comparable "stealth vs loud" dichotomy in the same sense
# (their rate-limit flags are about avoiding source-side throttling, not
# network-visibility trade-offs), so a blanket toggle there would just be
# guessing at what "aggressive" should mean for them.
# ---------------------------------------------------------------------------
AGGRESSIVE_CAPABLE_TOOLS = {"nmap", "naabu", "whatweb"}


def is_aggressive(tool_name: str) -> bool:
    conn = get_db()
    row = conn.execute("SELECT aggressive FROM tool_intensity WHERE tool_name = ?", (tool_name,)).fetchone()
    conn.close()
    return bool(row["aggressive"]) if row else False


# Tools with more than a binary aggressive/not choice — each option's
# `value` is used directly in that tool's own command construction (see
# spiderfoot_run/nuclei_run), so adding a new option here never requires
# touching the tool's own code, just this registry. The FIRST option in
# each list is always the pre-existing default behavior, verified
# against each tool's actual current command before being set here —
# an unconfigured tool must behave exactly as it always has.
TOOL_PROFILES = {
    "spiderfoot": {
        "default": "passive",
        "options": [
            {"value": "passive", "label": "Passive (default)",
             "description": "Never contacts the target directly — every finding comes from third-party sources "
                             "(DNS, WHOIS, Shodan, etc.). The safest choice, always within scope."},
            {"value": "strict", "label": "Strict (fastest)",
             "description": "SpiderFoot's own -x strict mode: only runs modules that query the domain directly, "
                             "skipping the chained modules that feed off another module's output (e.g. "
                             "look-up-a-hostname-SpiderFoot-just-found-elsewhere). Meaningfully faster than "
                             "Passive, but narrower — real multi-hop passive findings are traded away for speed, "
                             "not a free win. Targets a fixed, curated set of the event types this app actually "
                             "uses (hosts, emails, certs, tech, open ports, cloud buckets, leaked credentials, "
                             "high/critical CVEs) rather than every event type Passive mode would surface."},
            {"value": "footprint", "label": "Footprint",
             "description": "Broader attack-surface coverage, but includes some modules that actively contact "
                             "the target directly — confirm that's in scope before using this."},
            {"value": "investigate", "label": "Investigate",
             "description": "Checks blacklists and threat-intel feeds for existing compromise/danger indicators "
                             "on the target — a different angle than Footprint, not necessarily broader."},
            {"value": "all", "label": "All modules",
             "description": "Every module SpiderFoot has, including intrusive ones. Very slow, and heavily "
                             "overlaps with tools this app already runs elsewhere — rarely the right choice here."},
        ],
    },
    "nuclei": {
        "default": "cve,exposure,exposures,misconfig,misconfiguration,default-login,takeover",
        "options": [
            {"value": "cve", "label": "CVEs only",
             "description": "Fastest, lowest-noise — only checks for known CVEs, skips misconfiguration/"
                             "exposure/default-login/takeover templates entirely."},
            {"value": "cve,exposure,exposures,misconfig,misconfiguration,default-login,takeover",
             "label": "Balanced (default)",
             "description": "CVEs plus misconfigurations, exposed panels/files, default logins, and subdomain "
                             "takeover checks — these are consistently the highest-yield categories for external "
                             "recon specifically, confirmed against current community guidance."},
            {"value": "cve,exposure,exposures,misconfig,misconfiguration,default-login,takeover,technologies,fuzzing",
             "label": "Comprehensive",
             "description": "Adds technology fingerprinting and fuzzing-style templates on top of Balanced — "
                             "slower, more requests against the target, occasionally more false positives."},
        ],
    },
    "user-scanner": {
        "default": "core",
        "options": [
            {"value": "core", "label": "Core platforms (fast)",
             "description": "A curated ~20-module set of major, recognizable platforms (GitHub, GitLab, "
                             "LinkedIn, X, Instagram, Reddit, Discord, Keybase, and similar) — fast, low "
                             "noise, and the ones most likely to actually confirm a real person tied to "
                             "the company. Runs in seconds per identity."},
            {"value": "full", "label": "Full breadth (slow, loud)",
             "description": "Every module this tool has — 2,500+ for a username, 200+ for an email. "
                             "Comprehensive, but it's hundreds to thousands of individual active HTTP "
                             "requests against third-party sites for one person, takes minutes, and risks "
                             "rate-limits/CAPTCHAs/IP flags on some of those sites. Confirm that's actually "
                             "worth it for this specific person before picking it."},
        ],
    },
}


def get_tool_profile(tool_name: str, default: str) -> str:
    """Returns the stored profile value for a tool, or `default` if
    nothing's been explicitly chosen — so an unconfigured tool behaves
    exactly as it always has, byte-for-byte, until someone picks
    something else."""
    conn = get_db()
    row = conn.execute("SELECT profile FROM tool_profiles WHERE tool_name = ?", (tool_name,)).fetchone()
    conn.close()
    return row["profile"] if row else default


def set_tool_profile(tool_name: str, profile: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO tool_profiles (tool_name, profile) VALUES (?, ?) "
        "ON CONFLICT(tool_name) DO UPDATE SET profile = excluded.profile",
        (tool_name, profile),
    )
    conn.commit()
    conn.close()


def build_custom_cmd(template: str, domain: str) -> list[str]:
    tokens = shlex.split(template)
    return [t.replace("{domain}", domain) for t in tokens]


def build_custom_shell_cmd(template: str, domain: str) -> str:
    """For shell-mode custom tools: {domain} is substituted with a
    shell-quoted value so chaining (&&, ;, |) works as the user intends
    while the domain itself can't break out of its argument position."""
    return template.replace("{domain}", shlex.quote(domain))


def get_api_key(service: str) -> Optional[str]:
    conn = get_db()
    row = conn.execute("SELECT key FROM api_keys WHERE service = ?", (service,)).fetchone()
    conn.close()
    return row["key"] if row else None


def set_api_key(service: str, key: str):
    conn = get_db()
    if key:
        conn.execute(
            "INSERT INTO api_keys (service, key, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(service) DO UPDATE SET key = excluded.key, updated_at = excluded.updated_at",
            (service, key, now_iso()),
        )
    else:
        conn.execute("DELETE FROM api_keys WHERE service = ?", (service,))
    conn.commit()
    conn.close()


def get_ai_config() -> Optional[dict]:
    """Returns {base_url, api_key, model} or None if the optional AI
    analysis feature hasn't been configured at all — the normal state
    for anyone not using it, and every caller of this must handle that
    case gracefully rather than assume a config exists."""
    conn = get_db()
    row = conn.execute("SELECT base_url, api_key, model FROM ai_config WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def set_ai_config(base_url: str, api_key: Optional[str], model: str):
    """Pass an empty/falsy base_url to clear the config entirely,
    reverting to the unconfigured (feature simply unavailable) state."""
    conn = get_db()
    if base_url and model:
        conn.execute(
            "INSERT INTO ai_config (id, base_url, api_key, model, updated_at) VALUES (1, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET base_url = excluded.base_url, api_key = excluded.api_key, "
            "model = excluded.model, updated_at = excluded.updated_at",
            (base_url.rstrip("/"), api_key or None, model, now_iso()),
        )
    else:
        conn.execute("DELETE FROM ai_config WHERE id = 1")
    conn.commit()
    conn.close()


def mask_key(k: Optional[str]) -> Optional[str]:
    if not k:
        return None
    if len(k) <= 6:
        return "*" * len(k)
    return f"{k[:3]}…{k[-3:]}"


def upsert_port(conn, scan_id: int, host: str, port: int, source: str, service: Optional[str] = None):
    row = conn.execute(
        "SELECT source, service FROM ports WHERE scan_id = ? AND host = ? AND port = ?",
        (scan_id, host, port),
    ).fetchone()
    if row:
        sources = set(filter(None, (row["source"] or "").split(",")))
        sources.add(source)
        svc = service or row["service"]
        conn.execute(
            "UPDATE ports SET source = ?, service = ? WHERE scan_id = ? AND host = ? AND port = ?",
            (",".join(sorted(sources)), svc, scan_id, host, port),
        )
    else:
        conn.execute(
            "INSERT INTO ports (scan_id, host, port, source, service) VALUES (?, ?, ?, ?, ?)",
            (scan_id, host, port, source, service),
        )


def store_intel(conn, scan_id: int, host: str, source: str, field: str, value):
    if value is None or value == "":
        return
    conn.execute(
        "INSERT INTO host_intel (scan_id, host, source, field, value) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(scan_id, host, source, field) DO UPDATE SET value = excluded.value",
        (scan_id, host, source, field, str(value)),
    )


def filter_emails_to_domain(emails: set[str], domain: str, extra_domains: Optional[set[str]] = None) -> set[str]:
    """Keeps only emails whose own domain matches the target domain (or
    one of a small set of known-valid variants — a discovered TLD
    variant, a redirect target) — discarding anything else, even if it
    appeared directly on the target's own pages or in a search result
    mentioning the target. Confirmed directly as a real, recurring
    problem across multiple independent sources (a hosting provider's
    own support email in a site footer; a search-engine result that
    happens to mention the target domain alongside an unrelated
    third-party contact address) — all get picked up by naive
    email-pattern matching otherwise. An allowlist here is the right
    shape, not a denylist: there's no way to anticipate every possible
    ISP/hosting-provider domain in advance, but the one thing every
    genuine contact email for this target has in common is actually
    being @ this domain."""
    valid_domains = {domain.lower()}
    if extra_domains:
        valid_domains.update(d.lower() for d in extra_domains if d)
    kept = set()
    for email in emails:
        if "@" not in email:
            continue
        email_domain = email.rsplit("@", 1)[1].lower()
        if any(email_domain == d or email_domain.endswith("." + d) for d in valid_domains):
            kept.add(email)
    return kept


def add_emails(conn, scan_id: int, emails: set[str], source: str):
    for e in emails:
        conn.execute(
            "INSERT OR IGNORE INTO emails (scan_id, email, source) VALUES (?, ?, ?)",
            (scan_id, e, source),
        )


def get_confirmed_live_urls(scan_id: int) -> list[str]:
    """The actual answer to "what should a triggered vulnerability scan
    target" — URLs from this scan's http_assets that were reconfirmed
    live the last time /api/scans/{id}/validate ran, not just whatever
    the original enumeration pass happened to see. Deliberately returns
    an empty list rather than the stale full asset set if validation has
    never been run, so a caller can't accidentally scan against
    unvalidated data by mistake — an empty result here should read as
    "run validation first," not "nothing was ever found."
    """
    conn = get_db()
    rows = conn.execute(
        "SELECT url FROM http_assets WHERE scan_id = ? AND validation_status = 'confirmed' AND url IS NOT NULL",
        (scan_id,),
    ).fetchall()
    conn.close()
    return sorted({r["url"] for r in rows if r["url"]})


async def check_dns_now(host: str, timeout: float = 5) -> bool:
    """Lives here rather than in app.py specifically because it's needed
    by both app.py (live validation) and company.py (checking whether a
    TLD-variant domain, e.g. sensepost.co.za, actually exists) — shared
    infra, not something specific to either module's own concerns."""
    try:
        loop = asyncio.get_event_loop()
        await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=timeout)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Websocket connection manager — one channel per scan_id
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active: dict[int, list[WebSocket]] = {}

    async def connect(self, scan_id: int, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: int, ws: WebSocket):
        if scan_id in self.active and ws in self.active[scan_id]:
            self.active[scan_id].remove(ws)

    async def broadcast(self, scan_id: int, message: dict):
        for ws in list(self.active.get(scan_id, [])):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(scan_id, ws)


manager = ConnectionManager()


async def log_line(scan_id: int, line: str, level: str = "info"):
    conn = get_db()
    conn.execute(
        "INSERT INTO scan_logs (scan_id, line, level, ts) VALUES (?, ?, ?, ?)",
        (scan_id, line, level, now_iso()),
    )
    conn.commit()
    conn.close()
    await manager.broadcast(scan_id, {"type": "log", "line": line, "level": level})


# ---------------------------------------------------------------------------
# Command rationale — a one-line "why is this app running this, and why
# now" note logged immediately before every "$ <command>" line. Someone
# reading the live output (or the saved "Commands run" section of a
# finished report) shouldn't have to already know what shuffledns or dnsx
# are, or infer for themselves why a scan bothers running both subfinder
# AND amass rather than just one — that's exactly the kind of thing that's
# obvious to whoever built this pipeline and opaque to everyone else
# reading its output later, including future-us.
#
# Keyed off the tool's *base* name (recon-ng's own module, ffuf's own
# target URL, and nmap's exact flag set all vary per call — matched by
# prefix below, or left to the dynamic "$ ..." line itself to show). This
# is deliberately a static, human-written dict, not a live --help pull:
# the question it answers is "why does *this app* run this tool here",
# which a tool's own help text can't tell you.
# ---------------------------------------------------------------------------
TOOL_RATIONALE_PREFIXES: list[tuple[str, str]] = [
    ("dig (AXFR", "attempts a DNS zone transfer (AXFR) against this name server — almost "
                  "always refused by a correctly configured server, but a misconfigured "
                  "one leaks the entire zone file in a single request."),
    ("dig (NS", "looks up the domain's authoritative name servers, so each one can be "
                "tried for a zone transfer below."),
    ("dig (SPF", "reads the domain's SPF TXT record — checks whether mail claiming to be "
                 "from this domain is authenticated at all, and how permissive the policy is."),
    ("dig (DMARC", "reads the domain's DMARC TXT record — SPF/DKIM only authenticate mail; "
                   "DMARC is what tells a receiving server what to actually do with mail "
                   "that fails those checks (reject it, quarantine it, or nothing)."),
    ("nuclei (template update", "refreshes nuclei's community-maintained vulnerability templates "
                                "before scanning — the templates define what nuclei is even "
                                "capable of detecting, and they're updated far more often than "
                                "this app is."),
    ("recon-ng (show hosts", "reads back whatever recon-ng's own modules wrote to its internal "
                             "workspace, so those findings can be pulled into this scan's results."),
    ("recon-ng (add", "seeds recon-ng's workspace with this domain so its modules below have a "
                       "starting point to work from."),
]

TOOL_RATIONALE: dict[str, str] = {
    "whois": "registry lookup for the domain's registrar, registrant/organisation, and "
             "creation/expiry dates — a passive record lookup, no traffic to the target itself.",
    "theharvester": "aggregates emails, hosts, and names from public sources (search engines, "
                     "PGP key servers, etc.) that this app's own directly-integrated sources don't cover.",
    "gowitness": "screenshots each live HTTP(S) host, so hosts can be triaged visually instead "
                 "of opening every URL by hand.",
    "whatweb": "fingerprints the web stack behind each live host (CMS, server, JS libraries, "
               "versions where exposed) — the main source for spotting outdated, likely-vulnerable components.",
    "gau": "pulls every URL Wayback Machine/CommonCrawl/OTX have ever archived for the domain — "
           "finds old or forgotten endpoints a live crawl alone would never see.",
    "katana": "actively crawls each live host for in-use endpoints, forms, and JS-referenced "
              "paths — the current-state counterpart to gau's historical/archived URLs.",
    "shuffledns": "brute-forces subdomains from the configured wordlist via mass DNS resolution "
                  "(massdns) — the main way this app finds subdomains that were never in any "
                  "public source subfinder/amass/assetfinder could have found.",
    "spiderfoot": "runs SpiderFoot's own passive OSINT module set as a second, independently "
                  "maintained pass alongside this app's direct integrations — catches whatever they miss.",
    "recon-ng": "runs a recon-ng module to pull one specific kind of OSINT that recon-ng's own "
                "module ecosystem covers.",
    "subfinder": "passive subdomain enumeration via certificate transparency logs, DNS "
                 "aggregators, and search engines — no traffic ever reaches the target itself.",
    "amass": "a second, independently-sourced passive subdomain pass — different data sources "
             "from subfinder, run in addition to it rather than instead of it.",
    "assetfinder": "a third lightweight passive subdomain source — cheap to run, occasionally "
                   "turns up something the other two miss.",
    "dnsx": "resolves each discovered subdomain to confirm it's actually live and get its real "
            "IP(s) — a name showing up in a source above isn't necessarily still a resolvable host.",
    "httpx": "probes each resolved host over HTTP(S) to confirm it's actually serving a web "
             "response (status, title, tech) before other tools spend time on it.",
    "naabu": "a fast port sweep across every resolved IP, run before nmap so nmap's much slower "
             "service/version scan only has to target ports naabu already confirmed open.",
    "nmap": "the detailed port/service scan (version detection, and in full mode, NSE scripts) "
            "against the narrower port list naabu already confirmed open.",
    "crosslinked": "scrapes LinkedIn (via search-engine results, not a LinkedIn login) for "
                   "employee names/titles at the company, for the Company module's people view.",
    "ffuf": "fuzzes for hidden files/directories on a live host by requesting a wordlist of "
            "common paths — finds things no crawler would ever find a link to.",
    "nuclei": "runs community-maintained CVE and misconfiguration templates against each live "
              "host — the main automated vulnerability-signature check in this app.",
    "wpscan": "WordPress-specific: enumerates plugins/themes/users and checks them against "
              "known-vulnerable version databases — only run once WordPress is actually detected.",
    "dalfox": "actively tests discovered URL parameters for reflected/DOM XSS — the one tool "
              "here that sends deliberately malformed input rather than just reading/enumerating.",
    "dig": "a direct DNS record query — see the more specific note logged with each individual lookup below.",
    "user-scanner": "checks one already-discovered name or email against a set of third-party "
                     "platforms to find accounts actually registered to that identity — manually "
                     "triggered per person from the Company profile, not part of the automatic scan.",
}


def _tool_rationale(label: str) -> Optional[str]:
    for prefix, why in TOOL_RATIONALE_PREFIXES:
        if label.startswith(prefix):
            return why
    base = label.split(" (", 1)[0].strip().lower()
    return TOOL_RATIONALE.get(base)


async def _log_rationale(scan_id: int, label: str):
    why = _tool_rationale(label)
    if why:
        await log_line(scan_id, f"[why] {label}: {why}", "why")


# ---------------------------------------------------------------------------
# Subprocess runner — streams stdout line by line as it's produced
# ---------------------------------------------------------------------------
# asyncio's default StreamReader buffer is only 64KB — a single output
# line longer than that (no newline within it) raises LimitOverrunError,
# whose own message text is literally "Separator is not found, and chunk
# exceed the limit". katana in particular can produce oversized lines
# while crawling (a page with a large embedded base64 data URI, heavily
# minified JS parsed via -jc, etc.), and the earlier version of this app
# had no protection against it at all: the exception propagated out of
# _consume_proc_stream, discarding every line already read in that call —
# a whole tool run's results silently thrown away because of one long
# line, not because the tool itself actually failed. Set generously high
# here specifically to make hitting the limit at all rare, with recovery
# logic below as a backstop for whatever's still bigger than this.
STREAM_READ_LIMIT = 10 * 1024 * 1024  # 10 MB


async def _consume_proc_stream(scan_id: int, proc, label: str, quiet: bool = False) -> list[str]:
    """quiet=True still captures and returns every line (needed for tools
    like gau whose actual output IS the data — there's no separate results
    file to read afterward, unlike katana/nuclei/ffuf), it just skips
    broadcasting each one to the live log/scan_logs table individually.
    For a tool that can legitimately produce tens of thousands of small,
    individually-valid lines (a long-lived domain's full historical URL
    list, say) where this app only ever keeps a small capped subset, that
    per-line echo was pure overhead — real, valid data, just far more of
    it streamed live than anything downstream actually uses. The caller
    logs its own summary after capping/filtering instead.
    """
    lines: list[str] = []
    assert proc.stdout is not None
    while True:
        try:
            raw = await proc.stdout.readline()
        except (asyncio.LimitOverrunError, ValueError) as e:
            # The line being read is longer than STREAM_READ_LIMIT with no
            # newline in it yet. Recovery per asyncio's own documented
            # pattern: discard exactly what's already been buffered while
            # searching (e.consumed bytes) and go around again — this
            # naturally converges once enough of the oversized line has
            # been discarded to reach its actual newline, rather than
            # looping on the same error forever or losing every line
            # already captured before this point.
            consumed = getattr(e, "consumed", 0)
            try:
                if consumed:
                    await proc.stdout.read(consumed)
            except Exception:
                pass
            if not quiet:
                await log_line(
                    scan_id,
                    f"[{label}] skipped an oversized output line (>{STREAM_READ_LIMIT // (1024 * 1024)}MB, no "
                    f"newline found) — usually one crawled page/URL with an unusually large embedded payload, "
                    f"not a sign the tool itself failed; everything else it found is unaffected",
                    "warn",
                )
            continue
        if not raw:
            break
        line = raw.decode(errors="replace").rstrip("\n")
        if line.strip():
            lines.append(line)
            if not quiet:
                await log_line(scan_id, line, "out")
    await proc.wait()
    await log_line(scan_id, f"[done] {label} exited {proc.returncode} ({len(lines)} lines)", "meta")
    return lines


async def _kill_proc(proc):
    """Best-effort hard kill + reap, used when a stage gets cancelled
    (skip/stop) so the actual OS process doesn't linger as an orphan.

    Killing proc alone only signals that one process — if it's a shell
    (run_stream_shell) or spawned children of its own, those children are
    NOT killed by that and are left running as orphans. Both subprocess
    creation points below launch with start_new_session=True specifically
    so the whole process tree shares one process group we can kill with
    os.killpg(), which does take down children too."""
    pid = proc.pid
    try:
        if hasattr(os, "killpg"):
            os.killpg(pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        await proc.wait()
    except Exception:
        pass


async def run_stream(scan_id: int, cmd: list[str], label: str, cwd: Optional[Path] = None, quiet: bool = False) -> list[str]:
    """Exec mode — cmd is an argv list, no shell involved. Used for built-in
    tools and non-shell custom tools. `cwd` is only needed for tools that
    write result files relative to the working directory instead of
    printing to stdout (e.g. crosslinked) — everything else leaves it as
    the default (the app's own directory).

    `quiet=True` still captures and returns every line, it just skips
    streaming each one to the live log individually — see
    _consume_proc_stream for when that's the right call (a tool whose
    output is legitimately large in volume, not just occasionally
    oversized in one line, where only a small filtered/capped subset
    actually gets used downstream)."""
    binary = cmd[0]
    if not shutil.which(binary):
        await log_line(scan_id, f"[skip] {binary} not found on PATH — skipping {label}", "warn")
        return []

    await _log_rationale(scan_id, label)
    await log_line(scan_id, f"$ {' '.join(cmd)}", "cmd")
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
            cwd=str(cwd) if cwd else None,
            limit=STREAM_READ_LIMIT,
        )
        return await _consume_proc_stream(scan_id, proc, label, quiet=quiet)
    except asyncio.CancelledError:
        if proc is not None:
            await _kill_proc(proc)
        raise
    except Exception as e:
        await log_line(scan_id, f"[error] {label} failed: {e}", "error")
        return []


async def run_quiet(scan_id: int, cmd: list[str], label: str, cwd: Optional[Path] = None) -> bool:
    """Like run_stream, but for tools that write their own results file
    (via -o or similar) whose raw stdout would just be redundant with
    that file — or, worse, actively harmful to stream verbatim to the
    live log. katana specifically was found (from a real scan's output,
    not assumed) to include the full raw HTTP response body — complete
    page HTML, inline scripts, everything — in its JSONL output by
    default. Streaming that through the normal run_stream/log_line path
    meant every single crawled page became its own multi-KB-to-MB scan_log
    entry, even though this app's own parsing (parse_katana_jsonl) only
    ever extracts the endpoint URL from each line and discards the rest.
    That was very likely the dominant contributor to scans "nuking the
    browser" on large sites — not just line *count*, but individual line
    *size*, which a DOM/line cap alone doesn't help with.

    stdout is discarded entirely via DEVNULL (not piped-and-ignored,
    genuinely never buffered) so the subprocess can't block waiting on a
    full pipe nobody's draining. stderr is still captured and logged if
    the process exits non-zero, so a genuine tool failure is still
    visible — this only suppresses the high-volume "everything found,
    verbatim" stream, not error diagnostics. Returns True on a clean
    (0) exit, False otherwise (not-installed and cancellation are both
    already logged here before returning).
    """
    binary = cmd[0]
    if not shutil.which(binary):
        await log_line(scan_id, f"[skip] {binary} not found on PATH — skipping {label}", "warn")
        return False

    await _log_rationale(scan_id, label)
    await log_line(scan_id, f"$ {' '.join(cmd)}", "cmd")
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
            cwd=str(cwd) if cwd else None,
            limit=STREAM_READ_LIMIT,
        )
        _, stderr_data = await proc.communicate()
        if proc.returncode != 0:
            stderr_text = (stderr_data or b"").decode(errors="replace").strip()
            tail = stderr_text[-2000:] if stderr_text else "(no error output)"
            await log_line(scan_id, f"[error] {label} exited {proc.returncode}: {tail}", "error")
            return False
        await log_line(scan_id, f"[done] {label} exited 0", "meta")
        return True
    except asyncio.CancelledError:
        if proc is not None:
            await _kill_proc(proc)
        raise
    except Exception as e:
        await log_line(scan_id, f"[error] {label} failed: {e}", "error")
        return False


async def run_stream_shell(scan_id: int, cmd_str: str, label: str) -> list[str]:
    """Shell mode — cmd_str is a full shell command line, so &&, ;, |,
    redirection etc. all work. Used only for custom tools with shell=True,
    where the person explicitly opted in and {domain} was already
    shell-quoted by build_custom_shell_cmd before this is called."""
    await _log_rationale(scan_id, label)
    await log_line(scan_id, f"$ {cmd_str}", "cmd")
    proc = None
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
            limit=STREAM_READ_LIMIT,
        )
        return await _consume_proc_stream(scan_id, proc, label)
    except asyncio.CancelledError:
        if proc is not None:
            await _kill_proc(proc)
        raise
    except Exception as e:
        await log_line(scan_id, f"[error] {label} failed: {e}", "error")
        return []


# ---------------------------------------------------------------------------
# HTTP helpers for API-based sources — stdlib only, no new deps.
#
# The User-Agent below matters more than it looks like it should. Confirmed
# directly against Wikimedia's own governance pages: "if you don't supply
# a User-Agent header, or you supply an empty or generic one, your request
# will fail with an HTTP 403 error" — and there's active, recent (2026)
# enforcement specifically tightening this ("progressively rate limit,
# then block requests from generic user-agents"). The previous bare
# "surface-recon/1.0" is exactly the pattern that policy targets: no
# contact information, doesn't follow Wikimedia's documented preferred
# format (`<client name>/<version> (<contact information>)`). Given every
# Wikidata/Wikipedia call in company_lookup goes through this same
# function, a request silently failing here — caught by this app's own
# `except Exception: continue` handling — would look exactly like "no
# matching company data," every time, for every company, regardless of
# whether Wikidata actually had a match. Applied globally (not just for
# Wikimedia calls specifically) since a genuinely descriptive User-Agent
# is just good practice for any external API, not a Wikimedia-only fix.
# ---------------------------------------------------------------------------
USER_AGENT = "Mimir-Recon/1.0 (local external-attack-surface recon tool; run by its own operator for authorized security testing)"


def _http_get_json(url: str, timeout: int = 20):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


async def http_get_json(url: str, timeout: int = 20):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _http_get_json(url, timeout))


def _http_get_json_headers(url: str, headers: dict, timeout: int = 20):
    req_headers = {"User-Agent": USER_AGENT}
    req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


async def http_get_json_headers(url: str, headers: dict, timeout: int = 20):
    """Like http_get_json, but for sources that need a custom auth header
    (e.g. LeakIX's api-key) rather than a key embedded in the URL."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _http_get_json_headers(url, headers, timeout))


def _http_get_text(url: str, timeout: int = 15, max_bytes: int = 300_000) -> str:
    """Raw text, not JSON — for fetching a page/file's actual content
    (social_scan's homepage scraping, JS secret scanning) rather than
    calling a structured API. Capped at max_bytes so a single oversized
    response (an accidentally-huge JS bundle, a misconfigured endpoint
    streaming forever) can't block a scan step indefinitely."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(max_bytes)
        charset = resp.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")


async def http_get_text(url: str, timeout: int = 15) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _http_get_text(url, timeout))


def _http_get_status(url: str, timeout: int = 10) -> tuple[int, str]:
    """Returns (status_code, body_text) — unlike http_get_text/
    http_get_json, this treats a 4xx/5xx as a normal, meaningful result
    rather than an exception. Needed for checks like cloud bucket
    enumeration where the status code itself (404 vs 403 vs 200) is the
    actual signal — "doesn't exist" vs "exists but private" vs "exists
    and publicly readable" — not just whether the request succeeded.
    Body is capped small (this only ever needs to confirm a bucket
    listing exists, not read the whole thing)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(20_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(20_000).decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            body = ""
        return e.code, body
    except Exception:
        return 0, ""


async def http_get_status(url: str, timeout: int = 10) -> tuple[int, str]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _http_get_status(url, timeout))

