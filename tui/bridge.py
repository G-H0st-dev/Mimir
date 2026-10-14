"""The only place the TUI talks to the engine. Nothing in here
reimplements scanning, enrichment, or reporting logic — it imports
app.py/core.py/company.py/vulnerability.py directly and calls the exact
same functions the FastAPI routes call, in-process.

Why this works: every "@app.post(...)"-decorated function in app.py is,
underneath the decorator, still a plain async function — FastAPI's
decorator just registers it with a router, it doesn't change how the
function itself can be called. None of them take a Request object; the
ones that take a Pydantic model just need that model constructed, which
is a normal Python object, not an HTTP concept. Confirmed directly
before building any of this: importing app.py does not start a server
(uvicorn.run() only happens inside `if __name__ == "__main__":`), and
init_db() only auto-runs via FastAPI's lifespan hook — which never fires
here — so this module calls it explicitly instead.

Two real seams, not reimplementations:
  - Live log viewing: the web UI gets new lines pushed over a WebSocket;
    the TUI has no socket to push to, so it polls the scan_logs table
    instead (tail_new_logs below). This also means the TUI can watch a
    scan that was started from the browser, for free — same database,
    either direction.
  - UploadFile-based endpoints (wordlist upload, backup restore) expect
    Starlette's UploadFile, which is just a plain class wrapping a file
    handle — constructed directly from a local path here, no multipart
    HTTP request involved.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import core  # noqa: E402
import app as web  # noqa: E402  (the FastAPI module — never served, just called)

_initialized = False


def ensure_db():
    """Idempotent — init_db() is all CREATE TABLE IF NOT EXISTS, so
    re-running it is harmless, but no reason to pay for it more than
    once per process."""
    global _initialized
    if not _initialized:
        core.init_db()
        _initialized = True


# Called at import time, not left for the App's own on_mount — screen
# widgets' on_mount hooks can fire their own first DB-touching worker
# before Textual gets around to calling the App's on_mount (confirmed
# directly: ScanScreen's tool-pills refresh hit "no such table" because
# it ran before MimirApp.on_mount's bridge.ensure_db() call did). Every
# screen imports this module before it can do anything DB-related
# anyway, so doing it here removes the ordering dependency entirely.
ensure_db()


def get_db():
    return core.get_db()


async def tail_new_logs(scan_id: int, since_id: int = 0):
    """Returns (new_rows, last_id) — every scan_logs row for this scan
    with id > since_id, in order. The TUI's live-log widgets poll this
    on a timer instead of holding a WebSocket open; `since_id` is the
    highest id already rendered, so repeated calls only ever return what's
    new. Works identically whether the scan was started from this TUI or
    from the browser — scan_logs is just a table, not an in-memory queue
    tied to one process."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, line, level, ts FROM scan_logs WHERE scan_id = ? AND id > ? ORDER BY id",
        (scan_id, since_id),
    ).fetchall()
    conn.close()
    rows = [dict(r) for r in rows]
    last_id = rows[-1]["id"] if rows else since_id
    return rows, last_id


async def get_scan_status(scan_id: int) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Scan lifecycle — mirrors start_scan/skip/stop exactly, since those
# routes are already nothing but "validate, write a row, fire off the
# same background task" (see app.py's start_scan). Only the HTTP framing
# (JSONResponse/status codes) is swapped for plain return values/raised
# ValueError, since there's no HTTP response to shape here.
# ---------------------------------------------------------------------------

async def start_scan(domain: str, mode: str = "fast", company_name: str | None = None) -> dict:
    import asyncio

    domain = domain.strip().lower().lstrip("*.").rstrip("/")
    domain = domain.replace("https://", "").replace("http://", "")
    if "*" in domain:
        raise ValueError(
            "wildcards like 'example.*' aren't valid domain syntax — check the TLD-variants "
            "screen instead, it checks common TLD variants (.com/.co.za/.org/etc.) for you"
        )
    if not domain or web.DOMAIN_BAD_CHARS.search(domain):
        raise ValueError("invalid domain")
    mode = "full" if mode == "full" else "fast"

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO scans (domain, mode, status, started_at, company_name) VALUES (?, ?, 'running', ?, ?)",
        (domain, mode, core.now_iso(), (company_name or "").strip() or None),
    )
    scan_id = cur.lastrowid
    conn.commit()
    conn.close()

    asyncio.create_task(web.run_pipeline_safe(scan_id, domain, mode))
    return {"scan_id": scan_id, "domain": domain, "mode": mode}


async def skip_current_step(scan_id: int) -> bool:
    task = web.RUNNING_STAGE_TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


async def stop_scan(scan_id: int) -> bool:
    status = await get_scan_status(scan_id)
    if not status or status["status"] != "running":
        return False
    web.STOP_REQUESTED[scan_id] = True
    task = web.RUNNING_STAGE_TASKS.get(scan_id)
    if task and not task.done():
        task.cancel()
    return True


async def list_scans() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return [dict(r) for r in rows]


async def get_scan_full(scan_id: int) -> dict | None:
    """Same shape as GET /api/scans/{id} — calling the route function
    directly rather than re-querying here keeps this from drifting out
    of sync if that function's set of joined tables ever changes."""
    result = await web.get_scan(scan_id)
    if isinstance(result, dict):
        return result
    return None  # a JSONResponse(404) comes back here for a missing scan


async def delete_scan(scan_id: int):
    await web.delete_scan(scan_id)


async def get_report_markdown(scan_id: int) -> str | None:
    """Same Markdown text as the web app's 'Export report' button —
    build_report_markdown() was factored out of app.py's export_report()
    route specifically so this could call it directly rather than
    reconstructing the report logic here or unpacking a StreamingResponse's
    BytesIO body. Returns None if the scan doesn't exist."""
    return web.build_report_markdown(scan_id)


async def export_scan_file(scan_id: int, fmt: str) -> tuple[str, bytes] | None:
    """Returns (filename, raw_bytes) for 'json', 'csv', or 'report', by
    calling the same web.export_* route functions and draining their
    StreamingResponse body — used for the TUI's save-to-disk export
    actions, where (unlike the report viewer) the exact exported file
    the browser would download is what's wanted, not just the text."""
    conn = get_db()
    scan = conn.execute("SELECT domain FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not scan:
        return None
    domain = scan["domain"]
    if fmt == "json":
        resp = await web.export_json(scan_id)
        ext = "json"
    elif fmt == "csv":
        resp = await web.export_csv(scan_id)
        ext = "csv"
    elif fmt == "report":
        resp = await web.export_report(scan_id)
        ext = "report.md"
    else:
        raise ValueError(f"unknown export format: {fmt}")
    if not hasattr(resp, "body_iterator"):
        raise ValueError("export failed — scan not found")
    chunks = [chunk async for chunk in resp.body_iterator]
    raw = b"".join(c if isinstance(c, bytes) else c.encode() for c in chunks)
    filename = f"surface_{domain}_{scan_id}.{ext}" if ext != "report.md" else f"surface_{domain}_{scan_id}_report.md"
    return filename, raw


# ---------------------------------------------------------------------------
# Company / Vulnerability modules
# ---------------------------------------------------------------------------

async def run_company_scan(scan_id: int) -> dict:
    status = await get_scan_status(scan_id)
    if not status:
        raise ValueError("scan not found")
    if status["status"] == "running":
        raise ValueError("the scan itself is still running — wait for it to finish first")
    if status.get("company_scan_running"):
        raise ValueError("a company scan is already running for this scan")
    import asyncio
    asyncio.create_task(web._run_company_scan_task_safe(scan_id))
    return {"ok": True, "started": True}


async def manual_company_lookup(scan_id: int, company_name: str) -> dict:
    result = await web.manual_company_lookup(scan_id, web.CompanyLookupIn(company_name=company_name))
    if isinstance(result, dict):
        return result
    raise ValueError(getattr(result, "body", b"lookup failed").decode("utf-8", "replace"))


async def get_ai_status() -> dict:
    return await web.get_ai_status()


async def run_ai_analysis(scan_id: int) -> dict:
    result = await web.run_ai_analysis(scan_id)
    if isinstance(result, dict):
        return result
    raise ValueError(getattr(result, "body", b"AI analysis failed").decode("utf-8", "replace"))


async def run_vulnerability_scan(scan_id: int) -> dict:
    status = await get_scan_status(scan_id)
    if not status:
        raise ValueError("scan not found")
    if status["status"] == "running":
        raise ValueError("scan is still running — wait for it to finish first")
    result = await web.run_vulnerability_scan(scan_id)
    if isinstance(result, dict):
        return result
    raise ValueError(getattr(result, "body", b"vulnerability scan failed").decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# Settings / config — thin pass-throughs. Screens call these rather than
# importing `web` directly so every engine touchpoint stays listed in one
# file; the Pydantic models are constructed here from plain kwargs so
# screens never need to know they exist.
# ---------------------------------------------------------------------------

TRIAGE_STATUSES = ["open", "false_positive", "reported", "risk_accepted", "fixed"]


async def triage_vulnerability(finding_id: int, status: str, note: str | None = None):
    result = await web.update_vulnerability_triage(finding_id, web.TriageUpdateIn(triage_status=status, triage_note=note))
    if isinstance(result, dict) and result.get("ok"):
        return result
    raise ValueError(getattr(result, "body", b"triage update failed").decode("utf-8", "replace"))


async def triage_leak(finding_id: int, status: str, note: str | None = None):
    result = await web.update_leak_triage(finding_id, web.TriageUpdateIn(triage_status=status, triage_note=note))
    if isinstance(result, dict) and result.get("ok"):
        return result
    raise ValueError(getattr(result, "body", b"triage update failed").decode("utf-8", "replace"))


async def save_ai_config(base_url: str, api_key: str | None, model: str):
    await web.save_ai_config(web.AiConfigIn(base_url=base_url, api_key=api_key, model=model))


async def get_config() -> dict:
    return await web.get_config()


async def set_api_key(service: str, key: str):
    await web.save_api_key(web.ApiKeyIn(service=service, key=key))


async def toggle_tool(tool_name: str, enabled: bool):
    # toggle_tool/toggle_all_tools take a raw dict, not a Pydantic model —
    # the one inconsistency in app.py's config endpoints, confirmed by
    # reading the actual signature rather than assumed from the pattern
    # every other endpoint here follows.
    await web.toggle_tool({"name": tool_name, "enabled": enabled})


async def toggle_all_tools(enabled: bool):
    await web.toggle_all_tools({"enabled": enabled})


async def add_custom_tool(name: str, command_template: str, output_format: str = "plain", shell: bool = False):
    return await web.add_custom_tool(web.CustomToolIn(
        name=name, command_template=command_template, output_format=output_format, shell=shell,
    ))


async def delete_custom_tool(tool_id: int):
    await web.delete_custom_tool(tool_id)


async def add_api_source(name: str, category: str, url_template: str, json_path: str = "",
                          intel_fields: str = "", api_key: str = ""):
    return await web.add_api_source(web.ApiSourceIn(
        name=name, category=category, url_template=url_template,
        json_path=json_path, intel_fields=intel_fields, api_key=api_key,
    ))


async def delete_api_source(source_id: int):
    await web.delete_api_source(source_id)


async def upload_wordlist(file_path: str):
    from starlette.datastructures import UploadFile
    p = Path(file_path).expanduser()
    if not p.is_file():
        raise ValueError(f"no such file: {p}")
    with open(p, "rb") as f:
        upload = UploadFile(filename=p.name, file=f)
        return await web.upload_wordlist(upload)


async def delete_wordlist(wordlist_id: int):
    await web.delete_wordlist(wordlist_id)


async def download_backup(dest_path: str) -> str:
    """Writes a full-state backup (VACUUM INTO snapshot, same as the
    browser's Settings -> backup download button) to dest_path and
    returns the path written. No HTTP download prompt exists here, so
    the TUI just needs somewhere on disk to put the file."""
    resp = await web.download_backup()
    chunks = [chunk async for chunk in resp.body_iterator]
    raw = b"".join(c if isinstance(c, bytes) else c.encode() for c in chunks)
    p = Path(dest_path).expanduser()
    p.write_bytes(raw)
    return str(p)


async def restore_backup(file_path: str):
    from starlette.datastructures import UploadFile
    p = Path(file_path).expanduser()
    if not p.is_file():
        raise ValueError(f"no such file: {p}")
    with open(p, "rb") as f:
        upload = UploadFile(filename=p.name, file=f)
        return await web.restore_backup(upload)
