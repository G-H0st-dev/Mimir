"""The Scan tab — domain input, run/skip/stop, live output, and the
same result panels the web Scan page shows (Why each tool ran, Hosts &
assets, Emails, OSINT intel), each collapsible via Textual's built-in
Collapsible widget — the terminal-native equivalent of the collapsible
panels just added to the browser version.

Live updates are DB-polling based (see bridge.tail_new_logs) rather than
WebSocket-pushed, which has a real upside here: this screen can attach
to and watch a scan that was started from the browser just as well as
one started from this TUI, since both write to the same scan_logs table.
"""
import asyncio

from rich.text import Text
from textual import work
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button, Collapsible, DataTable, Input, ProgressBar, RichLog, Static,
)

import bridge

LEVEL_STYLE = {
    "cmd": "bold cyan",
    "why": "italic #9fb3c8",
    "meta": "#a9b7c6",
    "warn": "#ffd166",
    "error": "bold #ff5566",
    "out": "#6b7a8a",
}

POLL_INTERVAL = 0.6


class ScanScreen(Vertical):
    current_scan_id: reactive[int | None] = reactive(None)
    since_log_id = 0
    _poll_timer = None

    def compose(self):
        with Horizontal():
            with Vertical(classes="sidebar", id="scan-sidebar"):
                yield Static("TARGET DOMAIN", classes="panel-title")
                yield Input(placeholder="example.com", id="domain-input")
                yield Static("", id="mode-label", classes="hint")
                with Horizontal(id="mode-row"):
                    yield Button("Fast", id="mode-fast", variant="primary")
                    yield Button("Full stack", id="mode-full")
                yield Static("COMPANY NAME (optional)", classes="panel-title")
                yield Input(placeholder="e.g. Acme Corporation", id="company-input")
                yield Button("Run scan", id="run-btn", variant="primary")
                with Horizontal(id="control-row"):
                    yield Button("Skip step", id="skip-btn", disabled=True)
                    yield Button("Stop scan", id="stop-btn", variant="error", disabled=True)
                yield Static(id="run-status", classes="hint")
                yield Static("TOOLS THIS MODE", classes="panel-title")
                yield Static(id="tool-pills")

            with VerticalScroll(classes="main", id="scan-main"):
                yield Static(id="scan-label", classes="panel-title")
                yield ProgressBar(id="progress", total=100, show_eta=False)
                with Collapsible(title="Live output", id="col-log", collapsed=False):
                    yield RichLog(id="log-view", markup=False, wrap=True, max_lines=2000)
                with Collapsible(title="Why each tool ran", id="col-why", collapsed=True):
                    yield RichLog(id="why-view", markup=False, wrap=True, max_lines=500)
                with Collapsible(title="Hosts & assets", id="col-hosts", collapsed=False):
                    yield DataTable(id="hosts-table")
                with Collapsible(title="Emails harvested", id="col-emails", collapsed=True):
                    yield DataTable(id="emails-table")
                with Collapsible(title="OSINT & enrichment intel", id="col-intel", collapsed=True):
                    yield DataTable(id="intel-table")

    def on_mount(self):
        self._mode = "fast"
        self.query_one("#hosts-table", DataTable).add_columns(
            "Subdomain", "IP", "Sources", "HTTP", "Title", "Tech", "Ports"
        )
        self.query_one("#emails-table", DataTable).add_columns("Email", "Source")
        self.query_one("#intel-table", DataTable).add_columns("Host", "Source", "Field", "Value")
        self.run_worker(self._refresh_tool_pills())
        self._poll_timer = self.set_interval(POLL_INTERVAL, self._poll, pause=True)

    # -- mode selection ----------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "mode-fast":
            self._set_mode("fast")
        elif bid == "mode-full":
            self._set_mode("full")
        elif bid == "run-btn":
            self.run_worker(self._start_scan())
        elif bid == "skip-btn":
            self.run_worker(self._skip_step())
        elif bid == "stop-btn":
            self.run_worker(self._stop_scan())

    def _set_mode(self, mode: str):
        self._mode = mode
        self.query_one("#mode-fast", Button).variant = "primary" if mode == "fast" else "default"
        self.query_one("#mode-full", Button).variant = "primary" if mode == "full" else "default"
        self.run_worker(self._refresh_tool_pills())

    async def _refresh_tool_pills(self):
        cfg = await bridge.get_config()
        tools = [t for t in cfg["builtin_tools"] if self._mode in t.get("modes", [])]
        shown = tools[:14]
        pieces = []
        for t in shown:
            ok = t["available"] and t["enabled"]
            pieces.append((f"{t['name']}", "tool-pill-ok" if ok else "tool-pill-missing"))
        text = Text()
        for i, (name, cls) in enumerate(pieces):
            if i:
                text.append("  ")
            text.append(name, style="#39ff6a" if cls == "tool-pill-ok" else "#ff5566")
        extra = len(tools) - len(shown)
        if extra > 0:
            text.append(f"  (+{extra} more)", style="#6b7a8a")
        pills = self.query_one("#tool-pills", Static)
        pills.update(text)

    # -- run / skip / stop ---------------------------------------------------

    async def _start_scan(self):
        domain = self.query_one("#domain-input", Input).value.strip()
        company_name = self.query_one("#company-input", Input).value.strip()
        status = self.query_one("#run-status", Static)
        if not domain:
            status.update(Text("enter a domain first", style="#ff5566"))
            return
        try:
            result = await bridge.start_scan(domain, self._mode, company_name or None)
        except ValueError as e:
            status.update(Text(str(e), style="#ff5566"))
            return
        status.update(Text(f"started scan #{result['scan_id']}", style="#39ff6a"))
        self.watch_scan(result["scan_id"])

    def watch_scan(self, scan_id: int):
        """Start (or switch to) watching a scan — used both by this
        screen's own Run button and, from the History screen, to watch
        a scan that's still running when selected there.

        Deliberately not named _attach — Widget already defines a
        Textual-internal _attach(self, parent) lifecycle hook, and a
        same-named method here silently shadows it instead of
        overriding something meant to be overridden, which breaks
        mounting in a confusing way (confirmed directly: Textual called
        this with a DOM node as `scan_id` during compose, before
        on_mount had even run). Same reasoning applies broadly — avoid
        reusing Widget's own dunder-adjacent method names for anything
        screen-specific."""
        self.current_scan_id = scan_id
        self.since_log_id = 0
        self.query_one("#log-view", RichLog).clear()
        self.query_one("#why-view", RichLog).clear()
        self.query_one("#run-btn", Button).disabled = True
        self.query_one("#skip-btn", Button).disabled = False
        self.query_one("#stop-btn", Button).disabled = False
        if self._poll_timer:
            self._poll_timer.resume()

    async def _skip_step(self):
        if self.current_scan_id is None:
            return
        await bridge.skip_current_step(self.current_scan_id)

    async def _stop_scan(self):
        if self.current_scan_id is None:
            return
        await bridge.stop_scan(self.current_scan_id)

    # -- live polling --------------------------------------------------------

    def _poll(self):
        if self.current_scan_id is not None:
            self.run_worker(self._poll_once(), exclusive=True, group="scan-poll")

    async def _poll_once(self):
        scan_id = self.current_scan_id
        if scan_id is None:
            return
        rows, last_id = await bridge.tail_new_logs(scan_id, self.since_log_id)
        if rows:
            self.since_log_id = last_id
            log = self.query_one("#log-view", RichLog)
            why = self.query_one("#why-view", RichLog)
            for r in rows:
                style = LEVEL_STYLE.get(r["level"], "")
                log.write(Text(r["line"], style=style))
                if r["level"] == "why":
                    label, _, rest = r["line"].removeprefix("[why] ").partition(": ")
                    t = Text()
                    t.append(label + ": ", style="bold cyan")
                    t.append(rest, style="#9fb3c8")
                    why.write(t)

        status = await bridge.get_scan_status(scan_id)
        if not status:
            return
        label = self.query_one("#scan-label", Static)
        label.update(f"{status['domain']} — {status['mode']} — {status['status']} "
                     f"({status.get('progress_stage') or '—'})")
        bar = self.query_one("#progress", ProgressBar)
        bar.update(progress=status.get("progress_percent") or 0)

        if status["status"] != "running":
            self._poll_timer.pause()
            self.query_one("#run-btn", Button).disabled = False
            self.query_one("#skip-btn", Button).disabled = True
            self.query_one("#stop-btn", Button).disabled = True
            await self._load_results(scan_id)

    async def _load_results(self, scan_id: int):
        data = await bridge.get_scan_full(scan_id)
        if not data:
            return
        hosts = self.query_one("#hosts-table", DataTable)
        hosts.clear()
        assets_by_sub = {a["subdomain"]: a for a in data["http_assets"]}
        ports_by_host = {}
        for p in data["ports"]:
            ports_by_host.setdefault(p["host"], []).append(str(p["port"]))
        for s in data["subdomains"]:
            asset = assets_by_sub.get(s["subdomain"], {})
            ports = ", ".join(ports_by_host.get(s["subdomain"], [])[:8])
            hosts.add_row(
                s["subdomain"], s.get("ip") or "", s.get("sources") or "",
                str(asset.get("status_code") or ""), (asset.get("title") or "")[:40],
                (asset.get("tech") or "")[:30], ports,
            )
        emails = self.query_one("#emails-table", DataTable)
        emails.clear()
        for e in data["emails"]:
            emails.add_row(e["email"], e.get("source") or "")
        intel = self.query_one("#intel-table", DataTable)
        intel.clear()
        for i in data["host_intel"][:500]:
            intel.add_row(i["host"], i["source"], i["field"], (i.get("value") or "")[:80])

    async def refresh_data(self):
        await self._refresh_tool_pills()
