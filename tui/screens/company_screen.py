"""Company module — picks a completed scan, runs (or re-runs) the company
OSINT pass (social accounts, Wikidata/Wikipedia company record, CrossLinked
employees, TLD-variant checks, news/press, breach exposure), watches it run
via the same log-polling pattern as the Scan screen, and renders the
resulting host_intel rows as a profile. host_intel is a generic
(host, source, field, value) table — this screen groups it by `source`
into the same categories the web app's Company page shows, rather than
re-deriving a parallel data model.
"""
from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Collapsible, DataTable, Input, RichLog, Static

import bridge

LEVEL_STYLE = {
    "cmd": "bold cyan", "why": "italic #9fb3c8", "meta": "#a9b7c6",
    "warn": "#ffd166", "error": "bold #ff5566", "out": "#6b7a8a",
}
POLL_INTERVAL = 0.8


class CompanyScreen(Vertical):
    _scan_id: int | None = None
    since_log_id = 0
    _poll_timer = None

    def compose(self):
        with Horizontal(id="company-toolbar"):
            yield Input(placeholder="scan ID", id="company-scan-id", classes="id-input")
            yield Button("Load", id="company-load")
            yield Button("Run company scan", id="company-run", variant="primary", disabled=True)
            yield Input(placeholder="override company name (optional)", id="company-name-input")
            yield Button("Lookup name", id="company-lookup", disabled=True)
        yield Static(id="company-status", classes="hint")
        with VerticalScroll():
            with Collapsible(title="Live output", id="company-col-log", collapsed=True):
                yield RichLog(id="company-log-view", markup=False, wrap=True, max_lines=1000)
            with Collapsible(title="Company info", id="company-col-info", collapsed=False):
                yield Static(id="company-info-body")
            with Collapsible(title="Social media accounts", id="company-col-social", collapsed=False):
                yield Static(id="company-social-body")
            with Collapsible(title="Possible staff / phone numbers", id="company-col-staff", collapsed=True):
                yield Static(id="company-staff-body")
            with Collapsible(title="Employees (CrossLinked)", id="company-col-employees", collapsed=True):
                yield DataTable(id="company-employees-table")
            with Collapsible(title="TLD variants", id="company-col-tld", collapsed=True):
                yield Static(id="company-tld-body")
            with Collapsible(title="News / press", id="company-col-news", collapsed=True):
                yield Static(id="company-news-body")
            with Collapsible(title="Breach / exposure findings", id="company-col-leaks", collapsed=True):
                yield DataTable(id="company-leaks-table")

    def on_mount(self):
        self.query_one("#company-employees-table", DataTable).add_columns("Name", "Title/Role", "URL")
        self.query_one("#company-leaks-table", DataTable).add_columns("Host", "Type", "Detail")
        self._poll_timer = self.set_interval(POLL_INTERVAL, self._poll, pause=True)

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "company-load":
            self.run_worker(self._load_from_input())
        elif bid == "company-run":
            self.run_worker(self._run_scan())
        elif bid == "company-lookup":
            self.run_worker(self._lookup())

    async def _load_from_input(self):
        raw = self.query_one("#company-scan-id", Input).value.strip()
        status = self.query_one("#company-status", Static)
        if not raw.isdigit():
            status.update(Text("enter a numeric scan ID (see Scan History for IDs)", style="#ff5566"))
            return
        await self.load_scan(int(raw))

    async def load_scan(self, scan_id: int):
        """Public entry point — also usable from other screens later
        (e.g. a 'view company profile' action on the History screen)."""
        status = self.query_one("#company-status", Static)
        s = await bridge.get_scan_status(scan_id)
        if not s:
            status.update(Text(f"scan #{scan_id} not found", style="#ff5566"))
            return
        self._scan_id = scan_id
        self.query_one("#company-scan-id", Input).value = str(scan_id)
        self.query_one("#company-lookup", Button).disabled = False
        self.since_log_id = 0
        self.query_one("#company-log-view", RichLog).clear()
        running = bool(s.get("status") == "running")
        company_running = bool(s.get("company_scan_running"))
        self.query_one("#company-run", Button).disabled = running or company_running
        status.update(
            f"{s['domain']} — scan {s['status']}"
            + (", company scan running…" if company_running else
               (f", company data last gathered {s['company_scanned_at']}" if s.get("company_scanned_at") else ", no company data yet"))
        )
        if company_running:
            self._poll_timer.resume()
        await self._render_profile(scan_id)

    async def _run_scan(self):
        if self._scan_id is None:
            return
        status = self.query_one("#company-status", Static)
        try:
            await bridge.run_company_scan(self._scan_id)
        except ValueError as e:
            status.update(Text(str(e), style="#ff5566"))
            return
        status.update(Text("company scan started…", style="#39ff6a"))
        self.query_one("#company-run", Button).disabled = True
        self.query_one("#company-col-log", Collapsible).collapsed = False
        self.since_log_id = 0
        self.query_one("#company-log-view", RichLog).clear()
        self._poll_timer.resume()

    async def _lookup(self):
        if self._scan_id is None:
            return
        name = self.query_one("#company-name-input", Input).value.strip()
        status = self.query_one("#company-status", Static)
        if not name:
            status.update(Text("enter a company name to look up first", style="#ff5566"))
            return
        try:
            await bridge.manual_company_lookup(self._scan_id, name)
        except ValueError as e:
            status.update(Text(str(e), style="#ff5566"))
            return
        status.update(Text(f'looked up "{name}" — see Company info above if it validated against this domain', style="#39ff6a"))
        await self._render_profile(self._scan_id)

    def _poll(self):
        if self._scan_id is not None:
            self.run_worker(self._poll_once(), exclusive=True, group="company-poll")

    async def _poll_once(self):
        scan_id = self._scan_id
        if scan_id is None:
            return
        rows, last_id = await bridge.tail_new_logs(scan_id, self.since_log_id)
        if rows:
            self.since_log_id = last_id
            log = self.query_one("#company-log-view", RichLog)
            for r in rows:
                log.write(Text(r["line"], style=LEVEL_STYLE.get(r["level"], "")))
        s = await bridge.get_scan_status(scan_id)
        if not s:
            return
        if not s.get("company_scan_running"):
            self._poll_timer.pause()
            self.query_one("#company-run", Button).disabled = s["status"] == "running"
            status = self.query_one("#company-status", Static)
            status.update(f"{s['domain']} — company data last gathered {s.get('company_scanned_at') or '—'}")
            await self._render_profile(scan_id)

    async def _render_profile(self, scan_id: int):
        data = await bridge.get_scan_full(scan_id)
        if not data:
            return
        intel = data["host_intel"]

        def rows_for(source, prefix=None):
            out = [i for i in intel if i["source"] == source]
            if prefix is not None:
                out = [i for i in out if i["field"].startswith(prefix)]
            return out

        # -- company info -------------------------------------------------
        company_rows = [i for i in intel if i["source"] == "company" and not i["field"].startswith("tld_variant:")]
        if company_rows:
            lines = [f"[bold]{r['field']}[/]: {r['value']}" for r in company_rows]
            self.query_one("#company-info-body", Static).update("\n".join(lines))
        else:
            self.query_one("#company-info-body", Static).update(Text("No confirmed company record yet — run the company scan, or supply a company name above to look it up manually.", style="#6b7a8a"))

        # -- social accounts ------------------------------------------------
        social_rows = [i for i in intel if i["source"] == "social" and i["field"].startswith("page:")]
        if social_rows:
            lines = [f"[bold]{r['field'].split(':',1)[1]}[/]: {r['value']}" for r in social_rows]
            self.query_one("#company-social-body", Static).update("\n".join(lines))
        else:
            self.query_one("#company-social-body", Static).update(Text("No social media accounts found.", style="#6b7a8a"))

        # -- staff / phones ---------------------------------------------
        staff = [i for i in intel if i["source"] == "social" and (i["field"].startswith("possible_staff_name:") or i["field"].startswith("phone:"))]
        if staff:
            lines = [f"[bold]{r['field']}[/]: {r['value']}" for r in staff]
            self.query_one("#company-staff-body", Static).update("\n".join(lines))
        else:
            self.query_one("#company-staff-body", Static).update(Text("None found.", style="#6b7a8a"))

        # -- employees (crosslinked) -------------------------------------
        emp_table = self.query_one("#company-employees-table", DataTable)
        emp_table.clear()
        names = sorted({i["field"].split(":", 1)[1] for i in intel if i["source"] == "crosslinked" and i["field"].startswith("employee:")})
        for name in names:
            title = next((i["value"] for i in intel if i["source"] == "crosslinked" and i["field"] == f"employee:{name}"), "")
            url = next((i["value"] for i in intel if i["source"] == "crosslinked" and i["field"] == f"employee_url:{name}"), "")
            emp_table.add_row(name, title, url)

        # -- TLD variants (flat list of other-TLD domains that resolve;
        # just the live domain string, e.g. example.co.za — no separate
        # status field exists in host_intel for these, see company.js) --
        tld_variants = [r["value"] for r in rows_for("company", "tld_variant:")]
        if tld_variants:
            self.query_one("#company-tld-body", Static).update("\n".join(f"- {v}" for v in tld_variants))
        else:
            self.query_one("#company-tld-body", Static).update(Text("None found.", style="#6b7a8a"))

        # -- news / press (value is JSON-encoded {title,url,source,date}) --
        import json
        news_rows = [i for i in intel if i["source"] == "news" and i["field"].startswith("article:")]
        if news_rows:
            lines = []
            for r in news_rows:
                try:
                    a = json.loads(r["value"])
                    lines.append(f"- [bold]{a.get('title', '?')}[/] — {a.get('source', '')} ({a.get('date', '')})\n  {a.get('url', '')}")
                except (ValueError, TypeError):
                    lines.append(f"- {r['value']}")
            self.query_one("#company-news-body", Static).update("\n".join(lines))
        else:
            self.query_one("#company-news-body", Static).update(Text("No press mentions found.", style="#6b7a8a"))

        # -- breach / exposure (leaks table) -------------------------------
        leaks_table = self.query_one("#company-leaks-table", DataTable)
        leaks_table.clear()
        for l in data["leaks"]:
            leaks_table.add_row(l["host"], l.get("leak_type") or "unknown", (l.get("detail") or "")[:80])

    async def refresh_data(self):
        if self._scan_id is not None:
            await self._render_profile(self._scan_id)
