"""Scan History — browse past scans, re-watch one that's still running,
view the same Markdown recon report the web app's "Export report" button
produces, and export JSON/CSV/report to disk. Exports are the TUI's
necessary substitute for the browser's file-download prompt: there's no
browser here to hand a Content-Disposition response to, so files are
written straight into an exports/ folder next to the database and the
screen just reports the path.
"""
from pathlib import Path

from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, MarkdownViewer, Static

import bridge

EXPORT_DIR = bridge.ROOT / "exports"


class ReportViewerScreen(ModalScreen):
    """A full-screen modal showing one scan's Markdown report — pushed
    on top of the main app rather than sharing HistoryScreen's layout,
    since a report can run long and deserves the whole terminal."""

    BINDINGS = [("escape", "dismiss_self", "Close"), ("q", "dismiss_self", "Close")]

    def __init__(self, markdown_text: str, title: str):
        super().__init__()
        self._markdown = markdown_text
        self._title = title

    def compose(self):
        with Vertical(id="report-modal"):
            yield Static(self._title, classes="panel-title")
            yield MarkdownViewer(self._markdown, show_table_of_contents=True, id="report-view")
            yield Button("Close (Esc)", id="close-report")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "close-report":
            self.action_dismiss_self()

    def action_dismiss_self(self):
        self.dismiss()


class HistoryScreen(Vertical):
    _selected_scan_id: int | None = None

    def compose(self):
        with Horizontal(id="history-toolbar"):
            yield Button("Refresh", id="hist-refresh")
            yield Button("Watch live", id="hist-watch", disabled=True)
            yield Button("View report", id="hist-report", disabled=True)
            yield Button("Export JSON", id="hist-export-json", disabled=True)
            yield Button("Export CSV", id="hist-export-csv", disabled=True)
            yield Button("Delete", id="hist-delete", variant="error", disabled=True)
        yield Static(id="hist-status", classes="hint")
        with VerticalScroll():
            yield DataTable(id="scans-table")

    def on_mount(self):
        table = self.query_one("#scans-table", DataTable)
        table.add_columns("ID", "Domain", "Mode", "Status", "Started", "Completed", "Company")
        table.cursor_type = "row"
        self.run_worker(self.refresh_data())

    async def refresh_data(self):
        scans = await bridge.list_scans()
        self._rows_by_key = {}
        table = self.query_one("#scans-table", DataTable)
        table.clear()
        for s in scans:
            key = table.add_row(
                str(s["id"]), s["domain"], s["mode"], s["status"],
                (s["started_at"] or "")[:19], (s["completed_at"] or "")[:19] or "—",
                s.get("company_name") or "—",
                key=str(s["id"]),
            )
        self._set_selected(None)

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        scan_id = int(event.row_key.value)
        self.run_worker(self._select(scan_id))

    async def _select(self, scan_id: int):
        status = await bridge.get_scan_status(scan_id)
        self._set_selected(scan_id, status)

    def _set_selected(self, scan_id: int | None, status: dict | None = None):
        self._selected_scan_id = scan_id
        has_sel = scan_id is not None
        self.query_one("#hist-report", Button).disabled = not has_sel
        self.query_one("#hist-export-json", Button).disabled = not has_sel
        self.query_one("#hist-export-csv", Button).disabled = not has_sel
        self.query_one("#hist-delete", Button).disabled = not has_sel
        running = bool(status and status["status"] == "running")
        self.query_one("#hist-watch", Button).disabled = not running
        hint = self.query_one("#hist-status", Static)
        if status:
            hint.update(f"selected scan #{scan_id} — {status['domain']} ({status['status']})")
        else:
            hint.update("")

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        if bid == "hist-refresh":
            self.run_worker(self.refresh_data())
        elif bid == "hist-watch" and self._selected_scan_id is not None:
            self._watch_live(self._selected_scan_id)
        elif bid == "hist-report" and self._selected_scan_id is not None:
            self.run_worker(self._view_report(self._selected_scan_id))
        elif bid == "hist-export-json" and self._selected_scan_id is not None:
            self.run_worker(self._export(self._selected_scan_id, "json"))
        elif bid == "hist-export-csv" and self._selected_scan_id is not None:
            self.run_worker(self._export(self._selected_scan_id, "csv"))
        elif bid == "hist-delete" and self._selected_scan_id is not None:
            self.run_worker(self._delete(self._selected_scan_id))

    def _watch_live(self, scan_id: int):
        """Switches to the Scan tab and hands this scan off to
        ScanScreen's own polling — same mechanism ScanScreen uses for a
        scan it started itself, so a scan kicked off from the browser
        shows up here exactly the same way."""
        from textual.widgets import TabbedContent
        tabbed = self.app.query_one(TabbedContent)
        tabbed.active = "tab-scan"
        scan_screen = self.app.query_one("#scan-screen")
        scan_screen.watch_scan(scan_id)

    async def _view_report(self, scan_id: int):
        status = self.query_one("#hist-status", Static)
        report = await bridge.get_report_markdown(scan_id)
        if report is None:
            status.update(Text("scan not found", style="#ff5566"))
            return
        domain_row = await bridge.get_scan_status(scan_id)
        title = f"Report — {domain_row['domain'] if domain_row else scan_id} (#{scan_id})"
        await self.app.push_screen(ReportViewerScreen(report, title))

    async def _export(self, scan_id: int, fmt: str):
        status = self.query_one("#hist-status", Static)
        try:
            result = await bridge.export_scan_file(scan_id, fmt)
        except ValueError as e:
            status.update(Text(str(e), style="#ff5566"))
            return
        if result is None:
            status.update(Text("scan not found", style="#ff5566"))
            return
        filename, raw = result
        EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        path = EXPORT_DIR / filename
        path.write_bytes(raw)
        status.update(Text(f"exported to {path}", style="#39ff6a"))

    async def _delete(self, scan_id: int):
        await bridge.delete_scan(scan_id)
        status = self.query_one("#hist-status", Static)
        status.update(Text(f"deleted scan #{scan_id}", style="#a9b7c6"))
        await self.refresh_data()
