"""Mimir TUI — main application shell.

Navigation mirrors the web app's top nav exactly: Scan, Scan History,
Company, Vulnerability, Settings — as tabs rather than pushed screens,
since that's the closer match to how the browser version behaves (one
page, switch what's showing, state in the other tabs doesn't reset).
"""
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, TabbedContent, TabPane

import bridge
from screens.scan_screen import ScanScreen
from screens.history_screen import HistoryScreen
from screens.company_screen import CompanyScreen
from screens.vulnerability_screen import VulnerabilityScreen
from screens.settings_screen import SettingsScreen


class MimirApp(App):
    CSS_PATH = "mimir.tcss"
    TITLE = "MIMIR //"
    SUB_TITLE = "attack surface enumeration — terminal edition"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+r", "refresh_current", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-scan"):
            with TabPane("Scan", id="tab-scan"):
                yield ScanScreen(id="scan-screen")
            with TabPane("Scan History", id="tab-history"):
                yield HistoryScreen(id="history-screen")
            with TabPane("Company", id="tab-company"):
                yield CompanyScreen(id="company-screen")
            with TabPane("Vulnerability", id="tab-vuln"):
                yield VulnerabilityScreen(id="vuln-screen")
            with TabPane("Settings", id="tab-settings"):
                yield SettingsScreen(id="settings-screen")
        yield Footer()

    def on_mount(self) -> None:
        bridge.ensure_db()

    def action_refresh_current(self) -> None:
        """Ctrl+R re-loads whichever tab is currently visible — each
        screen implements refresh() itself (reloading scan pickers,
        re-fetching config, etc.)."""
        tabbed = self.query_one(TabbedContent)
        active_pane = tabbed.get_pane(tabbed.active)
        if active_pane is None:
            return
        for child in active_pane.children:
            if hasattr(child, "refresh_data"):
                self.run_worker(child.refresh_data())


def main():
    MimirApp().run()


if __name__ == "__main__":
    main()
