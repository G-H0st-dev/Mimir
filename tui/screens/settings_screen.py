"""Settings — the terminal equivalent of the web app's Settings tab:
API keys, AI analysis config, built-in tool enable/disable, custom
tools, custom API sources, wordlists, and full-state backup/restore.
Everything here is a thin wrapper around bridge.get_config() plus the
same save/toggle/add/delete bridge functions the other screens already
use for their own config touchpoints.
"""
from rich.text import Text
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Collapsible, DataTable, Input, Select, Static

import bridge


class SettingsScreen(Vertical):
    _config: dict | None = None
    _selected_tool: str | None = None
    _selected_custom_tool_id: int | None = None
    _selected_api_source_id: int | None = None
    _selected_wordlist_id: int | None = None

    def compose(self):
        with VerticalScroll():
            with Collapsible(title="API keys", id="set-col-keys", collapsed=False):
                yield Static(id="set-keys-status")
                with Horizontal(classes="settings-form-row"):
                    yield Select([("shodan", "shodan"), ("leakix", "leakix"), ("wpscan", "wpscan"), ("hunter", "hunter")], id="set-key-service", prompt="service…")
                    yield Input(placeholder="API key", password=True, id="set-key-value")
                    yield Button("Save key", id="set-key-save", variant="primary")

            with Collapsible(title="AI analysis (optional)", id="set-col-ai", collapsed=True):
                yield Static(id="set-ai-status")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="base URL (e.g. http://localhost:11434/v1)", id="set-ai-url")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="API key (optional)", password=True, id="set-ai-key")
                    yield Input(placeholder="model name", id="set-ai-model")
                    yield Button("Save", id="set-ai-save", variant="primary")

            with Collapsible(title="Built-in tools", id="set-col-tools", collapsed=True):
                yield DataTable(id="set-tools-table")
                with Horizontal(classes="settings-form-row"):
                    yield Button("Enable selected", id="set-tool-enable")
                    yield Button("Disable selected", id="set-tool-disable")
                    yield Button("Enable all", id="set-tool-enable-all")
                    yield Button("Disable all", id="set-tool-disable-all", variant="error")

            with Collapsible(title="Custom tools", id="set-col-custom-tools", collapsed=True):
                yield DataTable(id="set-custom-tools-table")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="name", id="set-ct-name")
                    yield Input(placeholder="command template (use {domain})", id="set-ct-cmd")
                    yield Select([("plain", "plain"), ("json", "json")], id="set-ct-format", value="plain")
                    yield Checkbox("shell", id="set-ct-shell")
                    yield Button("Add", id="set-ct-add", variant="primary")
                yield Button("Delete selected", id="set-ct-delete", variant="error")

            with Collapsible(title="Custom API sources", id="set-col-api-sources", collapsed=True):
                yield DataTable(id="set-api-sources-table")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="name", id="set-as-name")
                    yield Input(placeholder="category", id="set-as-category")
                    yield Input(placeholder="URL template (use {domain})", id="set-as-url")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="JSON path (optional)", id="set-as-jsonpath")
                    yield Input(placeholder="intel fields (optional)", id="set-as-fields")
                    yield Input(placeholder="API key (optional)", password=True, id="set-as-key")
                    yield Button("Add", id="set-as-add", variant="primary")
                yield Button("Delete selected", id="set-as-delete", variant="error")

            with Collapsible(title="Wordlists", id="set-col-wordlists", collapsed=True):
                yield DataTable(id="set-wordlists-table")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="local file path to upload", id="set-wl-path")
                    yield Button("Upload", id="set-wl-upload", variant="primary")
                yield Button("Delete selected", id="set-wl-delete", variant="error")

            with Collapsible(title="Backup / restore", id="set-col-backup", collapsed=True):
                yield Static(id="set-backup-status", classes="hint")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="destination path for backup .db", id="set-backup-dest", value="./surface_backup.db")
                    yield Button("Download backup", id="set-backup-download", variant="primary")
                with Horizontal(classes="settings-form-row"):
                    yield Input(placeholder="path to backup .db to restore", id="set-backup-src")
                    yield Button("Restore backup", id="set-backup-restore", variant="error")

    def on_mount(self):
        self.query_one("#set-tools-table", DataTable).add_columns("Name", "Category", "Available", "Enabled")
        self.query_one("#set-tools-table", DataTable).cursor_type = "row"
        self.query_one("#set-custom-tools-table", DataTable).add_columns("Name", "Command template", "Format", "Shell")
        self.query_one("#set-custom-tools-table", DataTable).cursor_type = "row"
        self.query_one("#set-api-sources-table", DataTable).add_columns("Name", "Category", "URL template", "API key")
        self.query_one("#set-api-sources-table", DataTable).cursor_type = "row"
        self.query_one("#set-wordlists-table", DataTable).add_columns("Name", "Lines", "Size (bytes)", "Uploaded")
        self.query_one("#set-wordlists-table", DataTable).cursor_type = "row"
        self.run_worker(self.refresh_data())

    # -- loading / rendering --------------------------------------------

    async def refresh_data(self):
        self._config = await bridge.get_config()
        cfg = self._config

        keys = cfg["api_keys"]
        lines = [f"[bold]{svc}[/]: {'configured (' + info['masked'] + ')' if info['configured'] else 'not set'}" for svc, info in keys.items()]
        self.query_one("#set-keys-status", Static).update("\n".join(lines))

        ai = cfg["ai_config"]
        if ai["configured"]:
            self.query_one("#set-ai-status", Static).update(f"configured — {ai['model']} @ {ai['base_url']} (key {'set' if ai['api_key_set'] else 'not set'})")
            self.query_one("#set-ai-url", Input).value = ai["base_url"] or ""
            self.query_one("#set-ai-model", Input).value = ai["model"] or ""
        else:
            self.query_one("#set-ai-status", Static).update(Text("not configured — entirely optional, everything else works without it", style="#6b7a8a"))

        tools_table = self.query_one("#set-tools-table", DataTable)
        tools_table.clear()
        for t in cfg["builtin_tools"]:
            tools_table.add_row(
                t["name"], t.get("category") or "", "yes" if t["available"] else "no",
                "yes" if t["enabled"] else "no", key=t["name"],
            )

        ct_table = self.query_one("#set-custom-tools-table", DataTable)
        ct_table.clear()
        for c in cfg["custom_tools"]:
            ct_table.add_row(c["name"], c["command_template"], c.get("output_format") or "plain", "yes" if c.get("shell") else "no", key=str(c["id"]))

        as_table = self.query_one("#set-api-sources-table", DataTable)
        as_table.clear()
        for s in cfg["custom_api_sources"]:
            as_table.add_row(s["name"], s.get("category") or "", s["url_template"], s.get("api_key_masked") or "—", key=str(s["id"]))

        wl_table = self.query_one("#set-wordlists-table", DataTable)
        wl_table.clear()
        for w in cfg["wordlists"]:
            wl_table.add_row(w["name"], str(w.get("line_count") or ""), str(w.get("size_bytes") or ""), (w.get("uploaded_at") or "")[:19], key=str(w["id"]))

    def on_data_table_row_selected(self, event: DataTable.RowSelected):
        tid = event.data_table.id
        if tid == "set-tools-table":
            self._selected_tool = event.row_key.value
        elif tid == "set-custom-tools-table":
            self._selected_custom_tool_id = int(event.row_key.value)
        elif tid == "set-api-sources-table":
            self._selected_api_source_id = int(event.row_key.value)
        elif tid == "set-wordlists-table":
            self._selected_wordlist_id = int(event.row_key.value)

    # -- button handling --------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        handlers = {
            "set-key-save": self._save_key,
            "set-ai-save": self._save_ai,
            "set-tool-enable": lambda: self._toggle_selected_tool(True),
            "set-tool-disable": lambda: self._toggle_selected_tool(False),
            "set-tool-enable-all": lambda: self._toggle_all_tools(True),
            "set-tool-disable-all": lambda: self._toggle_all_tools(False),
            "set-ct-add": self._add_custom_tool,
            "set-ct-delete": self._delete_custom_tool,
            "set-as-add": self._add_api_source,
            "set-as-delete": self._delete_api_source,
            "set-wl-upload": self._upload_wordlist,
            "set-wl-delete": self._delete_wordlist,
            "set-backup-download": self._download_backup,
            "set-backup-restore": self._restore_backup,
        }
        fn = handlers.get(bid)
        if fn:
            self.run_worker(fn())

    async def _save_key(self):
        service = self.query_one("#set-key-service", Select).value
        value = self.query_one("#set-key-value", Input).value.strip()
        status = self.query_one("#set-keys-status", Static)
        if service is Select.NULL or not value:
            status.update(Text("pick a service and enter a key first", style="#ff5566"))
            return
        await bridge.set_api_key(service, value)
        self.query_one("#set-key-value", Input).value = ""
        await self.refresh_data()

    async def _save_ai(self):
        url = self.query_one("#set-ai-url", Input).value.strip()
        key = self.query_one("#set-ai-key", Input).value.strip()
        model = self.query_one("#set-ai-model", Input).value.strip()
        await bridge.save_ai_config(url, key or None, model)
        self.query_one("#set-ai-key", Input).value = ""
        await self.refresh_data()

    async def _toggle_selected_tool(self, enabled: bool):
        if self._selected_tool is None:
            return
        await bridge.toggle_tool(self._selected_tool, enabled)
        await self.refresh_data()

    async def _toggle_all_tools(self, enabled: bool):
        await bridge.toggle_all_tools(enabled)
        await self.refresh_data()

    async def _add_custom_tool(self):
        name = self.query_one("#set-ct-name", Input).value.strip()
        cmd = self.query_one("#set-ct-cmd", Input).value.strip()
        fmt = self.query_one("#set-ct-format", Select).value
        shell = self.query_one("#set-ct-shell", Checkbox).value
        if not name or not cmd:
            return
        await bridge.add_custom_tool(name, cmd, fmt if fmt is not Select.NULL else "plain", shell)
        self.query_one("#set-ct-name", Input).value = ""
        self.query_one("#set-ct-cmd", Input).value = ""
        await self.refresh_data()

    async def _delete_custom_tool(self):
        if self._selected_custom_tool_id is None:
            return
        await bridge.delete_custom_tool(self._selected_custom_tool_id)
        self._selected_custom_tool_id = None
        await self.refresh_data()

    async def _add_api_source(self):
        name = self.query_one("#set-as-name", Input).value.strip()
        category = self.query_one("#set-as-category", Input).value.strip()
        url = self.query_one("#set-as-url", Input).value.strip()
        json_path = self.query_one("#set-as-jsonpath", Input).value.strip()
        fields = self.query_one("#set-as-fields", Input).value.strip()
        key = self.query_one("#set-as-key", Input).value.strip()
        if not name or not category or not url:
            return
        await bridge.add_api_source(name, category, url, json_path, fields, key)
        for fid in ("#set-as-name", "#set-as-category", "#set-as-url", "#set-as-jsonpath", "#set-as-fields", "#set-as-key"):
            self.query_one(fid, Input).value = ""
        await self.refresh_data()

    async def _delete_api_source(self):
        if self._selected_api_source_id is None:
            return
        await bridge.delete_api_source(self._selected_api_source_id)
        self._selected_api_source_id = None
        await self.refresh_data()

    async def _upload_wordlist(self):
        path = self.query_one("#set-wl-path", Input).value.strip()
        status = self.query_one("#set-backup-status", Static)
        if not path:
            return
        try:
            await bridge.upload_wordlist(path)
        except ValueError as e:
            status.update(Text(str(e), style="#ff5566"))
            return
        self.query_one("#set-wl-path", Input).value = ""
        await self.refresh_data()

    async def _delete_wordlist(self):
        if self._selected_wordlist_id is None:
            return
        await bridge.delete_wordlist(self._selected_wordlist_id)
        self._selected_wordlist_id = None
        await self.refresh_data()

    async def _download_backup(self):
        dest = self.query_one("#set-backup-dest", Input).value.strip() or "./surface_backup.db"
        status = self.query_one("#set-backup-status", Static)
        path = await bridge.download_backup(dest)
        status.update(Text(f"backup written to {path}", style="#39ff6a"))

    async def _restore_backup(self):
        src = self.query_one("#set-backup-src", Input).value.strip()
        status = self.query_one("#set-backup-status", Static)
        if not src:
            status.update(Text("enter a backup file path first", style="#ff5566"))
            return
        try:
            await bridge.restore_backup(src)
        except ValueError as e:
            status.update(Text(str(e), style="#ff5566"))
            return
        status.update(Text("backup restored — reload other screens to see the new state", style="#39ff6a"))
        await self.refresh_data()
