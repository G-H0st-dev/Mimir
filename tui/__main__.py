"""Run with: python3 -m tui   (from the surface/ directory)

`python3 -m tui` puts surface/ on sys.path, not tui/ itself, but
app_main.py and bridge.py use bare imports (`import bridge`, `from
screens.scan_screen import ...`) that need tui/ itself on sys.path —
same as what already happens automatically when app_main.py is run
directly (`python3 tui/app_main.py`), since Python always adds a
run script's own directory. This makes -m invocation match that.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from app_main import main  # noqa: E402

if __name__ == "__main__":
    main()
