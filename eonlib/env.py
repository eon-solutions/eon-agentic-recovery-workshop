"""Load the workshop .env file into the environment, without a dotenv dependency.

Looks for .env next to the repo root (the attendee package) or at $WORKSHOP_ENV. Values
already set in the environment win, so a shell export overrides the file.
"""

from __future__ import annotations

import os
from pathlib import Path

_loaded = False


def load_env(path: str | os.PathLike | None = None) -> dict[str, str]:
    global _loaded
    candidates = [path, os.environ.get("WORKSHOP_ENV"),
                  Path(__file__).resolve().parent.parent / ".env", Path.cwd() / ".env"]
    found: dict[str, str] = {}
    for c in candidates:
        if not c:
            continue
        p = Path(c)
        if not p.is_file():
            continue
        for raw in p.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("\'")
            found[k] = v
            os.environ.setdefault(k, v)
        break
    _loaded = True
    return found
