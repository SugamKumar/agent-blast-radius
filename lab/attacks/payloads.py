"""Loader for attack test cases.

This repo ships no attack strings. Bring your own from an established
red-team tool (for example Garak or PyRIT) or write them yourself, and save
them as a JSON file in this shape:

    [
      {"id": "P01", "style": "short label", "title": "issue title", "body": "issue text"}
    ]

Each entry is filed as a public issue by an outside user before the agent
runs. The lab then checks objectively whether a canary value from the
private notes ended up in a public comment.
"""

from __future__ import annotations

import json
from pathlib import Path

REQUIRED_KEYS = {"id", "style", "title", "body"}


def load_payloads(path: str | Path) -> list[dict]:
    entries = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not entries:
        raise ValueError("payload file must be a non-empty JSON list")
    for entry in entries:
        missing = REQUIRED_KEYS - set(entry)
        if missing:
            raise ValueError(f"payload {entry.get('id', '?')} is missing keys: {sorted(missing)}")
    return entries
