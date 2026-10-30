"""Journal des demandes : une ligne JSON par demande, jamais de valeur de secret."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

MAX_BYTES = 1024 * 1024  # au-delà, l'ancien journal passe dans `audit.jsonl.1` (un seul fichier d'archive)


def append(path: Path, entry: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > MAX_BYTES:
        os.replace(path, path.with_suffix(path.suffix + ".1"))
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def read_recent(path: Path, limit: int = 200) -> list[dict[str, Any]]:
    """Les `limit` dernières entrées, de la plus récente à la plus ancienne. Les lignes illisibles sont ignorées."""
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return list(reversed(rows))
