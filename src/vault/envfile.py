"""Lecture d'un fichier `.env` classique, pour le transformer en entrées du coffre."""

from __future__ import annotations

import re

LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def parse_env(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Renvoie (paires nom/valeur valides, noms ignorés). Les références `vault:` et les lignes vides sont ignorées."""
    pairs: list[tuple[str, str]] = []
    ignored: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LINE.match(line)
        if match is None:
            continue
        name, value = match.groups()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if value == "" or value.startswith("vault:"):
            continue
        if name in seen:
            ignored.append(name)
            continue
        seen.add(name)
        pairs.append((name, value))
    return pairs, ignored
