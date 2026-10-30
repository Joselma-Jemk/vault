"""Emplacements du coffre. `VAULT_HOME` permet de les déplacer (tests, sauvegarde)."""

from __future__ import annotations

import getpass
import os
from pathlib import Path


def vault_dir() -> Path:
    override = os.environ.get("VAULT_HOME")
    if override:
        return Path(override)
    appdata = os.environ.get("APPDATA")
    base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    return base / "Vault"


def vault_file() -> Path:
    return vault_dir() / "vault.enc"


def audit_file() -> Path:
    return vault_dir() / "audit.jsonl"


def server_name() -> str:
    """Nom du canal local : propre à l'utilisateur Windows courant."""
    return f"vault-{getpass.getuser()}"
