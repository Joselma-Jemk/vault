"""Sauvegarde chiffrée du coffre : même chiffrement que le coffre, avec un mot de passe propre à la sauvegarde."""

from __future__ import annotations

import json
import os
from pathlib import Path

from vault import crypto
from vault.store import VaultError, VaultStore, validate_password

BACKUP_FORMAT = "vault-backup-1"


def write_backup(store: VaultStore, path: Path, password: str) -> None:
    """Écrit une sauvegarde chiffrée. Le mot de passe de sauvegarde doit être fort, il n'est pas celui du coffre."""
    validate_password(password)
    payload = {"format": BACKUP_FORMAT, "data": store.export_payload()}
    blob = crypto.encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"), password)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(blob))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def read_backup(path: Path, password: str) -> dict:
    """Contenu d'une sauvegarde. Lève VaultError si le mot de passe est faux ou si le fichier est invalide."""
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
        plaintext = crypto.decrypt(blob, password)
        payload = json.loads(plaintext.decode("utf-8"))
    except crypto.WrongPassword as exc:
        raise VaultError(str(exc)) from exc
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise VaultError("Sauvegarde illisible") from exc
    if not isinstance(payload, dict) or payload.get("format") != BACKUP_FORMAT:
        raise VaultError("Ce fichier n'est pas une sauvegarde Vault")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise VaultError("Sauvegarde illisible")
    return data
