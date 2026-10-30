"""Coffre : entrées chiffrées dans un seul fichier, écrit de façon atomique."""

from __future__ import annotations

import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from vault import crypto

NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MIN_PASSWORD_LENGTH = 8
MAX_VALUE_LENGTH = 16 * 1024


class VaultError(Exception):
    """Erreur métier du coffre (nom invalide, entrée absente, etc.)."""


@dataclass
class Entry:
    value: str
    created: str
    updated: str
    last_used: str | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def validate_name(name: str) -> str:
    if not NAME_PATTERN.match(name):
        raise VaultError(
            "Nom invalide : lettres, chiffres et _ uniquement, 64 caractères maximum, "
            "sans chiffre en premier"
        )
    return name


def validate_value(value: str) -> str:
    if not value:
        raise VaultError("La valeur ne peut pas être vide")
    if len(value.encode("utf-8")) > MAX_VALUE_LENGTH:
        raise VaultError(f"La valeur dépasse {MAX_VALUE_LENGTH // 1024} Ko")
    return value


def validate_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise VaultError(f"Le mot de passe doit faire {MIN_PASSWORD_LENGTH} caractères minimum")
    return password


class VaultStore:
    """Coffre déverrouillé. Les valeurs ne vivent qu'en mémoire, jamais sur le disque en clair."""

    def __init__(self, path: Path, password: str, entries: dict[str, Entry]) -> None:
        self._path = path
        self._password = password
        self._entries = entries

    # --- ouverture et création -------------------------------------------------

    @classmethod
    def create(cls, path: Path, password: str) -> VaultStore:
        if path.exists():
            raise VaultError("Un coffre existe déjà à cet emplacement")
        store = cls(path, validate_password(password), {})
        store.save()
        return store

    @classmethod
    def open(cls, path: Path, password: str) -> VaultStore:
        blob = json.loads(path.read_text(encoding="utf-8"))
        plaintext = crypto.decrypt(blob, password)
        try:
            raw = json.loads(plaintext.decode("utf-8"))
            entries = {name: Entry(**data) for name, data in raw["entries"].items()}
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise VaultError("Contenu du coffre illisible") from exc
        return cls(path, password, entries)

    @classmethod
    def exists(cls, path: Path) -> bool:
        return path.exists()

    # --- lecture ---------------------------------------------------------------

    def list_metadata(self) -> list[dict[str, str | None]]:
        """Noms et dates, jamais les valeurs."""
        return [
            {
                "name": name,
                "created": entry.created,
                "updated": entry.updated,
                "last_used": entry.last_used,
            }
            for name, entry in sorted(self._entries.items())
        ]

    def get_value(self, name: str) -> str:
        """Valeur d'une entrée. Réservé au courtier et à la copie dans l'interface, jamais à la CLI."""
        try:
            return self._entries[name].value
        except KeyError as exc:
            raise VaultError(f"Entrée inconnue : {name}") from exc

    def __contains__(self, name: object) -> bool:
        return name in self._entries

    # --- écriture --------------------------------------------------------------

    def set(self, name: str, value: str) -> None:
        validate_name(name)
        validate_value(value)
        now = now_iso()
        previous = self._entries.get(name)
        created = previous.created if previous else now
        last_used = previous.last_used if previous else None
        self._entries[name] = Entry(value=value, created=created, updated=now, last_used=last_used)
        self.save()

    def delete(self, name: str) -> None:
        if name not in self._entries:
            raise VaultError(f"Entrée inconnue : {name}")
        del self._entries[name]
        self.save()

    def mark_used(self, name: str) -> None:
        if name in self._entries:
            self._entries[name].last_used = now_iso()
            self.save()

    def change_password(self, current: str, new: str) -> None:
        """Change le mot de passe maître. Exige l'ancien, et ne le remplace qu'après écriture réussie."""
        if not hmac.compare_digest(current.encode("utf-8"), self._password.encode("utf-8")):
            raise VaultError("Mot de passe actuel incorrect")
        validate_password(new)
        previous = self._password
        self._password = new
        try:
            self.save()
        except OSError:
            self._password = previous
            raise

    def save(self) -> None:
        raw = {"entries": {name: vars(entry) for name, entry in self._entries.items()}}
        plaintext = json.dumps(raw, ensure_ascii=False).encode("utf-8")
        blob = crypto.encrypt(plaintext, self._password)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(blob))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._path)
