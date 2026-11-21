"""Coffre : entrées chiffrées dans un seul fichier, écrit de façon atomique."""

from __future__ import annotations

import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
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


@dataclass
class Project:
    """Dossier enregistré par l'utilisateur, avec les seules entrées qu'il a le droit d'utiliser."""

    entries: list[str]
    created: str
    updated: str


def normalize_dir(path: str) -> str:
    """Chemin absolu normalisé, en minuscules sous Windows : sert de clé stable pour un projet."""
    return os.path.normcase(os.path.abspath(path))


def _ancestors(path: str):
    """Dossiers parents, du plus proche au plus lointain."""
    current = path
    while True:
        parent = os.path.dirname(current)
        if parent == current:
            return
        yield parent
        current = parent


class VaultStore:
    """Coffre déverrouillé. Les valeurs ne vivent qu'en mémoire, jamais sur le disque en clair."""

    def __init__(
        self,
        path: Path,
        password: str,
        entries: dict[str, Entry],
        projects: dict[str, Project] | None = None,
        expiries: dict[str, str] | None = None,
        tags: dict[str, list[str]] | None = None,
    ) -> None:
        self._path = path
        self._password = password
        self._entries = entries
        self._projects = projects or {}
        # Ces deux tables vivent à côté des entrées : une ancienne version les ignore, sans rien casser.
        self._expiries = expiries or {}
        self._tags = tags or {}

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
            projects = {path_: Project(**data) for path_, data in raw.get("projects", {}).items()}
            expiries = {str(k): str(v) for k, v in raw.get("expiries", {}).items()}
            tags = {str(k): [str(t) for t in v] for k, v in raw.get("tags", {}).items()}
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise VaultError("Contenu du coffre illisible") from exc
        return cls(path, password, entries, projects, expiries, tags)

    @classmethod
    def exists(cls, path: Path) -> bool:
        return path.exists()

    # --- lecture ---------------------------------------------------------------

    def list_metadata(self) -> list[dict[str, str | bool | None]]:
        """Noms, dates et état (en attente ou non), jamais les valeurs."""
        return [
            {
                "name": name,
                "created": entry.created,
                "updated": entry.updated,
                "last_used": entry.last_used,
                "pending": entry.value == "",
            }
            for name, entry in sorted(self._entries.items())
        ]

    def is_pending(self, name: str) -> bool:
        """Entrée déclarée mais pas encore renseignée : son nom existe, sa valeur non."""
        return name in self._entries and self._entries[name].value == ""

    def get_value(self, name: str) -> str:
        """Valeur d'une entrée. Réservé au courtier et à la copie dans l'interface, jamais à la CLI."""
        try:
            return self._entries[name].value
        except KeyError as exc:
            raise VaultError(f"Entrée inconnue : {name}") from exc

    def __contains__(self, name: object) -> bool:
        return name in self._entries

    # --- projets ---------------------------------------------------------------

    def list_projects(self) -> list[dict[str, object]]:
        """Projets enregistrés : dossier, entrées autorisées et dates. Jamais de valeurs."""
        return [
            {
                "path": path,
                "entries": list(project.entries),
                "effective": sorted(self.effective_entries(path)),
                "created": project.created,
                "updated": project.updated,
            }
            for path, project in sorted(self._projects.items())
        ]

    def resolve_project(self, directory: str) -> str:
        """Projet enregistré pour ce dossier : lui-même, ou le plus proche parent enregistré."""
        current = normalize_dir(directory)
        if current in self._projects:
            return current
        for parent in _ancestors(current):
            if parent in self._projects:
                return parent
        raise VaultError("Aucun projet enregistré pour ce dossier : demande à l'utilisateur de l'ajouter dans Vault")

    def effective_entries(self, project_path: str) -> set[str]:
        """Entrées réellement utilisables dans ce projet.

        Un sous-projet n'hérite jamais de plus que son parent : ses entrées sont intersectées avec celles du parent.
        """
        own = set(self._projects[project_path].entries)
        for parent in _ancestors(project_path):
            if parent in self._projects:
                return own & self.effective_entries(parent)
        return own

    def set_project(self, directory: str, entries: list[str]) -> None:
        """Enregistre ou met à jour un projet. Seules les entrées existantes peuvent être autorisées."""
        path = normalize_dir(directory)
        if not os.path.isdir(path):
            raise VaultError(f"Dossier introuvable : {directory}")
        unknown = [name for name in entries if name not in self._entries]
        if unknown:
            raise VaultError(f"Entrée inconnue : {', '.join(unknown)}")
        for name in entries:
            validate_name(name)
        now = now_iso()
        previous = self._projects.get(path)
        created = previous.created if previous else now
        self._projects[path] = Project(entries=sorted(set(entries)), created=created, updated=now)
        self.save()

    def delete_project(self, directory: str) -> None:
        path = normalize_dir(directory)
        if path not in self._projects:
            raise VaultError(f"Projet inconnu : {directory}")
        del self._projects[path]
        self.save()

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

    def declare(self, name: str) -> bool:
        """Crée une entrée en attente, sans valeur. Renvoie False si l'entrée existe déjà.

        Une entrée en attente ne contient aucun secret : Claude peut la déclarer pour que le code la référence,
        et l'utilisateur renseigne ensuite la valeur dans Vault.
        """
        validate_name(name)
        if name in self._entries:
            return False
        now = now_iso()
        self._entries[name] = Entry(value="", created=now, updated=now)
        self.save()
        return True

    def delete(self, name: str) -> None:
        if name not in self._entries:
            raise VaultError(f"Entrée inconnue : {name}")
        del self._entries[name]
        self._expiries.pop(name, None)
        self._tags.pop(name, None)
        self.save()

    # --- expiration et étiquettes ----------------------------------------------

    def expiry_of(self, name: str) -> str | None:
        return self._expiries.get(name)

    def set_expiry(self, name: str, date_text: str | None) -> None:
        """Date d'expiration au format AAAA-MM-JJ, ou None pour l'effacer."""
        if name not in self._entries:
            raise VaultError(f"Entrée inconnue : {name}")
        if date_text is None or date_text == "":
            self._expiries.pop(name, None)
        else:
            try:
                date.fromisoformat(date_text)
            except ValueError as exc:
                raise VaultError("Date invalide : utilise le format AAAA-MM-JJ") from exc
            self._expiries[name] = date_text
        self.save()

    def expiring_within(self, days: int, today: date) -> list[tuple[str, str]]:
        """Entrées déjà expirées ou qui expirent dans `days` jours, les plus proches d'abord."""
        limit = today + timedelta(days=days)
        result = []
        for name, text in self._expiries.items():
            if name in self._entries and date.fromisoformat(text) <= limit:
                result.append((name, text))
        return sorted(result, key=lambda item: item[1])

    def tags_of(self, name: str) -> list[str]:
        return list(self._tags.get(name, []))

    def set_tags(self, name: str, tags: list[str]) -> None:
        if name not in self._entries:
            raise VaultError(f"Entrée inconnue : {name}")
        cleaned = sorted({t.strip() for t in tags if t.strip()})[:10]
        if cleaned:
            self._tags[name] = cleaned
        else:
            self._tags.pop(name, None)
        self.save()

    def all_tags(self) -> list[str]:
        return sorted({t for tags in self._tags.values() for t in tags})

    # --- sauvegarde et import ----------------------------------------------------

    def export_payload(self) -> dict:
        """Contenu complet du coffre en clair, à chiffrer avant toute écriture (voir backup.py)."""
        return {
            "entries": {name: vars(entry) for name, entry in self._entries.items()},
            "projects": {path: vars(project) for path, project in self._projects.items()},
            "expiries": dict(self._expiries),
            "tags": {name: list(tags) for name, tags in self._tags.items()},
        }

    def import_payload(self, payload: dict) -> dict[str, list[str]]:
        """Ajoute au coffre ce qui manque. Une entrée déjà présente n'est jamais écrasée."""
        added: list[str] = []
        skipped: list[str] = []
        for name, data in payload.get("entries", {}).items():
            try:
                validate_name(name)
                entry = Entry(**data)
            except (VaultError, TypeError):
                skipped.append(name)
                continue
            if name in self._entries or entry.value == "" or len(entry.value) > MAX_VALUE_LENGTH:
                skipped.append(name)
                continue
            self._entries[name] = entry
            added.append(name)
            expiry = payload.get("expiries", {}).get(name)
            if isinstance(expiry, str):
                try:
                    date.fromisoformat(expiry)
                    self._expiries[name] = expiry
                except ValueError:
                    pass
            tags = payload.get("tags", {}).get(name)
            if isinstance(tags, list):
                self._tags[name] = [str(t) for t in tags][:10]
        for path, data in payload.get("projects", {}).items():
            if path in self._projects or not os.path.isdir(path):
                continue
            try:
                project = Project(**data)
            except TypeError:
                continue
            kept = [n for n in project.entries if n in self._entries]
            self._projects[path] = Project(entries=kept, created=project.created, updated=project.updated)
        self.save()
        return {"added": sorted(added), "skipped": sorted(skipped)}

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
        raw = self.export_payload()
        plaintext = json.dumps(raw, ensure_ascii=False).encode("utf-8")
        blob = crypto.encrypt(plaintext, self._password)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(blob))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self._path)
