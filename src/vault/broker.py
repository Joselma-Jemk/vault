"""Courtier : exécute les demandes de la CLI, après approbation humaine.

Ce module ne dépend pas de Qt : l'approbation est une fonction injectée,
ce qui permet de tester toute la logique sans interface graphique.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vault import audit
from vault.store import VaultError, VaultStore, normalize_dir, validate_name

# Réponses possibles de l'approbation.
DENY = "refuse"
ONCE = "une_fois"
SESSION = "temporaire"

TEMP_GRANT_SECONDS = 600  # « autoriser 10 min » : la même commande ne redemande pas pendant ce temps
TRUST_SECONDS = 3600  # mode confiance : 1 h, activé seulement depuis l'interface, jamais par Claude
TRUST_LABEL = "confiance"
# Actions couvertes par le mode confiance. `run` et `gh-secret` restent toujours soumis à approbation.
TRUST_ACTIONS = frozenset({"exec", "export_env", "project_add"})
MAX_CONSECUTIVE_REFUSALS = 5  # après 5 refus d'affilée, les demandes sont refusées sans être affichées
REFUSAL_COOLDOWN_SECONDS = 120

# Reçoit un résumé lisible, renvoie DENY, ONCE ou SESSION (True est accepté comme ONCE).
ApproveFn = Callable[[str], Any]

REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
RUN_TIMEOUT_SECONDS = 300
# Une commande trop longue peut cacher une partie de ce que l'utilisateur approuve : elle est refusée.
MAX_COMMAND_LENGTH = 1500
MAX_MAPPINGS = 64
MASK = "***"
REFUSED_MESSAGE = "Refusé par l'utilisateur"


class Broker:
    def __init__(
        self,
        store: VaultStore,
        approve: ApproveFn,
        audit_path: Path,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._approve = approve
        self._audit_path = audit_path
        self._clock = clock
        self._grants: dict[tuple[str, str, str], float] = {}
        self._trust_until = 0.0
        self._refusals = 0
        self._cooldown_until = 0.0

    # --- point d'entrée --------------------------------------------------------

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action")
        try:
            if action == "list":
                return {"ok": True, "data": self._store.list_metadata()}
            if action == "gh_secret":
                return self._gh_secret(request)
            if action == "run":
                return self._run(request)
            if action == "exec":
                return self._exec(request)
            if action == "declare":
                return self._declare(request)
            if action == "project_add":
                return self._project_add(request)
            if action == "export_env":
                return self._export_env(request)
            return _error(f"Action inconnue : {action}")
        except VaultError as exc:
            return _error(str(exc))

    # --- actions ---------------------------------------------------------------

    def _declare(self, request: dict[str, Any]) -> dict[str, Any]:
        """Crée des entrées en attente (sans valeur). Aucun secret, donc aucune approbation demandée.

        Le droit d'utiliser l'entrée dans un projet reste à l'utilisateur, dans l'interface.
        """
        names = request.get("names")
        if not isinstance(names, list) or not names or len(names) > MAX_MAPPINGS:
            raise VaultError(f"Indique entre 1 et {MAX_MAPPINGS} noms")
        names = [validate_name(str(name)) for name in names]
        created: list[str] = []
        existing: list[str] = []
        for name in names:
            if self._store.declare(name):
                created.append(name)
                result = "créée en attente"
            else:
                existing.append(name)
                result = "existe déjà"
            self._audit("declare", name, "coffre", "auto", result)
        return {"ok": True, "data": {"created": created, "existing": existing}}

    def _project_add(self, request: dict[str, Any]) -> dict[str, Any]:
        """Enregistre un dossier comme projet. Approbation demandée, sauf en mode confiance.

        Ajoute des droits sans jamais en retirer : si le projet existe déjà, les entrées demandées s'y ajoutent.
        """
        directory = request.get("directory")
        if not isinstance(directory, str) or not directory:
            raise VaultError("Dossier manquant")
        path = normalize_dir(directory)
        _refuse_too_broad(path)
        if not os.path.isdir(path):
            raise VaultError(f"Dossier introuvable : {directory}")
        if request.get("all") is True:
            names = [row["name"] for row in self._store.list_metadata()]
        else:
            raw = request.get("names")
            if not isinstance(raw, list) or not raw or len(raw) > MAX_MAPPINGS:
                raise VaultError(f"Indique entre 1 et {MAX_MAPPINGS} noms, ou tout le coffre")
            names = [validate_name(str(name)) for name in raw]
        unknown = [name for name in names if name not in self._store]
        if unknown:
            raise VaultError(f"Entrée inconnue : {', '.join(unknown)}")
        if not names:
            raise VaultError("Le coffre est vide")

        shown = _printable(path)
        listed = ", ".join(sorted(names))
        summary = f"Enregistrer le dossier « {shown} » comme projet\nEntrées autorisées : {listed}"
        label = self._decide(summary, action="project_add", name=",".join(sorted(names)), target=shown)
        if label is None:
            return _error(REFUSED_MESSAGE)

        merged = sorted(set(names) | self._existing_entries(path))
        self._store.set_project(path, merged)
        self._audit("project_add", ",".join(sorted(names)), shown, label, "ok")
        return {"ok": True, "data": {"project": path, "entries": merged}}

    def _existing_entries(self, path: str) -> set[str]:
        for row in self._store.list_projects():
            if row["path"] == path:
                return set(row["entries"])  # type: ignore[arg-type]
        return set()

    def _export_env(self, request: dict[str, Any]) -> dict[str, Any]:
        """Écrit un fichier .env avec des valeurs en clair, dans le dossier d'un projet enregistré.

        La valeur ne revient jamais à la CLI : elle va seulement dans le fichier.
        """
        directory = request.get("project")
        if not isinstance(directory, str) or not directory:
            raise VaultError("Dossier du projet manquant")
        project = self._store.resolve_project(directory)
        allowed = self._store.effective_entries(project)

        raw = request.get("mapping")
        if raw is None:
            mapping = {name: name for name in sorted(allowed) if not self._store.is_pending(name)}
        else:
            mapping = _checked_mapping(raw)
        if not mapping:
            raise VaultError("Aucune entrée à exporter (liste vide, ou toutes en attente)")
        for name in mapping.values():
            if name not in allowed:
                raise VaultError(f"« {name} » n'est pas autorisée pour le projet {project}")
            self._require_value(name)

        target = _checked_target(project, directory, request.get("file", ".env"))
        overwrite = request.get("overwrite") is True
        if os.path.lexists(target) and not overwrite:
            raise VaultError(f"{target} existe déjà : ajoute --overwrite pour le remplacer")

        shown = _printable(target)
        bindings = ", ".join(f"{var} ← {name}" for var, name in sorted(mapping.items()))
        summary = (
            f"Projet « {_printable(project)} »\n"
            f"Écrire {len(mapping)} secret(s) EN CLAIR dans « {shown} »\n"
            f"Variables : {bindings}"
        )
        names = sorted(set(mapping.values()))
        label = self._decide(summary, action="export_env", name=",".join(names), target=shown)
        if label is None:
            return _error(REFUSED_MESSAGE)

        content = "".join(
            f"{var}={_dotenv_value(self._store.get_value(name))}\n" for var, name in sorted(mapping.items())
        )
        try:
            _write_text(target, content, overwrite)
        except OSError as exc:
            self._audit("export_env", ",".join(names), shown, label, "écriture impossible")
            return _error(f"Écriture impossible : {exc.strerror or exc.__class__.__name__}")
        self._mark_used(names)
        self._audit("export_env", ",".join(names), shown, label, "ok")
        data: dict[str, Any] = {"file": target, "count": len(mapping), "variables": sorted(mapping)}
        warning = _gitignore_warning(project, target)
        if warning:
            data["warning"] = warning
        return {"ok": True, "data": data}

    def _gh_secret(self, request: dict[str, Any]) -> dict[str, Any]:
        name = validate_name(str(request.get("name", "")))
        repo = str(request.get("repo", ""))
        if not REPO_PATTERN.match(repo):
            raise VaultError("Dépôt invalide, format attendu : proprietaire/depot")
        value = self._require_value(name)
        gh = shutil.which("gh")
        if gh is None:
            raise VaultError("La commande gh est introuvable (GitHub CLI)")

        summary = f"Poser le secret GitHub « {name} » sur le dépôt {repo}"
        label = self._decide(summary, action="gh_secret", name=name, target=repo)
        if label is None:
            return _error(REFUSED_MESSAGE)

        return self._execute(
            [gh, "secret", "set", name, "--repo", repo],
            env=None,
            stdin=value,
            values=[value],
            action="gh_secret",
            names=[name],
            target=repo,
            label=label,
        )

    def _run(self, request: dict[str, Any]) -> dict[str, Any]:
        name = validate_name(str(request.get("name", "")))
        env_var = str(request.get("env_var", ""))
        if not ENV_NAME_PATTERN.match(env_var):
            raise VaultError("Nom de variable d'environnement invalide")
        argv = _checked_argv(request.get("argv"))
        value = self._require_value(name)

        # Affichage avec les guillemets de Windows : deux commandes différentes ne s'affichent jamais pareil.
        command_line = subprocess.list2cmdline(argv)
        if len(command_line) > MAX_COMMAND_LENGTH:
            raise VaultError(f"Commande trop longue (plus de {MAX_COMMAND_LENGTH} caractères)")
        shown = _printable(command_line)
        summary = f"Lancer « {shown} » avec le secret « {name} » dans ${env_var}"
        # L'autorisation temporaire est liée à la liste exacte d'arguments, pas à son affichage.
        label = self._decide(
            summary, action="run", name=name, target=shown, grant_key=json.dumps(argv, ensure_ascii=True)
        )
        if label is None:
            return _error(REFUSED_MESSAGE)

        return self._execute(
            argv,
            env={**_base_env(), env_var: value},
            stdin=None,
            values=[value],
            action="run",
            names=[name],
            target=shown,
            label=label,
        )

    def _exec(self, request: dict[str, Any]) -> dict[str, Any]:
        """Lance une commande avec plusieurs secrets, résolus depuis un projet enregistré. Une seule approbation."""
        directory = request.get("project")
        if not isinstance(directory, str) or not directory:
            raise VaultError("Dossier du projet manquant")
        mapping = _checked_mapping(request.get("mapping"))
        argv = _checked_argv(request.get("argv"))

        # Le projet est celui du dossier courant, ou du plus proche parent enregistré.
        project = self._store.resolve_project(directory)
        allowed = self._store.effective_entries(project)
        for name in mapping.values():
            if name not in allowed:
                raise VaultError(f"« {name} » n'est pas autorisée pour le projet {project}")
            self._require_value(name)

        command_line = subprocess.list2cmdline(argv)
        if len(command_line) > MAX_COMMAND_LENGTH:
            raise VaultError(f"Commande trop longue (plus de {MAX_COMMAND_LENGTH} caractères)")
        shown = _printable(command_line)
        bindings = ", ".join(f"{var} ← {name}" for var, name in sorted(mapping.items()))
        summary = f"Projet « {_printable(project)} »\nLancer « {shown} »\nSecrets : {bindings}"
        names = sorted(set(mapping.values()))
        grant_key = json.dumps({"p": project, "m": sorted(mapping.items()), "a": argv}, ensure_ascii=True)
        label = self._decide(
            summary,
            action="exec",
            name=",".join(names),
            target=shown,
            grant_key=grant_key,
        )
        if label is None:
            return _error(REFUSED_MESSAGE)

        values = {var: self._store.get_value(name) for var, name in mapping.items()}
        return self._execute(
            argv,
            env={**_base_env(), **values},
            stdin=None,
            values=list(values.values()),
            action="exec",
            names=names,
            target=shown,
            label=label,
        )

    # --- exécution ---------------------------------------------------------------

    def _execute(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None,
        stdin: str | None,
        values: list[str],
        action: str,
        names: list[str],
        target: str,
        label: str,
    ) -> dict[str, Any]:
        """Lance la commande. Ne lève jamais : toute panne devient une réponse d'erreur pour la CLI."""
        kwargs: dict[str, Any] = {
            "input": stdin,
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",  # une sortie dans une autre page de code ne doit pas faire planter
            "timeout": RUN_TIMEOUT_SECONDS,
            "check": False,
        }
        if env is not None:
            kwargs["env"] = env
        if sys.platform == "win32":
            # L'application est une fenêtre sans console : sans ce drapeau, Windows ouvre un terminal visible,
            # au premier plan, pour chaque commande lancée. La sortie est de toute façon capturée.
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            completed = subprocess.run(argv, **kwargs)
        except subprocess.TimeoutExpired:
            self._mark_used(names)  # les valeurs ont bien été transmises à la commande
            self._audit(action, ",".join(names), target, label, "délai dépassé")
            return _error(f"Délai dépassé ({RUN_TIMEOUT_SECONDS} s), commande arrêtée")
        except OSError as exc:
            self._audit(action, ",".join(names), target, label, "lancement impossible")
            return _error(f"Impossible de lancer la commande : {_mask_all(str(exc), values)}")

        self._mark_used(names)
        result = "ok" if completed.returncode == 0 else f"code {completed.returncode}"
        self._audit(action, ",".join(names), target, label, result)
        return {
            "ok": completed.returncode == 0,
            "stdout": _mask_all(completed.stdout, values),
            "stderr": _mask_all(completed.stderr, values),
            "returncode": completed.returncode,
        }

    # --- outils internes -------------------------------------------------------

    def _mark_used(self, names: list[str]) -> None:
        for name in names:
            self._store.mark_used(name)

    def _require_value(self, name: str) -> str:
        if name not in self._store:
            raise VaultError(f"Entrée inconnue : {name}")
        if self._store.is_pending(name):
            raise VaultError(f"« {name} » est en attente : sa valeur reste à renseigner dans Vault")
        return self._store.get_value(name)

    def _decide(
        self, summary: str, *, action: str, name: str, target: str, grant_key: str | None = None
    ) -> str | None:
        """Renvoie l'étiquette du journal si l'action est autorisée, None si elle est refusée."""
        now = self._clock()
        key = (action, name, grant_key if grant_key is not None else target)
        self._forget_expired_grants(now)

        # Mode confiance : `exec`, l'export .env et l'ajout de projet, activé par l'utilisateur seulement.
        # `run` et `gh-secret` restent toujours soumis à approbation.
        if action in TRUST_ACTIONS and now < self._trust_until:
            return TRUST_LABEL

        if key in self._grants:
            return "approuvé (temporaire)"
        if now < self._cooldown_until:
            self._audit(action, name, target, "refusé (trop de refus récents)", "-")
            return None

        answer = _normalize(self._approve(summary))
        if answer == DENY:
            self._audit(action, name, target, "refusé", "-")
            self._refusals += 1
            if self._refusals >= MAX_CONSECUTIVE_REFUSALS:
                self._cooldown_until = now + REFUSAL_COOLDOWN_SECONDS
                self._refusals = 0
            return None

        self._refusals = 0
        if answer == SESSION:
            self._grants[key] = now + TEMP_GRANT_SECONDS
            return "approuvé (temporaire)"
        return "approuvé"

    def enable_trust(self, seconds: float = TRUST_SECONDS) -> None:
        self._trust_until = self._clock() + seconds

    def disable_trust(self) -> None:
        self._trust_until = 0.0

    def trust_remaining(self) -> float:
        return max(0.0, self._trust_until - self._clock())

    def _forget_expired_grants(self, now: float) -> None:
        for key, expires in list(self._grants.items()):
            if expires <= now:
                del self._grants[key]

    def _audit(self, action: str, name: str, target: str, decision: str, result: str) -> None:
        """Journal sans jamais écrire la valeur du secret."""
        audit.append(
            self._audit_path,
            {
                "ts": _utc_now(),
                "action": action,
                "name": name,
                "target": target,
                "decision": decision,
                "result": result,
            },
        )


def _checked_argv(argv: Any) -> list[str]:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise VaultError("La commande doit être une liste d'arguments non vide")
    return argv


def _checked_mapping(mapping: Any) -> dict[str, str]:
    if not isinstance(mapping, dict) or not mapping:
        raise VaultError("Aucune référence de secret à résoudre")
    if len(mapping) > MAX_MAPPINGS:
        raise VaultError(f"Trop de références (plus de {MAX_MAPPINGS})")
    checked: dict[str, str] = {}
    for var, name in mapping.items():
        if not isinstance(var, str) or not ENV_NAME_PATTERN.match(var):
            raise VaultError(f"Nom de variable d'environnement invalide : {var!r}")
        if not isinstance(name, str):
            raise VaultError(f"Nom d'entrée invalide pour {var}")
        checked[var] = validate_name(name)
    return checked


def _normalize(answer: Any) -> str:
    if answer is True:
        return ONCE
    if answer in (ONCE, SESSION):
        return answer
    return DENY


def _printable(text: str) -> str:
    """Rend visibles les caractères de contrôle (retours à la ligne, etc.) au lieu de les interpréter."""
    return "".join(c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in text)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _error(message: str) -> dict[str, Any]:
    return {"ok": False, "error": message}


def _base_env() -> dict[str, str]:
    """Environnement du processus, sans rien qui vienne de la CLI."""
    return dict(os.environ)


def _mask_all(text: str | None, secrets: list[str]) -> str:
    """Remplace chaque valeur (brute et en base64) par MASK dans une sortie."""
    if not text:
        return ""
    for secret in secrets:
        for needle in {secret, base64.b64encode(secret.encode("utf-8")).decode("ascii")}:
            text = text.replace(needle, MASK)
    return text


def _refuse_too_broad(path: str) -> None:
    """Un projet couvre tous ses sous-dossiers : refuse une racine de disque, le dossier personnel et ses parents."""
    if os.path.dirname(path) == path:
        raise VaultError("Un disque entier ne peut pas être un projet")
    home = normalize_dir(str(Path.home()))
    if path == home or home.startswith(path.rstrip(os.sep + "/") + os.sep):
        raise VaultError("Le dossier personnel (ou l'un de ses parents) est trop large pour être un projet")


def _checked_target(project: str, directory: str, file_name: Any) -> str:
    """Chemin du fichier à écrire : doit rester dans le dossier du projet, sans lien symbolique qui en sorte."""
    if not isinstance(file_name, str) or not file_name or "\x00" in file_name:
        raise VaultError("Nom de fichier invalide")
    candidate = os.path.abspath(os.path.join(directory, file_name))
    parent = os.path.realpath(os.path.dirname(candidate))
    root = os.path.normcase(os.path.realpath(project))
    low = os.path.normcase(parent)
    if low != root and not low.startswith(root + os.sep):
        raise VaultError("Le fichier doit rester dans le dossier du projet")
    if os.path.isdir(candidate):
        raise VaultError("La cible est un dossier")
    return os.path.join(parent, os.path.basename(candidate))


_PLAIN_VALUE = re.compile(r"^[A-Za-z0-9_./:@+=,%-]+$")


def _dotenv_value(value: str) -> str:
    """Valeur au format .env : brute si elle est simple, sinon entre guillemets avec échappements."""
    if _PLAIN_VALUE.match(value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n")
    return f'"{escaped}"'


def _write_text(target: str, content: str, overwrite: bool) -> None:
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL) | getattr(os, "O_BINARY", 0)
    fd = os.open(target, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content.encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())


def _gitignore_warning(project: str, target: str) -> str | None:
    """Prévient si le fichier est dans un dépôt git sans règle qui l'ignore (risque de le versionner par erreur)."""
    if not os.path.isdir(os.path.join(project, ".git")):
        return None
    name = os.path.basename(target)
    try:
        lines = Path(project, ".gitignore").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    ignored = any(line.strip().lstrip("/") in (name, ".env", ".env*", "*.env") for line in lines)
    return None if ignored else f"{name} n'est pas dans .gitignore : ne le versionne pas"
