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
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vault.store import VaultError, VaultStore, validate_name

# Décide si une action est autorisée. Reçoit un résumé lisible, renvoie True pour autoriser.
ApproveFn = Callable[[str], bool]

REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
RUN_TIMEOUT_SECONDS = 300
MASK = "***"


class Broker:
    def __init__(
        self,
        store: VaultStore,
        approve: ApproveFn,
        audit_path: Path,
    ) -> None:
        self._store = store
        self._approve = approve
        self._audit_path = audit_path

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
            return _error(f"Action inconnue : {action}")
        except VaultError as exc:
            return _error(str(exc))

    # --- actions ---------------------------------------------------------------

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
        if not self._decide(summary, action="gh_secret", name=name, target=repo):
            return _error("Refusé par l'utilisateur")

        completed = subprocess.run(
            [gh, "secret", "set", name, "--repo", repo],
            input=value,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT_SECONDS,
            check=False,
        )
        self._store.mark_used(name)
        result = "ok" if completed.returncode == 0 else f"code {completed.returncode}"
        self._audit("gh_secret", name, repo, "approuvé", result)
        return {
            "ok": completed.returncode == 0,
            "stdout": _mask(completed.stdout, value),
            "stderr": _mask(completed.stderr, value),
            "returncode": completed.returncode,
        }

    def _run(self, request: dict[str, Any]) -> dict[str, Any]:
        name = validate_name(str(request.get("name", "")))
        env_var = str(request.get("env_var", ""))
        if not ENV_NAME_PATTERN.match(env_var):
            raise VaultError("Nom de variable d'environnement invalide")
        argv = request.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise VaultError("La commande doit être une liste d'arguments non vide")
        value = self._require_value(name)

        command_line = " ".join(argv)
        summary = f"Lancer « {command_line} » avec le secret « {name} » dans ${env_var}"
        if not self._decide(summary, action="run", name=name, target=command_line):
            return _error("Refusé par l'utilisateur")

        env = {**_base_env(), env_var: value}
        completed = subprocess.run(
            argv,
            env=env,
            capture_output=True,
            text=True,
            timeout=RUN_TIMEOUT_SECONDS,
            check=False,
        )
        self._store.mark_used(name)
        self._audit("run", name, command_line, "approuvé", f"code {completed.returncode}")
        return {
            "ok": completed.returncode == 0,
            "stdout": _mask(completed.stdout, value),
            "stderr": _mask(completed.stderr, value),
            "returncode": completed.returncode,
        }

    # --- outils internes -------------------------------------------------------

    def _require_value(self, name: str) -> str:
        if name not in self._store:
            raise VaultError(f"Entrée inconnue : {name}")
        return self._store.get_value(name)

    def _decide(self, summary: str, *, action: str, name: str, target: str) -> bool:
        approved = bool(self._approve(summary))
        if not approved:
            self._audit(action, name, target, "refusé", "-")
        return approved

    def _audit(self, action: str, name: str, target: str, decision: str, result: str) -> None:
        """Journal sans jamais écrire la valeur du secret."""
        entry = {
            "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "action": action,
            "name": name,
            "target": target,
            "decision": decision,
            "result": result,
        }
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _error(message: str) -> dict[str, Any]:
    return {"ok": False, "error": message}


def _base_env() -> dict[str, str]:
    """Environnement du processus, sans rien qui vienne de la CLI."""
    return dict(os.environ)


def _mask(text: str | None, secret: str) -> str:
    """Remplace la valeur (brute et en base64) par MASK dans une sortie."""
    if not text:
        return ""
    for needle in {secret, base64.b64encode(secret.encode("utf-8")).decode("ascii")}:
        text = text.replace(needle, MASK)
    return text
