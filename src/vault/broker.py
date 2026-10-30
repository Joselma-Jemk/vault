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
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vault import audit
from vault.store import VaultError, VaultStore, validate_name

# Réponses possibles de l'approbation.
DENY = "refuse"
ONCE = "une_fois"
SESSION = "temporaire"

TEMP_GRANT_SECONDS = 600  # « autoriser 10 min » : la même commande ne redemande pas pendant ce temps
MAX_CONSECUTIVE_REFUSALS = 5  # après 5 refus d'affilée, les demandes sont refusées sans être affichées
REFUSAL_COOLDOWN_SECONDS = 120

# Reçoit un résumé lisible, renvoie DENY, ONCE ou SESSION (True est accepté comme ONCE).
ApproveFn = Callable[[str], Any]

REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ENV_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
RUN_TIMEOUT_SECONDS = 300
# Une commande trop longue peut cacher une partie de ce que l'utilisateur approuve : elle est refusée.
MAX_COMMAND_LENGTH = 1500
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
        label = self._decide(summary, action="gh_secret", name=name, target=repo)
        if label is None:
            return _error(REFUSED_MESSAGE)

        return self._execute(
            [gh, "secret", "set", name, "--repo", repo],
            env=None,
            stdin=value,
            value=value,
            action="gh_secret",
            name=name,
            target=repo,
            label=label,
        )

    def _run(self, request: dict[str, Any]) -> dict[str, Any]:
        name = validate_name(str(request.get("name", "")))
        env_var = str(request.get("env_var", ""))
        if not ENV_NAME_PATTERN.match(env_var):
            raise VaultError("Nom de variable d'environnement invalide")
        argv = request.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise VaultError("La commande doit être une liste d'arguments non vide")
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
            value=value,
            action="run",
            name=name,
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
        value: str,
        action: str,
        name: str,
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
        try:
            completed = subprocess.run(argv, **kwargs)
        except subprocess.TimeoutExpired:
            self._store.mark_used(name)  # la valeur a bien été transmise à la commande
            self._audit(action, name, target, label, "délai dépassé")
            return _error(f"Délai dépassé ({RUN_TIMEOUT_SECONDS} s), commande arrêtée")
        except OSError as exc:
            self._audit(action, name, target, label, "lancement impossible")
            return _error(f"Impossible de lancer la commande : {_mask(str(exc), value)}")

        self._store.mark_used(name)
        result = "ok" if completed.returncode == 0 else f"code {completed.returncode}"
        self._audit(action, name, target, label, result)
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

    def _decide(
        self, summary: str, *, action: str, name: str, target: str, grant_key: str | None = None
    ) -> str | None:
        """Renvoie l'étiquette du journal si l'action est autorisée, None si elle est refusée."""
        now = self._clock()
        key = (action, name, grant_key if grant_key is not None else target)
        self._forget_expired_grants(now)

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


def _mask(text: str | None, secret: str) -> str:
    """Remplace la valeur (brute et en base64) par MASK dans une sortie."""
    if not text:
        return ""
    for needle in {secret, base64.b64encode(secret.encode("utf-8")).decode("ascii")}:
        text = text.replace(needle, MASK)
    return text
