"""Une commande lancée par le courtier ne doit jamais ouvrir de fenêtre de terminal sous Windows."""

import ctypes
import subprocess
import sys
from pathlib import Path

import pytest

from vault import broker as broker_module
from vault.broker import ONCE, Broker
from vault.store import VaultStore

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="spécifique à Windows")


@pytest.fixture
def broker(tmp_path: Path) -> Broker:
    store = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    store.set("TOKEN", "valeur-secrete-1")
    root = tmp_path / "projet"
    root.mkdir()
    store.set_project(str(root), ["TOKEN"])
    return Broker(store, lambda summary: ONCE, tmp_path / "audit.jsonl")


@windows_only
def test_command_is_started_without_console_window(monkeypatch, broker: Broker) -> None:
    seen: dict = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(broker_module.subprocess, "run", fake_run)
    broker._execute([sys.executable, "-c", "pass"], env=None, stdin=None, values=[], action="exec",
                    names=["TOKEN"], target="t", label="une fois")
    assert seen["creationflags"] & subprocess.CREATE_NO_WINDOW


@windows_only
def test_real_child_has_no_console_window(broker: Broker) -> None:
    """Test réel : sans le drapeau, l'enfant hérite de la console du lanceur et GetConsoleWindow est non nul."""
    if not ctypes.windll.kernel32.GetConsoleWindow():
        pytest.skip("le lanceur de tests n'a pas de console, la comparaison n'a pas de sens")
    code = "import ctypes;print(ctypes.windll.kernel32.GetConsoleWindow())"
    argv = [sys.executable, "-c", code]

    with_console = subprocess.run(argv, capture_output=True, text=True)
    assert with_console.stdout.strip() != "0"  # sans drapeau : une fenêtre existe (c'est le défaut corrigé)

    result = broker._execute(argv, env=None, stdin=None, values=[], action="exec",
                             names=["TOKEN"], target="t", label="une fois")
    assert result["ok"] is True
    assert result["stdout"].strip() == "0"  # avec le courtier : aucune fenêtre
