"""Cas limites : pannes de commande, affichage trompeur, canal local, verrouillage, second lancement."""

import subprocess
import sys
import time
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication, QMessageBox

import vault.app as app_module
from vault import audit
from vault import broker as broker_module
from vault.__main__ import run
from vault.app import AutoLocker, MainWindow
from vault.broker import MAX_COMMAND_LENGTH, ONCE, SESSION, Broker
from vault.ipc import BrokerServer
from vault.store import VaultStore

SECRET = "tok_SECRET_VALUE_12345"


@pytest.fixture
def store(tmp_path: Path) -> VaultStore:
    s = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    s.set("GH_TOKEN", SECRET)
    return s


def make_broker(store: VaultStore, tmp_path: Path, answer=ONCE) -> tuple[Broker, list[str]]:
    asked: list[str] = []

    def approve(summary: str):
        asked.append(summary)
        return answer

    return Broker(store, approve, tmp_path / "audit.jsonl"), asked


def run_request(*argv: str) -> dict:
    return {"action": "run", "name": "GH_TOKEN", "env_var": "T", "argv": list(argv)}


# --- courtier : la CLI reçoit toujours une réponse -----------------------------------


def test_missing_executable_returns_error_instead_of_raising(store: VaultStore, tmp_path: Path) -> None:
    broker, _ = make_broker(store, tmp_path)
    reply = broker.handle(run_request("commande-qui-nexiste-pas-xyz"))
    assert reply["ok"] is False
    assert "Impossible de lancer" in reply["error"]
    assert SECRET not in reply["error"]


def test_timeout_returns_error(store: VaultStore, tmp_path: Path, monkeypatch) -> None:
    def too_slow(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="x", timeout=1)

    monkeypatch.setattr(broker_module.subprocess, "run", too_slow)
    broker, _ = make_broker(store, tmp_path)
    reply = broker.handle(run_request("x"))
    assert reply["ok"] is False
    assert "Délai dépassé" in reply["error"]
    assert "délai dépassé" in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_non_utf8_output_does_not_crash(store: VaultStore, tmp_path: Path) -> None:
    broker, _ = make_broker(store, tmp_path)
    code = "import sys; sys.stdout.buffer.write(b'caf\\xe9')"
    reply = broker.handle(run_request(sys.executable, "-c", code))
    assert reply["ok"] is True
    assert reply["stdout"].startswith("caf")


# --- courtier : ce que l'utilisateur lit est ce qui s'exécute -------------------------


@pytest.fixture
def run_stub(monkeypatch):
    monkeypatch.setattr(
        broker_module.subprocess,
        "run",
        lambda argv, **k: subprocess.CompletedProcess(argv, 0, stdout="", stderr=""),
    )


def test_grant_is_not_shared_between_different_argument_lists(store, tmp_path, run_stub) -> None:
    broker, asked = make_broker(store, tmp_path, answer=SESSION)
    broker.handle(run_request("echo", "ok"))
    broker.handle(run_request("echo ok"))  # un seul argument : autre commande, même texte joint
    assert len(asked) == 2


def test_arguments_with_spaces_are_quoted_in_the_summary(store, tmp_path, run_stub) -> None:
    broker, asked = make_broker(store, tmp_path)
    broker.handle(run_request("echo", "deux mots"))
    assert '"deux mots"' in asked[0]


def test_overlong_command_is_refused_without_prompt(store, tmp_path, run_stub) -> None:
    broker, asked = make_broker(store, tmp_path)
    reply = broker.handle(run_request("echo", "x" * (MAX_COMMAND_LENGTH + 1)))
    assert reply["ok"] is False
    assert asked == []


def test_control_characters_are_shown_escaped(store, tmp_path, run_stub) -> None:
    broker, asked = make_broker(store, tmp_path)
    broker.handle(run_request("echo", "ok\n\nAutoriser sans regarder"))
    assert "\n" not in asked[0]  # la commande ne peut pas ajouter de lignes à la fenêtre d'approbation
    assert "\\n" in asked[0]  # elle s'affiche à la place sous forme d'échappement visible


# --- canal local ------------------------------------------------------------------------


def test_broker_exception_becomes_error_reply_and_is_logged(qapp, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VAULT_HOME", str(tmp_path))

    class Exploding:
        def handle(self, request):
            raise RuntimeError("panne inattendue")

    server = BrokerServer()
    server.set_broker(Exploding())
    reply = server._respond(b'{"action": "list"}\n')

    assert reply["ok"] is False
    assert "Erreur interne" in reply["error"]
    assert "panne inattendue" in (tmp_path / "error.log").read_text(encoding="utf-8")


# --- journal -----------------------------------------------------------------------------


def test_audit_rotates_when_too_large(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(audit, "MAX_BYTES", 200)
    path = tmp_path / "audit.jsonl"
    for n in range(20):
        audit.append(path, {"n": n, "padding": "x" * 30})
    assert path.with_suffix(".jsonl.1").exists()
    assert path.stat().st_size <= 400  # le fichier courant reste petit


# --- verrouillage automatique -------------------------------------------------------------


def test_long_command_does_not_look_like_a_sleep(qapp) -> None:
    locked: list[int] = []
    locker = AutoLocker(lambda: locked.append(1))
    locker._last_tick = time.time() - 100  # la boucle Qt est restée bloquée 100 s par une commande
    locker.reset()  # le serveur signale qu'une demande vient d'être traitée
    locker._tick()
    assert locked == []


def test_real_sleep_gap_still_locks(qapp) -> None:
    locked: list[int] = []
    locker = AutoLocker(lambda: locked.append(1))
    locker._last_tick = time.time() - 100  # aucun signal du serveur : c'est bien une veille
    locker._tick()
    assert locked == [1]


@pytest.fixture
def window(qapp, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("VAULT_HOME", str(tmp_path))
    s = VaultStore.create(tmp_path / "vault.enc", "bon-mot-de-passe")
    s.set("GH_TOKEN", SECRET)
    win = MainWindow(s, BrokerServer())
    yield win
    win.close()


def test_lock_unplugs_broker_then_reattaches_after_unlock(window: MainWindow, tmp_path, monkeypatch) -> None:
    seen: list[bool] = []

    def fake_unlock(parent):
        seen.append(window._server._broker is None)  # pendant le verrouillage, plus aucun courtier
        return VaultStore.open(tmp_path / "vault.enc", "bon-mot-de-passe")

    monkeypatch.setattr(app_module, "unlock", fake_unlock)
    window.lock()
    assert seen == [True]
    assert window._server._broker is not None


def test_lock_clears_copied_secret(window: MainWindow, tmp_path, monkeypatch) -> None:
    window._table.selectRow(0)
    window._copy()
    assert QApplication.clipboard().text() == SECRET
    monkeypatch.setattr(app_module, "unlock", lambda parent: VaultStore.open(tmp_path / "vault.enc", "bon-mot-de-passe"))
    window.lock()
    assert QApplication.clipboard().text() != SECRET


def test_cancelling_unlock_quits(window: MainWindow, monkeypatch) -> None:
    quits: list[int] = []
    monkeypatch.setattr(app_module, "unlock", lambda parent: None)
    monkeypatch.setattr(QApplication, "quit", staticmethod(lambda: quits.append(1)))
    window.lock()
    assert quits == [1]
    assert window._server._broker is None


# --- démarrage -----------------------------------------------------------------------------


def test_second_instance_shows_message_and_exits(qapp, monkeypatch) -> None:
    shown: list[str] = []

    def busy(self):
        raise RuntimeError("Canal local indisponible")

    monkeypatch.setattr(BrokerServer, "start", busy)
    monkeypatch.setattr(QMessageBox, "critical", staticmethod(lambda parent, title, text: shown.append(text)))
    assert app_module.main() == 1
    assert "déjà ouvert" in shown[0]


def test_run_without_arguments_opens_gui_and_with_arguments_runs_cli(monkeypatch) -> None:
    import vault.app
    import vault.cli

    monkeypatch.setattr(vault.app, "main", lambda: 11)
    monkeypatch.setattr(vault.cli, "main", lambda argv: 22 if argv == ["list"] else 99)
    assert run([]) == 11
    assert run(["list"]) == 22
